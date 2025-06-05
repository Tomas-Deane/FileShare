#include "tofumanager.h"
#include "icryptoservice.h"
#include "authcontroller.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QByteArray>

TofuManager::TofuManager(ICryptoService    *cryptoService,
                         AuthController     *authController,
                         QObject            *parent)
    : QObject(parent)
    , m_cryptoService(cryptoService)
    , m_authController(authController)
{}

void TofuManager::clear()
{
    if (!m_list.isEmpty()) {
        m_list.clear();
        emit listChanged(m_list);
    }
}

QVector<VerifiedUser> TofuManager::verifiedUsers()
{
    return m_list;
}

void TofuManager::addVerifiedUser(const QString    &username,
                                  const QByteArray &ikPub)
{
    // Check if already present
    for (const auto &vu : m_list) {
        if (vu.username == username) {
            return; // no change
        }
    }

    VerifiedUser newVU;
    newVU.username = username;
    newVU.ikPub    = ikPub;
    m_list.append(newVU);

    emit listChanged(m_list);
    emit backupNeeded();
}

void TofuManager::removeVerifiedUser(const QString &username)
{
    for (int i = 0; i < m_list.size(); ++i) {
        if (m_list[i].username == username) {
            m_list.removeAt(i);
            emit listChanged(m_list);
            emit backupNeeded();
            return;
        }
    }
}

void TofuManager::loadFromRemote(const QString &encryptedB64,
                                 const QString &nonceB64)
{
    m_list.clear();

    // 1) Decode base64 → raw ciphertext + raw nonce
    QByteArray   ciphertext = QByteArray::fromBase64(encryptedB64.toUtf8());
    QByteArray   nonce      = QByteArray::fromBase64(nonceB64.toUtf8());

        // 2) Decrypt using sessionKek
            QByteArray sessionKek = m_authController->getSessionKek();
        QByteArray plain      = m_cryptoService->decrypt(ciphertext, sessionKek, nonce);

            if (plain.isEmpty()) {
                // Decryption failed; leave m_list empty and still emit
                    emit listChanged(m_list);
                return;
            }

            // 3) Parse the root JSON object (it contains all X3DH fields  "tofusers")
            QJsonDocument doc = QJsonDocument::fromJson(plain);
        if (!doc.isObject()) {
                // Invalid format
                    emit listChanged(m_list);
                return;
            }

            QJsonObject obj = doc.object();
        if (!obj.contains("tofusers") || !obj.value("tofusers").isArray()) {
                // No "tofusers" array → nothing to load
                    emit listChanged(m_list);
                return;
            }

            // 4) Extract the "tofusers" array and repopulate m_list
            QJsonArray arr = obj.value("tofusers").toArray();
    for (auto v : arr) {
        if (!v.isObject()) continue;
        QJsonObject obj = v.toObject();
        QString uname   = obj.value("username").toString();
        QByteArray ikPub = QByteArray::fromBase64(
            obj.value("ik_pub").toString().toUtf8()
            );
        if (!uname.isEmpty() && ikPub.size() == 32) {
            VerifiedUser vu;
            vu.username = uname;
            vu.ikPub    = ikPub;
            m_list.append(vu);
        }
    }

    emit listChanged(m_list);
}

void TofuManager::getEncryptedBackup(QString &outEncryptedB64,
                                     QString &outNonceB64)
{
            QJsonObject backupObj;

            // Identity keypair
            QByteArray ikPub   = m_authController->getIdentityPublicKey();
        QByteArray ikPriv  = m_authController->getIdentityPrivateKey();
        backupObj.insert("IK_pub",  QString::fromUtf8(ikPub.toBase64()));
        backupObj.insert("IK_priv", QString::fromUtf8(ikPriv.toBase64()));

            // Signed pre‐key  signature
            QByteArray spkPub  = m_authController->getSignedPreKeyPublic();
        QByteArray spkPriv = m_authController->getSignedPreKeyPrivate();
        QByteArray spkSig  = m_authController->getSignedPreKeySignature();
        backupObj.insert("SPK_pub",       QString::fromUtf8(spkPub.toBase64()));
        backupObj.insert("SPK_priv",      QString::fromUtf8(spkPriv.toBase64()));
        backupObj.insert("SPK_signature", QString::fromUtf8(spkSig.toBase64()));

            // One‐Time Pre‐Keys: public halves
            QJsonArray opkPubArray;
        const auto &opkPubs = m_authController->getOneTimePreKeyPubs();
        for (const QByteArray &pub : opkPubs) {
                opkPubArray.append(QString::fromUtf8(pub.toBase64()));
            }
        backupObj.insert("OPKs_pub", opkPubArray);

            // 1d) One‐Time Pre‐Keys: private halves
            QJsonArray opkPrivArray;
        const auto &opkPrivs = m_authController->getOneTimePreKeyPrivs();
        for (const QByteArray &priv : opkPrivs) {
                opkPrivArray.append(QString::fromUtf8(priv.toBase64()));
            }
        backupObj.insert("OPKs_priv", opkPrivArray);

            QJsonArray tofusersArray;
        for (const auto &vu : m_list) {
                QJsonObject entry;
                entry.insert("username", vu.username);
                entry.insert("ik_pub", QString::fromUtf8(vu.ikPub.toBase64()));
                tofusersArray.append(entry);
            }
        backupObj.insert("tofusers", tofusersArray);

            // Serialize the full JSON object to a compact QByteArray
            QJsonDocument doc(backupObj);
        QByteArray    plain = doc.toJson(QJsonDocument::Compact);

            // Encrypt the entire JSON blob under the session KEK.
            QByteArray sessionKek = m_authController->getSessionKek();
        QByteArray nonce;
        QByteArray ciphertext = m_cryptoService->encrypt(plain, sessionKek, nonce);

            // Base64-encode ciphertext and nonce for transport.
            outEncryptedB64 = QString::fromUtf8(ciphertext.toBase64());
        outNonceB64     = QString::fromUtf8(nonce.toBase64());
}
