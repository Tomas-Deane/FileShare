#include "sharecontroller.h"
#include "authcontroller.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QByteArray>
#include <QVector>

ShareController::ShareController(INetworkManager *networkManager,
                                 AuthController  *authController,
                                 ICryptoService  *cryptoService,
                                 QObject         *parent)
    : QObject(parent)
    , m_networkManager(networkManager)
    , m_authController(authController)
    , m_cryptoService(cryptoService)
{
    // Listen for *any* challenge. We'll filter by operation name ourselves.
    connect(m_networkManager, &INetworkManager::challengeResult,
            this, &ShareController::onChallenge);

    //  Server responses:
    connect(m_networkManager, &INetworkManager::getPreKeyBundleResult,
            this, &ShareController::onGetPreKeyBundleResult);

    connect(m_networkManager, &INetworkManager::retrieveFileDEKResult,
            this, &ShareController::onRetrieveFileDEKResult);

    // listen for OPK result
    connect(m_networkManager, &INetworkManager::getOPKResult,
            this, &ShareController::onGetOPKResult);

    connect(m_networkManager, &INetworkManager::shareFileResult,
            this, &ShareController::onShareFileNetwork);

    connect(m_networkManager, &INetworkManager::listSharedToResult,
            this, &ShareController::onListSharedToNetwork);

    connect(m_networkManager, &INetworkManager::listSharedFromResult,
            this, &ShareController::onListSharedFromNetwork);

    connect(m_networkManager, &INetworkManager::listSharersResult,
            this, &ShareController::onListSharersNetwork);

    //  handle download_shared_file responses
    connect(m_networkManager, &INetworkManager::downloadSharedFileResult,
            this, &ShareController::onDownloadSharedNetwork);

    // listen for removeSharedFile result
    connect(m_networkManager, &INetworkManager::removeSharedFileResult,
            this, &ShareController::onRemoveSharedFileNetwork);
}

// Start the “share file” flow.
void ShareController::shareFile(qint64 fileId, const QString &recipientUsername)
{
    if (m_authController->getSessionUsername().isEmpty()) {
        emit shareFileResult(false, "Not logged in");
        return;
    }

    m_pendingOp = GetPreKeyBundle;
    m_pendingRecipient = recipientUsername;
    m_pendingFileId = fileId;

    // Ask server for our challenge for “get_pre_key_bundle”
    QString me = m_authController->getSessionUsername();
    m_networkManager->requestChallenge(me, "get_pre_key_bundle");
}

// List files I shared TO targetUsername
void ShareController::listFilesSharedTo(const QString &targetUsername)
{
    if (m_authController->getSessionUsername().isEmpty()) {
        emit listSharedToResult(false, {}, "Not logged in");
        return;
    }

    m_pendingOp = ListSharedTo;
    m_pendingTargetUsername = targetUsername;

    QString me = m_authController->getSessionUsername();
    m_networkManager->requestChallenge(me, "list_shared_to");
}

// List files shared FROM targetUsername TO me
void ShareController::listFilesSharedFrom(const QString &targetUsername)
{
    if (m_authController->getSessionUsername().isEmpty()) {
        emit listSharedFromResult(false, {}, "Not logged in");
        return;
    }

    m_pendingOp = ListSharedFrom;
    m_pendingTargetUsername = targetUsername;

    QString me = m_authController->getSessionUsername();
    m_networkManager->requestChallenge(me, "list_shared_from");
}

void ShareController::listSharers()
{
    if (m_authController->getSessionUsername().isEmpty()) {
        emit listSharersResult(false, {}, "Not logged in");
        return;
    }

    m_pendingOp = ListSharers;
    QString me = m_authController->getSessionUsername();

    // Request a challenge for “list_sharers”
    m_networkManager->requestChallenge(me, "list_sharers");
}



// Called whenever ANY challengeResult arrives. We look at m_pendingOp to decide what to do next
void ShareController::onChallenge(const QByteArray &nonce, const QString &operation)
{
    QString me = m_authController->getSessionUsername();
    if (me.isEmpty()) return;

    switch (m_pendingOp) {
    case GetPreKeyBundle:
        if (operation == "get_pre_key_bundle") {
            // sign the nonce
            QByteArray sig = m_cryptoService->sign(
                nonce,
                m_authController->getSessionSecretKey()
                );

            QJsonObject req {
                { "username",        me },
                { "target_username", m_pendingRecipient },
                { "nonce",           QString::fromUtf8(nonce.toBase64()) },
                { "signature",       QString::fromUtf8(sig.toBase64()) }
            };
            m_networkManager->getPreKeyBundle(req);
        }
        break;

    case RetrieveFileDEK:
        if (operation == "retrieve_file_dek") {
            QByteArray sig = m_cryptoService->sign(
                nonce,
                m_authController->getSessionSecretKey()
                );
            QJsonObject req {
                { "username", me },
                { "file_id",  m_pendingFileId },
                { "nonce",    QString::fromUtf8(nonce.toBase64()) },
                { "signature", QString::fromUtf8(sig.toBase64()) }
            };
            m_networkManager->retrieveFileDEK(req);
        }
        break;

    case GetOPK:
        if (operation == "get_opk") {
            // Sign the nonce to request an OPK for the recipient
            QByteArray sig = m_cryptoService->sign(
                nonce,
                m_authController->getSessionSecretKey()
                );

            QJsonObject req {
                { "username",        me },
                { "target_username", m_pendingRecipient },
                { "nonce",           QString::fromUtf8(nonce.toBase64()) },
                { "signature",       QString::fromUtf8(sig.toBase64()) }
            };
            m_networkManager->getOPK(req);
        }
        break;

    case DoShareFile:
        if (operation == "share_file") {
            // Generate a fresh ephemeral X25519 keypair (EK_i)
            QByteArray ekPub, ekPriv;
            m_cryptoService->generateX25519KeyPair(ekPub, ekPriv);

            QByteArray ourIkPriv     = m_authController->getIdentityPrivateKey();
            QByteArray ourSpkPriv    = m_authController->getSignedPreKeyPrivate();
            QByteArray theirIkPub    = m_recipientIkPub;      // stashed in onGetPreKeyBundleResult
            QByteArray theirSpkPub   = m_recipientSpkPub;     // stashed in onGetPreKeyBundleResult
            QByteArray theirOpkPub   = m_stashedOpkPreKey;    // stashed in onGetOPKResult

            // Compute the four DH outputs (each 32 bytes):
            QByteArray dh1 = m_cryptoService->deriveSharedKey( ourIkPriv,  theirSpkPub );
            QByteArray dh2 = m_cryptoService->deriveSharedKey( ekPriv,     theirIkPub );
            QByteArray dh3 = m_cryptoService->deriveSharedKey( ekPriv,     theirSpkPub );
            QByteArray dh4 = m_cryptoService->deriveSharedKey( ekPriv,     theirOpkPub );

            if (dh1.isEmpty() || dh2.isEmpty() || dh3.isEmpty() || dh4.isEmpty()) {
                emit shareFileResult(false, "Failed to compute DHs for X3DH");
                m_pendingOp = None;
                return;
            }

            // Concatenate the four DH outputs (128 bytes total)
            QByteArray concatenatedDH = dh1 + dh2 + dh3 + dh4;

            // HKDF-SHA256 over concatenatedDH → 32-byte sharedKey
            QByteArray zeroSalt(32, '\0');
            QByteArray sharedKey = m_cryptoService->hkdfSha256(
                zeroSalt,
                concatenatedDH,
                32
                );
            if (sharedKey.size() != 32) {
                emit shareFileResult(false, "HKDF output error");
                m_pendingOp = None;
                return;
            }

            // Decrypt the file’s encrypted DEK under our session KEK
            QByteArray serverEncryptedDek = m_stashedEncryptedDek;
            QByteArray serverDekNonce     = m_stashedDekNonce;
            QByteArray fileDek = m_cryptoService->decrypt(
                serverEncryptedDek,
                m_authController->getSessionKek(),
                serverDekNonce
                );
            if (fileDek.isEmpty()) {
                emit shareFileResult(false, "Failed to decrypt file DEK");
                m_pendingOp = None;
                return;
            }

            // Re-encrypt the DEK under the new sharedKey
            QByteArray newDekNonce;
            QByteArray encryptedDekForRecipient =
                m_cryptoService->encrypt(fileDek, sharedKey, newDekNonce);

            // Zero out the plaintext DEK immediately
            m_cryptoService->secureZeroMemory(fileDek);

            // Sign the encrypted DEK before sending
            QByteArray sig = m_cryptoService->sign(
                encryptedDekForRecipient,
                m_authController->getSessionSecretKey()
                );

            // Build JSON payload for /share_file
            //     Include: EK_pub, IK_pub, SPK_pub, SPK_signature, OPK_ID, encrypted_file_key, file_key_nonce, nonce, signature
            QByteArray ikPub   = m_authController->getIdentityPublicKey();
            QByteArray spkPub  = m_authController->getSignedPreKeyPublic();
            QByteArray spkSig  = m_authController->getSignedPreKeySignature();

            QJsonObject req {
                { "username",               me },
                { "file_id",                m_pendingFileId },
                { "recipient_username",     m_pendingRecipient },
                { "signature",              QString::fromUtf8(sig.toBase64()) },
                { "EK_pub",                 QString::fromUtf8(ekPub.toBase64()) },
                { "IK_pub",                 QString::fromUtf8(ikPub.toBase64()) },
                { "SPK_pub",                QString::fromUtf8(spkPub.toBase64()) },
                { "SPK_signature",          QString::fromUtf8(spkSig.toBase64()) },
                { "OPK_ID",                 m_stashedOpkId },
                { "encrypted_file_key",     QString::fromUtf8(encryptedDekForRecipient.toBase64()) },
                { "file_key_nonce",         QString::fromUtf8(newDekNonce.toBase64()) },
                { "nonce",                  QString::fromUtf8(nonce.toBase64()) }
            };

            m_networkManager->shareFile(req);
        }
        break;

    case ListSharedTo:
        if (operation == "list_shared_to") {
            QByteArray sig = m_cryptoService->sign(
                nonce,
                m_authController->getSessionSecretKey()
                );
            QJsonObject req {
                { "username",         me },
                { "target_username",  m_pendingTargetUsername },
                { "nonce",            QString::fromUtf8(nonce.toBase64()) },
                { "signature",        QString::fromUtf8(sig.toBase64()) }
            };
            m_networkManager->listSharedTo(req);
        }
        break;

    case ListSharedFrom:
        if (operation == "list_shared_from") {
            QByteArray sig = m_cryptoService->sign(
                nonce,
                m_authController->getSessionSecretKey()
                );
            QJsonObject req {
                { "username",         me },
                { "target_username",  m_pendingTargetUsername },
                { "nonce",            QString::fromUtf8(nonce.toBase64()) },
                { "signature",        QString::fromUtf8(sig.toBase64()) }
            };
            m_networkManager->listSharedFrom(req);
        }
        break;

    case ListSharers:
        if (operation == "list_sharers") {
            QByteArray sig = m_cryptoService->sign(
                nonce,
                m_authController->getSessionSecretKey()
                );
            QJsonObject req {
                { "username",        me },
                { "target_username", me }, // “Who shared to me?”
                { "nonce",           QString::fromUtf8(nonce.toBase64()) },
                { "signature",       QString::fromUtf8(sig.toBase64()) }
            };
            m_networkManager->listSharers(req);
        }
        break;

    case DownloadSharedFile:
        if (operation == "download_shared_file") {
            // Server only needs a signature over share_id (ASCII)
            QByteArray shareIdBytes = QByteArray::number(m_pendingShareId);
            QByteArray sig = m_cryptoService->sign(
                shareIdBytes,
                m_authController->getSessionSecretKey()
                );

            QJsonObject req {
                { "username",    m_authController->getSessionUsername() },
                { "share_id",    m_pendingShareId },
                { "nonce",       QString::fromUtf8(nonce.toBase64()) },
                { "signature",   QString::fromUtf8(sig.toBase64()) }
            };
            m_networkManager->downloadSharedFile(req);
        }
        break;

    case RevokeShare:
        if (operation == "remove_shared_file") {
            // Sign the ASCII‐encoded share_id
            QByteArray shareIdBytes = QByteArray::number(m_pendingShareId);
            QByteArray sig = m_cryptoService->sign(
                shareIdBytes,
                m_authController->getSessionSecretKey()
                );

            QJsonObject req {
                { "username",    me },
                { "share_id",    m_pendingShareId },
                { "nonce",       QString::fromUtf8(nonce.toBase64()) },
                { "signature",   QString::fromUtf8(sig.toBase64()) }
            };
            m_networkManager->removeSharedFile(req);
        }
        break;

    default:
        break;
    }
}

void ShareController::onRemoveSharedFileNetwork(bool success, const QString &message)
{
    // Propagate the result back to whoever called revokeAccess()
    emit removeSharedFileResult(success, message);
    m_pendingOp = None;
}

// After /get_pre_key_bundle returns:
void ShareController::onGetPreKeyBundleResult(bool success,
                                              const QString &ik_pub_b64,
                                              const QString &spk_pub_b64,
                                              const QString &spk_sig_b64,
                                              const QString &message)
{
    if (!success) {
        emit shareFileResult(false, message);
        m_pendingOp = None;
        return;
    }

    // 1) Decode the recipient’s IK_pub
    m_recipientIkPub = QByteArray::fromBase64(ik_pub_b64.toUtf8());
    if (m_recipientIkPub.size() != X25519_PUBKEY_LEN) {
        emit shareFileResult(false, "Invalid recipient IK_pub");
        m_pendingOp = None;
        return;
    }

    // 2) Decode and stash the recipient’s SPK_pub and its signature
    m_recipientSpkPub       = QByteArray::fromBase64(spk_pub_b64.toUtf8());
    m_recipientSpkSignature = QByteArray::fromBase64(spk_sig_b64.toUtf8());
    if (m_recipientSpkPub.size() != X25519_PUBKEY_LEN) {
        emit shareFileResult(false, "Invalid recipient SPK_pub");
        m_pendingOp = None;
        return;
    }

    // 3) Next: fetch the file’s existing encrypted DEK from server
    m_pendingOp = RetrieveFileDEK;
    QString me = m_authController->getSessionUsername();
    m_networkManager->requestChallenge(me, "retrieve_file_dek");
}


// After /retrieve_file_dek returns:
void ShareController::onRetrieveFileDEKResult(bool success,
                                              const QString &encryptedDekB64,
                                              const QString &dekNonceB64,
                                              const QString &message)
{
    if (!success) {
        emit shareFileResult(false, message);
        m_pendingOp = None;
        return;
    }

    // 1) Stash the file’s encrypted DEK & nonce for later re‐encryption:
    m_stashedEncryptedDek = QByteArray::fromBase64(encryptedDekB64.toUtf8());
    m_stashedDekNonce     = QByteArray::fromBase64(dekNonceB64.toUtf8());

    // 2) Next: fetch exactly one OPK for the recipient
    m_pendingOp = GetOPK;
    QString me = m_authController->getSessionUsername();
    m_networkManager->requestChallenge(me, "get_opk");
}


// After /share_file completes:
void ShareController::onShareFileNetwork(bool success, const QString &message)
{
    emit shareFileResult(success, message);
    m_pendingOp = None;
}

// After /list_shared_to completes:
void ShareController::onListSharedToNetwork(bool success,
                                            const QJsonArray &shares,
                                            const QString &message)
{
    if (!success) {
        emit listSharedToResult(false, {}, message);
        m_pendingOp = None;
        return;
    }
    QList<SharedFile> list = parseSharedArray(shares);
    emit listSharedToResult(true, list, QString());
    m_pendingOp = None;
}

// After /list_shared_from completes:
void ShareController::onListSharedFromNetwork(bool success,
                                              const QJsonArray &shares,
                                              const QString &message)
{
    if (!success) {
        emit listSharedFromResult(false, {}, message);
        m_pendingOp = None;
        return;
    }

    QList<SharedFile> list = parseSharedArray(shares);
    emit listSharedFromResult(true, list, QString());
    m_pendingOp = None;
}

void ShareController::onGetOPKResult(bool success,
                                     int opk_id,
                                     const QString &pre_key_b64,
                                     const QString &message)
{
    if (!success) {
        emit shareFileResult(false, message);
        m_pendingOp = None;
        return;
    }

    // Stash the OPK ID and raw OPK public:
    m_stashedOpkId     = opk_id;
    m_stashedOpkPreKey = QByteArray::fromBase64(pre_key_b64.toUtf8());
    if (m_stashedOpkPreKey.size() != X25519_PUBKEY_LEN) {
        emit shareFileResult(false, "Invalid OPK from server");
        m_pendingOp = None;
        return;
    }

    // Now request a challenge for “share_file” so we can do DoShareFile():
    m_pendingOp = DoShareFile;
    QString me = m_authController->getSessionUsername();
    m_networkManager->requestChallenge(me, "share_file");
}

void ShareController::onListSharersNetwork(bool success,
                                           const QStringList &usernames,
                                           const QString &message)
{
    if (!success) {
        emit listSharersResult(false, {}, message);
    } else {
        emit listSharersResult(true, usernames, QString());
    }
    m_pendingOp = None;
}

void ShareController::downloadSharedFile(qint64 shareId, const QString &filename)
{
    if (m_authController->getSessionUsername().isEmpty()) {
        emit downloadSharedFileResult(false, QString(), QByteArray(), "Not logged in");
        return;
    }

    m_pendingOp        = DownloadSharedFile;
    m_pendingShareId   = shareId;
    m_pendingFilename  = filename;

    QString me = m_authController->getSessionUsername();
    // Request a challenge for “download_shared_file”
    m_networkManager->requestChallenge(me, "download_shared_file");
}

void ShareController::onDownloadSharedNetwork(bool success,
                                              const QString &encryptedFileB64,
                                              const QString &fileNonceB64,
                                              const QString &encryptedFileKeyB64,
                                              const QString &fileKeyNonceB64,
                                              const QString &EK_pub_b64,
                                              const QString &IK_pub_b64,
                                              const QString &SPK_pub_b64,
                                              const QString &SPK_sig_b64,
                                              int            opk_id,
                                              const QString &message)
{
    if (!success) {
        emit downloadSharedFileResult(false, QString(), QByteArray(), message);
        m_pendingOp = None;
        return;
    }

    // Base64 → raw buffers
    QByteArray encryptedFile    = QByteArray::fromBase64(encryptedFileB64.toUtf8());
    QByteArray fileNonce        = QByteArray::fromBase64(fileNonceB64.toUtf8());
    QByteArray encryptedFileKey = QByteArray::fromBase64(encryptedFileKeyB64.toUtf8());
    QByteArray fileKeyNonce     = QByteArray::fromBase64(fileKeyNonceB64.toUtf8());
    QByteArray ekPubInitiator   = QByteArray::fromBase64(EK_pub_b64.toUtf8());
    QByteArray ikPubInitiator   = QByteArray::fromBase64(IK_pub_b64.toUtf8());
    QByteArray spkPubInitiator  = QByteArray::fromBase64(SPK_pub_b64.toUtf8());

    // Retrieve our private keys
    QByteArray ourIkPriv  = m_authController->getIdentityPrivateKey();
    QByteArray ourSpkPriv = m_authController->getSignedPreKeyPrivate();
    QList<QByteArray> allOpkPrivs = m_authController->getOneTimePreKeyPrivs();
    if (opk_id < 0 || opk_id >= allOpkPrivs.size()) {
        emit downloadSharedFileResult(false, QString(), QByteArray(), "Invalid OPK ID");
        m_pendingOp = None;
        return;
    }
    QByteArray ourOpkPriv = allOpkPrivs.at(opk_id);
    QByteArray dh1 = m_cryptoService->deriveSharedKey( ourSpkPriv, ikPubInitiator);
    QByteArray dh2 = m_cryptoService->deriveSharedKey( ourIkPriv, ekPubInitiator);
    QByteArray dh3 = m_cryptoService->deriveSharedKey( ourSpkPriv, ekPubInitiator);
    QByteArray dh4 = m_cryptoService->deriveSharedKey( ourOpkPriv, ekPubInitiator);

    // Concatenate ∥ run HKDF exactly as the sender did:
    QByteArray concatenatedDH = dh1 + dh2 + dh3 + dh4;
    QByteArray zeroSalt(32, '\0');
    QByteArray sharedKey = m_cryptoService->hkdfSha256(zeroSalt, concatenatedDH, 32);

    if (dh1.isEmpty() || dh2.isEmpty() || dh3.isEmpty() || dh4.isEmpty()) {
        emit downloadSharedFileResult(false, QString(), QByteArray(), "Failed to compute DHs");
        m_pendingOp = None;
        return;
    }
    if (sharedKey.size() != 32) {
        emit downloadSharedFileResult(false, QString(), QByteArray(), "HKDF output error");
        m_pendingOp = None;
        return;
    }

    // Decrypt the file’s encrypted DEK with sharedKey (NOT the session-KEK!)
    QByteArray fileDek = m_cryptoService->decrypt(encryptedFileKey, sharedKey, fileKeyNonce);
    if (fileDek.isEmpty()) {
        emit downloadSharedFileResult(false, QString(), QByteArray(), "Failed to decrypt file DEK");
        m_pendingOp = None;
        return;
    }

    // Decrypt the file body under that DEK
    QByteArray plaintext = m_cryptoService->decrypt(encryptedFile, fileDek, fileNonce);

    // Zero out the raw DEK
    m_cryptoService->secureZeroMemory(fileDek);

    // Emit back our filename and plaintext
    QString outFilename = m_pendingFilename;
    emit downloadSharedFileResult(true, outFilename, plaintext, QString());
    m_pendingOp = None;
}

void ShareController::revokeAccess(qint64 shareId)
{
    if (m_authController->getSessionUsername().isEmpty()) {
        emit removeSharedFileResult(false, "Not logged in");
        return;
    }

    m_pendingOp = RevokeShare;
    m_pendingShareId = shareId;

    QString me = m_authController->getSessionUsername();
    m_networkManager->requestChallenge(me, "remove_shared_file");
}

// Convert a JSON‐array of share records into QList<SharedFile>
QList<SharedFile> ShareController::parseSharedArray(const QJsonArray &arr) const
{
    QList<SharedFile> output;
    for (auto v : arr) {
        if (!v.isObject()) continue;
        QJsonObject o = v.toObject();
        SharedFile sf;
        sf.share_id  = qint64(o.value("share_id").toInt());
        sf.file_id   = qint64(o.value("file_id").toInt());
        sf.filename  = o.value("filename").toString();
        sf.shared_by = o.value("shared_by").toString();
        sf.shared_at = o.value("shared_at").toString();
        output.append(sf);
    }
    return output;
}
