#include "verifycontroller.h"
#include "authcontroller.h"
#include "tofumanager.h"
#include "logger.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>

VerifyController::VerifyController(INetworkManager  *networkManager,
                                   AuthController   *authController,
                                   ICryptoService   *cryptoService,
                                   TofuManager *tofuManager,
                                   QObject          *parent)
    : QObject(parent)
    , m_networkManager(networkManager)
    , m_authController(authController)
    , m_cryptoService(cryptoService)
    , m_tofuManager(tofuManager)
{
    // Listen for challengeResult → onChallengeReceived
    connect(m_networkManager, &INetworkManager::challengeResult,
            this, &VerifyController::onChallengeReceived);

    // Listen for getPreKeyBundleResult
    connect(m_networkManager, &INetworkManager::getPreKeyBundleResult,
            this, &VerifyController::onGetPreKeyBundleResult);

    // Listen for getBackupTOFUResult
    connect(m_networkManager, &INetworkManager::getBackupTOFUResult,
            this, &VerifyController::onGetBackupTOFUResult);

    // Listen for backupTOFUResult
    connect(m_networkManager, &INetworkManager::backupTOFUResult,
            this, &VerifyController::onBackupTOFUResult);

    // Whenever TofuManager changes its list, update GUI & push backup if needed
    connect(m_tofuManager, &TofuManager::listChanged, this, [=](const QVector<VerifiedUser> &vec){
        QList<VerifiedUser> list = toQList(vec);
        emit updateVerifiedUsersList(list);
    });
    connect(m_tofuManager, &TofuManager::backupNeeded, this, [=]{
        QString me = m_authController->getSessionUsername();
        if (me.isEmpty()) {
            emit tofuBackupResult(false, "Not logged in");
            return;
        }
        m_pendingOperation = "backup_tofu";
        m_networkManager->requestChallenge(me, "backup_tofu");
    });

    connect(m_authController, &AuthController::loggedOut, this, &VerifyController::onLoggedOut);
}

QList<VerifiedUser> VerifyController::toQList(const QVector<VerifiedUser> &vec)
{
    QList<VerifiedUser> list;
    for (const auto &vu : vec) list.append(vu);
    return list;
}

void VerifyController::initializeVerifyPage()
{
    QString username = m_authController->getSessionUsername();
    if (username.isEmpty()) {
        m_tofuManager->clear();
        emit tofuLoadCompleted({}, "Not logged in");
        return;
    }

    // clear any existing in-memory list
    m_tofuManager->clear();

    // fetch existing TOFU backup from server
    m_pendingOperation = "get_backup_tofu";
    m_networkManager->requestChallenge(username, "get_backup_tofu");
}

void VerifyController::onLoggedOut()
{
    m_tofuManager->clear();
    emit tofuLoadCompleted({}, "Logged out");
}

void VerifyController::onChallengeReceived(const QByteArray &nonce,
                                           const QString   &operation)
{
    // get_backup_tofu fetch remote encrypted backup
    if (operation == "get_backup_tofu") {
        QString me = m_authController->getSessionUsername();
        if (me.isEmpty()) {
            emit tofuLoadCompleted({}, "Not logged in");
            return;
        }
        QByteArray sig = m_cryptoService->sign(nonce, m_authController->getSessionSecretKey());
        QJsonObject req{
            { "username", me },
            { "nonce",    QString::fromUtf8(nonce.toBase64()) },
            { "signature",QString::fromUtf8(sig.toBase64()) }
        };
        m_networkManager->getBackupTOFU(req);
    }

    // backup_tofu, push local in-memory list to server
    else if (operation == "backup_tofu") {
        QString me = m_authController->getSessionUsername();
        if (me.isEmpty()) {
            emit tofuBackupResult(false, "Not logged in");
            return;
        }
        QByteArray sig = m_cryptoService->sign(nonce, m_authController->getSessionSecretKey());
        QString encryptedB64, nonceB64;
        m_tofuManager->getEncryptedBackup(encryptedB64, nonceB64);
        QJsonObject req{
            { "username",         me },
            { "encrypted_backup", encryptedB64 },
            { "backup_nonce",     nonceB64 },
            { "nonce",            QString::fromUtf8(nonce.toBase64()) },
            { "signature",        QString::fromUtf8(sig.toBase64()) }
        };
        m_networkManager->backupTOFU(req);
    }

    // get_pre_key_bundle
    else if (operation == "get_pre_key_bundle") {
        if (m_pendingTargetUsername.isEmpty()) {
            Logger::log("No target username set for get_pre_key_bundle");
            emit oobCodeReady("", "Internal error (no target set)");
            return;
        }
        QString me = m_authController->getSessionUsername();
        if (me.isEmpty()) {
            emit oobCodeReady("", "Not logged in");
            return;
        }
        QByteArray sig = m_cryptoService->sign(nonce, m_authController->getSessionSecretKey());
        QJsonObject req{
            { "username",        me },
            { "target_username", m_pendingTargetUsername },
            { "nonce",           QString::fromUtf8(nonce.toBase64()) },
            { "signature",       QString::fromUtf8(sig.toBase64()) }
        };
        m_networkManager->getPreKeyBundle(req);
    }
}

void VerifyController::onGetPreKeyBundleResult(bool success,
                                               const QString &ik_pub_b64,
                                               const QString &/*spk_pub_b64*/,
                                               const QString &/*spk_sig_b64*/,
                                               const QString &message)
{
    if (!success) {
        emit oobCodeReady("", message);
        return;
    }

    // Decode the target’s IK_pub
    QByteArray theirIkPub = QByteArray::fromBase64(ik_pub_b64.toUtf8());

    // our IK comes from AuthController (loaded from backup)
    QByteArray ourIkPub   = m_authController->getIdentityPublicKey();

    Logger::log("OOB: ourIkPub   = " + QString::fromUtf8(ourIkPub.toHex()));
    Logger::log("OOB: theirIkPub = " + QString::fromUtf8(theirIkPub.toHex()));

    if (theirIkPub.isEmpty() || ourIkPub.isEmpty()) {
        emit oobCodeReady("", "Failed to retrieve identity keys");
        return;
    }

    // Compute the OOB code, AKA sort the two byte arrays, concat, SHA-256, hex, take first 60 chars
    QString code = m_cryptoService->computeOOBVerificationCode(ourIkPub, theirIkPub);
    emit oobCodeReady(code, "");

    // instead of verifying the user here, we should stash their username and IK in a map in verify controller
    if (m_pendingOperation == "get_pre_key_bundle" &&
        !m_pendingTargetUsername.isEmpty())
    {
        // stash targetUsername, theirIkPub in our map
        m_stashedUsers.insert(m_pendingTargetUsername, theirIkPub);

        // clear these so we don’t reuse them by accident
        m_pendingTargetUsername.clear();
        m_pendingOperation.clear();
    }
}

void VerifyController::onGetBackupTOFUResult(bool success,
                                             const QString &encrypted_backup_b64,
                                             const QString &backup_nonce_b64,
                                             const QString &message)
{
    if (!success) {
        // No existing backup or error, simply emit the local (empty) list
        QVector<VerifiedUser> emptyVec = m_tofuManager->verifiedUsers();
        QList<VerifiedUser>   emptyList = toQList(emptyVec);
        emit tofuLoadCompleted(emptyList, message);
        return;
    }

    // We got an encrypted backup, decrypt and populate TofuManager
    m_tofuManager->loadFromRemote(encrypted_backup_b64, backup_nonce_b64);
    QVector<VerifiedUser> loadedVec = m_tofuManager->verifiedUsers();
    QList<VerifiedUser>   loadedList = toQList(loadedVec);

    emit tofuLoadCompleted(loadedList, "");
}

void VerifyController::onBackupTOFUResult(bool success, const QString &message)
{
    emit tofuBackupResult(success, message);
}

void VerifyController::generateOOBCode(const QString &targetUsername)
{
    if (targetUsername.isEmpty()) {
        emit oobCodeReady("", "Enter a target username first");
        return;
    }
    QString me = m_authController->getSessionUsername();
    if (me.isEmpty()) {
        emit oobCodeReady("", "Not logged in");
        return;
    }
    m_pendingTargetUsername.clear();
    m_pendingTargetUsername = targetUsername;
    m_pendingOperation.clear();
    m_pendingOperation = "get_pre_key_bundle";
    m_networkManager->requestChallenge(me, "get_pre_key_bundle");
}

void VerifyController::verifyNewUser(const QString &targetUsername)
{
    if (targetUsername.isEmpty()) {
        emit oobCodeReady("", "Enter a username to verify");
        return;
    }

    if (!m_stashedUsers.contains(targetUsername)) {
        // either they never clicked “Generate Code” or the stash was cleared
        emit oobCodeReady("", "No pre-generated OOB code for '" + targetUsername + "'");
        return;
    }

    // Retrieve and remove from stash
    QByteArray theirIkPub = m_stashedUsers.value(targetUsername);
    m_stashedUsers.remove(targetUsername);

    // Now truly verify: add to the TofuManager
    m_tofuManager->addVerifiedUser(targetUsername, theirIkPub);
}

void VerifyController::deleteVerifiedUser(const QString &targetUsername)
{
    m_tofuManager->removeVerifiedUser(targetUsername);
}
