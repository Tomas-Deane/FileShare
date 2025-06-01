#include "profilecontroller.h"
#include "authcontroller.h"
#include "logger.h"

ProfileController::ProfileController(INetworkManager *netMgr,
                                     AuthController  *authController,
                                     ICryptoService  *cryptoService,
                                     QObject         *parent)
    : QObject(parent)
    , m_networkManager(netMgr)
    , m_authController(authController)
    , m_cryptoService(cryptoService)
{
    connect(m_networkManager, &INetworkManager::challengeResult,
            this, &ProfileController::onChallengeReceived);
    connect(m_networkManager, &INetworkManager::changeUsernameResult,
            this, &ProfileController::onChangeUsernameNetwork);
    connect(m_networkManager, &INetworkManager::changePasswordResult,
            this, &ProfileController::onChangePasswordNetwork);
}

void ProfileController::changeUsername(const QString &newUsername)
{
    if (m_authController->getSessionUsername().isEmpty()) {
        emit changeUsernameResult(false, "Not logged in");
        return;
    }
    m_pendingNewUsername = newUsername;
    m_networkManager->requestChallenge(
        m_authController->getSessionUsername(),
        "change_username"
        );
}

void ProfileController::changePassword(const QString &newPassword)
{
    if (m_authController->getSessionUsername().isEmpty()) {
        emit changePasswordResult(false, "Not logged in");
        return;
    }
    m_pendingNewPassword = newPassword;

    // generate new salt + Argon2 params with high security settings
    m_pendingSalt     = m_cryptoService->randomBytes(16);
    m_pendingOpsLimit = ICryptoService::OPSLIMIT_HIGH;
    m_pendingMemLimit = ICryptoService::MEMLIMIT_HIGH;

    // derive a brand‐new PDK
    QByteArray newPdk = m_cryptoService->deriveKey(
        newPassword,
        m_pendingSalt,
        m_pendingOpsLimit,
        m_pendingMemLimit
        );

    // re-encrypt both the long-term secrets under that new PDK
    //    first, the user's private signing key
    m_pendingEncryptedSK = m_cryptoService->encrypt(
        m_authController->getSessionSecretKey(),
        newPdk,
        m_pendingPrivKeyNonce
        );
    // then the existing file‐encryption KEK
    m_pendingEncryptedKek = m_cryptoService->encrypt(
        m_authController->getSessionKek(),
        newPdk,
        m_pendingKekNonce
        );

    // install the new PDK into your Auth session
    m_authController->updateSessionPdk(newPdk);

    // zero out *your* copy immediately
    m_cryptoService->secureZeroMemory(newPdk);

    m_networkManager->requestChallenge(
        m_authController->getSessionUsername(),
        "change_password"
        );
}

void ProfileController::onChallengeReceived(const QByteArray &nonce,
                                            const QString &operation)
{
    if (operation == "change_username") {
        processChangeUsername(nonce);
    } else if (operation == "change_password") {
        processChangePassword(nonce);
    }
}

void ProfileController::processChangeUsername(const QByteArray &nonce)
{
    QByteArray sig = m_cryptoService->sign(
        m_pendingNewUsername.toUtf8(),
        m_authController->getSessionSecretKey()
        );
    QJsonObject req{
        { "username",      m_authController->getSessionUsername() },
        { "new_username",  m_pendingNewUsername },
        { "nonce",         QString::fromUtf8(nonce.toBase64()) },
        { "signature",     QString::fromUtf8(sig.toBase64()) }
    };
    m_networkManager->changeUsername(req);
}

void ProfileController::processChangePassword(const QByteArray &nonce)
{
    QByteArray sig = m_cryptoService->sign(
        m_pendingEncryptedSK,
        m_authController->getSessionSecretKey()
        );
    QJsonObject req{
        { "username",          m_authController->getSessionUsername() },
        { "salt",              QString::fromUtf8(m_pendingSalt.toBase64()) },
        { "argon2_opslimit",   int(m_pendingOpsLimit) },
        { "argon2_memlimit",   int(m_pendingMemLimit) },
        { "encrypted_privkey", QString::fromUtf8(m_pendingEncryptedSK.toBase64()) },
        { "privkey_nonce",     QString::fromUtf8(m_pendingPrivKeyNonce.toBase64()) },
        { "encrypted_kek",     QString::fromUtf8(m_pendingEncryptedKek.toBase64()) },
        { "kek_nonce",         QString::fromUtf8(m_pendingKekNonce.toBase64()) },
        { "nonce",             QString::fromUtf8(nonce.toBase64()) },
        { "signature",         QString::fromUtf8(sig.toBase64()) }
    };
    m_networkManager->changePassword(req);
}

void ProfileController::onChangeUsernameNetwork(bool success, const QString &message)
{
    if (success) {
        m_authController->updateSessionUsername(m_pendingNewUsername);
    }
    m_pendingNewUsername.clear();
    emit changeUsernameResult(success, message);
}

void ProfileController::onChangePasswordNetwork(bool success, const QString &message)
{
    m_pendingNewPassword.clear();
    emit changePasswordResult(success, message);
}
