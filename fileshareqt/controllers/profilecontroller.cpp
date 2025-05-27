#include "profilecontroller.h"
#include "authcontroller.h"
#include <sodium.h>
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

    m_pendingSalt.resize(16);
    randombytes_buf(reinterpret_cast<unsigned char *>(m_pendingSalt.data()),
                    m_pendingSalt.size());
    m_pendingOpsLimit = crypto_pwhash_OPSLIMIT_MODERATE;
    m_pendingMemLimit = crypto_pwhash_MEMLIMIT_MODERATE;

    QByteArray newPdk = m_cryptoService->deriveKey(newPassword,
                                                   m_pendingSalt,
                                                   m_pendingOpsLimit,
                                                   m_pendingMemLimit);
    m_pendingEncryptedSK = m_cryptoService->encrypt(
        m_authController->getSessionSecretKey(),
        newPdk,
        m_pendingPrivKeyNonce);
    m_pendingEncryptedKek = m_cryptoService->encrypt(
        m_authController->getSessionKek(),
        newPdk,
        m_pendingKekNonce);

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
