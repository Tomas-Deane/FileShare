#include "authcontroller.h"
#include "networkmanager.h"
#include "crypto_utils.h"
#include "logger.h"

#include <sodium.h>
#include <QJsonObject>
#include <QJsonDocument>

AuthController::AuthController(QObject *parent)
    : QObject(parent)
    , networkManager(new NetworkManager(this))
{
    // Signup / login
    connect(networkManager, &NetworkManager::signupResult,
            this, &AuthController::onSignupResult);
    connect(networkManager, &NetworkManager::loginChallenge,
            this, &AuthController::onLoginChallenge);
    connect(networkManager, &NetworkManager::loginResult,
            this, &AuthController::onLoginResult);

    // Generic challenge for change ops
    connect(networkManager, &NetworkManager::challengeResult,
            this, &AuthController::onChallengeReceived);

    // Change operations result
    connect(networkManager, &NetworkManager::changeUsernameResult,
            this, &AuthController::onChangeUsernameNetwork);
    connect(networkManager, &NetworkManager::changePasswordResult,
            this, &AuthController::onChangePasswordNetwork);

    connect(networkManager, &NetworkManager::networkError,
            this, [=](const QString &e){ Logger::log("Network error: " + e); });

    // Forward connection status
    connect(networkManager, &NetworkManager::connectionStatusChanged,
            this,           &AuthController::onConnectionStatusChanged);
}

void AuthController::signup(const QString &username, const QString &password)
{
    if (username.isEmpty() || password.isEmpty()) {
        Logger::log("Signup aborted: missing username or password");
        emit signupResult(false, "Missing username or password");
        return;
    }
    pendingUsername = username;
    pendingPassword = password;

    // 1) Generate salt
    QByteArray salt(16, 0);
    randombytes_buf(reinterpret_cast<unsigned char*>(salt.data()), 16);

    // 2) Derive PDK
    auto pdk = CryptoUtils::derivePDK(
        password, salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE
        );
    sessionPdk = pdk;

    // 3) Generate keypair
    QByteArray pubKey, secKey;
    CryptoUtils::generateKeyPair(pubKey, secKey);

    // 4) Encrypt secret key
    QByteArray skNonce;
    auto encryptedSK = CryptoUtils::encryptSecretKey(secKey, pdk, skNonce);

    // 5) Build and send signup request
    QJsonObject req{
        { "username", username },
        { "salt", QString::fromUtf8(salt.toBase64()) },
        { "argon2_opslimit", int(crypto_pwhash_OPSLIMIT_MODERATE) },
        { "argon2_memlimit", int(crypto_pwhash_MEMLIMIT_MODERATE) },
        { "public_key", QString::fromUtf8(pubKey.toBase64()) },
        { "encrypted_privkey", QString::fromUtf8(encryptedSK.toBase64()) },
        { "privkey_nonce", QString::fromUtf8(skNonce.toBase64()) }
    };
    networkManager->signup(req);
}

void AuthController::login(const QString &username, const QString &password)
{
    if (username.isEmpty() || password.isEmpty()) {
        Logger::log("Login aborted: missing username or password");
        emit loginResult(false, "Missing username or password");
        return;
    }
    pendingUsername = username;
    pendingPassword = password;

    networkManager->login(username);
}

void AuthController::logout()
{
    if (!sessionSecretKey.isEmpty()) {
        sodium_memzero(
            reinterpret_cast<unsigned char*>(sessionSecretKey.data()),
            sessionSecretKey.size()
            );
        sessionSecretKey.clear();
    }
    if (!sessionPdk.isEmpty()) {
        sodium_memzero(
            reinterpret_cast<unsigned char*>(sessionPdk.data()),
            sessionPdk.size()
            );
        sessionPdk.clear();
    }
    sessionUsername.clear();
    emit loggedOut();
}

void AuthController::onSignupResult(bool success, const QString &message)
{
    Logger::log(QString("SignupResult: success=%1, message='%2'")
                    .arg(success).arg(message));
    emit signupResult(success, message);
}

void AuthController::onLoginChallenge(
    const QByteArray &nonce,
    const QByteArray &salt,
    int opslimit,
    int memlimit,
    const QByteArray &encryptedSK,
    const QByteArray &skNonce
    )
{
    // 1) Derive the PDK
    auto pdk = CryptoUtils::derivePDK(pendingPassword, salt, opslimit, memlimit);
    sessionPdk = pdk;

    // 2) Decrypt the user’s signing key
    auto secKey = CryptoUtils::decryptSecretKey(encryptedSK, pdk, skNonce);
    sessionSecretKey = secKey;

    // 3) Sign the challenge
    auto signature = CryptoUtils::signMessage(nonce, sessionSecretKey);

    // 4) Send authenticate request (now including the original nonce)
    networkManager->authenticate(
        pendingUsername,
        nonce,
        signature
        );
}

void AuthController::onLoginResult(bool success, const QString &message)
{
    Logger::log(QString("LoginResult: success=%1, message='%2'")
                    .arg(success).arg(message));

    if (success) {
        sessionUsername = pendingUsername;
        pendingPassword.clear();
        pendingUsername.clear();
        emit loggedIn(sessionUsername);
    }

    emit loginResult(success, message);
}

void AuthController::changeUsername(const QString &newUsername)
{
    if (sessionUsername.isEmpty()) {
        emit changeUsernameResult(false, "Not logged in");
        return;
    }
    pendingNewUsername = newUsername;
    // Ask the server for a challenge
    networkManager->requestChallenge(sessionUsername, "change_username");
}

void AuthController::changePassword(const QString &newPassword)
{
    if (sessionUsername.isEmpty()) {
        emit changePasswordResult(false, "Not logged in");
        return;
    }

    // 1) Generate a new salt
    pendingSalt.fill(char(0), 16);
    pendingSalt.resize(16);
    randombytes_buf(reinterpret_cast<unsigned char*>(pendingSalt.data()), 16);

    // 2) Argon2 parameters
    pendingOpsLimit = crypto_pwhash_OPSLIMIT_MODERATE;
    pendingMemLimit = crypto_pwhash_MEMLIMIT_MODERATE;

    // 3) Derive the new PDK and encrypt the secret key
    auto newPdk = CryptoUtils::derivePDK(
        newPassword,
        pendingSalt,
        pendingOpsLimit,
        pendingMemLimit
        );

    pendingEncryptedSK = CryptoUtils::encryptSecretKey(
        sessionSecretKey,
        newPdk,
        pendingPrivKeyNonce
        );

    // 4) Ask the server for a challenge
    networkManager->requestChallenge(sessionUsername, "change_password");
}

void AuthController::onChallengeReceived(const QByteArray &nonce,
                                         const QString &operation)
{
    if (operation == "change_username") {
        processChangeUsername(nonce);
    } else if (operation == "change_password") {
        processChangePassword(nonce);
    } else {
        Logger::log("Unsupported operation received: " + operation);
    }
}

void AuthController::processChangeUsername(const QByteArray &nonce)
{
    auto sig = CryptoUtils::signMessage(
        pendingNewUsername.toUtf8(),
        sessionSecretKey
        );

    QJsonObject req{
        { "username", sessionUsername },
        { "new_username", pendingNewUsername },
        { "nonce", QString::fromUtf8(nonce.toBase64()) },
        { "signature", QString::fromUtf8(sig.toBase64()) }
    };
    networkManager->changeUsername(req);
}

void AuthController::processChangePassword(const QByteArray &nonce)
{
    auto sig = CryptoUtils::signMessage(
        pendingEncryptedSK,
        sessionSecretKey
        );

    QJsonObject req{
        { "username", sessionUsername },
        { "salt", QString::fromUtf8(pendingSalt.toBase64()) },
        { "argon2_opslimit", int(pendingOpsLimit) },
        { "argon2_memlimit", int(pendingMemLimit) },
        { "encrypted_privkey", QString::fromUtf8(pendingEncryptedSK.toBase64()) },
        { "privkey_nonce", QString::fromUtf8(pendingPrivKeyNonce.toBase64()) },
        { "nonce", QString::fromUtf8(nonce.toBase64()) },
        { "signature", QString::fromUtf8(sig.toBase64()) }
    };
    networkManager->changePassword(req);
}

void AuthController::onChangeUsernameNetwork(bool success, const QString &message)
{
    if (success) {
        sessionUsername = pendingNewUsername;
        emit loggedIn(sessionUsername);
    }
    pendingNewUsername.clear();
    emit changeUsernameResult(success, message);
}

void AuthController::onChangePasswordNetwork(bool success, const QString &message)
{
    emit changePasswordResult(success, message);
}

void AuthController::onConnectionStatusChanged(bool online)
{
    Logger::log(QString("AuthController: connection is now %1")
                    .arg(online ? "ONLINE" : "OFFLINE"));
    emit connectionStatusChanged(online);
}

void AuthController::checkConnection()
{
    networkManager->checkConnection();
}
