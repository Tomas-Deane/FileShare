#include "authcontroller.h"
#include "networkmanager.h"
#include "crypto_utils.h"
#include "logger.h"
#include <sodium.h>

AuthController::AuthController(QObject *parent)
    : QObject(parent)
    , networkManager(new NetworkManager(this))
{
    connect(networkManager, &NetworkManager::signupResult,
            this, &AuthController::onSignupResult);
    connect(networkManager, &NetworkManager::loginChallenge,
            this, &AuthController::onLoginChallenge);
    connect(networkManager, &NetworkManager::loginResult,
            this, &AuthController::onLoginResult);
    connect(networkManager, &NetworkManager::networkError,
            this, [=](const QString &e){ Logger::log("Network error: " + e); });
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

    // 3) Generate keypair
    QByteArray pubKey, secKey;
    CryptoUtils::generateKeyPair(pubKey, secKey);

    // 4) Encrypt secret key
    QByteArray skNonce;
    auto encryptedSK = CryptoUtils::encryptSecretKey(secKey, pdk, skNonce);

    // 5) Build and send signup request
    QJsonObject req{
        { "action", "signup" },
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
    // 1) Derive PDK from stored password
    auto pdk = CryptoUtils::derivePDK(pendingPassword, salt, opslimit, memlimit);

    // 2) Decrypt secret key
    auto secKey = CryptoUtils::decryptSecretKey(encryptedSK, pdk, skNonce);

    // 3) Sign the challenge
    auto signature = CryptoUtils::signMessage(nonce, secKey);

    // 4) Send authenticate request
    networkManager->authenticate(pendingUsername, signature);
}

void AuthController::onLoginResult(bool success, const QString &message)
{
    Logger::log(QString("LoginResult: success=%1, message='%2'")
                    .arg(success).arg(message));
    emit loginResult(success, message);
}
