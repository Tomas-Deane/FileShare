#include "authcontroller.h"
#include "networkmanager.h"
#include "crypto_utils.h"
#include "logger.h"

#include <QJsonObject>
#include <QJsonDocument>
#include <sodium.h>

AuthController::AuthController(NetworkManager *netMgr, QObject *parent)
    : QObject(parent)
    , networkManager(netMgr)
{
    // connect signals from the network manager to slots in here
    connect(networkManager, &NetworkManager::signupResult,
            this, &AuthController::onNetSignupResult);
    connect(networkManager, &NetworkManager::loginChallenge,
            this, &AuthController::onNetLoginChallenge);
    connect(networkManager, &NetworkManager::loginResult,
            this, &AuthController::onNetLoginResult);
    connect(networkManager, &NetworkManager::serverMessage,
            this, &AuthController::onNetServerMessage);
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

    // 1) generate salt
    QByteArray salt(16, 0);
    randombytes_buf(reinterpret_cast<unsigned char*>(salt.data()), 16);
    Logger::log(QString("Generated salt: %1").arg(QString(salt.toHex())));

    // 2) derive PDK
    auto pdk = CryptoUtils::derivePDK(
        password, salt,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE
        );
    if (pdk.isEmpty()) {
        Logger::log("Argon2id key derivation failed");
        emit signupResult(false, "Key derivation failed");
        return;
    }
    Logger::log(QString("Derived PDK: %1").arg(QString(pdk.toHex())));

    // 3) generate keypair
    QByteArray pubKey, secKey;
    CryptoUtils::generateKeyPair(pubKey, secKey);
    Logger::log(QString("Generated keypair: pub=%1 sec=%2")
                    .arg(QString(pubKey.toHex()), QString(secKey.toHex())));

    // 4) encrypt secret key
    QByteArray skNonce;
    auto encryptedSK = CryptoUtils::encryptSecretKey(secKey, pdk, skNonce);
    Logger::log(QString("Encrypted SK: %1").arg(QString(encryptedSK.toHex())));

    // 5) build JSON and send
    QJsonObject req;
    req["action"]            = "signup";
    req["username"]          = username;
    req["salt"]              = QString::fromUtf8(salt.toBase64());
    req["argon2_opslimit"]   = int(crypto_pwhash_OPSLIMIT_MODERATE);
    req["argon2_memlimit"]   = int(crypto_pwhash_MEMLIMIT_MODERATE);
    req["public_key"]        = QString::fromUtf8(pubKey.toBase64());
    req["encrypted_privkey"] = QString::fromUtf8(encryptedSK.toBase64());
    req["privkey_nonce"]     = QString::fromUtf8(skNonce.toBase64());

    Logger::log(QString("Sending signup request: %1")
                    .arg(QString(QJsonDocument(req)
                                     .toJson(QJsonDocument::Compact))));
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

    Logger::log(QString("Sending login request for user '%1'").arg(username));
    networkManager->login(username);
}

void AuthController::onNetSignupResult(bool success, const QString &error)
{
    Logger::log(QString("SignupResult: success=%1, error='%2'")
                    .arg(success).arg(error));
    emit signupResult(success, error);
}

void AuthController::onNetLoginChallenge( // params from server db
    const QByteArray &nonce,
    const QByteArray &salt,
    int opslimit,
    int memlimit,
    const QByteArray &encryptedSK,
    const QByteArray &skNonce
    )
{
    Logger::log(QString("LoginChallenge received: nonce=%1 salt=%2 ops=%3 mem=%4")
                    .arg(QString(nonce.toHex()), QString(salt.toHex()))
                    .arg(opslimit).arg(memlimit));

    // re-derive PDK
    auto pdk = CryptoUtils::derivePDK(pendingPassword, salt, opslimit, memlimit);
    if (pdk.isEmpty()) {
        Logger::log("Argon2id re-derive failed");
        networkManager->authenticate(pendingUsername, {});
        return;
    }
    Logger::log(QString("Re-derived PDK: %1").arg(QString(pdk.toHex())));

    // decrypt secret key
    auto secKey = CryptoUtils::decryptSecretKey(encryptedSK, pdk, skNonce);
    if (secKey.isEmpty()) {
        Logger::log("Decrypt secretKey failed");
        networkManager->authenticate(pendingUsername, {});
        return;
    }
    Logger::log(QString("Decrypted secretKey: %1").arg(QString(secKey.toHex())));

    // sign challenge
    auto signature = CryptoUtils::signMessage(nonce, secKey);
    Logger::log(QString("Signature: %1").arg(QString(signature.toHex())));

    networkManager->authenticate(pendingUsername, signature);
}

void AuthController::onNetLoginResult(bool success, const QString &error) // for now this class handles logging (to keep networkManager purer). This logic may not belong here
{
    Logger::log(QString("LoginResult: success=%1, error='%2'")
                    .arg(success).arg(error));
    emit loginResult(success, error);
}

void AuthController::onNetServerMessage(const QString &rawJson)
{
    // still log every raw line:
    Logger::log(QString("Server → %1").arg(rawJson));
}
