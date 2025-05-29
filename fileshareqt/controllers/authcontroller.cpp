#include "authcontroller.h"
#include "logger.h"

#include <QJsonObject>
#include <QJsonDocument>

AuthController::AuthController(INetworkManager *netMgr,
                               ICryptoService  *cryptoSvc,
                               QObject         *parent)
    : QObject(parent)
    , cryptoService(cryptoSvc)
    , networkManager(netMgr)
{
    connect(networkManager, &INetworkManager::signupResult,
            this, &AuthController::onSignupResult);
    connect(networkManager, &INetworkManager::loginChallenge,
            this, &AuthController::onLoginChallenge);
    connect(networkManager, &INetworkManager::loginResult,
            this, &AuthController::onLoginResult);
    connect(networkManager, &INetworkManager::challengeResult,
            this, &AuthController::onChallengeReceived);
    connect(networkManager, &INetworkManager::connectionStatusChanged,
            this, &AuthController::onConnectionStatusChanged);
    connect(networkManager, &INetworkManager::networkError,
            this, [=](const QString &e){ Logger::log("Network error: " + e); });
}

QString AuthController::getSessionUsername() const {
    return sessionUsername;
}

QByteArray AuthController::getSessionSecretKey() const {
    return sessionSecretKey;
}

QByteArray AuthController::getSessionKek() const {
    return sessionKek;
}

void AuthController::updateSessionUsername(const QString &newUsername)
{
    sessionUsername = newUsername;
    emit loggedIn(sessionUsername);
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

    // generate salt
    QByteArray salt = cryptoService->randomBytes(16);

    // derive PDK
    sessionPdk = cryptoService->deriveKey(password, salt,
                                          ICryptoService::OPSLIMIT_MODERATE,
                                          ICryptoService::MEMLIMIT_MODERATE);

    // generate keypair
    QByteArray pubKey, secKey;
    cryptoService->generateKeyPair(pubKey, secKey);

    // encrypt secret key
    QByteArray skNonce;
    QByteArray encryptedSK = cryptoService->encrypt(secKey, sessionPdk, skNonce);

    // generate and encrypt KEK
    QByteArray kek = cryptoService->generateAeadKey();
    sessionKek = kek;
    QByteArray kekNonce;
    QByteArray encryptedKek = cryptoService->encrypt(kek, sessionPdk, kekNonce);

    QJsonObject req{
        { "username",           username },
        { "salt",               QString::fromUtf8(salt.toBase64()) },
        { "argon2_opslimit",    int(ICryptoService::OPSLIMIT_MODERATE) },
        { "argon2_memlimit",    int(ICryptoService::MEMLIMIT_MODERATE) },
        { "public_key",         QString::fromUtf8(pubKey.toBase64()) },
        { "encrypted_privkey",  QString::fromUtf8(encryptedSK.toBase64()) },
        { "privkey_nonce",      QString::fromUtf8(skNonce.toBase64()) },
        { "encrypted_kek",      QString::fromUtf8(encryptedKek.toBase64()) },
        { "kek_nonce",          QString::fromUtf8(kekNonce.toBase64()) }
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
    sessionSecretKey.fill(char(0));
    sessionPdk.fill(char(0));
    sessionKek.fill(char(0));
    sessionSecretKey.clear();
    sessionPdk.clear();
    sessionKek.clear();
    sessionUsername.clear();
    emit loggedOut();
}

void AuthController::onSignupResult(bool success, const QString &message)
{
    Logger::log(QString("SignupResult: %1 – %2").arg(success).arg(message));
    if (success) {
        Logger::log("Auto-logging in after signup …");
        login(pendingUsername, pendingPassword);
    }
    emit signupResult(success, message);
}

void AuthController::onLoginChallenge(
    const QByteArray &nonce,
    const QByteArray &salt,
    int opslimit,
    int memlimit,
    const QByteArray &encryptedSK,
    const QByteArray &skNonce,
    const QByteArray &encryptedKek,
    const QByteArray &kekNonce
    )
{
    // derive PDK
    sessionPdk = cryptoService->deriveKey(pendingPassword, salt, opslimit, memlimit);

    // decrypt SK & KEK
    sessionSecretKey = cryptoService->decrypt(encryptedSK, sessionPdk, skNonce);
    sessionKek       = cryptoService->decrypt(encryptedKek, sessionPdk, kekNonce);

    // sign & authenticate
    QByteArray sig = cryptoService->sign(nonce, sessionSecretKey);
    networkManager->authenticate(pendingUsername, nonce, sig);
}

void AuthController::onLoginResult(bool success, const QString &message)
{
    Logger::log(QString("LoginResult: %1 – %2").arg(success).arg(message));
    if (success) {
        sessionUsername = pendingUsername;
        pendingUsername.clear();
        pendingPassword.clear();
        emit loggedIn(sessionUsername);
    }
    emit loginResult(success, message);
}

void AuthController::onChallengeReceived(const QByteArray &nonce,
                                         const QString &operation)
{
    if (operation != "login" &&
        operation != "change_username" &&
        operation != "change_password") {
        Logger::log("AuthController: ignoring challenge for " + operation);
    }
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
