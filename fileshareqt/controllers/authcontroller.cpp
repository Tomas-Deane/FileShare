#include "authcontroller.h"
#include "logger.h"
#include <QJsonObject>
#include <QJsonDocument>
#include <QJsonArray>
#include <QByteArray>
#include <QJsonValue>

AuthController::AuthController(INetworkManager *netMgr,
                               ICryptoService  *cryptoSvc,
                               QObject         *parent)
    : QObject(parent)
    , networkManager(netMgr)
    , cryptoService(cryptoSvc)
{
    connect(networkManager, &INetworkManager::signupResult,
            this, &AuthController::onSignupResult);

    connect(networkManager, &INetworkManager::loginChallenge,
            this, &AuthController::onLoginChallenge);

    connect(networkManager, &INetworkManager::loginResult,
            this, &AuthController::onLoginResult);

    // **NEW**: listen for any challengeResult in order to handle "get_backup_tofu"
    connect(networkManager, &INetworkManager::challengeResult,
            this, &AuthController::onChallengeReceived);

    // **NEW**: listen for the /get_backup_tofu response
    connect(networkManager, &INetworkManager::getBackupTOFUResult,
            this, &AuthController::onGetBackupTOFUResult);

    connect(networkManager, &INetworkManager::connectionStatusChanged,
            this, &AuthController::onConnectionStatusChanged);
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

QByteArray AuthController::getIdentityPublicKey() const {
    return ikPublic;   // after backup is loaded, this is set; before that, it’s the ephemeral from signup/login
}

QByteArray AuthController::getIdentityPrivateKey() const {
    return ikPrivate;
}

QByteArray AuthController::getSignedPreKeyPublic() const {
    return spkPublic;
}

QByteArray AuthController::getSignedPreKeyPrivate() const {
    return spkPrivate;
}

QByteArray AuthController::getSignedPreKeySignature() const {
    return spkSignature;
}

QList<QByteArray> AuthController::getOneTimePreKeyPubs() const {
    return opkPubs;
}

QList<QByteArray> AuthController::getOneTimePreKeyPrivs() const {
    return opkPrivs;
}

void AuthController::updateSessionPdk(const QByteArray &newPdk)
{
    cryptoService->secureZeroMemory(sessionPdk);
    sessionPdk = newPdk;
}

void AuthController::updateSessionUsername(const QString &newUsername)
{
    sessionUsername = newUsername;
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

    // 1) Make a fresh salt + derive PDK
    QByteArray salt = cryptoService->randomBytes(16);
    sessionPdk = cryptoService->deriveKey(
        password,
        salt,
        ICryptoService::OPSLIMIT_MODERATE,
        ICryptoService::MEMLIMIT_MODERATE
        );

    // 2) Generate Ed25519 keypair (for signing)
    QByteArray edPubKey, edPrivKey;
    cryptoService->generateKeyPair(edPubKey, edPrivKey);

    // 3) Encrypt the Ed25519 SK under PDK
    QByteArray skNonce, encryptedSK = cryptoService->encrypt(edPrivKey, sessionPdk, skNonce);
    cryptoService->secureZeroMemory(edPrivKey);

    // 4) Generate a fresh KEK (for file encryption) and encrypt it under PDK
    QByteArray kek = cryptoService->generateAeadKey();
    sessionKek = kek;  // keep the KEK in memory for future file ops
    QByteArray kekNonce, encryptedKek = cryptoService->encrypt(kek, sessionPdk, kekNonce);
    cryptoService->secureZeroMemory(kek);

    // 5) Generate X25519 identity key pair
    cryptoService->generateX25519KeyPair(ikPublic, ikPrivate);

    // 6) Generate X25519 signed‐pre‐key pair
    cryptoService->generateX25519KeyPair(spkPublic, spkPrivate);

    // Decrypt the Ed25519 secret we just encrypted:
    QByteArray edSecret = cryptoService->decrypt(encryptedSK, sessionPdk, skNonce);
    sessionSecretKey = edSecret;  // keep Ed25519 SK to sign spkPublic
    QByteArray spkSig = cryptoService->sign(spkPublic, sessionSecretKey);
    spkSignature = spkSig;         // store SPK signature

    // 8) Generate OPKs (private + public) in memory
    const int OPK_COUNT = 10;
    for (int i = 0; i < OPK_COUNT; i++) {
        QByteArray opkPub, opkPriv;
        cryptoService->generateOneTimePreKey(opkPub, opkPriv);
        opkPubs .push_back(opkPub);
        opkPrivs.push_back(opkPriv);
    }

    // 9) Build backup JSON with all X3DH fields and an empty "tofusers" array
    QJsonObject backupObj;
    backupObj.insert("IK_pub",        QString::fromUtf8(ikPublic.toBase64()));
    backupObj.insert("IK_priv",       QString::fromUtf8(ikPrivate.toBase64()));
    backupObj.insert("SPK_pub",       QString::fromUtf8(spkPublic.toBase64()));
    backupObj.insert("SPK_priv",      QString::fromUtf8(spkPrivate.toBase64()));
    backupObj.insert("SPK_signature", QString::fromUtf8(spkSignature.toBase64()));

    // OPKs—public halves
    QJsonArray opkPubArray;
    for (auto &pub : opkPubs) {
        opkPubArray.append(QString::fromUtf8(pub.toBase64()));
    }
    backupObj.insert("OPKs_pub", opkPubArray);

    // OPKs—private halves
    QJsonArray opkPrivArray;
    for (auto &priv : opkPrivs) {
        opkPrivArray.append(QString::fromUtf8(priv.toBase64()));
    }
    backupObj.insert("OPKs_priv", opkPrivArray);

    // Start with zero verified users
    backupObj.insert("tofusers", QJsonArray());

    QJsonDocument backupDoc(backupObj);
    QByteArray plaintextBackup = backupDoc.toJson(QJsonDocument::Compact);

    // 10) Encrypt that entire JSON under sessionKek
    QByteArray backupNonce, ciphertextBackup =
                            cryptoService->encrypt(plaintextBackup, sessionKek, backupNonce);

    cryptoService->secureZeroMemory(plaintextBackup);

    QString encryptedBackupB64 = QString::fromUtf8(ciphertextBackup.toBase64());
    QString backupNonceB64     = QString::fromUtf8(backupNonce.toBase64());

    // 11) Build SignUpRequest payload
    QJsonObject req{
        { "username",          username },
        { "salt",              QString::fromUtf8(salt.toBase64()) },
        { "argon2_opslimit",   int(ICryptoService::OPSLIMIT_MODERATE) },
        { "argon2_memlimit",   int(ICryptoService::MEMLIMIT_MODERATE) },
        { "public_key",        QString::fromUtf8(edPubKey.toBase64()) },
        { "encrypted_privkey", QString::fromUtf8(encryptedSK.toBase64()) },
        { "privkey_nonce",     QString::fromUtf8(skNonce.toBase64()) },
        { "encrypted_kek",     QString::fromUtf8(encryptedKek.toBase64()) },
        { "kek_nonce",         QString::fromUtf8(kekNonce.toBase64()) },
        { "identity_key",      QString::fromUtf8(ikPublic.toBase64()) },
        { "signed_pre_key",    QString::fromUtf8(spkPublic.toBase64()) },
        { "signed_pre_key_sig",QString::fromUtf8(spkSignature.toBase64()) },
        { "encrypted_backup",  encryptedBackupB64 },
        { "backup_nonce",      backupNonceB64 }
    };

    // OPKs go in a JSON array
    QJsonArray opkArray;
    for (auto &pub : opkPubs) {
        opkArray.append(QString::fromUtf8(pub.toBase64()));
    }
    req.insert("one_time_pre_keys", opkArray);

    Logger::log("Sending signup request with initial TOFU backup included");
    networkManager->signup(req);
}

void AuthController::onSignupResult(bool success, const QString &message)
{
    Logger::log(QString("SignupResult: %1 – %2").arg(success).arg(message));
    if (success) {
        Logger::log("Auto-logging in after signup …");
        // Immediately proceed to login
        login(pendingUsername, pendingPassword);
    }
    emit signupResult(success, message);
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

// Step 1 of login: we got a challenge from server
void AuthController::onLoginChallenge(
    const QByteArray &nonce,
    const QByteArray &salt,
    int opslimit,
    int memlimit,
    const QByteArray &encryptedSK,
    const QByteArray &skNonce,
    const QByteArray &encryptedKek,
    const QByteArray &kekNonce
    ) {
    // Derive PDK
    sessionPdk = cryptoService->deriveKey(pendingPassword, salt, opslimit, memlimit);

    // Decrypt Ed25519 SK under PDK
    sessionSecretKey = cryptoService->decrypt(encryptedSK, sessionPdk, skNonce);
    // Decrypt KEK under PDK
    sessionKek = cryptoService->decrypt(encryptedKek, sessionPdk, kekNonce);

    // Sign the nonce to authenticate
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

void AuthController::requestGetBackupTOFU()
{
    if (sessionUsername.isEmpty()) return;

    // Ask for a challenge for "get_backup_tofu"
    networkManager->requestChallenge(sessionUsername, "get_backup_tofu");
}

// **NEW**: handle challenge for "get_backup_tofu"
void AuthController::onChallengeReceived(const QByteArray &nonce, const QString &operation)
{
    if (operation != "get_backup_tofu") {
        // Ignore any other challenge
        return;
    }

    // Sign the nonce with Ed25519 SK
    QByteArray sig = cryptoService->sign(nonce, sessionSecretKey);
    QJsonObject req{
        { "username", sessionUsername },
        { "nonce",    QString::fromUtf8(nonce.toBase64()) },
        { "signature",QString::fromUtf8(sig.toBase64()) }
    };
    networkManager->getBackupTOFU(req);
}

// decrypt the backup and parse JSON
void AuthController::onGetBackupTOFUResult(bool success,
                                           const QString &encryptedBackupB64,
                                           const QString &backupNonceB64,
                                           const QString &message)
{
    if (!success) {
        // No backup found or error; you might log and continue with defaults
        Logger::log("No existing TOFU backup or error: " + message);
        return;
    }

    // 1) Base64 decode ciphertext & nonce
    QByteArray ciphertext = QByteArray::fromBase64(encryptedBackupB64.toUtf8());
    QByteArray nonce      = QByteArray::fromBase64(backupNonceB64.toUtf8());

    // 2) Decrypt with sessionKek
    QByteArray plain = cryptoService->decrypt(ciphertext, sessionKek, nonce);
    if (plain.isEmpty()) {
        Logger::log("Failed to decrypt TOFU backup (maybe wrong KEK)");
        return;
    }

    // 3) Parse the JSON into our in-memory key variables
    parseBackupJson(plain);
    cryptoService->secureZeroMemory(plain);

    Logger::log("Successfully loaded X3DH keys from TOFU backup");
}

// Parse the JSON structure created at signup (or a later backup):
void AuthController::parseBackupJson(const QByteArray &plaintext)
{
    QJsonDocument doc = QJsonDocument::fromJson(plaintext);
    if (!doc.isObject()) {
        Logger::log("Invalid backup format (not a JSON object)");
        return;
    }
    QJsonObject obj = doc.object();

    // 1) IK_pub, IK_priv
    QString ikPubB64  = obj.value("IK_pub").toString();
    QString ikPrivB64 = obj.value("IK_priv").toString();
    ikPublic  = QByteArray::fromBase64(ikPubB64.toUtf8());
    ikPrivate = QByteArray::fromBase64(ikPrivB64.toUtf8());

    // 2) SPK_pub, SPK_priv, SPK_signature
    QString spkPubB64     = obj.value("SPK_pub").toString();
    QString spkPrivB64    = obj.value("SPK_priv").toString();
    QString spkSigB64     = obj.value("SPK_signature").toString();
    spkPublic    = QByteArray::fromBase64(spkPubB64.toUtf8());
    spkPrivate   = QByteArray::fromBase64(spkPrivB64.toUtf8());
    spkSignature = QByteArray::fromBase64(spkSigB64.toUtf8());

    // 3) OPKs_pub, OPKs_priv
    opkPubs.clear();
    opkPrivs.clear();
    if (obj.contains("OPKs_pub") && obj["OPKs_pub"].isArray()) {
        QJsonArray arr = obj["OPKs_pub"].toArray();
        for (auto v : arr) {
            opkPubs.push_back(QByteArray::fromBase64(v.toString().toUtf8()));
        }
    }
    if (obj.contains("OPKs_priv") && obj["OPKs_priv"].isArray()) {
        QJsonArray arr = obj["OPKs_priv"].toArray();
        for (auto v : arr) {
            opkPrivs.push_back(QByteArray::fromBase64(v.toString().toUtf8()));
        }
    }

    // 4) We ignore "tofusers" here because that’s just the verified‐users list; TofuManager handles that.
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

void AuthController::logout()
{
    // Securely wipe all secrets
    cryptoService->secureZeroMemory(sessionSecretKey);
    cryptoService->secureZeroMemory(sessionPdk);
    cryptoService->secureZeroMemory(sessionKek);
    cryptoService->secureZeroMemory(ikPrivate);
    cryptoService->secureZeroMemory(spkPrivate);
    cryptoService->secureZeroMemory(spkSignature);
    for (auto &priv : opkPrivs) {
        cryptoService->secureZeroMemory(priv);
    }
    opkPrivs.clear();
    sessionUsername.clear();
    emit loggedOut();
}
