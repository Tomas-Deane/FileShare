#include "authcontroller.h"
#include "networkmanager.h"
#include "crypto_utils.h"
#include "logger.h"

#include <sodium.h>
#include <QJsonObject>
#include <QJsonDocument>
#include <QUuid>
#include <QDateTime>

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

    connect(networkManager, &NetworkManager::challengeResult,
            this, &AuthController::onChallengeReceived);

    connect(networkManager, &NetworkManager::changeUsernameResult,
            this, &AuthController::onChangeUsernameNetwork);
    connect(networkManager, &NetworkManager::changePasswordResult,
            this, &AuthController::onChangePasswordNetwork);
    connect(networkManager, &NetworkManager::uploadFileResult,
            this, &AuthController::onUploadFileNetwork);

    connect(networkManager, &NetworkManager::listFilesResult,
            this, &AuthController::onListFilesNetwork);
    connect(networkManager, &NetworkManager::downloadFileResult,
            this, &AuthController::onDownloadFileNetwork);
    connect(networkManager, &NetworkManager::deleteFileResult,
            this, &AuthController::onDeleteFileNetwork);

    connect(networkManager, &NetworkManager::networkError,
            this, [=](const QString &e){ Logger::log("Network error: " + e); });

    connect(networkManager, &NetworkManager::connectionStatusChanged,
            this, &AuthController::onConnectionStatusChanged);
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
    QByteArray salt(16, 0);
    randombytes_buf(reinterpret_cast<unsigned char*>(salt.data()), salt.size());

    // derive PDK
    sessionPdk = CryptoUtils::derivePDK(password, salt,
                                        crypto_pwhash_OPSLIMIT_MODERATE,
                                        crypto_pwhash_MEMLIMIT_MODERATE);

    // generate keypair
    QByteArray pubKey, secKey;
    CryptoUtils::generateKeyPair(pubKey, secKey);

    // encrypt secret key and KEK
    QByteArray skNonce;
    QByteArray encryptedSK = CryptoUtils::encryptSecretKey(secKey, sessionPdk, skNonce);

    QByteArray kek(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 0);
    randombytes_buf(reinterpret_cast<unsigned char*>(kek.data()), kek.size());
    sessionKek = kek;
    QByteArray kekNonce;
    QByteArray encryptedKek = CryptoUtils::encryptSecretKey(kek, sessionPdk, kekNonce);

    QJsonObject req{
        { "username", username },
        { "salt", QString::fromUtf8(salt.toBase64()) },
        { "argon2_opslimit", int(crypto_pwhash_OPSLIMIT_MODERATE) },
        { "argon2_memlimit", int(crypto_pwhash_MEMLIMIT_MODERATE) },
        { "public_key", QString::fromUtf8(pubKey.toBase64()) },
        { "encrypted_privkey", QString::fromUtf8(encryptedSK.toBase64()) },
        { "privkey_nonce", QString::fromUtf8(skNonce.toBase64()) },
        { "encrypted_kek", QString::fromUtf8(encryptedKek.toBase64()) },
        { "kek_nonce", QString::fromUtf8(kekNonce.toBase64()) }
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
    sodium_memzero(sessionSecretKey.data(), sessionSecretKey.size());
    sodium_memzero(sessionPdk.data(), sessionPdk.size());
    sodium_memzero(sessionKek.data(), sessionKek.size());
    sessionSecretKey.clear();
    sessionPdk.clear();
    sessionKek.clear();
    sessionUsername.clear();
    emit loggedOut();
}

void AuthController::onSignupResult(bool success, const QString &message) {
    Logger::log(QString("SignupResult: %1 – %2").arg(success).arg(message));

    if (success) {
        // immediately trigger the usual login flow
        Logger::log("Auto-logging in after signup …");
        login(pendingUsername, pendingPassword);
        // (you can clear pendingUsername/password in onLoginResult)
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
    ) {
    // derive PDK
    sessionPdk = CryptoUtils::derivePDK(pendingPassword, salt, opslimit, memlimit);

    // decrypt SK & KEK
    sessionSecretKey = CryptoUtils::decryptSecretKey(encryptedSK, sessionPdk, skNonce);
    sessionKek = CryptoUtils::decryptSecretKey(encryptedKek, sessionPdk, kekNonce);

    // sign & authenticate
    QByteArray sig = CryptoUtils::signMessage(nonce, sessionSecretKey);
    networkManager->authenticate(pendingUsername, nonce, sig);
}

void AuthController::onLoginResult(bool success, const QString &message)
{
    Logger::log(QString("LoginResult: %1 – %2")
                    .arg(success).arg(message));
    if (success) {
        sessionUsername = pendingUsername;
        pendingUsername.clear();
        pendingPassword.clear();
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
    networkManager->requestChallenge(sessionUsername, "change_username");
}

void AuthController::changePassword(const QString &newPassword)
{
    if (sessionUsername.isEmpty()) {
        emit changePasswordResult(false, "Not logged in");
        return;
    }
    // generate new salt
    pendingSalt = QByteArray(16, 0);
    randombytes_buf(reinterpret_cast<unsigned char*>(pendingSalt.data()), pendingSalt.size());
    pendingOpsLimit = crypto_pwhash_OPSLIMIT_MODERATE;
    pendingMemLimit = crypto_pwhash_MEMLIMIT_MODERATE;

    // derive new PDK & re-encrypt keys
    QByteArray newPdk = CryptoUtils::derivePDK(newPassword, pendingSalt, pendingOpsLimit, pendingMemLimit);
    pendingEncryptedSK = CryptoUtils::encryptSecretKey(sessionSecretKey, newPdk, pendingPrivKeyNonce);
    pendingEncryptedKek = CryptoUtils::encryptSecretKey(sessionKek, newPdk, pendingKekNonce);

    networkManager->requestChallenge(sessionUsername, "change_password");
}

void AuthController::uploadFile(const QString &filename, const QString &fileContents)
{
    if (sessionUsername.isEmpty()) {
        emit uploadFileResult(false, "Not logged in");
        return;
    }
    pendingFileName = filename;
    pendingFileContents = fileContents;
    networkManager->requestChallenge(sessionUsername, "upload_file");
}

void AuthController::listFiles()
{
    if (sessionUsername.isEmpty()) {
        emit listFilesResult(false, {}, "Not logged in");
        return;
    }
    networkManager->requestChallenge(sessionUsername, "list_files");
}

void AuthController::downloadFile(const QString &filename)
{
    if (sessionUsername.isEmpty()) {
        emit downloadFileResult(false, filename, {}, "Not logged in");
        return;
    }
    selectedFilename = filename;
    networkManager->requestChallenge(sessionUsername, "download_file");
}

void AuthController::deleteFile(const QString &filename)
{
    if (sessionUsername.isEmpty()) {
        emit deleteFileResult(false, "Not logged in");
        return;
    }
    selectedFilename = filename;
    networkManager->requestChallenge(sessionUsername, "delete_file");
}

void AuthController::onChallengeReceived(const QByteArray &nonce,
                                         const QString &operation)
{
    if (operation == "change_username") {
        processChangeUsername(nonce);
    } else if (operation == "change_password") {
        processChangePassword(nonce);
    } else if (operation == "upload_file") {
        processUploadFile(nonce);
    } else if (operation == "list_files") {
        processListFiles(nonce);
    } else if (operation == "download_file") {
        processDownloadFile(nonce);
    } else if (operation == "delete_file") {
        processDeleteFile(nonce);
    } else {
        Logger::log("Unknown operation: " + operation);
    }
}

void AuthController::processChangeUsername(const QByteArray &nonce)
{
    QByteArray sig = CryptoUtils::signMessage(pendingNewUsername.toUtf8(), sessionSecretKey);
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
    QByteArray sig = CryptoUtils::signMessage(pendingEncryptedSK, sessionSecretKey);
    QJsonObject req{
        { "username", sessionUsername },
        { "salt", QString::fromUtf8(pendingSalt.toBase64()) },
        { "argon2_opslimit", int(pendingOpsLimit) },
        { "argon2_memlimit", int(pendingMemLimit) },
        { "encrypted_privkey", QString::fromUtf8(pendingEncryptedSK.toBase64()) },
        { "privkey_nonce", QString::fromUtf8(pendingPrivKeyNonce.toBase64()) },
        { "encrypted_kek", QString::fromUtf8(pendingEncryptedKek.toBase64()) },
        { "kek_nonce", QString::fromUtf8(pendingKekNonce.toBase64()) },
        { "nonce", QString::fromUtf8(nonce.toBase64()) },
        { "signature", QString::fromUtf8(sig.toBase64()) }
    };
    networkManager->changePassword(req);
}

void AuthController::processUploadFile(const QByteArray &nonce)
{
    // generate file DEK
    QByteArray fileDek(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 0);
    randombytes_buf(reinterpret_cast<unsigned char*>(fileDek.data()), fileDek.size());

    // encrypt file contents
    QByteArray fileNonce;
    QByteArray ciphertext = CryptoUtils::encryptSecretKey(
        QByteArray::fromBase64(pendingFileContents.toUtf8()),
        fileDek,
        fileNonce
        );

    // envelope DEK under session KEK
    QByteArray dekNonce;
    QByteArray encryptedDek = CryptoUtils::encryptSecretKey(fileDek, sessionKek, dekNonce);

    // sign the encrypted DEK
    QByteArray sig = CryptoUtils::signMessage(encryptedDek, sessionSecretKey);

    QJsonObject req{
        { "username", sessionUsername },
        { "filename", pendingFileName },
        { "encrypted_file", QString::fromUtf8(ciphertext.toBase64()) },
        { "file_nonce", QString::fromUtf8(fileNonce.toBase64()) },
        { "encrypted_dek", QString::fromUtf8(encryptedDek.toBase64()) },
        { "dek_nonce", QString::fromUtf8(dekNonce.toBase64()) },
        { "nonce", QString::fromUtf8(nonce.toBase64()) },
        { "signature", QString::fromUtf8(sig.toBase64()) }
    };
    networkManager->uploadFile(req);
}

void AuthController::processListFiles(const QByteArray &nonce)
{
    QByteArray sig = CryptoUtils::signMessage(nonce, sessionSecretKey);
    QJsonObject req{
        { "username", sessionUsername },
        { "nonce", QString::fromUtf8(nonce.toBase64()) },
        { "signature", QString::fromUtf8(sig.toBase64()) }
    };
    networkManager->listFiles(req);
}

void AuthController::processDownloadFile(const QByteArray &nonce)
{
    QByteArray sig = CryptoUtils::signMessage(selectedFilename.toUtf8(), sessionSecretKey);
    QJsonObject req{
        { "username", sessionUsername },
        { "filename", selectedFilename },
        { "nonce", QString::fromUtf8(nonce.toBase64()) },
        { "signature", QString::fromUtf8(sig.toBase64()) }
    };
    networkManager->downloadFile(req);
}

void AuthController::processDeleteFile(const QByteArray &nonce)
{
    QByteArray sig = CryptoUtils::signMessage(selectedFilename.toUtf8(), sessionSecretKey);
    QJsonObject req{
        { "username",    sessionUsername },
        { "filename",    selectedFilename },
        { "nonce",       QString::fromUtf8(nonce.toBase64()) },
        { "signature",   QString::fromUtf8(sig.toBase64()) }
    };
    networkManager->deleteFile(req);
}

void AuthController::onChangeUsernameNetwork(bool success, const QString &message)
{
    if (success) sessionUsername = pendingNewUsername;
    pendingNewUsername.clear();
    emit changeUsernameResult(success, message);
}

void AuthController::onChangePasswordNetwork(bool success, const QString &message)
{
    emit changePasswordResult(success, message);
}

void AuthController::onUploadFileNetwork(bool success, const QString &message)
{
    pendingFileContents.clear();
    emit uploadFileResult(success, message);
}

void AuthController::onListFilesNetwork(bool success, const QStringList &files, const QString &message)
{
    emit listFilesResult(success, files, message);
}

void AuthController::onDownloadFileNetwork(bool success,
                                           const QString &encryptedFileB64,
                                           const QString &fileNonceB64,
                                           const QString &encryptedDekB64,
                                           const QString &dekNonceB64,
                                           const QString &message)
{
    if (!success) {
        emit downloadFileResult(false, selectedFilename, {}, message);
        return;
    }
    QByteArray encryptedFile = QByteArray::fromBase64(encryptedFileB64.toUtf8());
    QByteArray fileNonce     = QByteArray::fromBase64(fileNonceB64.toUtf8());
    QByteArray encryptedDek  = QByteArray::fromBase64(encryptedDekB64.toUtf8());
    QByteArray dekNonce      = QByteArray::fromBase64(dekNonceB64.toUtf8());

    QByteArray fileDek = CryptoUtils::decryptSecretKey(encryptedDek, sessionKek, dekNonce);
    QByteArray data   = CryptoUtils::decryptSecretKey(encryptedFile, fileDek, fileNonce);
    emit downloadFileResult(true, selectedFilename, data, {});
}

void AuthController::onDeleteFileNetwork(bool success, const QString &message)
{
    emit deleteFileResult(success, message);
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
