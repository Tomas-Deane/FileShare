#include "filecontroller.h"
#include "authcontroller.h"
#include <QJsonObject>
#include <QJsonDocument>

FileController::FileController(INetworkManager *netMgr,
                               AuthController    *authController,
                               ICryptoService    *cryptoService,
                               QObject           *parent)
    : QObject(parent)
    , m_networkManager(netMgr)
    , m_authController(authController)
    , m_cryptoService(cryptoService)
{
    connect(m_networkManager, &INetworkManager::challengeResult,
            this, &FileController::onChallenge);

    connect(m_networkManager, &INetworkManager::uploadFileResult,
            this, &FileController::onUploadNetwork);
    connect(m_networkManager, &INetworkManager::listFilesResult,
            this, &FileController::onListNetwork);
    connect(m_networkManager, &INetworkManager::downloadFileResult,
            this, &FileController::onDownloadNetwork);
    connect(m_networkManager, &INetworkManager::deleteFileResult,
            this, &FileController::onDeleteNetwork);
}

QString FileController::currentUsername() const {
    return m_authController->getSessionUsername();
}

void FileController::uploadFile(const QString &filename, const QByteArray &base64Contents)
{
    m_pendingFileName = filename;
    m_pendingFileContents = base64Contents;
    m_networkManager->requestChallenge(currentUsername(), "upload_file");
}

void FileController::listFiles()
{
    m_networkManager->requestChallenge(currentUsername(), "list_files");
}

void FileController::downloadFile(const QString &filename)
{
    m_selectedDownload = filename;
    m_networkManager->requestChallenge(currentUsername(), "download_file");
}

void FileController::deleteFile(const QString &filename)
{
    m_selectedDownload = filename;
    m_networkManager->requestChallenge(currentUsername(), "delete_file");
}

void FileController::onChallenge(const QByteArray &nonce, const QString &operation)
{
    if (operation == "upload_file")        processUpload(nonce);
    else if (operation == "list_files")    processList(nonce);
    else if (operation == "download_file") processDownload(nonce);
    else if (operation == "delete_file")   processDelete(nonce);
}

void FileController::processUpload(const QByteArray &nonce)
{
    // generate file DEK
    QByteArray fileDek = m_cryptoService->generateAeadKey();

    // decrypt base64 to binary
    QByteArray plaintext = QByteArray::fromBase64(m_pendingFileContents);

    // encrypt file
    QByteArray fileNonce;
    QByteArray ciphertext = m_cryptoService->encrypt(plaintext, fileDek, fileNonce);

    // envelope DEK under session KEK
    QByteArray dekNonce;
    QByteArray encryptedDek = m_cryptoService->encrypt(
        fileDek,
        m_authController->getSessionKek(),
        dekNonce
        );

    // zero out our secrets as soon as we're done with them
    m_cryptoService->secureZeroMemory(plaintext);
    m_cryptoService->secureZeroMemory(fileDek);

    // sign encrypted DEK
    QByteArray sig = m_cryptoService->sign(
        encryptedDek,
        m_authController->getSessionSecretKey()
        );

    QJsonObject req{
        { "username",         currentUsername() },
        { "filename",         m_pendingFileName },
        { "encrypted_file",   QString::fromUtf8(ciphertext.toBase64()) },
        { "file_nonce",       QString::fromUtf8(fileNonce.toBase64()) },
        { "encrypted_dek",    QString::fromUtf8(encryptedDek.toBase64()) },
        { "dek_nonce",        QString::fromUtf8(dekNonce.toBase64()) },
        { "nonce",            QString::fromUtf8(nonce.toBase64()) },
        { "signature",        QString::fromUtf8(sig.toBase64()) }
    };
    m_networkManager->uploadFile(req);
}

void FileController::processList(const QByteArray &nonce)
{
    QByteArray sig = m_cryptoService->sign(
        nonce,
        m_authController->getSessionSecretKey()
        );
    QJsonObject req{
        { "username",  currentUsername() },
        { "nonce",     QString::fromUtf8(nonce.toBase64()) },
        { "signature", QString::fromUtf8(sig.toBase64()) }
    };
    m_networkManager->listFiles(req);
}

void FileController::processDownload(const QByteArray &nonce)
{
    QByteArray sig = m_cryptoService->sign(
        m_selectedDownload.toUtf8(),
        m_authController->getSessionSecretKey()
        );
    QJsonObject req{
        { "username",  currentUsername() },
        { "filename",  m_selectedDownload },
        { "nonce",     QString::fromUtf8(nonce.toBase64()) },
        { "signature", QString::fromUtf8(sig.toBase64()) }
    };
    m_networkManager->downloadFile(req);
}

void FileController::processDelete(const QByteArray &nonce)
{
    QByteArray sig = m_cryptoService->sign(
        m_selectedDownload.toUtf8(),
        m_authController->getSessionSecretKey()
        );
    QJsonObject req{
        { "username",  currentUsername() },
        { "filename",  m_selectedDownload },
        { "nonce",     QString::fromUtf8(nonce.toBase64()) },
        { "signature", QString::fromUtf8(sig.toBase64()) }
    };
    m_networkManager->deleteFile(req);
}

void FileController::onUploadNetwork(bool success, const QString &message)
{
    m_pendingFileContents.clear();
    emit uploadFileResult(success, message);
}

void FileController::onListNetwork(bool success,
                                   const QStringList &files,
                                   const QString &message)
{
    m_downloadCache.clear();
    emit listFilesResult(success, files, message);
}

void FileController::onDownloadNetwork(bool success,
                                       const QString &encryptedFileB64,
                                       const QString &fileNonceB64,
                                       const QString &encryptedDekB64,
                                       const QString &dekNonceB64,
                                       const QString &message)
{
    if (!success) {
        emit downloadFileResult(false, m_selectedDownload, {}, message);
        return;
    }

    QByteArray encryptedFile = QByteArray::fromBase64(encryptedFileB64.toUtf8());
    QByteArray fileNonce     = QByteArray::fromBase64(fileNonceB64.toUtf8());
    QByteArray encryptedDek  = QByteArray::fromBase64(encryptedDekB64.toUtf8());
    QByteArray dekNonce      = QByteArray::fromBase64(dekNonceB64.toUtf8());

    QByteArray fileDek = m_cryptoService->decrypt(
        encryptedDek,
        m_authController->getSessionKek(),
        dekNonce
        );
    QByteArray data = m_cryptoService->decrypt(
        encryptedFile,
        fileDek,
        fileNonce
        );

    // zero out the raw DEK immediately
    m_cryptoService->secureZeroMemory(fileDek);

    m_downloadCache.insert(m_selectedDownload, data);
    emit downloadFileResult(true, m_selectedDownload, data, {});
}

void FileController::onDeleteNetwork(bool success, const QString &message)
{
    if (success) {
        m_downloadCache.remove(m_selectedDownload);
    }
    emit deleteFileResult(success, message);
}
