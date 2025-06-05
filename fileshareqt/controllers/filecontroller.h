#ifndef FILECONTROLLER_H
#define FILECONTROLLER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QByteArray>
#include <QJsonObject>

#include "icryptoservice.h"
#include "inetworkmanager.h"
#include "cache.h"

class NetworkManager;
class AuthController;

class FileController : public QObject
{
    Q_OBJECT

public:
     FileController(INetworkManager *networkManager,
                            AuthController    *authController,
                            ICryptoService    *cryptoService,
                            QObject           *parent = nullptr);

    void uploadFile(const QString &filename, const QByteArray &base64Contents);
    void listFiles();
    void downloadFile(qint64 fileId, const QString &filename);
    void deleteFile(const QString &filename);

    // Return a const reference to our generic cache
    const Cache<QString, QByteArray, true>& downloadCache() const
    {
        return m_downloadCache;
    }

signals:
    void uploadFileResult(bool success, const QString &message);
    void listFilesResult(bool success, const QList<FileEntry> &files, const QString &message);
    void downloadFileResult(bool success, const QString &filename, const QByteArray &data, const QString &message);
    void deleteFileResult(bool success, const QString &message);

private slots:
    void onChallenge(const QByteArray &nonce, const QString &operation);
    void onUploadNetwork(bool success, const QString &message);
    void onListNetwork(bool success, const QList<FileEntry> &files, const QString &message);
    void onDownloadNetwork(bool success,
                           const QString &encryptedFileB64,
                           const QString &fileNonceB64,
                           const QString &encryptedDekB64,
                           const QString &dekNonceB64,
                           const QString &message);
    void onDeleteNetwork(bool success, const QString &message);

private:
    INetworkManager   *m_networkManager;
    AuthController   *m_authController;
    ICryptoService   *m_cryptoService;
    QString            m_pendingFileName;
    QByteArray         m_pendingFileContents;
    QString            m_selectedDownload;

    Cache<QString, QByteArray, true> m_downloadCache;

    qint64       m_selectedDownloadId    = -1;
    QString      m_selectedDownloadName;

    void processUpload(const QByteArray &nonce);
    void processList(const QByteArray &nonce);
    void processDownload(const QByteArray &nonce);
    void processDelete(const QByteArray &nonce);

    QString currentUsername() const;
};

#endif // FILECONTROLLER_H
