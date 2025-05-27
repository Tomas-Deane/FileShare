#ifndef FILECONTROLLER_H
#define FILECONTROLLER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QMap>
#include <QByteArray>
#include <QJsonObject>
#include "icryptoservice.h"
#include "inetworkmanager.h"

class NetworkManager;
class AuthController;

class FileController : public QObject
{
    Q_OBJECT
public:
    explicit FileController(INetworkManager *networkManager,
                            AuthController    *authController,
                            ICryptoService    *cryptoService,
                            QObject           *parent = nullptr);

     void uploadFile(const QString &filename, const QByteArray &base64Contents);
     void listFiles();
     void downloadFile(const QString &filename);
     void deleteFile(const QString &filename);

    const QMap<QString, QByteArray>& downloadCache() const { return m_downloadCache; }

signals:
    void uploadFileResult(bool success, const QString &message);
    void listFilesResult(bool success, const QStringList &files, const QString &message);
    void downloadFileResult(bool success, const QString &filename, const QByteArray &data, const QString &message);
    void deleteFileResult(bool success, const QString &message);

private slots:
    void onChallenge(const QByteArray &nonce, const QString &operation);
    void onUploadNetwork(bool success, const QString &message);
    void onListNetwork(bool success, const QStringList &files, const QString &message);
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
    QMap<QString, QByteArray> m_downloadCache;

    void processUpload(const QByteArray &nonce);
    void processList(const QByteArray &nonce);
    void processDownload(const QByteArray &nonce);
    void processDelete(const QByteArray &nonce);

    QString currentUsername() const;
};

#endif // FILECONTROLLER_H
