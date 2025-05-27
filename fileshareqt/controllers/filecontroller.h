#ifndef FILECONTROLLER_H
#define FILECONTROLLER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QMap>
#include <QByteArray>
#include <QJsonObject>

#include "networkmanager.h"
#include "authcontroller.h"

class FileController : public QObject
{
    Q_OBJECT

public:
    // Now also take an AuthController* so we can get the real username
    explicit FileController(NetworkManager *networkManager,
                            AuthController *authController,
                            QObject *parent = nullptr);

    Q_INVOKABLE void uploadFile(const QString &filename, const QByteArray &base64Contents);
    Q_INVOKABLE void listFiles();
    Q_INVOKABLE void downloadFile(const QString &filename);
    Q_INVOKABLE void deleteFile(const QString &filename);

    // Access to client‐side cache if needed
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
    NetworkManager   *m_networkManager;
    AuthController   *m_authController;
    QString            m_pendingFileName;
    QByteArray         m_pendingFileContents; // already base64‐encoded
    QString            m_selectedDownload;
    QMap<QString, QByteArray> m_downloadCache;

    void processUpload(const QByteArray &nonce);
    void processList(const QByteArray &nonce);
    void processDownload(const QByteArray &nonce);
    void processDelete(const QByteArray &nonce);

    // helper to get current username
    QString currentUsername() const { return m_authController->getSessionUsername(); }
};

#endif // FILECONTROLLER_H
