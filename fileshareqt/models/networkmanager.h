#ifndef NETWORKMANAGER_H
#define NETWORKMANAGER_H

#include "inetworkmanager.h"
#include <curl/curl.h>
#include <QObject>
#include <QByteArray>
#include <QJsonObject>
#include <QString>

// We no longer need <openssl/ssl.h> or <openssl/err.h> etc.

class NetworkManager : public INetworkManager
{
    Q_OBJECT

public:
    NetworkManager(QObject *parent = nullptr);
    ~NetworkManager() override;

    // INetworkManager interface
    void signup(const QJsonObject &payload) override;
    void login(const QString &username) override;
    void authenticate(const QString &username,
                      const QByteArray &nonce,
                      const QByteArray &signature) override;

    void requestChallenge(const QString &username,
                          const QString &operation) override;
    void changeUsername(const QJsonObject &payload) override;
    void changePassword(const QJsonObject &payload) override;
    void uploadFile(const QJsonObject &payload) override;
    void listFiles(const QJsonObject &payload) override;
    void downloadFile(const QJsonObject &payload) override;
    void deleteFile(const QJsonObject &payload) override;
    void retrieveFileDEK(const QJsonObject &payload) override;

    // X3DH
    void getPreKeyBundle(const QJsonObject &payload) override;
    void getOPK(const QJsonObject &payload) override;

    // TOFU backup
    void backupTOFU(const QJsonObject &payload) override;
    void getBackupTOFU(const QJsonObject &payload) override;

    // Share endpoints
    void shareFile(const QJsonObject &payload) override;
    void listSharedTo(const QJsonObject &payload) override;
    void listSharedFrom(const QJsonObject &payload) override;
    void listSharers(const QJsonObject &payload) override;
    void downloadSharedFile(const QJsonObject &payload) override;

    // revoke a share (POST /remove_shared_file)
    void removeSharedFile(const QJsonObject &payload) override;

    void checkConnection() override;

private:
    // Single libcurl handle. You can also create/destroy per‐request, but reusing is fine.
    CURL *curl;

    // Helper to do HTTPS POST/receive response as QByteArray
    QByteArray postJson(const QString &host,
                        quint16 port,
                        const QString &path,
                        const QJsonObject &obj,
                        bool &ok,
                        QString &message);

    // Write callback for libcurl to accumulate response bytes
    static size_t writeToByteArray(void *ptr, size_t size, size_t nmemb, void *userdata);
};

#endif // NETWORKMANAGER_H
