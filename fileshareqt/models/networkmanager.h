#ifndef NETWORKMANAGER_H
#define NETWORKMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QJsonObject>
#include <openssl/ssl.h>
#include <openssl/err.h>

// POSIX sockets
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

class NetworkManager : public QObject
{
    Q_OBJECT

public:
    explicit NetworkManager(QObject *parent = nullptr);
    ~NetworkManager();

     void signup(const QJsonObject &payload);
     void login(const QString &username);
     void authenticate(const QString &username,
                                  const QByteArray &nonce,
                                  const QByteArray &signature);

    // New operations
     void requestChallenge(const QString &username,
                                      const QString &operation);
     void changeUsername(const QJsonObject &payload);
     void changePassword(const QJsonObject &payload);
     void uploadFile(const QJsonObject &payload);
     void listFiles(const QJsonObject &payload);
     void downloadFile(const QJsonObject &payload);
     void deleteFile(const QJsonObject &payload);

    // Ping/check connection without user action
     void checkConnection();

signals:
    void signupResult(bool success, const QString &message);
    void loginChallenge(const QByteArray &nonce,
                        const QByteArray &salt,
                        int opslimit,
                        int memlimit,
                        const QByteArray &encryptedPrivKey,
                        const QByteArray &privKeyNonce,
                        const QByteArray &encryptedKek,
                        const QByteArray &kekNonce);
    void loginResult(bool success, const QString &message);

    void challengeResult(const QByteArray &nonce,
                         const QString &operation);
    void networkError(const QString &msg);

    void changeUsernameResult(bool success, const QString &message);
    void changePasswordResult(bool success, const QString &message);
    void uploadFileResult(bool success, const QString &message);
    void listFilesResult(bool success, const QStringList &files, const QString &message);
    void downloadFileResult(bool success,
                            const QString &encryptedFileB64,
                            const QString &fileNonceB64,
                            const QString &encryptedDekB64,
                            const QString &dekNonceB64,
                            const QString &message);
    void deleteFileResult(bool success, const QString &message);

    void connectionStatusChanged(bool online);

private:
    // Does a TCP connect + SSL handshake, returns an SSL* on success
    //   - sockOut is filled with the underlying socket fd
    //   - on failure, returns nullptr and emits connectionStatusChanged(false)
    SSL *openSslConnection(const QString &host,
                           quint16 port,
                           int &sockOut,
                           QString &errorMsg);

    QByteArray postJson(const QString &host,
                        quint16 port,
                        const QString &path,
                        const QJsonObject &obj,
                        bool &ok,
                        QString &message);

    SSL_CTX *ssl_ctx;
    void initOpenSSL();
    void cleanupOpenSSL();
};

#endif // NETWORKMANAGER_H
