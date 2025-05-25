#ifndef NETWORKMANAGER_H
#define NETWORKMANAGER_H

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <openssl/ssl.h>
#include <openssl/err.h>
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

    Q_INVOKABLE void signup(const QJsonObject &payload);
    Q_INVOKABLE void login(const QString &username);
    Q_INVOKABLE void authenticate(const QString &username,
                                  const QByteArray &nonce,
                                  const QByteArray &signature);

    // New operations
    Q_INVOKABLE void requestChallenge(const QString &username,
                                      const QString &operation);
    Q_INVOKABLE void changeUsername(const QJsonObject &payload);
    Q_INVOKABLE void changePassword(const QJsonObject &payload);

signals:
    void signupResult(bool success, const QString &message);

    // Emitted when login() returns a challenge + full login info
    void loginChallenge(
        const QByteArray &nonce,
        const QByteArray &salt,
        int opslimit,
        int memlimit,
        const QByteArray &encryptedPrivKey,
        const QByteArray &privKeyNonce
        );
    void loginResult(bool success, const QString &message);

    // Generic challenge for change-ops
    void challengeResult(const QByteArray &nonce,
                         const QString &operation);

    void networkError(const QString &msg);

    // New signals
    void changeUsernameResult(bool success, const QString &message);
    void changePasswordResult(bool success, const QString &message);

    void connectionStatusChanged(bool online);

private:
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
