#ifndef AUTHCONTROLLER_H
#define AUTHCONTROLLER_H

#include <QObject>
#include <QString>
#include <QByteArray>

class NetworkManager;

class AuthController : public QObject
{
    Q_OBJECT

public:
    explicit AuthController(NetworkManager *netMgr, QObject *parent = nullptr);

    // Called by MainWindow:
    Q_INVOKABLE void signup(const QString &username, const QString &password);
    Q_INVOKABLE void login(const QString &username, const QString &password);

signals:
    void signupResult(bool success, const QString &error);
    void loginResult(bool success, const QString &error);

private slots:
    // network events:
    void onNetSignupResult(bool success, const QString &error);
    void onNetLoginChallenge(
        const QByteArray &nonce,
        const QByteArray &salt,
        int opslimit,
        int memlimit,
        const QByteArray &encryptedPrivKey,
        const QByteArray &privKeyNonce
        );
    void onNetLoginResult(bool success, const QString &error);
    void onNetServerMessage(const QString &rawJson);

private:
    NetworkManager *networkManager;
    QString pendingUsername;
    QString pendingPassword;
};

#endif // AUTHCONTROLLER_H
