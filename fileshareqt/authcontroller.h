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
    explicit AuthController(QObject *parent = nullptr);

    Q_INVOKABLE void signup(const QString &username, const QString &password);
    Q_INVOKABLE void login(const QString &username, const QString &password);
    Q_INVOKABLE void logout();

signals:
    void signupResult(bool success, const QString &message);
    void loginResult(bool success, const QString &message);

    // New signals for UI state updates
    void loggedIn(const QString &username);
    void loggedOut();

private slots:
    void onSignupResult(bool success, const QString &message);
    void onLoginChallenge(
        const QByteArray &nonce,
        const QByteArray &salt,
        int opslimit,
        int memlimit,
        const QByteArray &encryptedSK,
        const QByteArray &skNonce
        );
    void onLoginResult(bool success, const QString &message);

private:
    NetworkManager *networkManager;

    // Credentials during the handshake
    QString pendingUsername;
    QString pendingPassword;

    // Session state (cleared on logout)
    QString sessionUsername;
    QByteArray sessionSecretKey;
    QByteArray sessionPdk;
};

#endif // AUTHCONTROLLER_H
