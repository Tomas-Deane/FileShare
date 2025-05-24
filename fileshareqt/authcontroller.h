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

    // New operations
    Q_INVOKABLE void changeUsername(const QString &newUsername);
    Q_INVOKABLE void changePassword(const QString &newPassword);

signals:
    void signupResult(bool success, const QString &message);
    void loginResult(bool success, const QString &message);
    void loggedIn(const QString &username);
    void loggedOut();

    // Results for change operations
    void changeUsernameResult(bool success, const QString &message);
    void changePasswordResult(bool success, const QString &message);

private slots:
    // Login flow
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

    // Handle server‐side generic challenge
    void onChallengeReceived(const QByteArray &nonce,
                             const QString &operation);

    // After sending change requests
    void onChangeUsernameNetwork(bool success, const QString &message);
    void onChangePasswordNetwork(bool success, const QString &message);

private:
    NetworkManager *networkManager;

    // Credentials during the handshake
    QString pendingUsername;
    QString pendingPassword;

    // Session state (cleared on logout)
    QString sessionUsername;
    QByteArray sessionSecretKey;
    QByteArray sessionPdk;

    // For change‐username
    QString pendingNewUsername;

    // For change‐password
    QByteArray pendingSalt;
    quint64   pendingOpsLimit;
    quint64   pendingMemLimit;
    QByteArray pendingEncryptedSK;
    QByteArray pendingPrivKeyNonce;

    void processChangeUsername(const QByteArray &nonce);
    void processChangePassword(const QByteArray &nonce);
};

#endif // AUTHCONTROLLER_H
