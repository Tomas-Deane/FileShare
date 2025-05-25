// File: fileshareqt/authcontroller.h
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
    Q_INVOKABLE void uploadFile(const QString &fileContents);

    // Expose ping/check
    Q_INVOKABLE void checkConnection();

signals:
    void signupResult(bool success, const QString &message);
    void loginResult(bool success, const QString &message);
    void loggedIn(const QString &username);
    void loggedOut();

    // Results for change operations
    void changeUsernameResult(bool success, const QString &message);
    void changePasswordResult(bool success, const QString &message);
    void uploadFileResult(bool success, const QString &message);

    // Forwarded connection status
    void connectionStatusChanged(bool online);

private slots:
    // Signup/login callbacks
    void onSignupResult(bool success, const QString &message);
    void onLoginChallenge(
        const QByteArray &nonce,
        const QByteArray &salt,
        int opslimit,
        int memlimit,
        const QByteArray &encryptedSK,
        const QByteArray &skNonce,
        const QByteArray &encryptedKek,
        const QByteArray &kekNonce
        );
    void onLoginResult(bool success, const QString &message);

    // Handle server‐side generic challenge
    void onChallengeReceived(const QByteArray &nonce,
                             const QString &operation);

    void onConnectionStatusChanged(bool online);

    // After sending change requests
    void onChangeUsernameNetwork(bool success, const QString &message);
    void onChangePasswordNetwork(bool success, const QString &message);
    void onUploadFileNetwork(bool success, const QString &message);

private:
    NetworkManager *networkManager;

    // Credentials during the handshake
    QString pendingUsername;
    QString pendingPassword;

    // For file upload
    QString pendingFileContents;

    // Session state (cleared on logout)
    QString sessionUsername;
    QByteArray sessionSecretKey;
    QByteArray sessionPdk;
    QByteArray sessionKek;

    // For change‐username
    QString pendingNewUsername;

    // For change‐password
    QByteArray pendingSalt;
    quint64   pendingOpsLimit;
    quint64   pendingMemLimit;
    QByteArray pendingEncryptedSK;
    QByteArray pendingPrivKeyNonce;
    QByteArray pendingEncryptedKek;
    QByteArray pendingKekNonce;

    void processChangeUsername(const QByteArray &nonce);
    void processChangePassword(const QByteArray &nonce);
    void processUploadFile(const QByteArray &nonce);
};

#endif // AUTHCONTROLLER_H
