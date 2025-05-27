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

    Q_INVOKABLE void checkConnection();

    QString getSessionUsername() const;
    QByteArray getSessionSecretKey() const;
    QByteArray getSessionKek() const;

public slots:
    void updateSessionUsername(const QString &newUsername);

signals:
    void signupResult(bool success, const QString &message);
    void loginResult(bool success, const QString &message);
    void loggedIn(const QString &username);
    void loggedOut();
    void connectionStatusChanged(bool online);

private slots:
    void onSignupResult(bool success, const QString &message);
    void onLoginChallenge(const QByteArray &nonce,
                          const QByteArray &salt,
                          int opslimit,
                          int memlimit,
                          const QByteArray &encryptedSK,
                          const QByteArray &skNonce,
                          const QByteArray &encryptedKek,
                          const QByteArray &kekNonce);
    void onLoginResult(bool success, const QString &message);
    void onChallengeReceived(const QByteArray &nonce, const QString &operation);
    void onConnectionStatusChanged(bool online);

private:
    NetworkManager *networkManager;
    QString pendingUsername;
    QString pendingPassword;
    QString sessionUsername;
    QByteArray sessionSecretKey;
    QByteArray sessionPdk;
    QByteArray sessionKek;

    void processUploadFile(const QByteArray &nonce) = delete;   // now in FileController
    void processListFiles(const QByteArray &nonce) = delete;
    void processDownloadFile(const QByteArray &nonce) = delete;
    void processDeleteFile(const QByteArray &nonce) = delete;
};

#endif // AUTHCONTROLLER_H
