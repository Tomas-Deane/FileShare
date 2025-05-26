#ifndef AUTHCONTROLLER_H
#define AUTHCONTROLLER_H

#include <QObject>
#include <QString>
#include <QStringList>
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
    Q_INVOKABLE void uploadFile(const QString &filename, const QString &fileContents);
    Q_INVOKABLE void listFiles();
    Q_INVOKABLE void downloadFile(const QString &filename);
    Q_INVOKABLE void deleteFile(const QString &filename);

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

    // Results for new download/list operations
    void listFilesResult(bool success, const QStringList &files, const QString &message);
    void downloadFileResult(bool success, const QString &filename, const QByteArray &data, const QString &message);

    // Delete result
    void deleteFileResult(bool success, const QString &message);

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
    void onChallengeReceived(const QByteArray &nonce, const QString &operation);

    void onConnectionStatusChanged(bool online);

    // After sending change requests
    void onChangeUsernameNetwork(bool success, const QString &message);
    void onChangePasswordNetwork(bool success, const QString &message);
    void onUploadFileNetwork(bool success, const QString &message);

    // New network callbacks
    void onListFilesNetwork(bool success, const QStringList &files, const QString &message);
    void onDownloadFileNetwork(bool success,
                               const QString &encryptedFileB64,
                               const QString &fileNonceB64,
                               const QString &encryptedDekB64,
                               const QString &dekNonceB64,
                               const QString &message);
    void onDeleteFileNetwork(bool success, const QString &message);

private:
    NetworkManager *networkManager;

    // Credentials during the handshake
    QString pendingUsername;
    QString pendingPassword;

    // For file upload
    QString pendingFileName;
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

    // For download/delete
    QString selectedFilename;

    // Challenge processors
    void processChangeUsername(const QByteArray &nonce);
    void processChangePassword(const QByteArray &nonce);
    void processUploadFile(const QByteArray &nonce);
    void processListFiles(const QByteArray &nonce);
    void processDownloadFile(const QByteArray &nonce);
    void processDeleteFile(const QByteArray &nonce);
};

#endif // AUTHCONTROLLER_H
