#ifndef PROFILECONTROLLER_H
#define PROFILECONTROLLER_H

#include <QObject>
#include <QString>
#include <QByteArray>

class AuthController;
class NetworkManager;

class ProfileController : public QObject
{
    Q_OBJECT

public:
    explicit ProfileController(AuthController *authController, QObject *parent = nullptr);

    Q_INVOKABLE void changeUsername(const QString &newUsername);
    Q_INVOKABLE void changePassword(const QString &newPassword);

signals:
    void changeUsernameResult(bool success, const QString &message);
    void changePasswordResult(bool success, const QString &message);

private slots:
    void onChallengeReceived(const QByteArray &nonce, const QString &operation);
    void onChangeUsernameNetwork(bool success, const QString &message);
    void onChangePasswordNetwork(bool success, const QString &message);

private:
    AuthController *m_authController;
    NetworkManager *m_networkManager;

    // For change username
    QString m_pendingNewUsername;

    // For change password
    QString m_pendingNewPassword;
    QByteArray m_pendingSalt;
    quint64 m_pendingOpsLimit;
    quint64 m_pendingMemLimit;
    QByteArray m_pendingEncryptedSK;
    QByteArray m_pendingPrivKeyNonce;
    QByteArray m_pendingEncryptedKek;
    QByteArray m_pendingKekNonce;

    void processChangeUsername(const QByteArray &nonce);
    void processChangePassword(const QByteArray &nonce);
};

#endif // PROFILECONTROLLER_H
