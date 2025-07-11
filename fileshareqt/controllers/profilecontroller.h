#ifndef PROFILECONTROLLER_H
#define PROFILECONTROLLER_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include "icryptoservice.h"
#include "inetworkmanager.h"

class AuthController;
class NetworkManager;

class ProfileController : public QObject {
    Q_OBJECT
public:
     ProfileController(INetworkManager    *networkManager,
                               AuthController     *authController,
                               ICryptoService     *cryptoService,
                               QObject            *parent = nullptr);

     void changeUsername(const QString &newUsername);
     void changePassword(const QString &newPassword);

signals:
    void changeUsernameResult(bool success, const QString &message);
    void changePasswordResult(bool success, const QString &message);

private slots:
    void onChallengeReceived(const QByteArray &nonce, const QString &operation);
    void onChangeUsernameNetwork(bool success, const QString &message);
    void onChangePasswordNetwork(bool success, const QString &message);

private:
    AuthController *m_authController;
    INetworkManager  *m_networkManager;
    ICryptoService  *m_cryptoService;

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
