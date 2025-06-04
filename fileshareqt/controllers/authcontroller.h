#ifndef AUTHCONTROLLER_H
#define AUTHCONTROLLER_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include "icryptoservice.h"
#include "inetworkmanager.h"

class NetworkManager;

class AuthController : public QObject {
    Q_OBJECT

public:
     AuthController(INetworkManager *networkManager,
                            ICryptoService *cryptoService,
                            QObject *parent = nullptr);

    void signup(const QString &username, const QString &password);
    void login(const QString &username, const QString &password);
    void logout();

    void updateSessionPdk(const QByteArray &newPdk);
    void updateSessionUsername(const QString &newUsername);

    void checkConnection();

    QString getSessionUsername() const;
    QByteArray getSessionSecretKey() const;
    QByteArray getSessionKek() const;

    // Expose *your* X25519 identity public key (IK_pub) to other controllers (for OOB code).
    // After we load the backup, this will be overwritten with the backed‐up copy.
    QByteArray getIdentityPublicKey() const;

    // Expose the private half too (in case you need it; typically you only need the pub for verify)
    QByteArray getIdentityPrivateKey() const;

    // Expose SPK and OPKs if needed (not used in OOB code, but you might need them later)
    QByteArray getSignedPreKeyPublic()   const;
    QByteArray getSignedPreKeyPrivate()  const;
    QByteArray getSignedPreKeySignature() const;
    QList<QByteArray> getOneTimePreKeyPubs()  const;
    QList<QByteArray> getOneTimePreKeyPrivs() const;

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
    // handle server's “challenge” result for get_backup_tofu
    void onChallengeReceived(const QByteArray &nonce, const QString &operation);

    // handle server’s response to /get_backup_tofu
    void onGetBackupTOFUResult(bool success,
                               const QString &encryptedBackupB64,
                               const QString &backupNonceB64,
                               const QString &message);
    void onConnectionStatusChanged(bool online);

private:
    INetworkManager *networkManager;
    ICryptoService *cryptoService;

    QString pendingUsername;
    QString pendingPassword;
    QString sessionUsername;
    QByteArray sessionSecretKey;   // Ed25519 secret (decrypted on login)
    QByteArray sessionPdk;         // PDK (derived from password)
    QByteArray sessionKek;         // KEK (for file encryption)

    QByteArray ikPublic;         // X25519 identity public  (32 bytes)
    QByteArray ikPrivate;        // X25519 identity private (32 bytes)
    QByteArray spkPublic;        // X25519 signed pre-key public (32 bytes)
    QByteArray spkPrivate;       // X25519 signed pre-key private (32 bytes)
    QByteArray spkSignature;     // Ed25519 signature over spkPublic (64 bytes)
    QList<QByteArray> opkPrivs;  // in-memory private halves of OPKs (each 32 bytes)
    QList<QByteArray> opkPubs;   // public halves of one-time keys (each 32 bytes)
    // —————————————————————————————————————————

    // Helpers:
    void requestGetBackupTOFU();
    void parseBackupJson(const QByteArray &plaintext);

    void processLogin(const QByteArray &nonce);
};

#endif // AUTHCONTROLLER_H
