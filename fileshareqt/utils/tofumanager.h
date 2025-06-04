#ifndef TOFUMANAGER_H
#define TOFUMANAGER_H

#include <QObject>
#include <QVector>
#include <QString>
#include <QByteArray>

// Structure representing a verified user
struct VerifiedUser {
    QString   username;
    QByteArray ikPub;   // Raw 32‐byte identity key
};

class ICryptoService;
class AuthController;
class INetworkManager;

class TofuManager : public QObject {
    Q_OBJECT

public:
    TofuManager(ICryptoService    *cryptoService,
                AuthController     *authController,
                QObject            *parent = nullptr);

    // Completely clear the in‐memory TOFU list (called on logout)
    void clear();

    // Load from an encrypted remote backup (base64‐encoded strings), decrypting
    // with sessionKek, then populate m_list. Emits listChanged()
    void loadFromRemote(const QString &encryptedB64,
                        const QString &nonceB64);

    // given the current in‐memory list, serialise to JSON, encrypt with sessionKek,
    // and return base64‐encoded ciphertext + nonce. (called when performing a backup)
    void getEncryptedBackup(QString &outEncryptedB64,
                            QString &outNonceB64);

    // Add a newly verified user (username + raw 32‐byte ikPub). emits listChanged() and backupNeeded().
    // PASS BY REFERENCE | we pass by reference here as both values *could* be large.
    // we want to avoid making large unnecessary copies, even if we do not intend to modify the caller's original
    void addVerifiedUser(const QString     &username,
                         const QByteArray  &ikPub);

    // Removes a user by username. emits listChanged() and backupNeeded() if removed
    void removeVerifiedUser(const QString &username);

    // Return a const reference to the current in‐memory list
    QVector<VerifiedUser> verifiedUsers();

signals:
    // Emitted whenever the in‐memory list changes (after add/remove or loadFromRemote)
    void listChanged(const QVector<VerifiedUser> &newList);

    // Emitted whenever the in‐memory list changes, signaling that we should push a backup to the server
    void backupNeeded();

private:
    ICryptoService    *m_cryptoService;
    AuthController    *m_authController;

    QVector<VerifiedUser> m_list;
};

#endif // TOFUMANAGER_H
