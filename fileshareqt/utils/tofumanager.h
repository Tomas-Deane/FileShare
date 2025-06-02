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
                INetworkManager    *networkManager,
                QObject            *parent = nullptr);

    // Completely clear the in‐memory TOFU list (called on logout)
    void clear();

    // Load from an encrypted remote backup (base64‐encoded strings), decrypting
    // with sessionKek, then populate m_list. Emits listChanged().
    void loadFromRemote(const QString &encryptedB64,
                        const QString &nonceB64);

    // Given the current in‐memory list, serialize to JSON, encrypt with sessionKek,
    // and return base64‐encoded ciphertext + nonce. (Called when performing a backup.)
    void getEncryptedBackup(QString &outEncryptedB64,
                            QString &outNonceB64) const;

    // Add a newly verified user (username + raw 32‐byte ikPub). Emits listChanged() and backupNeeded().
    void addVerifiedUser(const QString     &username,
                         const QByteArray  &ikPub);

    // Remove a user by username. Emits listChanged() and backupNeeded() if removed.
    void removeVerifiedUser(const QString &username);

    // Return a const reference to the current in‐memory list.
    QVector<VerifiedUser> verifiedUsers() const;

signals:
    // Emitted whenever the in‐memory list changes (after add/remove or loadFromRemote)
    void listChanged(const QVector<VerifiedUser> &newList);

    // Emitted whenever the in‐memory list changes, signaling that we should push a backup to the server
    void backupNeeded();

private:
    ICryptoService    *m_cryptoService;
    AuthController    *m_authController;
    INetworkManager   *m_networkManager;

    QVector<VerifiedUser> m_list;
};

#endif // TOFUMANAGER_H
