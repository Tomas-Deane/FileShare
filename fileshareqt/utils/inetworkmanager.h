#ifndef INETWORKMANAGER_H
#define INETWORKMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QJsonObject>

#include "fileentry.h"

class INetworkManager : public QObject {
    Q_OBJECT

public:
    explicit INetworkManager(QObject *parent = nullptr) : QObject(parent) {}
    ~INetworkManager() override = default;

    // Core flow
    virtual void signup(const QJsonObject &payload) = 0;
    virtual void login(const QString &username) = 0;
    virtual void authenticate(const QString &username,
                              const QByteArray &nonce,
                              const QByteArray &signature) = 0;

    // Challenge‐based operations
    virtual void requestChallenge(const QString &username,
                                  const QString &operation) = 0;
    virtual void changeUsername(const QJsonObject &payload) = 0;
    virtual void changePassword(const QJsonObject &payload) = 0;
    virtual void uploadFile(const QJsonObject &payload) = 0;
    virtual void listFiles(const QJsonObject &payload) = 0;
    virtual void downloadFile(const QJsonObject &payload) = 0;
    virtual void deleteFile(const QJsonObject &payload) = 0;
    virtual void retrieveFileDEK(const QJsonObject &payload) = 0;

    // X3DH: getPreKeyBundle
    virtual void getPreKeyBundle(const QJsonObject &payload) = 0;
    virtual void getOPK(const QJsonObject &payload) = 0;

    // TOFU backup
    virtual void backupTOFU(const QJsonObject &payload) = 0;
    virtual void getBackupTOFU(const QJsonObject &payload) = 0;

    // share a file (POST /share_file)
    virtual void shareFile(const QJsonObject &payload) = 0;
    virtual void listSharedTo(const QJsonObject &payload) = 0;
    virtual void listSharedFrom(const QJsonObject &payload) = 0;
    virtual void listSharers(const QJsonObject &payload) = 0;
    virtual void downloadSharedFile(const QJsonObject &payload) = 0;

    // revoke a share (POST /remove_shared_file)
    virtual void removeSharedFile(const QJsonObject &payload) = 0;

    // Misc
    virtual void checkConnection() = 0;

signals:
    void signupResult(bool success, const QString &message);
    void loginChallenge(const QByteArray &nonce,
                        const QByteArray &salt,
                        int opslimit,
                        int memlimit,
                        const QByteArray &encryptedPrivKey,
                        const QByteArray &privKeyNonce,
                        const QByteArray &encryptedKek,
                        const QByteArray &kekNonce);
    void loginResult(bool success, const QString &message);

    void challengeResult(const QByteArray &nonce,
                         const QString &operation);
    void networkError(const QString &msg);

    void changeUsernameResult(bool success, const QString &message);
    void changePasswordResult(bool success, const QString &message);
    void uploadFileResult(bool success, const QString &message);
    void listFilesResult(bool success,
                         const QList<FileEntry> &files,
                         const QString &message);
    void downloadFileResult(bool success,
                            const QString &encryptedFileB64,
                            const QString &fileNonceB64,
                            const QString &encryptedDekB64,
                            const QString &dekNonceB64,
                            const QString &message);
    void deleteFileResult(bool success, const QString &message);

    void removeSharedFileResult(bool success, const QString &message);

    void downloadSharedFileResult(bool   success,
                                  const QString &encryptedFileB64,
                                  const QString &fileNonceB64,
                                  const QString &encryptedFileKeyB64,
                                  const QString &fileKeyNonceB64,
                                  const QString &EK_pub_b64,
                                  const QString &IK_pub_b64,
                                  const QString &SPK_pub_b64,
                                  const QString &SPK_sig_b64,
                                  int            opk_id,
                                  const QString &message);

    void retrieveFileDEKResult(bool success,
         const QString &encryptedDekB64,
         const QString &dekNonceB64,
         const QString &message);

    // X3DH
    void getPreKeyBundleResult(bool success,
                               const QString &ik_pub_b64,
                               const QString &spk_pub_b64,
                               const QString &spk_sig_b64,
                               const QString &message);

    void getOPKResult(bool success, int opk_id, const QString &pre_key_b64, const QString &message);

    // TOFU backup
    void backupTOFUResult(bool success, const QString &message);
    void getBackupTOFUResult(bool success,
                             const QString &encrypted_backup_b64,
                             const QString &backup_nonce_b64,
                             const QString &message);

    // file sharing
    void shareFileResult(bool success, const QString &message);
    void listSharedToResult(bool success,
                            const QJsonArray &shares,
                            const QString &message);

    void listSharedFromResult(bool success,
                              const QJsonArray &shares,
                              const QString &message);

    void listSharersResult(bool success, const QStringList &usernames, const QString &message);

    void connectionStatusChanged(bool online);
};

#endif // INETWORKMANAGER_H
