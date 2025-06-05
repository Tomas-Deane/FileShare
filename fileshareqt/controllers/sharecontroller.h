// File: ./fileshareqt/controllers/sharecontroller.h
#ifndef SHARECONTROLLER_H
#define SHARECONTROLLER_H

#include <QObject>
#include <QString>
#include <QJsonArray>
#include <QMap>
#include "tofumanager.h"
#include "icryptoservice.h"
#include "inetworkmanager.h"

class AuthController;

struct SharedFile {
    qint64 share_id;
    qint64 file_id;
    QString filename;
    QString shared_by;    // who shared it (for listSharedFrom)
    QString shared_at;    // ISO timestamp
};

class ShareController : public QObject
{
    Q_OBJECT

public:
    explicit ShareController(INetworkManager  *networkManager,
                             AuthController   *authController,
                             ICryptoService   *cryptoService,
                             TofuManager *tofuManager,
                             QObject          *parent = nullptr);

    // ⓵ Share a file with a particular recipientUsername.
    //     `fileId` is the internal ID of the file you want to share.
    //     `recipientUsername` is the username of the person you share to.
    void shareFile(qint64 fileId, const QString &recipientUsername);

    // ⓶ List all files I (current user) have shared TO `targetUsername`.
    void listFilesSharedTo(const QString &targetUsername);

    // ⓷ List all files shared FROM `targetUsername` TO me.
    void listFilesSharedFrom(const QString &targetUsername);

    void listSharers();

    void downloadSharedFile(qint64 shareId, const QString &filename);

    // Revoke a previously‐granted share (share_id).
    void revokeAccess(qint64 shareId);

signals:
    // Emitted when a share operation completes (success==true if server returned OK)
    void shareFileResult(bool success, const QString &message);

    void removeSharedFileResult(bool success, const QString &message);

    // Emitted when “list to” comes back; the list is a vector of SharedFile
    void listSharedToResult(bool success,
                            const QList<SharedFile> &shares,
                            const QString &message);

    // Emitted when “list from” comes back
    void listSharedFromResult(bool success,
                              const QList<SharedFile> &shares,
                              const QString &message);

    void listSharersResult(bool success, const QStringList &usernames, const QString &message);

    void downloadSharedFileResult(bool success,
                                  const QString &filename,
                                  const QByteArray &data,
                                  const QString &message);

private slots:
    // Called whenever the network layer gives us a challenge
    void onChallenge(const QByteArray &nonce, const QString &operation);

    // Called when the /get_pre_key_bundle result arrives
    void onGetPreKeyBundleResult(bool success,
                                 const QString &ik_pub_b64,
                                 const QString &spk_pub_b64,
                                 const QString &spk_sig_b64,
                                 const QString &message);

    // Called when the /retrieve_file_dek result arrives
    void onRetrieveFileDEKResult(bool success,
                                 const QString &encryptedDekB64,
                                 const QString &dekNonceB64,
                                 const QString &message);

    // Called when the /share_file response arrives
    void onShareFileNetwork(bool success, const QString &message);

    // Called when the /list_shared_to response arrives
    void onListSharedToNetwork(bool success,
                               const QJsonArray &shares,
                               const QString &message);

    // Called when the /list_shared_from response arrives
    void onListSharedFromNetwork(bool success,
                                 const QJsonArray &shares,
                                 const QString &message);

    // New slot to receive the network result
    void onListSharersNetwork(bool success,
                              const QStringList &usernames,
                              const QString &message);

    void onDownloadSharedNetwork(bool   success,
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

    // Called when removeSharedFileResult arrives
    void onRemoveSharedFileNetwork(bool success, const QString &message);

    // Called when the /get_opk result arrives
    void onGetOPKResult(bool success, int opk_id, const QString &pre_key_b64, const QString &message);

private:
    INetworkManager *m_networkManager;
    AuthController  *m_authController;
    ICryptoService  *m_cryptoService;
    TofuManager *m_tofuManager;

    // We stash state so that when a challenge arrives, we know what to do:
    enum PendingOp {
        None,
        GetPreKeyBundle,
        RetrieveFileDEK,
        GetOPK,
        DoShareFile,
        ListSharedTo,
        ListSharedFrom,
        ListSharers,
        DownloadSharedFile,
        RevokeShare
    };

    PendingOp        m_pendingOp = None;
    QString          m_pendingRecipient;   // for shareFile
    qint64           m_pendingFileId      = -1;
    QByteArray       m_recipientIkPub;    // after getPreKeyBundle
    QByteArray       m_recipientSpkPub;      // <–– new: stash recipient’s SPK_pub
    QByteArray       m_recipientSpkSignature;

    QString          m_pendingTargetUsername;  // for listSharedTo / listSharedFrom

    // After retrieving DEK from server, stash it here until we do ECDH‐encrypt:
    QByteArray       m_stashedEncryptedDek; // raw bytes of encrypted DEK
    QByteArray       m_stashedDekNonce;     // raw nonce for that DEK

    //stash returned OPK ID & raw OPK (base64)
    int              m_stashedOpkId = -1;
    QByteArray       m_stashedOpkPreKey;

    // Helper: convert QJsonArray→QList<SharedFile>
    QList<SharedFile> parseSharedArray(const QJsonArray &arr) const;

    qint64           m_pendingShareId = -1;  // stash the share_id
    QString m_pendingFilename;

    static const int X25519_PUBKEY_LEN = 32;
};

#endif // SHARECONTROLLER_H
