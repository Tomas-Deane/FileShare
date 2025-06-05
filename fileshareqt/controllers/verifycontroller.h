#ifndef VERIFYCONTROLLER_H
#define VERIFYCONTROLLER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
#include <QMap>
#include "icryptoservice.h"
#include "inetworkmanager.h"
#include "tofumanager.h"

class AuthController;
class NetworkManager;
class TofuManager;

class VerifyController : public QObject {
    Q_OBJECT
public:
    explicit VerifyController(INetworkManager* net,
                              AuthController*    auth,
                              ICryptoService*    cs,
                              TofuManager*       tofuMgr,
                              QObject*           parent = nullptr);

    /// Call when user switches to the Verify tab or logs in:
    void initializeVerifyPage();

    /// GUI calls:
    void generateOOBCode(const QString &targetUsername);
    void verifyNewUser(const QString &targetUsername);
    void deleteVerifiedUser(const QString &targetUsername);

signals:
    /// Emitted when the OOB code is ready to display (or error)
    void oobCodeReady(const QString &code, const QString &errorMessage);

    /// Emitted when Verified‐Users list should be refreshed in GUI
    void updateVerifiedUsersList(const QList<VerifiedUser> &currentList);

    /// Emitted when backupTOFU succeeded/failed
    void tofuBackupResult(bool success, const QString &message);

    /// Emitted when loading remote backup is done
    void tofuLoadCompleted(const QList<VerifiedUser> &loadedList, const QString &errorMessage);

private slots:
    /// React to network‐layer challenge for a given operation
    void onChallengeReceived(const QByteArray &nonce, const QString &operation);

    /// Handle server response for getPreKeyBundle
    void onGetPreKeyBundleResult(bool success,
                                 const QString &ik_pub_b64,
                                 const QString &spk_pub_b64,
                                 const QString &spk_sig_b64,
                                 const QString &message);

    /// Handle server response for getBackupTOFU
    void onGetBackupTOFUResult(bool success,
                               const QString &encrypted_backup_b64,
                               const QString &backup_nonce_b64,
                               const QString &message);

    /// Handle server response for backupTOFU
    void onBackupTOFUResult(bool success, const QString &message);

    /// When login or logout happens in AuthController
    void onLoggedOut();

private:
    INetworkManager  *m_networkManager;
    AuthController   *m_authController;
    ICryptoService   *m_cryptoService;
    TofuManager      *m_tofuManager;        // dedicated in‐memory TOFU manager

    // State for “generate code” flow:
    QString    m_pendingTargetUsername;
    QString    m_pendingOperation; // either "get_pre_key_bundle" or "get_backup_tofu" or "backup_tofu"

    QMap<QString, QByteArray> m_stashedUsers;

    // Helper: convert QVector<VerifiedUser> to QList<VerifiedUser> for signals
    static QList<VerifiedUser> toQList(const QVector<VerifiedUser> &vec);
};

#endif // VERIFYCONTROLLER_H
