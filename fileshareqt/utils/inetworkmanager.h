// utils/inetworkmanager.h
#ifndef INETWORKMANAGER_H
#define INETWORKMANAGER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QJsonObject>

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
    void listFilesResult(bool success, const QStringList &files, const QString &message);
    void downloadFileResult(bool success,
                            const QString &encryptedFileB64,
                            const QString &fileNonceB64,
                            const QString &encryptedDekB64,
                            const QString &dekNonceB64,
                            const QString &message);
    void deleteFileResult(bool success, const QString &message);

    void connectionStatusChanged(bool online);
};

#endif // INETWORKMANAGER_H
