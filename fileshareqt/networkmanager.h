#ifndef NETWORKMANAGER_H
#define NETWORKMANAGER_H

#include <QObject>
#include <QtNetwork/QTcpSocket>
#include <QJsonObject>

class NetworkManager : public QObject
{
    Q_OBJECT
public:
    explicit NetworkManager(QObject *parent = nullptr);
    void connectToHost(const QString &host, quint16 port);
    void signup(const QJsonObject &payload);
    void login(const QString &username);
    void authenticate(const QString &username, const QByteArray &signature);

signals:
    void connected();
    void disconnected();
    void signupResult(bool success, const QString &error);
    void loginChallenge(
        const QByteArray &nonce,
        const QByteArray &salt,
        int opslimit,
        int memlimit,
        const QByteArray &encryptedPrivKey,
        const QByteArray &privKeyNonce
        );
    void loginResult(bool success, const QString &error);

    void serverMessage(const QString &rawJson); // emit raw json from server (for logging)

private slots:
    void onConnectedSlot();
    void onDisconnectedSlot();
    void onReadyRead();

private:
    void sendJson(const QJsonObject &obj);
    void handleMessage(const QJsonObject &msg);

    QTcpSocket *socket;
    QByteArray   buffer;
    enum Pending { None, Signup, Login, Authenticate } pending = None;
};

#endif // NETWORKMANAGER_H
