#include "networkmanager.h"
#include <QJsonDocument>
#include <QJsonValue>

NetworkManager::NetworkManager(QObject *parent)
    : QObject(parent)
    , socket(new QTcpSocket(this))
{
    connect(socket, &QTcpSocket::connected,    this, &NetworkManager::onConnectedSlot);
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onDisconnectedSlot);
    connect(socket, &QTcpSocket::readyRead,    this, &NetworkManager::onReadyRead);
}

void NetworkManager::connectToHost(const QString &host, quint16 port)
{
    socket->connectToHost(host, port);
}

void NetworkManager::signup(const QJsonObject &payload)
{
    pending = Signup;
    sendJson(payload);
}

void NetworkManager::login(const QString &username)
{
    pending = Login;
    QJsonObject loginObj;
    loginObj["action"]   = "login";
    loginObj["username"] = username;
    sendJson(loginObj);
}

void NetworkManager::authenticate(const QString &username, const QByteArray &signature)
{
    pending = Authenticate;
    QJsonObject authObj;
    authObj["action"]    = "authenticate";
    authObj["username"]  = username;
    authObj["signature"] = QString::fromUtf8(signature.toBase64());
    sendJson(authObj);
}

void NetworkManager::onConnectedSlot()    { emit connected(); } // forward connected/disconnected signals from network manager so other components can effectively use the TCP socket's connected/disconnected signals without actually knowing the TCP socket's instance
void NetworkManager::onDisconnectedSlot(){ emit disconnected(); }

void NetworkManager::onReadyRead()
{
    buffer.append(socket->readAll()); // read all info from socket (TCP is stream, so we might read partial messages, need delimiter (/n)
    int i;
    while ((i = buffer.indexOf('\n')) != -1) { // /n indicates end of message, add to persistent buffer until message end, then process message
        QByteArray line = buffer.left(i);
        buffer.remove(0, i + 1);

        emit serverMessage(QString::fromUtf8(line));

        auto doc = QJsonDocument::fromJson(line);
        if (doc.isObject()) { // otherwise: message is bad (not valid JSON), discard
            handleMessage(doc.object());
        }
    }
}

void NetworkManager::sendJson(const QJsonObject &obj)
{
    QJsonDocument doc(obj);
    QByteArray ba = doc.toJson(QJsonDocument::Compact) + "\n";
    socket->write(ba);
}

void NetworkManager::handleMessage(const QJsonObject &msg)
{
    QString status = msg.value("status").toString();

    if (pending == Signup) { // networkManager keeps a pending variable (enum) that represents the current expected server response
        if (status == "ok")
            emit signupResult(true, {});
        else
            emit signupResult(false, msg.value("error").toString());
        pending = None;
    }
    else if (pending == Login) {
        if (status == "challenge") {
            QByteArray nonce       = QByteArray::fromBase64(
                msg.value("nonce").toString().toUtf8());
            QByteArray salt        = QByteArray::fromBase64(
                msg.value("salt").toString().toUtf8());
            int opslimit           = msg.value("argon2_opslimit").toInt();
            int memlimit           = msg.value("argon2_memlimit").toInt();
            QByteArray encryptedSK = QByteArray::fromBase64(
                msg.value("encrypted_privkey").toString().toUtf8());
            QByteArray skNonce     = QByteArray::fromBase64(
                msg.value("privkey_nonce").toString().toUtf8());

            emit loginChallenge(
                nonce, salt, opslimit, memlimit, encryptedSK, skNonce
                );
        } else {
            emit loginResult(false, msg.value("error").toString());
        }
        pending = None;
    }
    else if (pending == Authenticate) {
        if (status == "ok") {
            QString message = msg.value("message").toString();
            emit loginResult(true, message);
        } else {
            emit loginResult(false, msg.value("error").toString());
        }
        pending = None;
    }
}
