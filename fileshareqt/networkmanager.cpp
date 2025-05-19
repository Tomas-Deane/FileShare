#include "networkmanager.h"

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

void NetworkManager::sendMessage(const QString &message)
{
    QByteArray data = message.toUtf8();
    data.append('\n');
    socket->write(data);
}

void NetworkManager::onConnectedSlot()
{
    emit connected();
}

void NetworkManager::onDisconnectedSlot()
{
    emit disconnected();
}

void NetworkManager::onReadyRead()
{
    buffer.append(socket->readAll());
    int idx;
    while ((idx = buffer.indexOf('\n')) != -1) {
        QByteArray line = buffer.left(idx);
        buffer.remove(0, idx + 1);
        emit messageReceived(QString::fromUtf8(line));
    }
}
