#ifndef NETWORKMANAGER_H
#define NETWORKMANAGER_H

#include <QObject>
#include <QtNetwork/QTcpSocket>

class NetworkManager : public QObject
{
    Q_OBJECT
public:
    explicit NetworkManager(QObject *parent = nullptr);
    void connectToHost(const QString &host, quint16 port);
    void sendMessage(const QString &message);

signals:
    void connected();
    void disconnected();
    void messageReceived(const QString &message);

private slots:
    void onConnectedSlot();
    void onDisconnectedSlot();
    void onReadyRead();

private:
    QTcpSocket *socket;
    QByteArray buffer;
};

#endif // NETWORKMANAGER_H
