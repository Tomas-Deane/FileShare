#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , networkManager(new NetworkManager(this))
{
    ui->setupUi(this);

    // Wire up network signals to our slots
    connect(networkManager, &NetworkManager::connected,    this, &MainWindow::onConnected);
    connect(networkManager, &NetworkManager::disconnected, this, &MainWindow::onDisconnected);
    connect(networkManager, &NetworkManager::messageReceived,
            this, &MainWindow::onDataReceived);

    ui->sendButton->setEnabled(false);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_connectButton_clicked()
{
    const QString host = ui->hostLineEdit->text();
    const quint16 port = static_cast<quint16>(ui->portLineEdit->text().toUInt());
    ui->logTextEdit->append(QString("Connecting to %1:%2…").arg(host).arg(port));
    networkManager->connectToHost(host, port);
}

void MainWindow::on_sendButton_clicked()
{
    const QString msg = ui->inputLineEdit->text();
    if (msg.isEmpty())
        return;
    networkManager->sendMessage(msg);
    ui->logTextEdit->append("Me: " + msg);
    ui->inputLineEdit->clear();
}

void MainWindow::onConnected()
{
    ui->logTextEdit->append("Connected!");
    ui->sendButton->setEnabled(true);
    ui->connectButton->setEnabled(false);
}

void MainWindow::onDisconnected()
{
    ui->logTextEdit->append("Disconnected.");
    ui->sendButton->setEnabled(false);
    ui->connectButton->setEnabled(true);
}

void MainWindow::onDataReceived(const QString &message)
{
    ui->logTextEdit->append("Server: " + message);
}
