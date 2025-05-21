#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "networkmanager.h"
#include "authcontroller.h"
#include "logger.h"

#include <sodium.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , networkManager(new NetworkManager(this))
    , authController(new AuthController(networkManager, this))
{
    ui->setupUi(this);

    // start with connect/signup disabled until we have TCP
    ui->signupButton->setEnabled(false);
    ui->loginButton->setEnabled(false);

    ui->label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    ui->label->setMinimumSize(0, 0);
    ui->label->setScaledContents(true);
    QPixmap pix(":/nrmc_image.png");
    ui->label->setPixmap(pix);

    // set gui log text box
    Logger::initialize(ui->consoleTextEdit);

    // hook up network‐state signals
    connect(networkManager, &NetworkManager::connected,
            this, &MainWindow::onServerConnected);
    connect(networkManager, &NetworkManager::disconnected,
            this, &MainWindow::onServerDisconnected);

    if (sodium_init() < 0) {
        Logger::log("sodium_init() failed");
    } else {
        Logger::log("sodium initialized");
    }

    // Auto-connect to server on startup
    const QString host = "gobbler.info";
    quint16 port = 3210; // we are using this port 3210 for nrmc
    Logger::log(QString("Auto-connecting to %1:%2").arg(host).arg(port));
    networkManager->connectToHost(host, port);

    Logger::log("UI setup complete");
}

MainWindow::~MainWindow()
{
    Logger::log("Application exiting");
    delete ui;
}

void MainWindow::onServerConnected()
{
    Logger::log("Connected to server");
    ui->signupButton->setEnabled(true);
    ui->loginButton->setEnabled(true);
}

void MainWindow::onServerDisconnected()
{
    Logger::log("Disconnected from server");
    ui->signupButton->setEnabled(false);
    ui->loginButton->setEnabled(false);
}

void MainWindow::on_signupButton_clicked()
{
    const QString username = ui->usernameLineEdit->text();
    const QString password = ui->passwordLineEdit->text();
    authController->signup(username, password);
}

void MainWindow::on_loginButton_clicked()
{
    const QString username = ui->usernameLineEdit->text();
    const QString password = ui->passwordLineEdit->text();
    authController->login(username, password);
}
