#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "authcontroller.h"
#include "logger.h"
#include <sodium.h>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , authController(new AuthController(this))
{
    ui->setupUi(this);

    // Enable buttons immediately
    ui->signupButton->setEnabled(true);
    ui->loginButton->setEnabled(true);

    // Logo
    ui->label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    ui->label->setMinimumSize(0, 0);
    ui->label->setScaledContents(true);
    QPixmap pix(":/nrmc_image.png");
    ui->label->setPixmap(pix);

    // Logger
    Logger::initialize(ui->consoleTextEdit);

    if (sodium_init() < 0) {
        Logger::log("sodium_init() failed");
    } else {
        Logger::log("sodium initialized");
    }

    Logger::log("UI setup complete");
}

MainWindow::~MainWindow()
{
    Logger::log("Application exiting");
    delete ui;
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
