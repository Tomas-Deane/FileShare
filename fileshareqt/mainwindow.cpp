#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "authcontroller.h"
#include "logger.h"
#include <sodium.h>
#include <QPixmap>
#include <QSizePolicy>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , authController(new AuthController(this))
{
    ui->setupUi(this);

    // Enable buttons
    ui->signupButton->setEnabled(true);
    ui->loginButton->setEnabled(true);

    // Logo setup
    ui->label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    ui->label->setMinimumSize(0, 0);
    ui->label->setScaledContents(true);
    QPixmap pix(":/nrmc_image.png");
    ui->label->setPixmap(pix);

    // Console logger
    Logger::initialize(ui->consoleTextEdit);

    if (sodium_init() < 0) {
        Logger::log("sodium_init() failed");
    } else {
        Logger::log("sodium initialized");
    }

    // Connect UI to AuthController state signals
    connect(authController, &AuthController::loggedIn,
            this, &MainWindow::handleLoggedIn);
    connect(authController, &AuthController::loggedOut,
            this, &MainWindow::handleLoggedOut);

    // Connect change‐username/password result signals
    connect(authController, &AuthController::changeUsernameResult,
            this, &MainWindow::onChangeUsernameResult);
    connect(authController, &AuthController::changePasswordResult,
            this, &MainWindow::onChangePasswordResult);

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

void MainWindow::on_logOutButton_clicked()
{
    authController->logout();
}

void MainWindow::handleLoggedIn(const QString &username)
{
    ui->loggedInLabel->setText("Logged in as " + username);
    ui->usernameLabel->setText("Username: " + username);
}

void MainWindow::handleLoggedOut()
{
    ui->loggedInLabel->setText("Not logged in");
    ui->usernameLabel->setText("Username: ");
}

void MainWindow::on_changeUsernameButton_clicked()
{
    const QString newUsername = ui->changeUsernameLineEdit->text();
    authController->changeUsername(newUsername);
}

void MainWindow::on_changePasswordButton_clicked()
{
    const QString newPassword = ui->changePasswordLineEdit->text();
    authController->changePassword(newPassword);
}

void MainWindow::onChangeUsernameResult(bool success, const QString &message)
{
    if (success) {
        Logger::log("Username changed successfully");
        // UI already updated via handleLoggedIn when AuthController emits it
    } else {
        Logger::log("Failed to change username: " + message);
    }
}

void MainWindow::onChangePasswordResult(bool success, const QString &message)
{
    if (success) {
        Logger::log("Password changed successfully");
    } else {
        Logger::log("Failed to change password: " + message);
    }
}
