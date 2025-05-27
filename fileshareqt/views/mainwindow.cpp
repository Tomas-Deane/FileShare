#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "authcontroller.h"
#include "profilecontroller.h"
#include "filecontroller.h"
#include "logger.h"

#include <sodium.h>
#include <QPixmap>
#include <QTimer>
#include <QFileDialog>
#include <QFileInfo>
#include <QMimeDatabase>
#include <QFile>

 MainWindow::MainWindow(AuthController* authCtrl,
        FileController* fileCtrl,
        ProfileController* profileCtrl,
        QWidget *parent)
        : QMainWindow(parent)
        , ui(new Ui::MainWindow)
        , authController(authCtrl)
        , profileController(profileCtrl)
        , fileController(fileCtrl)
        , pendingDeleteItem(nullptr)
{
    ui->setupUi(this);

    // FileController signals
    connect(fileController, &FileController::uploadFileResult,
            this, &MainWindow::onUploadFileResult);
    connect(fileController, &FileController::listFilesResult,
            this, &MainWindow::onListFilesResult);
    connect(fileController, &FileController::downloadFileResult,
            this, &MainWindow::onDownloadFileResult);
    connect(fileController, &FileController::deleteFileResult,
            this, &MainWindow::onDeleteFileResult);

    // Console logger
    Logger::initialize(ui->consoleTextEdit);
    if (sodium_init() < 0) {
        Logger::log("sodium_init() failed");
    } else {
        Logger::log("sodium initialized");
    }

    // Core connections
    connect(authController, &AuthController::loggedIn,
            this, &MainWindow::handleLoggedIn);
    connect(authController, &AuthController::loggedOut,
            this, &MainWindow::handleLoggedOut);

    connect(profileController, &ProfileController::changeUsernameResult,
            this, &MainWindow::onChangeUsernameResult);
    connect(profileController, &ProfileController::changePasswordResult,
            this, &MainWindow::onChangePasswordResult);

    connect(authController, &AuthController::connectionStatusChanged,
            this, &MainWindow::updateConnectionStatus);

    // When switching tabs
    connect(ui->tabWidget, &QTabWidget::currentChanged,
            this, &MainWindow::on_tabWidget_currentChanged);

    Logger::log("UI setup complete");
    QTimer::singleShot(0, this, [this]{
        authController->checkConnection();
    });

    // Setup password‐strength bars
    auto setupBar = [&](QProgressBar *bar, QLabel *label){
        bar->setRange(0,100);
        bar->setValue(0);
        label->setText("Too weak");
        bar->setFixedHeight(20);
        bar->setTextVisible(false);
        bar->setStyleSheet(R"(
            QProgressBar {
                border: 1px solid #555;
                border-radius: 5px;
                background: #333;
            }
            QProgressBar::chunk {
                background-color: #39ff14;
                width: 10px;
            }
        )");
    };
    setupBar(ui->passwordStrengthBar, ui->passwordStrengthLabel);
    setupBar(ui->passwordStrengthBar_2, ui->passwordStrengthLabel_2);

    // Profile‐tab password‐strength updates
    connect(ui->changePasswordLineEdit, &QLineEdit::textChanged,
            this, &MainWindow::on_changePasswordLineEdit_textChanged);
}

MainWindow::~MainWindow()
{
    Logger::log("Application exiting");
    delete ui;
}

void MainWindow::on_signupButton_clicked()
{
    QString pwd = ui->signupPasswordLineEdit->text();
    QString reason;
    if (!pwEvaluator.isAcceptable(pwd, &reason)) {
        Logger::log("Signup aborted: " + reason);
        return;
    }
    authController->signup(
        ui->signupUsernameLineEdit->text(),
        pwd
        );
}

void MainWindow::on_loginButton_clicked()
{
    authController->login(
        ui->loginUsernameLineEdit->text(),
        ui->loginPasswordLineEdit->text()
        );
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
    ui->downloadFileList->clear();
    ui->downloadFileNameLabel->setText("No file selected");
    ui->downloadFileTypeLabel->setText("-");
}

void MainWindow::on_changeUsernameButton_clicked()
{
    profileController->changeUsername(ui->changeUsernameLineEdit->text());
}

void MainWindow::on_changePasswordButton_clicked()
{
    profileController->changePassword(ui->changePasswordLineEdit->text());
}

void MainWindow::onChangeUsernameResult(bool success, const QString &message)
{
    Logger::log(success
                    ? "Username changed successfully"
                    : "Failed to change username: " + message);
}

void MainWindow::onChangePasswordResult(bool success, const QString &message)
{
    Logger::log(success
                    ? "Password changed successfully"
                    : "Failed to change password: " + message);
}

void MainWindow::onUploadFileResult(bool success, const QString &message)
{
    if (success) {
        Logger::log("File uploaded successfully");
    } else {
        Logger::log("File upload failed: " + message);
    }
}

void MainWindow::updateConnectionStatus(bool online)
{
    ui->serverConnectionLabel->setText(
        online ? "Server Connection: Online"
               : "Server Connection: Offline"
        );
}

void MainWindow::on_selectFileButton_clicked()
{
    QString fullPath = QFileDialog::getOpenFileName(
        this, tr("Select a file to upload")
        );
    if (fullPath.isEmpty()) return;

    QFileInfo fi(fullPath);
    currentUploadPath = fi.fileName();
    ui->fileNameLabel->setText(currentUploadPath);
    ui->fileTypeLabel->setText(fi.suffix());

    QFile f(fullPath);
    if (!f.open(QIODevice::ReadOnly)) {
        Logger::log("Cannot open file for preview");
        return;
    }
    currentUploadData = f.readAll();
    f.close();

    QMimeDatabase db;
    auto mime = db.mimeTypeForFile(fi);
    if (mime.name().startsWith("text/")) {
        ui->uploadTextPreview->setPlainText(QString::fromUtf8(currentUploadData));
        ui->uploadPreviewStack->setCurrentIndex(0);
    }
    else if (mime.name().startsWith("image/")) {
        QPixmap pix;
        pix.loadFromData(currentUploadData);
        ui->uploadImagePreview->setPixmap(
            pix.scaled(ui->uploadImagePreview->size(),
                       Qt::KeepAspectRatio,
                       Qt::SmoothTransformation)
            );
        ui->uploadPreviewStack->setCurrentIndex(1);
    }
    else {
        ui->uploadTextPreview->setPlainText(tr("No preview available"));
        ui->uploadPreviewStack->setCurrentIndex(0);
    }
}

void MainWindow::on_uploadFileButton_clicked()
{
    if (currentUploadData.isEmpty() || currentUploadPath.isEmpty()) {
        Logger::log("No file selected");
        return;
    }
    QByteArray b64 = currentUploadData.toBase64();
    fileController->uploadFile(currentUploadPath, b64);
}

void MainWindow::onListFilesResult(bool success,
                                   const QStringList &files,
                                   const QString &message)
{
    if (!success) {
        Logger::log("Failed to list files: " + message);
        return;
    }
    ui->downloadFileList->clear();
    ui->downloadFileList->addItems(files);
    ui->downloadFileNameLabel->setText("No file selected");
    ui->downloadFileTypeLabel->setText("-");
    ui->downloadPreviewStack->setCurrentIndex(0);
}

void MainWindow::on_downloadFileList_itemSelectionChanged()
{
    auto item = ui->downloadFileList->currentItem();
    bool hasOne = (item != nullptr);
    ui->deleteButton->setEnabled(hasOne);
    if (!hasOne) {
        ui->downloadFileNameLabel->setText("No file selected");
        ui->downloadFileTypeLabel->setText("-");
        ui->downloadPreviewStack->setCurrentIndex(0);
        return;
    }

    QString name = item->text();
    ui->downloadFileNameLabel->setText(name);
    ui->downloadFileTypeLabel->setText(QFileInfo(name).suffix());

    const auto &cache = fileController->downloadCache();
    if (!cache.contains(name)) {
        fileController->downloadFile(name);
        return;
    }

    const QByteArray data = cache.value(name);
    QMimeDatabase db;
    auto mime = db.mimeTypeForFile(name);
    if (mime.name().startsWith("text/")) {
        ui->downloadTextPreview->setPlainText(QString::fromUtf8(data));
        ui->downloadPreviewStack->setCurrentIndex(0);
    }
    else if (mime.name().startsWith("image/")) {
        QPixmap pix;
        pix.loadFromData(data);
        ui->downloadImagePreview->setPixmap(
            pix.scaled(ui->downloadImagePreview->size(),
                       Qt::KeepAspectRatio,
                       Qt::SmoothTransformation)
            );
        ui->downloadPreviewStack->setCurrentIndex(1);
    }
    else {
        ui->downloadTextPreview->setPlainText(tr("No preview"));
        ui->downloadPreviewStack->setCurrentIndex(0);
    }
}

void MainWindow::onDownloadFileResult(bool success,
                                      const QString &filename,
                                      const QByteArray & /*data*/,
                                      const QString &message)
{
    if (!success) {
        Logger::log("Failed to download '" + filename + "': " + message);
        return;
    }

    // refresh preview if this is the current item
    auto item = ui->downloadFileList->currentItem();
    if (item && item->text() == filename) {
        on_downloadFileList_itemSelectionChanged();
    }
}

void MainWindow::on_downloadFileButton_clicked()
{
    auto item = ui->downloadFileList->currentItem();
    if (!item) {
        Logger::log("No file selected to download");
        return;
    }
    const QString filename = item->text();
    const auto &cache = fileController->downloadCache();
    if (!cache.contains(filename)) {
        Logger::log("No data available for '" + filename + "'");
        return;
    }
    const QByteArray data = cache.value(filename);

    QString path = QFileDialog::getSaveFileName(this,
                                                tr("Save File As"), filename);
    if (path.isEmpty()) return;

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly)) {
        Logger::log("Failed to open file for writing: " + path);
        return;
    }
    f.write(data);
    f.close();
    Logger::log("File saved to " + path);
}

void MainWindow::on_deleteButton_clicked()
{
    QListWidgetItem *item = ui->downloadFileList->currentItem();
    if (!item) return;
    pendingDeleteItem = item;
    fileController->deleteFile(item->text());
}

void MainWindow::onDeleteFileResult(bool success, const QString &message)
{
    if (!success) {
        Logger::log("Failed to delete file: " + message);
        return;
    }
    if (pendingDeleteItem) {
        int row = ui->downloadFileList->row(pendingDeleteItem);
        ui->downloadFileList->blockSignals(true);
        delete ui->downloadFileList->takeItem(row);
        ui->downloadFileList->blockSignals(false);
        pendingDeleteItem = nullptr;
    }

    ui->downloadFileList->setCurrentRow(-1);
    ui->downloadFileList->clearSelection();

    ui->deleteButton->setEnabled(false);
    ui->downloadFileNameLabel->setText("No file selected");
    ui->downloadFileTypeLabel->setText("-");
    ui->downloadPreviewStack->setCurrentIndex(0);
    Logger::log("File deleted successfully");
}

void MainWindow::on_tabWidget_currentChanged(int index)
{
    constexpr int uploadIndex   = MainWindow::Upload;
    constexpr int downloadIndex = MainWindow::Download;

    if (index != uploadIndex) {
        ui->fileNameLabel->setText(tr("No file selected"));
        ui->fileTypeLabel->setText(tr("-"));
        ui->uploadTextPreview->clear();
        ui->uploadImagePreview->clear();
        ui->uploadImagePreview->setText(tr("No Image File Selected"));
        ui->uploadPreviewStack->setCurrentIndex(1);
        currentUploadData.clear();
        currentUploadPath.clear();
    }

    if (index == downloadIndex) {
        ui->downloadTextPreview->clear();
        ui->downloadImagePreview->clear();
        ui->downloadImagePreview->setText(tr("No Image File Selected"));
        ui->downloadPreviewStack->setCurrentIndex(0);
        fileController->listFiles();
    } else {
        ui->downloadTextPreview->clear();
        ui->downloadImagePreview->clear();
        ui->downloadImagePreview->setText(tr("No Image File Selected"));
        ui->downloadPreviewStack->setCurrentIndex(0);
    }
}

void MainWindow::on_signupPasswordLineEdit_textChanged(const QString &text)
{
    updatePasswordStrength(text,
                           ui->passwordStrengthBar,
                           ui->passwordStrengthLabel);
}

void MainWindow::on_changePasswordLineEdit_textChanged(const QString &text)
{
    updatePasswordStrength(text,
                           ui->passwordStrengthBar_2,
                           ui->passwordStrengthLabel_2);
}

void MainWindow::updatePasswordStrength(const QString &text,
                                        QProgressBar *bar,
                                        QLabel *label)
{
    StrengthResult res = pwEvaluator.evaluate(text);
    bar->setValue(res.score);

    QString chunkColor;
    if (res.score < 30)      chunkColor = "#ff1744";
    else if (res.score < 70) chunkColor = "#f1c40f";
    else                      chunkColor = "#39ff14";

    bar->setStyleSheet(QString(R"(
        QProgressBar {
            border: 1px solid #555;
            border-radius: 5px;
            background: #333;
        }
        QProgressBar::chunk {
            background-color: %1;
            width: 10px;
        }
    )").arg(chunkColor));

    QString reason;
    if (!pwEvaluator.isAcceptable(text, &reason)) {
        label->setText(reason);
    } else {
        label->setText(res.description);
    }
}
