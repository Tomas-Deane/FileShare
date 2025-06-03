#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "authcontroller.h"
#include "profilecontroller.h"
#include "filecontroller.h"
#include "verifycontroller.h"
#include "sharecontroller.h"
#include "logger.h"

#include <QPixmap>
#include <QTimer>
#include <QFileDialog>
#include <QFileInfo>
#include <QMimeDatabase>
#include <QFile>

MainWindow::MainWindow(AuthController* authCtrl,
                       FileController* fileCtrl,
                       ProfileController* profileCtrl,
                       VerifyController* verifyCtrl,
                       ShareController*    shareCtrl,
                       QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , authController(authCtrl)
    , profileController(profileCtrl)
    , fileController(fileCtrl)
    , verifyController(verifyCtrl)
    , shareController(shareCtrl)
    , sharedFileMgr(new SharedFileManager(this))
    , pendingDeleteItem(nullptr)
    , m_pendingSaveShare(false)
    , m_pendingSaveFilename()
{
    ui->setupUi(this);

    // Update codeLabel when OOB code arrives:
    connect(verifyController, &VerifyController::oobCodeReady, this, [=](const QString &code, const QString &err){
        if (!err.isEmpty()) {
            ui->codeLabel->setText(err);
        } else {
            ui->codeLabel->setText(code);
        }
    });

    // Populate the “verifiedUsersList” whenever updated:
    connect(verifyController, &VerifyController::updateVerifiedUsersList, this, [=](const QList<VerifiedUser> &list){
        ui->verifiedUsersList->clear();
        for (auto &vu : list) {
            ui->verifiedUsersList->addItem(vu.username);
        }
    });

    // Listen for the result of shareController->shareFile(...)
    connect(shareController, &ShareController::shareFileResult, this, [=](bool success, const QString &message){
        if (success) {
                Logger::log("File shared successfully");
            } else {
                Logger::log("File share failed: " + message);
            }
        });

    connect(verifyController, &VerifyController::updateVerifiedUsersList, this,
            [=](const QList<VerifiedUser> &list){
                ui->sharesToVerifiedUsersList->clear();
                for (auto &vu : list) {
                    ui->sharesToVerifiedUsersList->addItem(vu.username);
                }
            });

    // 2) When the user clicks/selects a verified username in Shares To:
    connect(ui->sharesToVerifiedUsersList, &QListWidget::itemSelectionChanged,
            this, &MainWindow::on_sharesToVerifiedUsersList_itemSelectionChanged);

    // 3) When shareController returns “listSharedTo” result:
    connect(shareController, &ShareController::listSharedToResult,
            this, &MainWindow::onSharesToFilesResult);

    // 4) If you want to automatically refresh when the tab becomes active:
    connect(ui->tabWidget, &QTabWidget::currentChanged,
            this, [=](int idx){
                using TI = MainWindow::TabIndex;
                if (idx == TI::SharesTo) {
                    // Ensure we have an up‐to‐date verified‐user list:
                    verifyController->initializeVerifyPage();

                    // Clear file list for the moment, until a user is picked:
                    ui->sharesToFilesList->clear();
                }
            });

    // Populate “shareNewUserList” in the Share New tab in exactly the same way:
    connect(verifyController, &VerifyController::updateVerifiedUsersList, this,
            [=](const QList<VerifiedUser> &list){
                ui->shareNewUserList->clear();
                for (auto &vu : list) {
                    ui->shareNewUserList->addItem(vu.username);
                }
            });

    // Optionally, show success/errors from backup:
    connect(verifyController, &VerifyController::tofuBackupResult, this, [=](bool success, const QString &msg){
        if (success) {
            Logger::log("TOFU backup succeeded");
        } else {
            Logger::log("TOFU backup failed: " + msg);
        }
    });

    connect(verifyController, &VerifyController::tofuLoadCompleted,
            this, [=](const QList<VerifiedUser> &list, const QString &err){
                if (!err.isEmpty()) {
                    Logger::log("Failed to load TOFU from server: " + err);
                } else {
                    Logger::log("Loaded TOFU list (“" + QString::number(list.size()) + "” users) from server");
                }
            });

    // When ShareController emits listSharersResult, populate sharedFromUsersList:
    connect(shareController, &ShareController::listSharersResult,
            this, [=](bool success, const QStringList &users, const QString &message) {
                ui->sharesFromUsersList->clear();
                if (!success) {
                    Logger::log("Failed to fetch sharers: " + message);
                    return;
                }
                for (const QString &u : users) {
                    ui->sharesFromUsersList->addItem(u);
                }
            });

    // When the user selects one of those sharers, call listFilesSharedFrom:
    connect(ui->sharesFromUsersList, &QListWidget::itemSelectionChanged,
            this, &MainWindow::on_sharedFromUsersList_itemSelectionChanged);

    // We already have a slot for listSharedFromResult in ShareController:
    connect(shareController, &ShareController::listSharedFromResult,
            this, &MainWindow::onSharesFromFilesResult);

    // When the user selects a file in "Shares From" (sharesFromFilesList), show a preview:
    connect(ui->sharesFromFilesList, &QListWidget::itemSelectionChanged,
            this, &MainWindow::on_sharesFromFilesList_itemSelectionChanged);

    // Also hook up downloadSharedFileResult to cache + preview:
    connect(shareController, &ShareController::downloadSharedFileResult,
            this, &MainWindow::on_downloadSharedFileResult);

    // Whenever ShareController finishes downloading a shared file, update the cache:
    connect(shareController, &ShareController::downloadSharedFileResult,
            this, &MainWindow::on_downloadSharedFileResult);

    connect(ui->generateCodeButton, &QPushButton::clicked, this, [=]{
        QString target = ui->targetUsernameLineEdit->text().trimmed();
        verifyController->generateOOBCode(target);
    });

    connect(ui->verifyNewUserButton, &QPushButton::clicked, this, [=]{
        QString target = ui->targetUsernameLineEdit->text().trimmed();
        verifyController->verifyNewUser(target);
    });

    connect(ui->deleteVerifiedUserButton, &QPushButton::clicked, this, [=]{
        // Get the currently‐selected username from the verified list
        QListWidgetItem *item = ui->verifiedUsersList->currentItem();
        if (!item) {
            // nothing selected → no action
            return;
        }
        QString toDelete = item->text();
        verifyController->deleteVerifiedUser(toDelete);
    });

    // remember starting tab so refreshPage knows what to run first if needed
    m_prevTabIndex = ui->tabWidget->currentIndex();

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

    // When switching tabs: only refresh, no clearing
    connect(ui->tabWidget, &QTabWidget::currentChanged,
            this, &MainWindow::on_tabWidget_currentChanged);

    Logger::log("UI setup complete");
    QTimer::singleShot(0, this, [this]{
        authController->checkConnection();
    });

    // Setup password-strength bars
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

    // Profile-tab password-strength updates
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
    ui->downloadPreviewStack->setCurrentIndex(0);

    // Clear Shares‐From UI as well:
    ui->sharesFromUsersList->clear();
    ui->sharesFromFilesList->clear();
    ui->downloadImagePreview_2->clear();
    ui->downloadTextPreview_2->clear();
    ui->downloadPreviewStack_2->setCurrentIndex(0);

    // Wipe shared‐cache:
    sharedFileMgr->clear();
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

void MainWindow::on_shareFileButton_clicked()
{
    // 1) Find which file is currently selected in the “Share New” file list:
    QListWidgetItem *fileItem = ui->shareNewFileList->currentItem();
    if (!fileItem) {
        Logger::log("No file selected to share");
        return;
    }

    // We stored a placeholder “fileId” in Qt::UserRole when populating that list.
    bool ok = false;
    int fileId = fileItem->data(Qt::UserRole).toInt(&ok);
    if (!ok) {
        Logger::log("Invalid file ID; cannot share");
        return;
    }

    // 2) Find which verified user is selected in the “Share New” user list:
    QListWidgetItem *userItem = ui->shareNewUserList->currentItem();
    if (!userItem) {
        Logger::log("No recipient selected to share");
        return;
    }

    QString recipientUsername = userItem->text();
    if (recipientUsername.isEmpty()) {
        Logger::log("Empty recipient username; cannot share");
        return;
    }

    // 3) Finally, ask the ShareController to do the share flow:
    shareController->shareFile(static_cast<qint64>(fileId), recipientUsername);
}

void MainWindow::on_sharesToVerifiedUsersList_itemSelectionChanged()
{
    // Which username is selected?
    QListWidgetItem *item = ui->sharesToVerifiedUsersList->currentItem();
    if (!item) {
        ui->sharesToFilesList->clear();
        return;
    }

    QString targetUsername = item->text();
    if (targetUsername.isEmpty()) {
        ui->sharesToFilesList->clear();
        return;
    }

    // Ask shareController for all files CURRENT_USER has shared TO targetUsername:
    shareController->listFilesSharedTo(targetUsername);
}

// When shareController returns the shares → populate the files list
void MainWindow::onSharesToFilesResult(bool success,
                                       const QList<SharedFile> &shares,
                                       const QString &message)
{
    ui->sharesToFilesList->clear();

    if (!success) {
        Logger::log("Failed to fetch files shared TO user: " + message);
        return;
    }

    // Each SharedFile has: share_id, file_id, filename, shared_by, shared_at
    for (auto &sf : shares) {
        auto item = new QListWidgetItem(sf.filename, ui->sharesToFilesList);
        // Store the share_id or file_id if you need later—for now, we just show filenames:
        item->setData(Qt::UserRole, QVariant::fromValue(sf.share_id));
        // Optionally, show the timestamp as tooltip:
        item->setToolTip(QString("Shared at: %1").arg(sf.shared_at));
    }
}

void MainWindow::onListFilesResult(bool success,
                                   const QList<FileEntry> &files,
                                   const QString &message)
{
    if (!success) {
        Logger::log("Failed to list files: " + message);
        return;
    }

    int currentTab = ui->tabWidget->currentIndex();
    using TI = MainWindow::TabIndex;

    if (currentTab == TI::Download) {
        // Populate the Download tab’s list
        ui->downloadFileList->clear();
        for (const FileEntry &fe : files) {
            auto item = new QListWidgetItem(fe.filename, ui->downloadFileList);
            // Store the real file‐ID (from server) in UserRole
            item->setData(Qt::UserRole, QVariant::fromValue(fe.id));
        }
        ui->downloadFileNameLabel->setText("No file selected");
        ui->downloadFileTypeLabel->setText("-");
        ui->downloadPreviewStack->setCurrentIndex(0);
    }
    else if (currentTab == TI::ShareNew) {
        // Populate the Share New tab’s list with (filename, id)
        ui->shareNewFileList->clear();
        for (const auto &fe : files) {
            auto item = new QListWidgetItem(fe.filename, ui->shareNewFileList);
            // Now set the actual server‐provided file ID
            item->setData(Qt::UserRole, QVariant::fromValue(fe.id));
        }
    }
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

    QString  name = item->text();
    ui->downloadFileNameLabel->setText(name);
    ui->downloadFileTypeLabel->setText(QFileInfo(name).suffix());

    // If it’s already in cache, show it immediately:
    const auto &cache = fileController->downloadCache();
    if (cache.contains(name)) {
        auto data = cache.value(name);
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
        return;
    }

    // ─── Not in cache: request from server by ID ───
    bool ok = false;
    qint64 fileId = item->data(Qt::UserRole).toLongLong(&ok);
    if (!ok) {
        Logger::log("Invalid file ID; cannot download");
        return;
    }
    fileController->downloadFile(fileId, name);
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
    QString name = item->text();

    // Grab the ID out of UserRole
    bool ok = false;
    qint64 fileId = item->data(Qt::UserRole).toLongLong(&ok);
    if (!ok) {
        Logger::log("Invalid file ID; cannot download");
        return;
    }

    const auto &cache = fileController->downloadCache();
    if (!cache.contains(name)) {
        Logger::log("No data available for '" + name + "'");
        return;
    }
    const QByteArray data = cache.value(name);

    // Use 'name' here, not 'filename'
    QString path = QFileDialog::getSaveFileName(this,
                                                tr("Save File As"), name);
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

void MainWindow::on_sharedFromUsersList_itemSelectionChanged()
{
    // Which sharer‐username is selected?
    QListWidgetItem *item = ui->sharesFromUsersList->currentItem();
    if (!item) {
        ui->sharesFromFilesList->clear();
        return;
    }

    QString sharer = item->text();
    if (sharer.isEmpty()) {
        ui->sharesFromFilesList->clear();
        return;
    }

    // Tell ShareController to fetch all files that `sharer` shared to me:
    shareController->listFilesSharedFrom(sharer);
}

void MainWindow::onSharesFromFilesResult(bool success,
                                         const QList<SharedFile> &shares,
                                         const QString &message)
{
    ui->sharesFromFilesList->clear();
    if (!success) {
        Logger::log("Failed to fetch files shared FROM user: " + message);
        return;
    }

    for (const auto &sf : shares) {
        auto item = new QListWidgetItem(sf.filename, ui->sharesFromFilesList);
        item->setData(Qt::UserRole, QVariant::fromValue(sf.share_id));
        item->setToolTip(QString("Shared by %1 at %2")
                             .arg(sf.shared_by)
                             .arg(sf.shared_at));
    }
}

void MainWindow::on_saveSharesFromFileButton_clicked()
{
    // 1) What did the user select?
    QListWidgetItem *item = ui->sharesFromFilesList->currentItem();
    if (!item) {
        Logger::log("No shared file selected to save");
        return;
    }

    // We stored share_id in Qt::UserRole when populating the list:
    bool ok = false;
    qint64 shareId = item->data(Qt::UserRole).toLongLong(&ok);
    if (!ok) {
        Logger::log("Invalid share ID; cannot save");
        return;
    }

    // The user sees the filename as the item text:
    QString filename = item->text();
    if (filename.isEmpty()) {
        Logger::log("Empty filename; cannot save");
        return;
    }

    // 2) Check if we already have the raw bytes in our cache:
    if (sharedFileMgr->has(filename)) {
        // We already downloaded it; pop up “Save As…” immediately.
        QString path = QFileDialog::getSaveFileName(
            this,
            tr("Save Shared File As"),
            filename
            );
        if (path.isEmpty()) {
            // user canceled
            return;
        }
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly)) {
            Logger::log("Failed to open file for writing: " + path);
            return;
        }
        QByteArray data = sharedFileMgr->get(filename);
        f.write(data);
        f.close();
        Logger::log("Shared file '" + filename + "' saved to " + path);
        return;
    }

    // 3) Otherwise, mark that we want to save when it finishes downloading:
    m_pendingSaveShare    = true;
    m_pendingSaveFilename = filename;
    Logger::log(QString("Requesting download of shared file '%1' (share_id=%2)")
                    .arg(filename).arg(shareId));
    shareController->downloadSharedFile(shareId, filename);
}

void MainWindow::on_downloadSharedFileResult(bool success,
                                             const QString &filename,
                                             const QByteArray &data,
                                             const QString &message)
{
    if (!success) {
        Logger::log("Failed to download shared file '" + filename + "': " + message);
        // If a save was pending, reset it so we don’t ask again:
        m_pendingSaveShare = false;
        m_pendingSaveFilename.clear();
        return;
    }

    // 1) Cache the bytes so that next time we can reuse them:
    sharedFileMgr->insert(filename, data);

    // 2) If the currently selected item is still this same filename, preview it:
    QListWidgetItem *item = ui->sharesFromFilesList->currentItem();
    if (item && item->text() == filename) {
        previewSharedFile(filename, data);
    }

    // 3) If the user had clicked “Save” (i.e. m_pendingSaveShare is true),
    //    immediately pop up Save As… using our newly‐cached data:
    if (m_pendingSaveShare && m_pendingSaveFilename == filename) {
        QString path = QFileDialog::getSaveFileName(
            this,
            tr("Save Shared File As"),
            filename
            );
        if (!path.isEmpty()) {
            QFile f(path);
            if (f.open(QIODevice::WriteOnly)) {
                QByteArray saveData = sharedFileMgr->get(filename);
                f.write(saveData);
                f.close();
                Logger::log("Shared file '" + filename + "' saved to " + path);
            } else {
                Logger::log("Failed to open file for writing: " + path);
            }
        }
        // Clear the “pending save” state now that we’ve shown the dialog:
        m_pendingSaveShare    = false;
        m_pendingSaveFilename.clear();
    }
}

void MainWindow::on_sharesFromFilesList_itemSelectionChanged()
{
    // Which shared‐file item is currently selected?
    QListWidgetItem *item = ui->sharesFromFilesList->currentItem();
    if (!item) {
        // Clear the preview panes:
        ui->downloadImagePreview_2->clear();
        ui->downloadTextPreview_2->clear();
        ui->downloadPreviewStack_2->setCurrentIndex(0);
        return;
    }

    QString filename = item->text();
    if (filename.isEmpty()) {
        // same as no selection
        ui->downloadImagePreview_2->clear();
        ui->downloadTextPreview_2->clear();
        ui->downloadPreviewStack_2->setCurrentIndex(0);
        return;
    }

    // If we already have bytes cached, just preview them:
    if (sharedFileMgr->has(filename)) {
        QByteArray data = sharedFileMgr->get(filename);
        previewSharedFile(filename, data);
        return;
    }

    // Otherwise, request a download from the ShareController.
    // We need the share‐ID that we stored earlier as Qt::UserRole:
    bool ok = false;
    qint64 shareId = item->data(Qt::UserRole).toLongLong(&ok);
    if (!ok) {
        // Invalid share ID; bail out
        return;
    }

    Logger::log(QString("Requesting download of shared file '%1' for preview (share_id=%2)")
                    .arg(filename).arg(shareId));
    shareController->downloadSharedFile(shareId, filename);
    // Once `on_downloadSharedFileResult` fires, we'll both cache + preview.
}

void MainWindow::previewSharedFile(const QString &filename, const QByteArray &data)
{
    // Determine MIME type by filename:
    QMimeDatabase db;
    auto mime = db.mimeTypeForFile(filename);

    if (mime.name().startsWith("text/")) {
        ui->downloadTextPreview_2->setPlainText(QString::fromUtf8(data));
        ui->downloadPreviewStack_2->setCurrentIndex(0);
    }
    else if (mime.name().startsWith("image/")) {
        QPixmap pix;
        pix.loadFromData(data);
        ui->downloadImagePreview_2->setPixmap(
            pix.scaled(ui->downloadImagePreview_2->size(),
                       Qt::KeepAspectRatio,
                       Qt::SmoothTransformation)
            );
        ui->downloadPreviewStack_2->setCurrentIndex(1);
    }
    else {
        ui->downloadTextPreview_2->setPlainText(tr("No preview available"));
        ui->downloadPreviewStack_2->setCurrentIndex(0);
    }
}

void MainWindow::on_tabWidget_currentChanged(int index)
{
    // First, clear anything from the previously‐active tab:
    clearPage(m_prevTabIndex);
   // Then refresh the newly‐active tab:
    refreshPage(index);
    m_prevTabIndex = index;
}

// Clear out any UI elements when leaving a tab
void MainWindow::clearPage(int idx)
{
    using TI = MainWindow::TabIndex;
    switch (idx) {
        case TI::SharesFrom:
            // When leaving “Shares From”, blank out both image/text previews
            ui->downloadImagePreview_2->clear();
            ui->downloadTextPreview_2->clear();
            ui->downloadPreviewStack_2->setCurrentIndex(0);
            break;
        default:
            break;
    }
}

void MainWindow::refreshPage(int idx)
{
    using TI = MainWindow::TabIndex;
    switch (idx) {
    case TI::Download:
        fileController->listFiles();
        break;

    case TI::ShareNew:
        verifyController->initializeVerifyPage();
        fileController->listFiles();
        break;

    case TI::Verify:
        verifyController->initializeVerifyPage();
        break;

    case TI::SharesFrom:
        // Before listing “shares from”, load TOFU keys exactly like Verify/ShareNew/SharesTo:
        verifyController->initializeVerifyPage();
        // Now fetch all usernames who have shared files to us:
        shareController->listSharers();
        break;

    default:
        break;
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
