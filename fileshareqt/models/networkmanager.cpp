#include "networkmanager.h"
#include "logger.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QStringList>
#include <QFile>
#include <QDir>
#include <QUrl>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QEventLoop>

// POSIX sockets
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

QJsonObject safeRequestLog(const QJsonObject &obj) {
    QJsonObject safe;
    QStringList sensitiveFields = {
        "password", "salt", "nonce", "encrypted_privkey", "encrypted_kek",
        "encrypted_file", "encrypted_file_key", "encrypted_data",
        "challenge", "signature", "pre_key", "IK_pub", "SPK_pub",
        "SPK_signature", "EK_pub", "backup_nonce", "file_nonce",
        "dek_nonce", "kek_nonce", "privkey_nonce", "encrypted_backup",
        "encrypted_dek", "encrypted_privkey", "encrypted_kek"
    };
    
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        if (sensitiveFields.contains(it.key())) {
            safe[it.key()] = "[REDACTED]";
        } else {
            safe[it.key()] = it.value();
        }
    }
    return safe;
}

NetworkManager::NetworkManager(QObject *parent)
    : INetworkManager(parent)
    , ssl_ctx(nullptr)
    , m_networkManager(new QNetworkAccessManager(this))
{
    initOpenSSL();
}

NetworkManager::~NetworkManager()
{
    cleanupOpenSSL();
}

void NetworkManager::initOpenSSL()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        Logger::log("Failed to create SSL_CTX");
        return;
    }

    // Enable certificate verification
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(ssl_ctx, 4);

    // Load CA bundle
    QString caPath = QDir::currentPath() + "/ssl/ca-bundle.crt";
    if (!QFile::exists(caPath)) {
        Logger::log("CA bundle not found at: " + caPath);
        return;
    }

    if (!SSL_CTX_load_verify_locations(ssl_ctx, caPath.toUtf8().constData(), nullptr)) {
        Logger::log("Failed to load CA bundle");
        return;
    }

    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
}

void NetworkManager::cleanupOpenSSL()
{
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
    }
    EVP_cleanup();
}

SSL *NetworkManager::openSslConnection(const QString &host,
                                       quint16 port,
                                       int &sockOut,
                                       QString &errorMsg)
{
    struct addrinfo hints = {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *res = nullptr;
    int gai_err = getaddrinfo(host.toUtf8().constData(),
                              QByteArray::number(port).constData(),
                              &hints, &res);
    if (gai_err != 0) {
        errorMsg = QString("DNS lookup failed: %1").arg(gai_strerror(gai_err));
        emit connectionStatusChanged(false);
        return nullptr;
    }

    int sock = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        if (::connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        ::close(sock);
        sock = -1;
    }
    freeaddrinfo(res);

    if (sock < 0) {
        errorMsg = QString("Could not connect to %1:%2").arg(host).arg(port);
        emit connectionStatusChanged(false);
        return nullptr;
    }

    SSL *ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        errorMsg = "Failed to create SSL structure";
        ::close(sock);
        emit connectionStatusChanged(false);
        return nullptr;
    }

    // Set the hostname for SNI
    SSL_set_tlsext_host_name(ssl, host.toUtf8().constData());
    
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        errorMsg = QString("SSL handshake failed: %1").arg(err_buf);
        SSL_free(ssl);
        ::close(sock);
        emit connectionStatusChanged(false);
        return nullptr;
    }

    // Verify the certificate
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        errorMsg = "No peer certificate";
        SSL_free(ssl);
        ::close(sock);
        emit connectionStatusChanged(false);
        return nullptr;
    }

    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        errorMsg = QString("Certificate verification failed: %1")
            .arg(X509_verify_cert_error_string(verify_result));
        X509_free(cert);
        SSL_free(ssl);
        ::close(sock);
        emit connectionStatusChanged(false);
        return nullptr;
    }

    X509_free(cert);
    sockOut = sock;
    emit connectionStatusChanged(true);
    return ssl;
}

QByteArray NetworkManager::postJson(const QString &host,
                                    quint16 port,
                                    const QString &path,
                                    const QJsonObject &obj,
                                    bool &ok,
                                    QString &message)
{
    ok = false;
    Logger::log(QString("postJson to https://%1:%2%3").arg(host).arg(port).arg(path));

    // Construct URL safely using Qt's URL handling
    QUrl url;
    url.setScheme("https");
    url.setHost(host);
    url.setPort(port);
    url.setPath(path);

    // Create request with proper headers
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setHeader(QNetworkRequest::UserAgentHeader, "FileShareQt");

    // Send request
    QByteArray body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    QNetworkReply *reply = m_networkManager->post(request, body);

    // Wait for response
    QEventLoop loop;
    connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();

    // Handle response
    if (reply->error() != QNetworkReply::NoError) {
        message = reply->errorString();
        emit networkError(message);
        reply->deleteLater();
        return {};
    }

    QByteArray response = reply->readAll();
    reply->deleteLater();

    // Parse response
    QJsonDocument doc = QJsonDocument::fromJson(response);
    if (doc.isObject()) {
        QJsonObject obj = doc.object();
        if (obj.contains("status") && obj["status"].toString() == "ok") {
            ok = true;
            message = obj["message"].toString();
        } else if (obj.contains("detail")) {
            message = obj["detail"].toString();
        }
    }

    return response;
}

void NetworkManager::signup(const QJsonObject &payload)
{
    Logger::log("Sending signup request: " +
                QString::fromUtf8(QJsonDocument(safeRequestLog(payload)).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/signup", payload, ok, message);
    Logger::log("Received signup response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit signupResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit signupResult(true, obj["message"].toString());
    } else {
        emit signupResult(false, obj["detail"].toString());
    }
}

void NetworkManager::login(const QString &username)
{
    Logger::log("Sending login request for user '" + username + "'");
    QJsonObject req{{"username", username}};
    Logger::log("Login request payload: " +
                QString::fromUtf8(QJsonDocument(safeRequestLog(req)).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/login", req, ok, message);
    Logger::log("Received login response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit loginResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "challenge") {
        // Only emit challenge with nonce, salt and parameters are stored locally
        emit loginChallenge(
            QByteArray::fromBase64(obj["nonce"].toString().toUtf8()),
            QByteArray(),  // Salt is stored locally
            0,  // Opslimit is stored locally
            0,  // Memlimit is stored locally
            QByteArray(),  // Encrypted privkey is stored locally
            QByteArray(),  // Privkey nonce is stored locally
            QByteArray(),  // Encrypted KEK is stored locally
            QByteArray()   // KEK nonce is stored locally
            );
    } else {
        emit loginResult(false, obj["detail"].toString());
    }
}

void NetworkManager::requestChallenge(const QString &username,
                                      const QString &operation)
{
    QJsonObject req{{"username", username}, {"operation", operation}};
    Logger::log(QString("Requesting challenge for '%1' op='%2'")
                    .arg(username).arg(operation));
    Logger::log("Challenge request payload: " +
                QString::fromUtf8(QJsonDocument(safeRequestLog(req)).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/challenge", req, ok, message);

    Logger::log("Received challenge response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit networkError(message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "challenge") {
        emit challengeResult(
            QByteArray::fromBase64(obj["nonce"].toString().toUtf8()),
            operation
            );
    } else {
        emit networkError(obj["detail"].toString());
    }
}

void NetworkManager::authenticate(const QString &username,
                                  const QByteArray &nonce,
                                  const QByteArray &signature)
{
    QJsonObject req{
        {"username", username},
        {"nonce", QString::fromUtf8(nonce.toBase64())},
        {"signature", QString::fromUtf8(signature.toBase64())}
    };
    Logger::log("Sending authenticate request for user '" + username + "'");
    Logger::log("Authenticate request payload: " +
                QString::fromUtf8(QJsonDocument(safeRequestLog(req)).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/authenticate", req, ok, message);

    Logger::log("Received authenticate response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit loginResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        // Use locally stored data for login
        emit loginResult(true, obj["message"].toString());
    } else {
        emit loginResult(false, obj["detail"].toString());
    }
}

void NetworkManager::changeUsername(const QJsonObject &payload)
{
    Logger::log("Sending changeUsername request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/change_username", payload, ok, message);
    Logger::log("Received changeUsername response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit changeUsernameResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit changeUsernameResult(true, obj["message"].toString());
    } else {
        emit changeUsernameResult(false, obj["detail"].toString());
    }
}

void NetworkManager::changePassword(const QJsonObject &payload)
{
    Logger::log("Sending changePassword request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/change_password", payload, ok, message);
    Logger::log("Received changePassword response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit changePasswordResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit changePasswordResult(true, obj["message"].toString());
    } else {
        emit changePasswordResult(false, obj["detail"].toString());
    }
}

void NetworkManager::uploadFile(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/upload_file", payload, ok, message);
    Logger::log("Received uploadFile response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit uploadFileResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit uploadFileResult(true, obj["message"].toString());
    } else {
        emit uploadFileResult(false, obj["detail"].toString());
    }
}

void NetworkManager::listFiles(const QJsonObject &payload)
{
    Logger::log("Sending listFiles request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/list_files", payload, ok, message);
    Logger::log("Received listFiles response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit listFilesResult(false, QStringList(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QStringList files;
        for (const QJsonValue &val : obj["files"].toArray()) files.append(val.toString());
        emit listFilesResult(true, files, QString());
    } else {
        emit listFilesResult(false, QStringList(), obj["detail"].toString());
    }
}

void NetworkManager::downloadFile(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/download_file", payload, ok, message);
    if (!ok) {
        emit downloadFileResult(false, QString(), QString(), QString(), QString(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit downloadFileResult(
            true,
            obj["encrypted_file"].toString(),
            obj["file_nonce"].toString(),
            obj["encrypted_dek"].toString(),
            obj["dek_nonce"].toString(),
            QString()
            );
    } else {
        emit downloadFileResult(false, QString(), QString(), QString(), QString(), obj["detail"].toString());
    }
}

void NetworkManager::deleteFile(const QJsonObject &payload)
{
    Logger::log("Sending deleteFile request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/delete_file", payload, ok, message);
    Logger::log("Received deleteFile response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit deleteFileResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit deleteFileResult(true, obj["message"].toString());
    } else {
        emit deleteFileResult(false, obj["detail"].toString());
    }
}

void NetworkManager::checkConnection()
{
    int sock = -1;
    QString error;
    SSL *ssl = openSslConnection("gobbler.info", 3210, sock, error);
    if (!ssl) return;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    ::close(sock);
}
