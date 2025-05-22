#include "networkmanager.h"
#include "logger.h"
#include <QJsonDocument>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

NetworkManager::NetworkManager(QObject *parent)
    : QObject(parent), ssl_ctx(nullptr)
{
    initOpenSSL();  // Set up OpenSSL (load algorithms, create context)
}

NetworkManager::~NetworkManager()
{
    cleanupOpenSSL();  // Tear down OpenSSL (free context, cleanup)
}

void NetworkManager::initOpenSSL()
{
    // Load human-readable error strings for libssl & libcrypto
    SSL_load_error_strings();
    // Register available encryption algorithms (both libssl and libcrypto)
    OpenSSL_add_ssl_algorithms();
    // Create a new SSL_CTX object as framework for TLS/SSL
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    // TLS_client_method selects the highest version of TLS (Transport Layer Security)
    if (!ssl_ctx) {
        Logger::log("Failed to create SSL_CTX");  // No SSL context = cannot do TLS
    }
}

void NetworkManager::cleanupOpenSSL()
{
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);  // Release SSL context
        ssl_ctx = nullptr;
    }
    // Remove all algorithms from libcrypto (cleanup)
    EVP_cleanup();
}

void NetworkManager::signup(const QJsonObject &payload)
{
    // Log the outgoing signup JSON payload
    Logger::log("Sending signup request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    bool ok = false;           // Will be set true if HTTP+TLS exchange succeeds
    QString message;           // Will hold error or raw response body

    // Send HTTPS POST to host "gobbler.info" on TCP port 3210, path "/signup"
    QByteArray resp = postJson("gobbler.info", 3210, "/signup", payload, ok, message);

    Logger::log("Received signup response: " + QString::fromUtf8(resp));
    if (!ok) {
        // Network or protocol error
        emit signupResult(false, message);
        return;
    }

    // Parse the JSON response body
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit signupResult(true, obj["status"].toString());
    } else {
        // On error, server sends {"detail": "..."}
        emit signupResult(false, obj["detail"].toString());
    }
}

void NetworkManager::login(const QString &username)
{
    // Build simple JSON: { "username": "<username>" }
    QJsonObject req;
    req["username"] = username;

    Logger::log("Sending login request for user '" + username + "'");
    Logger::log("Login request payload: " +
                QString::fromUtf8(QJsonDocument(req).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("gobbler.info", 3210, "/login", req, ok, message);

    Logger::log("Received login response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit loginResult(false, message);
        return;
    }

    // Expecting { "status": "challenge", "nonce": "...", ... }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "challenge") {
        // Decode Base64‐encoded fields into raw bytes
        emit loginChallenge(
            QByteArray::fromBase64(obj["nonce"].toString().toUtf8()),
            QByteArray::fromBase64(obj["salt"].toString().toUtf8()),
            obj["argon2_opslimit"].toInt(),
            obj["argon2_memlimit"].toInt(),
            QByteArray::fromBase64(obj["encrypted_privkey"].toString().toUtf8()),
            QByteArray::fromBase64(obj["privkey_nonce"].toString().toUtf8())
            );
    } else {
        // On error, server sends {"detail": "..."}
        emit loginResult(false, obj["detail"].toString());
    }
}

void NetworkManager::authenticate(const QString &username, const QByteArray &signature)
{
    // Build JSON with Base64 signature
    QJsonObject req;
    req["username"]  = username;
    req["signature"] = QString::fromUtf8(signature.toBase64());

    Logger::log("Sending authenticate request for user '" + username + "'");
    Logger::log("Authenticate request payload: " +
                QString::fromUtf8(QJsonDocument(req).toJson(QJsonDocument::Compact)));

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
        emit loginResult(true, obj["message"].toString());
    } else {
        emit loginResult(false, obj["detail"].toString());
    }
}

QByteArray NetworkManager::postJson(const QString &host,
                                    quint16 port,
                                    const QString &path,
                                    const QJsonObject &obj,
                                    bool &ok,
                                    QString &message)
{
    ok = false;

    Logger::log(QString("postJson to https://%1:%2%3")
                    .arg(host).arg(port).arg(path));

    struct hostent *he = gethostbyname(host.toUtf8().constData()); // DNS lookup to resolve hostname → IP address
    if (!he) {
        message = "DNS lookup failed";
        emit networkError(message);
        return {};
    }

    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    // AF_INET = IPv4 address family
    // 0 = use default protocol (IPPROTO_TCP for SOCK_STREAM)
    if (sock < 0) {
        message = "Socket creation failed";
        emit networkError(message);
        return {};
    }

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;                         // IPv4
    addr.sin_port   = htons(port);                     // Convert port to network byte order
    addr.sin_addr   = *(struct in_addr*)he->h_addr;    // Copy resolved IP

    if (::connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        ::close(sock);
        message = QString("TCP connect failed to %1:%2").arg(host).arg(port);
        emit networkError(message);
        return {};
    }

    SSL *ssl = SSL_new(ssl_ctx);            // Create SSL object
    SSL_set_fd(ssl, sock);                  // Attach TCP socket FD to SSL

    if (SSL_connect(ssl) <= 0) {            // Perform TLS handshake as client
        SSL_free(ssl);
        ::close(sock);
        message = "SSL handshake failed";
        emit networkError(message);
        return {};
    }

    QByteArray body = QJsonDocument(obj).toJson(QJsonDocument::Compact);
    QByteArray req =
        "POST " + path.toUtf8() + " HTTP/1.1\r\n" +
        "Host: " + host.toUtf8() + "\r\n" +
        "Content-Type: application/json\r\n" +
        "Content-Length: " + QByteArray::number(body.size()) + "\r\n" +
        "Connection: close\r\n\r\n" +
        body;

    SSL_write(ssl, req.constData(), req.size());

    QByteArray resp;
    char buf[4096];
    while (true) {
        int len = SSL_read(ssl, buf, sizeof(buf));
        if (len <= 0) break;
        resp.append(buf, len);
    }

    SSL_shutdown(ssl);  // Send "close notify" alert
    SSL_free(ssl);      // Free SSL object
    ::close(sock);      // Close underlying TCP socket

    int sep = resp.indexOf("\r\n\r\n");
    if (sep < 0) {
        message = "Invalid HTTP response";
        emit networkError(message);
        return {};
    }

    QByteArray bodyResp = resp.mid(sep + 4);
    message = QString::fromUtf8(bodyResp);
    ok = true;
    return bodyResp;
}
