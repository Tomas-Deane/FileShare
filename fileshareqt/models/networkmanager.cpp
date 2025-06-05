#include "networkmanager.h"
#include "logger.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QStringList>
#include <QJsonObject>
#include <QByteArray>

#include <curl/curl.h>
#include <QVariant>

// ------------------------------------------------------------------------------------------------
// Constructor & Destructor: initialize and cleanup libcurl
// ------------------------------------------------------------------------------------------------

NetworkManager::NetworkManager(QObject *parent)
    : INetworkManager(parent)
    , curl(nullptr)
{
    // Initialize libcurl globally:
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Create a single “easy” handle (you can also create per‐request if you want):
    curl = curl_easy_init();
    if (!curl) {
        Logger::log("NetworkManager: curl_easy_init() failed");
    }
}

NetworkManager::~NetworkManager()
{
    if (curl) {
        curl_easy_cleanup(curl);
        curl = nullptr;
    }
    curl_global_cleanup();
}

// Static write callback: append incoming response data into a QByteArray

size_t NetworkManager::writeToByteArray(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    // userdata is expected to be a pointer to a QByteArray
    size_t total = size * nmemb;
    QByteArray *response = reinterpret_cast<QByteArray *>(userdata);
    response->append(reinterpret_cast<char *>(ptr), static_cast<int>(total));
    return total;
}

// postJson(): perform an HTTPS POST of JSON → return response body (or empty on error)

QByteArray NetworkManager::postJson(const QString &host,
                                    quint16 port,
                                    const QString &path,
                                    const QJsonObject &obj,
                                    bool &ok,
                                    QString &message)
{
    ok = false;
    message.clear();

    if (!curl) {
        message = "libcurl not initialized";
        emit networkError(message);
        return {};
    }

    // 1) Build the complete URL: https://host:port/path
    QString url = QString("https://%1:%2%3").arg(host).arg(port).arg(path);
    QByteArray urlUtf8 = url.toUtf8();

    // 2) Convert QJsonObject → QByteArray (compact JSON)
    QByteArray body = QJsonDocument(obj).toJson(QJsonDocument::Compact);

    // 3) Set up headers: Content-Type: application/json
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    // 4) Prepare a place to capture the response body:
    QByteArray responseBuffer;

    // 5) Configure the curl easy handle:
    curl_easy_reset(curl);                // reset any previous options
    curl_easy_setopt(curl, CURLOPT_URL, urlUtf8.constData());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.constData());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());

    // 6) Strict certificate + hostname verification
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    // 7) libcurl to write response data into our QByteArray:
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &NetworkManager::writeToByteArray);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBuffer);

    // 8) Some servers require a 10-second timeout.
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    // 9) Perform the request:
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        // Fetch libcurl’s error reason:
        QString errStr = curl_easy_strerror(res);
        message = QString("Network error: %1").arg(errStr);
        emit networkError(message);
        curl_slist_free_all(headers);
        return {};
    }

    // 10) Get HTTP status code:
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    // 11) Clean up the headers list (libcurl needs us to free it manually)
    curl_slist_free_all(headers);

    // 12) If status is not 2xx, try to parse “detail” key from JSON:
    if (http_code < 200 || http_code >= 300) {
        // Attempt to parse {"detail": "..."} from responseBuffer:
        QJsonDocument doc = QJsonDocument::fromJson(responseBuffer);
        if (doc.isObject() && doc.object().contains("detail")) {
            message = doc.object().value("detail").toString();
        } else {
            message = QString("HTTP error %1").arg(http_code);
        }
        return {};
    }

    // 13) Success!
    ok = true;
    return responseBuffer;  // raw JSON body (e.g. {"status":"ok", ...})
}

void NetworkManager::signup(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/signup", payload, ok, message);

    Logger::log("Sending signup request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
    Logger::log("Received signup response: " + QString::fromUtf8(resp));

    if (!ok) {
        emit signupResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit signupResult(true, obj["status"].toString());
    } else {
        emit signupResult(false, obj["detail"].toString());
    }
}

void NetworkManager::login(const QString &username)
{
    QJsonObject req{{"username", username}};
    Logger::log("Sending login request for user '" + username + "'");
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/login", req, ok, message);
    Logger::log("Received login response: " + QString::fromUtf8(resp));

    if (!ok) {
        emit loginResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "challenge") {
        emit loginChallenge(
            QByteArray::fromBase64(obj["nonce"].toString().toUtf8()),
            QByteArray::fromBase64(obj["salt"].toString().toUtf8()),
            obj["argon2_opslimit"].toInt(),
            obj["argon2_memlimit"].toInt(),
            QByteArray::fromBase64(obj["encrypted_privkey"].toString().toUtf8()),
            QByteArray::fromBase64(obj["privkey_nonce"].toString().toUtf8()),
            QByteArray::fromBase64(obj["encrypted_kek"].toString().toUtf8()),
            QByteArray::fromBase64(obj["kek_nonce"].toString().toUtf8())
            );
    } else {
        emit loginResult(false, obj["detail"].toString());
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
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/authenticate", req, ok, message);
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

void NetworkManager::requestChallenge(const QString &username,
                                      const QString &operation)
{
    QJsonObject req{{"username", username}, {"operation", operation}};
    Logger::log(QString("Requesting challenge for '%1' op='%2'")
                    .arg(username).arg(operation));
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/challenge", req, ok, message);
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

void NetworkManager::changeUsername(const QJsonObject &payload)
{
    Logger::log("Sending changeUsername request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/change_username", payload, ok, message);
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
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/change_password", payload, ok, message);
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
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/upload_file", payload, ok, message);
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
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/list_files", payload, ok, message);
    Logger::log("Received listFiles response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit listFilesResult(false, QList<FileEntry>(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QJsonArray arr = obj["files"].toArray();
        QList<FileEntry> fileList;
        fileList.reserve(arr.size());
        for (const QJsonValue &v : arr) {
            if (!v.isObject()) continue;
            QJsonObject fileObj = v.toObject();
            // constructs a fresh FileEntry (this calls the “normal” construtor)
            FileEntry fe;
            fe.filename = fileObj.value("filename").toString();
            fe.id = static_cast<qint64>(fileObj.value("id").toInt());
            // “id” comes from the server’s JSON; it should always exist
            fe.id = static_cast<qint64>( fileObj.value("id").toInt() );
             // copy constructor is called here
            fileList.append(fe);
        }
        emit listFilesResult(true, fileList, QString());
    }
}

void NetworkManager::downloadFile(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/download_file", payload, ok, message);
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
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/delete_file", payload, ok, message);
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

void NetworkManager::retrieveFileDEK(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/retrieve_file_dek", payload, ok, message);
    Logger::log("Received retrieveFileDEK response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit retrieveFileDEKResult(false, QString(), QString(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit retrieveFileDEKResult(
            true,
            obj.value("encrypted_dek").toString(),
            obj.value("dek_nonce").toString(),
            QString()
            );
    } else {
        emit retrieveFileDEKResult(false, QString(), QString(), obj.value("detail").toString());
    }
}

void NetworkManager::getPreKeyBundle(const QJsonObject &payload)
{
    Logger::log("Sending getPreKeyBundle request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/get_pre_key_bundle", payload, ok, message);
    Logger::log("Received getPreKeyBundle response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit getPreKeyBundleResult(false, "", "", "", message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QJsonObject bundle = obj["prekey_bundle"].toObject();
        QString ik_pub  = bundle["IK_pub"].toString();
        QString spk_pub = bundle["SPK_pub"].toString();
        QString spk_sig = bundle["SPK_signature"].toString();
        emit getPreKeyBundleResult(true, ik_pub, spk_pub, spk_sig, "");
    } else {
        emit getPreKeyBundleResult(false, "", "", "", obj["detail"].toString());
    }
}

void NetworkManager::getOPK(const QJsonObject &payload)
{
    Logger::log("Sending getOPK request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/opk", payload, ok, message);
    Logger::log("Received getOPK response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit getOPKResult(false, 0, QString(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj.contains("opk_id")) {
        int opk_id          = obj["opk_id"].toInt();
        QString pre_key_b64 = obj["pre_key"].toString();
        emit getOPKResult(true, opk_id, pre_key_b64, QString());
    } else if (obj["status"].toString() == "ok") {
        int opk_id          = obj["opk_id"].toInt();
        QString pre_key_b64 = obj["pre_key"].toString();
        emit getOPKResult(true, opk_id, pre_key_b64, QString());
    } else {
        emit getOPKResult(false, 0, QString(), obj.value("detail").toString());
    }
}

void NetworkManager::backupTOFU(const QJsonObject &payload)
{
    Logger::log("Sending backupTOFU request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/backup_tofu", payload, ok, message);
    Logger::log("Received backupTOFU response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit backupTOFUResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj.contains("status") && obj["status"].toString() == "ok") {
        emit backupTOFUResult(true, obj["message"].toString());
    } else {
        emit backupTOFUResult(false, obj["detail"].toString());
    }
}

void NetworkManager::getBackupTOFU(const QJsonObject &payload)
{
    Logger::log("Sending getBackupTOFU request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/get_backup_tofu", payload, ok, message);
    Logger::log("Received getBackupTOFU response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit getBackupTOFUResult(false, "", "", message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QString enc   = obj["encrypted_backup"].toString();
        QString nonce = obj["backup_nonce"].toString();
        emit getBackupTOFUResult(true, enc, nonce, "");
    } else {
        emit getBackupTOFUResult(false, "", "", obj["detail"].toString());
    }
}

void NetworkManager::shareFile(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/share_file", payload, ok, message);
    Logger::log("Received shareFile response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit shareFileResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit shareFileResult(true, obj.value("message").toString());
    } else {
        emit shareFileResult(false, obj.value("detail").toString());
    }
}

void NetworkManager::listSharedTo(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/list_shared_to", payload, ok, message);
    Logger::log("Received listSharedTo response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit listSharedToResult(false, QJsonArray(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QJsonArray arr = obj.value("shares").toArray();
        emit listSharedToResult(true, arr, QString());
    } else {
        emit listSharedToResult(false, QJsonArray(), obj.value("detail").toString());
    }
}

void NetworkManager::listSharedFrom(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/list_shared_from", payload, ok, message);
    Logger::log("Received listSharedFrom response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit listSharedFromResult(false, QJsonArray(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QJsonArray arr = obj.value("shares").toArray();
        emit listSharedFromResult(true, arr, QString());
    } else {
        emit listSharedFromResult(false, QJsonArray(), obj.value("detail").toString());
    }
}

void NetworkManager::listSharers(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/list_sharers", payload, ok, message);
    Logger::log("Received listSharers response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit listSharersResult(false, QStringList(), message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        QStringList users;
        for (const QJsonValue &v : obj["usernames"].toArray()) {
            users.append(v.toString());
        }
        emit listSharersResult(true, users, QString());
    } else {
        emit listSharersResult(false, QStringList(), obj["detail"].toString());
    }
}

void NetworkManager::getOPK(const QJsonObject &payload)
{
    Logger::log("Sending getOPK request: " +
                QString::fromUtf8(QJsonDocument(payload).toJson(QJsonDocument::Compact)));

    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/opk", payload, ok, message);
    Logger::log("Received getOPK response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit getOPKResult(false, 0, QString(), message);
        return;
    }

    auto obj = QJsonDocument::fromJson(resp).object();

    // Changed: if “opk_id” is present, treat as success
    if (obj.contains("opk_id"))
    {
        int opk_id            = obj["opk_id"].toInt();
        QString pre_key_b64   = obj["pre_key"].toString();
        emit getOPKResult(true, opk_id, pre_key_b64, QString());
    }
    else if (obj["status"].toString() == "ok")
    {
        // for backward-compat, if server ever wraps it in { "status":"ok", … }
        int opk_id          = obj["opk_id"].toInt();
        QString pre_key_b64 = obj["pre_key"].toString();
        emit getOPKResult(true, opk_id, pre_key_b64, QString());
    }
    else
    {
        emit getOPKResult(false, 0, QString(), obj.value("detail").toString());
    }
}

void NetworkManager::downloadSharedFile(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/download_shared_file", payload, ok, message);
    if (!ok) {
        emit downloadSharedFileResult(false,
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      0,
                                      message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit downloadSharedFileResult(
            true,
            obj["encrypted_file"].toString(),
            obj["file_nonce"].toString(),
            obj["encrypted_file_key"].toString(),
            obj["file_key_nonce"].toString(),
            obj["EK_pub"].toString(),
            obj["IK_pub"].toString(),
            obj["SPK_pub"].toString(),
            obj["SPK_signature"].toString(),
            obj["opk_id"].toInt(),
            QString()
            );
    } else {
        emit downloadSharedFileResult(false,
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      QString(),
                                      0,
                                      obj["detail"].toString());
    }
}

void NetworkManager::removeSharedFile(const QJsonObject &payload)
{
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/remove_shared_file", payload, ok, message);
    Logger::log("Received removeSharedFile response: " + QString::fromUtf8(resp));
    if (!ok) {
        emit removeSharedFileResult(false, message);
        return;
    }
    auto obj = QJsonDocument::fromJson(resp).object();
    if (obj["status"].toString() == "ok") {
        emit removeSharedFileResult(true, obj.value("message").toString());
    } else {
        emit removeSharedFileResult(false, obj.value("detail").toString());
    }
}

void NetworkManager::checkConnection()
{
    // We can do a HEAD request to “/health” or just a GET to /health:
    // For simplicity, just re‐use postJson with an empty JSON object.  Or do:
    QJsonObject dummy;
    bool ok = false;
    QString message;
    QByteArray resp = postJson("nrmc.gobbler.info", 443, "/health", dummy, ok, message);
    if (!ok) {
        emit networkError(message);
        emit connectionStatusChanged(false);
    } else {
        emit connectionStatusChanged(true);
    }
}
