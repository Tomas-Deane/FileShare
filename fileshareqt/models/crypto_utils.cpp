#include "crypto_utils.h"
#include "logger.h"
#include <sodium.h>

void CryptoUtils::initializeLibrary()
{
    static bool initialized = false;
    if (!initialized) {
        if (sodium_init() < 0) {
            qWarning() << "libsodium initialization failed";
        }
        initialized = true;
    }
}

QByteArray CryptoUtils::randomBytes(int length)
{
    QByteArray buf(length, 0);
    randombytes_buf(reinterpret_cast<unsigned char*>(buf.data()), buf.size());
    return buf;
}

QByteArray CryptoUtils::generateAeadKey() {
    return randomBytes(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}

void CryptoUtils::generateX25519KeyPair(QByteArray &publicKey,
                                        QByteArray &secretKey)
{
    // libsodium: crypto_kx_keypair or crypto_box_keypair both produce X25519 keys.
    publicKey .resize(crypto_kx_PUBLICKEYBYTES);
    secretKey .resize(crypto_kx_SECRETKEYBYTES);
    crypto_kx_keypair(
        reinterpret_cast<unsigned char*>(publicKey.data()),
        reinterpret_cast<unsigned char*>(secretKey.data())
        );
    Logger::log("Generated X25519 keypair (Curve25519)");
}

void CryptoUtils::generateOneTimePreKey(QByteArray &opkPub,
                                        QByteArray &opkPriv)
{
    // identical to generateX25519KeyPair
    generateX25519KeyPair(opkPub, opkPriv);
}

QString CryptoUtils::computeOOBCode(const QByteArray &ik1_pub,
                                    const QByteArray &ik2_pub)
{
    // 1. Sort the two QByteArrays bytewise:
    QByteArray a = ik1_pub, b = ik2_pub;
    if (a < b) {
        // keep as-is
    } else {
        std::swap(a,b);
    }
    // 2. Concatenate:
    QByteArray concat = a + b;
    // 3. SHA256:
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash,
                       reinterpret_cast<const unsigned char*>(concat.constData()),
                       (unsigned long long)concat.size());
    // 4. Convert to lowercase hex:
    char hexOut[crypto_hash_sha256_BYTES * 2 + 1];
    sodium_bin2hex(hexOut,
                   sizeof(hexOut),
                   hash,
                   crypto_hash_sha256_BYTES);
    // 5. Take the first 60 hex chars:
    QString hexStr = QString::fromUtf8(hexOut);
    return hexStr.left(60).toLower();
}

QByteArray CryptoUtils::derivePDK(const QString &password,
                                  const QByteArray &salt,
                                  quint64 opslimit,
                                  quint64 memlimit)
{
    QByteArray pdk(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 0);
    if (crypto_pwhash_argon2id(
            reinterpret_cast<unsigned char*>(pdk.data()), pdk.size(),
            password.toUtf8().constData(), (unsigned long long)password.size(),
            reinterpret_cast<const unsigned char*>(salt.constData()),
            (unsigned long long)opslimit,
            (unsigned long long)memlimit,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        Logger::log("PDK derivation failed");
        return {};
    }
    Logger::log("Derived PDK");
    return pdk;
}

void CryptoUtils::generateKeyPair(QByteArray &publicKey,
                                  QByteArray &secretKey)
{
    publicKey.resize(crypto_sign_PUBLICKEYBYTES);
    secretKey.resize(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(
        reinterpret_cast<unsigned char*>(publicKey.data()),
        reinterpret_cast<unsigned char*>(secretKey.data())
        );
    Logger::log("Generated Ed25519 keypair");
}

QByteArray CryptoUtils::encryptSecretKey(const QByteArray &secretKey,
                                         const QByteArray &pdk,
                                         QByteArray &nonce)
{
    nonce = randomBytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    Logger::log("Generated nonce for encryption");

    QByteArray out(secretKey.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES, 0);
    unsigned long long clen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(out.data()), &clen,
        reinterpret_cast<const unsigned char*>(secretKey.constData()), (unsigned long long)secretKey.size(),
        nullptr, 0, nullptr,
        reinterpret_cast<const unsigned char*>(nonce.constData()),
        reinterpret_cast<const unsigned char*>(pdk.constData())
        );
    out.resize((int)clen);
    Logger::log("Encrypted secret key");
    return out;
}

QByteArray CryptoUtils::decryptSecretKey(const QByteArray &encryptedSK,
                                         const QByteArray &pdk,
                                         const QByteArray &nonce)
{
    QByteArray out(encryptedSK.size(), 0);
    unsigned long long plen;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(out.data()), &plen,
            nullptr,
            reinterpret_cast<const unsigned char*>(encryptedSK.constData()), (unsigned long long)encryptedSK.size(),
            nullptr, 0,
            reinterpret_cast<const unsigned char*>(nonce.constData()),
            reinterpret_cast<const unsigned char*>(pdk.constData())
            ) != 0) {
        Logger::log("Secret key decryption failed");
        return {};
    }
    out.resize((int)plen);
    Logger::log("Decrypted secret key");
    return out;
}

QByteArray CryptoUtils::signMessage(const QByteArray &message,
                                    const QByteArray &secretKey)
{
    QByteArray sig(crypto_sign_BYTES, 0);
    crypto_sign_detached(
        reinterpret_cast<unsigned char*>(sig.data()), nullptr,
        reinterpret_cast<const unsigned char*>(message.constData()), (unsigned long long)message.size(),
        reinterpret_cast<const unsigned char*>(secretKey.constData())
        );
    Logger::log("Generated signature");
    return sig;
}

QByteArray CryptoUtils::computeSharedKey(const QByteArray &ourPriv,
                                         const QByteArray &theirPub)
{
    // --- Perform a Curve25519 ECDH: crypto_scalarmult(scalar, base) ---
    if (ourPriv.size() != crypto_scalarmult_SCALARBYTES ||
        theirPub.size() != crypto_scalarmult_BYTES) {
        return {};
    }

    QByteArray shared(crypto_scalarmult_BYTES, 0);
    if (crypto_scalarmult(
            reinterpret_cast<unsigned char*>(shared.data()),
            reinterpret_cast<const unsigned char*>(ourPriv.constData()),
            reinterpret_cast<const unsigned char*>(theirPub.constData())
            ) != 0) {
        Logger::log("ECDH (crypto_scalarmult) failed");
        return {};
    }
    return shared;
}

QByteArray CryptoUtils::hkdfSha256(const QByteArray &salt,
                                     const QByteArray &ikm,
                                     int outputLength)
{
    // 1) Extract: PRK = HMAC-SHA256(salt, ikm)
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, (const unsigned char*)salt.constData(), salt.size());
    crypto_auth_hmacsha256_update(&state, (const unsigned char*)ikm.constData(), ikm.size());
    crypto_auth_hmacsha256_final(&state, prk);

    // 2) Expand: OKM = HKDF-Expand(PRK, info="", L)
    //    We will do a single-block expand (since 32 bytes ≤ 32).
    //    T(1) = HMAC-SHA256(PRK, T(0)=empty || 0x01).
    unsigned char okm[crypto_auth_hmacsha256_BYTES];
    unsigned char info_and_counter[1];
    info_and_counter[0] = 0x01; // single block
    crypto_auth_hmacsha256_state state2;
    crypto_auth_hmacsha256_init(&state2, prk, sizeof(prk));
    // no "info" field ⇒ just the single counter
    crypto_auth_hmacsha256_update(&state2, info_and_counter, 1);
    crypto_auth_hmacsha256_final(&state2, okm);

    return QByteArray((char*)okm, outputLength);
}


void CryptoUtils::secureZeroMemory(QByteArray &data)
{
    if (!data.isEmpty()) {
        sodium_memzero(data.data(), data.size());
        data.clear();
    }
}
