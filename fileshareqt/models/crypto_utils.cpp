#include "crypto_utils.h"
#include "logger.h"
#include <sodium.h>

void CryptoUtils::initialiseLibrary()
{
    static bool initialized = false;
    if (!initialized) {
        if (sodium_init() < 0) {
            qWarning() << "libsodium initialization failed";
        }
        initialized = true;
    }
}

// deriveKey
QByteArray CryptoUtils::deriveKey(const QString &password,
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

// randomBytes
QByteArray CryptoUtils::randomBytes(int length)
{
    QByteArray buf(length, 0);
    randombytes_buf(reinterpret_cast<unsigned char*>(buf.data()), buf.size());
    return buf;
}

// generateKeyPair (Ed25519)
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

// generateAeadKey
QByteArray CryptoUtils::generateAeadKey()
{
    return randomBytes(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}

// generateX25519KeyPair
void CryptoUtils::generateX25519KeyPair(QByteArray &publicKey,
                                        QByteArray &secretKey)
{
    publicKey.resize(crypto_kx_PUBLICKEYBYTES);
    secretKey.resize(crypto_kx_SECRETKEYBYTES);
    crypto_kx_keypair(
        reinterpret_cast<unsigned char*>(publicKey.data()),
        reinterpret_cast<unsigned char*>(secretKey.data())
        );
    Logger::log("Generated X25519 keypair (Curve25519)");
}

// generateOneTimePreKey  (just forward to the above)
void CryptoUtils::generateOneTimePreKey(QByteArray &opkPub,
                                        QByteArray &opkPriv)
{
    generateX25519KeyPair(opkPub, opkPriv);
}

// computeOOBVerificationCode
QString CryptoUtils::computeOOBVerificationCode(const QByteArray &ik1_pub,
                                                const QByteArray &ik2_pub)
{
    QByteArray a = ik1_pub, b = ik2_pub;
    if (a < b) {
    } else {
        std::swap(a, b);
    }
    QByteArray concat = a + b;
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash,
                       reinterpret_cast<const unsigned char*>(concat.constData()),
                       (unsigned long long)concat.size());
    char hexOut[crypto_hash_sha256_BYTES * 2 + 1];
    sodium_bin2hex(hexOut,
                   sizeof(hexOut),
                   hash,
                   crypto_hash_sha256_BYTES);
    QString hexStr = QString::fromUtf8(hexOut);
    return hexStr.left(60).toLower();
}

// encrypt (AEAD)
QByteArray CryptoUtils::encrypt(const QByteArray &plaintext,
                                const QByteArray &key,
                                QByteArray &nonce)
{
    nonce = randomBytes(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    Logger::log("Generated nonce for encryption");
    QByteArray out(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES, 0);
    unsigned long long clen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        reinterpret_cast<unsigned char*>(out.data()), &clen,
        reinterpret_cast<const unsigned char*>(plaintext.constData()), (unsigned long long)plaintext.size(),
        nullptr, 0, nullptr,
        reinterpret_cast<const unsigned char*>(nonce.constData()),
        reinterpret_cast<const unsigned char*>(key.constData())
        );
    out.resize((int)clen);
    Logger::log("Encrypted data");
    return out;
}

// decrypt (AEAD)
QByteArray CryptoUtils::decrypt(const QByteArray &ciphertext,
                                const QByteArray &key,
                                const QByteArray &nonce)
{
    QByteArray out(ciphertext.size(), 0);
    unsigned long long plen;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            reinterpret_cast<unsigned char*>(out.data()), &plen,
            nullptr,
            reinterpret_cast<const unsigned char*>(ciphertext.constData()), (unsigned long long)ciphertext.size(),
            nullptr, 0,
            reinterpret_cast<const unsigned char*>(nonce.constData()),
            reinterpret_cast<const unsigned char*>(key.constData())
            ) != 0) {
        Logger::log("Decryption failed");
        return {};
    }
    out.resize((int)plen);
    Logger::log("Decrypted data");
    return out;
}

// sign (Ed25519)
QByteArray CryptoUtils::sign(const QByteArray &message,
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

// secureZeroMemory
void CryptoUtils::secureZeroMemory(QByteArray &data)
{
    if (!data.isEmpty()) {
        sodium_memzero(data.data(), data.size());
        data.clear();
    }
}

// deriveSharedKey (Curve25519/ECDH)
QByteArray CryptoUtils::deriveSharedKey(const QByteArray &ourPriv,
                                        const QByteArray &theirPub)
{
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

// hkdfSha256
QByteArray CryptoUtils::hkdfSha256(const QByteArray &salt,
                                   const QByteArray &ikm,
                                   int outputLength)
{
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, (const unsigned char*)salt.constData(), salt.size());
    crypto_auth_hmacsha256_update(&state, (const unsigned char*)ikm.constData(), ikm.size());
    crypto_auth_hmacsha256_final(&state, prk);

    unsigned char okm[crypto_auth_hmacsha256_BYTES];
    unsigned char info_and_counter[1];
    info_and_counter[0] = 0x01;
    crypto_auth_hmacsha256_state state2;
    crypto_auth_hmacsha256_init(&state2, prk, sizeof(prk));
    crypto_auth_hmacsha256_update(&state2, info_and_counter, 1);
    crypto_auth_hmacsha256_final(&state2, okm);

    return QByteArray((char*)okm, outputLength);
}
