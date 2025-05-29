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

// used to generate our 256 byte keys (KEKs, DEKs)
QByteArray CryptoUtils::generateAeadKey() {
    return randomBytes(crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}

QByteArray CryptoUtils::derivePDK(const QString &password,
                                  const QByteArray &salt,
                                  quint64 opslimit,
                                  quint64 memlimit)
{
    QByteArray pdk(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 0);
    if (crypto_pwhash_argon2id(
            reinterpret_cast<unsigned char*>(pdk.data()), pdk.size(),
            password.toUtf8().constData(), password.size(),
            reinterpret_cast<const unsigned char*>(salt.constData()),
            opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0) {
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
    Logger::log("Generated keypair");
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
        reinterpret_cast<const unsigned char*>(secretKey.constData()), secretKey.size(),
        nullptr, 0, nullptr,
        reinterpret_cast<const unsigned char*>(nonce.constData()),
        reinterpret_cast<const unsigned char*>(pdk.constData())
        );
    out.resize(clen);
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
            reinterpret_cast<const unsigned char*>(encryptedSK.constData()), encryptedSK.size(),
            nullptr, 0,
            reinterpret_cast<const unsigned char*>(nonce.constData()),
            reinterpret_cast<const unsigned char*>(pdk.constData())
            ) != 0) {
        Logger::log("Secret key decryption failed");
        return {};
    }
    out.resize(plen);
    Logger::log("Decrypted secret key");
    return out;
}

QByteArray CryptoUtils::signMessage(const QByteArray &message,
                                    const QByteArray &secretKey)
{
    QByteArray sig(crypto_sign_BYTES, 0);
    crypto_sign_detached(
        reinterpret_cast<unsigned char*>(sig.data()), nullptr,
        reinterpret_cast<const unsigned char*>(message.constData()), message.size(),
        reinterpret_cast<const unsigned char*>(secretKey.constData())
        );
    Logger::log("Generated signature");
    return sig;
}
