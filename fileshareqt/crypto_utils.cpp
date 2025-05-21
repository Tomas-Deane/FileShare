// File: fileshareqt/crypto_utils.cpp
#include "crypto_utils.h"
#include <sodium.h>

QByteArray CryptoUtils::derivePDK(const QString &password,
                                  const QByteArray &salt,
                                  quint64 opslimit,
                                  quint64 memlimit)
{
    QByteArray pdk(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, 0);
    if (crypto_pwhash_argon2id(
            reinterpret_cast<unsigned char*>(pdk.data()), pdk.size(), // reinterpret_cast<unsigned char*> means treat these bits as if they were the new type
            password.toUtf8().constData(), password.size(),            // libsodium expects pointers to unsigned char (byte buffer) but QByteArray gives char*
            reinterpret_cast<const unsigned char*>(salt.constData()), // pdk.data() returns char*, reinterpret_cast<unsigned char*>(pdk.data()) says it is unsigned char
            opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13) != 0) { // static_cast<unsigned char*>(pdk.data()) wont compile (no known conversion)
        return {};                                                     // C-style cast (unsigned char*)pdk.data() risks conversions, so reinterpret cast is standardly used.
    }
    return pdk;
}

void CryptoUtils::generateKeyPair(QByteArray &publicKey, // using OS's CSPRNG
                                  QByteArray &secretKey)
{
    publicKey.resize(crypto_sign_PUBLICKEYBYTES);
    secretKey.resize(crypto_sign_SECRETKEYBYTES);
    crypto_sign_keypair(
        reinterpret_cast<unsigned char*>(publicKey.data()),
        reinterpret_cast<unsigned char*>(secretKey.data())
        );
}

QByteArray CryptoUtils::encryptSecretKey(const QByteArray &secretKey,
                                         const QByteArray &pdk,
                                         QByteArray &nonce)
{
    nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(reinterpret_cast<unsigned char*>(nonce.data()), nonce.size());

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
        return {};
    }
    out.resize(plen);
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
    return sig;
}
