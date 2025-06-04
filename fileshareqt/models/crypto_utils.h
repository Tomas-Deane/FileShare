// crypto_utils.h

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <QByteArray>
#include <QString>
#include <QDebug>

#include "icryptoservice.h"

class CryptoUtils : public ICryptoService {
public:
    CryptoUtils() {
        qDebug() << "CryptoUtils Ctor";
    }
    ~CryptoUtils() override {
        qDebug() << "CryptoUtils Dtor";
    }

    // deriveKey (Argon2id)
    QByteArray deriveKey(const QString &password,
                         const QByteArray &salt,
                         quint64 opslimit,
                         quint64 memlimit) override;

    // randomBytes
    QByteArray randomBytes(int length) override;

    // generateKeyPair (Ed25519)
    void generateKeyPair(QByteArray &publicKey,
                         QByteArray &secretKey) override;

    // generateAeadKey
    QByteArray generateAeadKey() override;

    // generateX25519KeyPair
    void generateX25519KeyPair(QByteArray &publicKey,
                               QByteArray &secretKey) override;

    // generateOneTimePreKey
    void generateOneTimePreKey(QByteArray &opkPub,
                               QByteArray &opkPriv) override;

    // computeOOBVerificationCode
    QString computeOOBVerificationCode(const QByteArray &ik1_pub,
                                       const QByteArray &ik2_pub) override;

    // encrypt (AEAD)
    QByteArray encrypt(const QByteArray &plaintext,
                       const QByteArray &key,
                       QByteArray &nonce) override;

    // decrypt (AEAD)
    QByteArray decrypt(const QByteArray &ciphertext,
                       const QByteArray &key,
                       const QByteArray &nonce) override;

    // sign (Ed25519)
    QByteArray sign(const QByteArray &message,
                    const QByteArray &secretKey) override;

    // secureZeroMemory
    void secureZeroMemory(QByteArray &data) override;

    // deriveSharedKey (Curve25519/ECDH)
    QByteArray deriveSharedKey(const QByteArray &ourPriv,
                               const QByteArray &theirPub) override;

    // hkdfSha256
    QByteArray hkdfSha256(const QByteArray &salt,
                          const QByteArray &ikm,
                          int outputLength) override;

    static void initialiseLibrary();
};

#endif // CRYPTO_UTILS_H
