#ifndef CRYPTOSERVICE_H
#define CRYPTOSERVICE_H

#include "icryptoservice.h"
#include <QByteArray>
#include <QString>

class CryptoService : public ICryptoService
{
public:
    // Initialize libsodium library
    CryptoService();

    // Derive a key (e.g. PDK) from password+salt
    QByteArray deriveKey(const QString &password,
                         const QByteArray &salt,
                         quint64 opslimit,
                         quint64 memlimit) override;

    // Generate cryptographically secure random bytes
    QByteArray randomBytes(int length) override;

    // Generate a signing keypair
    void generateKeyPair(QByteArray &publicKey,
                         QByteArray &secretKey) override;

    // Get a fresh random AEAD key of length 32 bytes
    QByteArray generateAeadKey() override;

    // Generate an X25519 keypair (Curve25519) for X3DH identity keys / OPKs
    void generateX25519KeyPair(QByteArray &publicKey,
                               QByteArray &secretKey) override;

    // Create a single one‐time pre‐key (Curve25519)
    void generateOneTimePreKey(QByteArray &opkPub,
                               QByteArray &opkPriv) override;

    // Compute OOB verification code from two identity‐pubkeys
    QString computeOOBVerificationCode(const QByteArray &ik1_pub,
                                       const QByteArray &ik2_pub) override;

    // Symmetric encryption (AEAD)
    QByteArray encrypt(const QByteArray &plaintext,
                       const QByteArray &key,
                       QByteArray &nonce) override;

    // Symmetric decryption (AEAD)
    QByteArray decrypt(const QByteArray &ciphertext,
                       const QByteArray &key,
                       const QByteArray &nonce) override;

    // Signature generation
    QByteArray sign(const QByteArray &message,
                    const QByteArray &secretKey) override;

    // Securely zero-out sensitive data
    void secureZeroMemory(QByteArray &data) override;
};

#endif // CRYPTOSERVICE_H
