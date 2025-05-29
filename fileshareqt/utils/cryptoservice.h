#ifndef CRYPTOSERVICE_H
#define CRYPTOSERVICE_H

#include "icryptoservice.h"

// Concrete implementation of ICryptoService using CryptoUtils and libsodium.
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

    QByteArray generateAeadKey() override;

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
};

#endif // CRYPTOSERVICE_H
