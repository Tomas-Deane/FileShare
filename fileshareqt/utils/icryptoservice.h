#ifndef ICRYPTOSERVICE_H
#define ICRYPTOSERVICE_H

#include <QString>
#include <QByteArray>

// pure-virtual interface for all crypto operations
class ICryptoService
{
public:
    virtual ~ICryptoService() = default;

    // default Argon2id parameters (matches libsodiums moderate settings)
    const static quint64 OPSLIMIT_MODERATE = 3;
    const static quint64 MEMLIMIT_MODERATE = 268435456; // 256 MiB

    // Derive a key (e.g. PDK) from password+salt
    virtual QByteArray deriveKey(const QString &password,
                                 const QByteArray &salt,
                                 quint64 opslimit,
                                 quint64 memlimit) = 0;

    // Generate cryptographically secure random bytes
    virtual QByteArray randomBytes(int length) = 0;

    // Generate a signing keypair
    virtual void generateKeyPair(QByteArray &publicKey,
                                 QByteArray &secretKey) = 0;

    // Get a fresh random AEAD key of length 32 bytes
    virtual QByteArray generateAeadKey() = 0;


    // Symmetric encryption (AEAD)
    virtual QByteArray encrypt(const QByteArray &plaintext,
                               const QByteArray &key,
                               QByteArray &nonce) = 0;

    // Symmetric decryption (AEAD)
    virtual QByteArray decrypt(const QByteArray &ciphertext,
                               const QByteArray &key,
                               const QByteArray &nonce) = 0;

    // Signature generation
    virtual QByteArray sign(const QByteArray &message,
                            const QByteArray &secretKey) = 0;

    // Securely zero-out sensitive data
    virtual void secureZeroMemory(QByteArray &data) = 0;

};

#endif // ICRYPTOSERVICE_H
