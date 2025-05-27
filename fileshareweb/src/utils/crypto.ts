import sodium from 'libsodium-wrappers-sumo';

// TypeScript module declaration
declare global {
  interface Window {
    crypto: Crypto;
  }
}

// Export the module
export {};

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface EncryptedPrivateKey {
  encryptedPrivateKey: Uint8Array;
  nonce: Uint8Array;
}

export class CryptoError extends Error {
  constructor(message: string, public cause?: any) {
    super(message);
    this.name = 'CryptoError';
  }
}

// Initialize libsodium
let sodiumReady = false;
export async function initSodium(): Promise<void> {
  if (!sodiumReady) {
    await sodium.ready;
    sodiumReady = true;
  }
}

export async function generateSalt(): Promise<Uint8Array> {
  try {
    await initSodium();
    // Generate 128-bit (16-byte) salt for Argon2id
    return sodium.randombytes_buf(16);
  } catch (error) {
    throw new CryptoError("Failed to generate salt", error);
  }
}

export async function derivePDK(
  password: string,
  salt: Uint8Array,
  opsLimit: number,
  memLimit: number
): Promise<Uint8Array> {
  try {
    await initSodium();
    return sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      password,
      salt,
      opsLimit,
      memLimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
  } catch (error) {
    throw new CryptoError("Failed to derive PDK", error);
  }
}

export async function generateKeyPair(): Promise<KeyPair> {
  try {
    await initSodium();
    const keypair = sodium.crypto_sign_keypair();
    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.privateKey
    };
  } catch (error) {
    throw new CryptoError("Failed to generate key pair", error);
  }
}

export async function generateKEK(): Promise<Uint8Array> {
  try {
    await initSodium();
    // Generate 256-bit (32-byte) KEK using libsodium's CSPRNG
    return sodium.randombytes_buf(32);
  } catch (error) {
    throw new CryptoError("Failed to generate KEK", error);
  }
}

export async function encryptPrivateKey(
  privateKey: Uint8Array,
  pdk: Uint8Array,
  nonce: Uint8Array
): Promise<EncryptedPrivateKey> {
  try {
    await initSodium();
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      privateKey,
      null, // No additional data
      null, // No additional data
      nonce,
      pdk
    );
    return {
      encryptedPrivateKey: encrypted,
      nonce: nonce
    };
  } catch (error) {
    throw new CryptoError("Failed to encrypt private key", error);
  }
}

export async function decryptPrivateKey(
  encryptedPrivateKey: Uint8Array,
  pdk: Uint8Array,
  nonce: Uint8Array
): Promise<Uint8Array> {
  try {
    await initSodium();
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, // No additional data
      encryptedPrivateKey,
      null, // No additional data
      nonce,
      pdk
    );
  } catch (error) {
    throw new CryptoError("Failed to decrypt private key", error);
  }
}

export async function encryptKEK(
  kek: Uint8Array,
  pdk: Uint8Array,
  nonce: Uint8Array
): Promise<EncryptedPrivateKey> {
  try {
    await initSodium();
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      kek,
      null, // No additional data
      null, // No additional data
      nonce,
      pdk
    );
    return {
      encryptedPrivateKey: encrypted,
      nonce: nonce
    };
  } catch (error) {
    throw new CryptoError("Failed to encrypt KEK", error);
  }
}

export async function decryptKEK(
  encryptedKek: Uint8Array,
  pdk: Uint8Array,
  nonce: Uint8Array
): Promise<Uint8Array> {
  try {
    await initSodium();
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, // No additional data
      encryptedKek,
      null, // No additional data
      nonce,
      pdk
    );
  } catch (error) {
    throw new CryptoError("Failed to decrypt KEK", error);
  }
}

export async function signChallenge(
  challenge: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  try {
    await initSodium();
    return sodium.crypto_sign_detached(challenge, privateKey);
  } catch (error) {
    throw new CryptoError("Failed to sign challenge", error);
  }
}

export async function generateFileKey(): Promise<Uint8Array> {
  const key = new Uint8Array(32); // XChaCha20-Poly1305 key size
  window.crypto.getRandomValues(key);
  return key;
}

export async function encryptFile(
  data: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array
): Promise<Uint8Array> {
  // Use libsodium's crypto_aead_xchacha20poly1305_ietf_encrypt
  await sodium.ready;
  return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    data,
    null, // no additional data
    null, // no additional data
    nonce,
    key
  );
}

export async function decryptFile(
  encrypted: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array
): Promise<Uint8Array> {
  await sodium.ready;
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null, // no additional data
    encrypted,
    null, // no additional data
    nonce,
    key
  );
}

export const generateX3DHKeys = async () => {
  await sodium.ready;
  
  // Generate Identity Key (IK)
  const identityKeyPair = sodium.crypto_sign_keypair();
  const IK_pub = identityKeyPair.publicKey;
  const IK_priv = identityKeyPair.privateKey;

  // Generate Signed Pre-Key (SPK)
  const signedPreKeyPair = sodium.crypto_sign_keypair();
  const SPK_pub = signedPreKeyPair.publicKey;
  const SPK_priv = signedPreKeyPair.privateKey;

  // Sign the SPK with IK
  const SPK_signature = sodium.crypto_sign_detached(
    SPK_pub,
    IK_priv
  );

  // Generate One-Time Pre-Keys (OPKs)
  const OPKs = [];
  const numOPKs = 100; // Generate 100 one-time pre-keys
  for (let i = 0; i < numOPKs; i++) {
    const opkPair = sodium.crypto_sign_keypair();
    OPKs.push(opkPair.publicKey);
  }

  return {
    identity_key: IK_pub,
    signed_pre_key: SPK_pub,
    signed_pre_key_sig: SPK_signature,
    one_time_pre_keys: OPKs
  };
};