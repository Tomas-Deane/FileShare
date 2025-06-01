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
    // Create AAD that binds the ciphertext to its context
    const aad = new TextEncoder().encode("private_key_encryption");
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      privateKey,
      aad,
      null,
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
    // Create AAD that binds the ciphertext to its context
    const aad = new TextEncoder().encode("private_key_encryption");
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      encryptedPrivateKey,
      aad,
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
    // Create AAD that binds the ciphertext to its context
    const aad = new TextEncoder().encode("kek_encryption");
    const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      kek,
      aad,
      null,
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
    // Create AAD that binds the ciphertext to its context
    const aad = new TextEncoder().encode("kek_encryption");
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      encryptedKek,
      aad,
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
  await sodium.ready;
  // Create AAD that binds the ciphertext to its context
  const aad = new TextEncoder().encode("file_encryption");
  return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    data,
    aad,
    null,
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
  // Create AAD that binds the ciphertext to its context
  const aad = new TextEncoder().encode("file_encryption");
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    encrypted,
    aad,
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
  const OPKs_priv = [];
  const numOPKs = 100; // Generate 100 one-time pre-keys
  for (let i = 0; i < numOPKs; i++) {
    const opkPair = sodium.crypto_sign_keypair();
    OPKs.push(opkPair.publicKey);
    OPKs_priv.push(opkPair.privateKey);
  }

  return {
    identity_key: IK_pub,
    identity_key_private: IK_priv,
    signed_pre_key: SPK_pub,
    signed_pre_key_private: SPK_priv,
    signed_pre_key_sig: SPK_signature,
    one_time_pre_keys: OPKs,
    one_time_pre_keys_private: OPKs_priv
  };
};

export async function generateOOBVerificationCode(ik1_b64: string, ik2_b64: string) {
  // Validate base64 inputs
  const base64Regex = /^[A-Za-z0-9+/]+={0,2}$/;
  if (!base64Regex.test(ik1_b64) || !base64Regex.test(ik2_b64)) {
    throw new Error("Invalid base64 input: Both ik1_b64 and ik2_b64 must be valid base64-encoded strings.");
  }
  const ik1 = Uint8Array.from(atob(ik1_b64), c => c.charCodeAt(0));
  const ik2 = Uint8Array.from(atob(ik2_b64), c => c.charCodeAt(0));
  const [a, b] = [ik1, ik2].sort((x, y) => {
    for (let i = 0; i < x.length; i++) {
      if (x[i] !== y[i]) return x[i] - y[i];
    }
    return 0;
  });
  const concat = new Uint8Array(a.length + b.length);
  concat.set(a, 0);
  concat.set(b, a.length);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', concat);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex.slice(0, 60); // 60 hex chars
}