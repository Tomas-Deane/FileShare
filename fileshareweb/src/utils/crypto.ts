import sodium from 'libsodium-wrappers-sumo';

// TypeScript module declaration
declare global {
  interface Window {
    crypto: Crypto;
    runX3DHTest: () => Promise<void>;
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

export async function generateEphemeralKeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
  await sodium.ready;
  
  // Generate Ed25519 key pair instead of X25519
  const keyPair = sodium.crypto_sign_keypair();
  
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey  // This will be 64 bytes
  };
}

export async function deriveX3DHSharedSecret({
  myIKPriv,
  myEKPriv,
  recipientIKPub,
  recipientSPKPub,
  recipientSPKSignature,
  recipientOPKPub
}: {
  myIKPriv: Uint8Array,
  myEKPriv: Uint8Array,
  recipientIKPub: Uint8Array,
  recipientSPKPub: Uint8Array,
  recipientSPKSignature: Uint8Array,
  recipientOPKPub: Uint8Array
}) {
  await sodium.ready;

  // Add debug logging for key lengths
  console.log('Key lengths:', {
    myIKPriv: myIKPriv.length,
    myEKPriv: myEKPriv.length,
    recipientIKPub: recipientIKPub.length,
    recipientSPKPub: recipientSPKPub.length,
    recipientOPKPub: recipientOPKPub.length
  });

  // 1. Verify SPK signature
  const valid = sodium.crypto_sign_verify_detached(
    recipientSPKSignature,
    recipientSPKPub,
    recipientIKPub
  );
  if (!valid) throw new Error('Invalid SPK signature');

  try {
    // 2. Convert Ed25519 keys to X25519 for DH
    const myIKPriv_x = sodium.crypto_sign_ed25519_sk_to_curve25519(myIKPriv);
    const myEKPriv_x = sodium.crypto_sign_ed25519_sk_to_curve25519(myEKPriv);
    const recipientIKPub_x = sodium.crypto_sign_ed25519_pk_to_curve25519(recipientIKPub);
    const recipientSPKPub_x = sodium.crypto_sign_ed25519_pk_to_curve25519(recipientSPKPub);
    const recipientOPKPub_x = sodium.crypto_sign_ed25519_pk_to_curve25519(recipientOPKPub);

    // 3. Perform DHs (see X3DH spec)
    const DH1 = sodium.crypto_scalarmult(myIKPriv_x, recipientSPKPub_x);
    const DH2 = sodium.crypto_scalarmult(myEKPriv_x, recipientIKPub_x);
    const DH3 = sodium.crypto_scalarmult(myEKPriv_x, recipientSPKPub_x);
    const DH4 = sodium.crypto_scalarmult(myEKPriv_x, recipientOPKPub_x);

    // 4. Concatenate all DH results and hash to derive shared secret
    const combined = new Uint8Array(DH1.length + DH2.length + DH3.length + DH4.length);
    combined.set(DH1, 0);
    combined.set(DH2, DH1.length);
    combined.set(DH3, DH1.length + DH2.length);
    combined.set(DH4, DH1.length + DH2.length + DH3.length);

    // 5. Generate final shared secret using the combined DH results
    const sharedSecret = sodium.crypto_generichash(32, combined);
    return sharedSecret;

  } catch (error: unknown) {
    console.error('Key conversion error:', error);
    if (error instanceof Error) {
      throw new Error(`Key conversion failed: ${error.message}`);
    } else {
      throw new Error('Key conversion failed: Unknown error');
    }
  }
}

export async function deriveX3DHSharedSecretRecipient({
  senderEKPub,
  senderIKPub,
  myIKPriv,
  mySPKPriv,
  myOPKPriv,
}: {
  senderEKPub: Uint8Array,
  senderIKPub: Uint8Array,
  myIKPriv: Uint8Array,
  mySPKPriv: Uint8Array,
  myOPKPriv: Uint8Array
}) {
  await sodium.ready;  

  try {
    // Convert all Ed25519 keys to X25519
    const senderEKPub_x = sodium.crypto_sign_ed25519_pk_to_curve25519(senderEKPub);
    const senderIKPub_x = sodium.crypto_sign_ed25519_pk_to_curve25519(senderIKPub);
    const myIKPriv_x = sodium.crypto_sign_ed25519_sk_to_curve25519(myIKPriv);
    const mySPKPriv_x = sodium.crypto_sign_ed25519_sk_to_curve25519(mySPKPriv);
    const myOPKPriv_x = sodium.crypto_sign_ed25519_sk_to_curve25519(myOPKPriv);

    // DH computations
    const DH1 = sodium.crypto_scalarmult(mySPKPriv_x, senderIKPub_x);  // DH(SPKb, IKa)
    const DH2 = sodium.crypto_scalarmult(myIKPriv_x, senderEKPub_x);   // DH(IKb, EKa)
    const DH3 = sodium.crypto_scalarmult(mySPKPriv_x, senderEKPub_x);  // DH(SPKb, EKa)
    const DH4 = sodium.crypto_scalarmult(myOPKPriv_x, senderEKPub_x);  // DH(OPKb, EKa)

    const combined = new Uint8Array(DH1.length + DH2.length + DH3.length + DH4.length);
    combined.set(DH1, 0);
    combined.set(DH2, DH1.length);
    combined.set(DH3, DH1.length + DH2.length);
    combined.set(DH4, DH1.length + DH2.length + DH3.length);

    const sharedSecret = sodium.crypto_generichash(32, combined);
    return sharedSecret;

  } catch (error: unknown) {
    console.error('Key conversion error:', error);
    if (error instanceof Error) {
      throw new Error(`Key conversion failed: ${error.message}`);
    } else {
      throw new Error('Key conversion failed: Unknown error');
    }
  }
}


export async function encryptWithAESGCM(key: Uint8Array, data: Uint8Array) {
  await sodium.ready;
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    data,
    null, // no additional data
    null, // no additional data
    nonce,
    key
  );
  // Return both ciphertext and nonce, as both are needed for decryption
  return {
    ciphertext, // Uint8Array
    nonce       // Uint8Array
  };
}

export async function testX3DHKeyExchange() {
  await sodium.ready;
  console.log('Starting X3DH key exchange test...');

  // Generate key bundles for both parties
  const aliceBundle = await generateX3DHKeys();
  const bobBundle = await generateX3DHKeys();

  // Generate ephemeral key for Alice (sender)
  const aliceEphemeral = await generateEphemeralKeyPair();

  console.log('Generated key bundles and ephemeral key');

  // Alice (sender) derives shared secret
  const aliceSharedSecret = await deriveX3DHSharedSecret({
    myIKPriv: aliceBundle.identity_key_private,
    myEKPriv: aliceEphemeral.privateKey,
    recipientIKPub: bobBundle.identity_key,
    recipientSPKPub: bobBundle.signed_pre_key,
    recipientSPKSignature: bobBundle.signed_pre_key_sig,
    recipientOPKPub: bobBundle.one_time_pre_keys[0] // Using first OPK
  });

  console.log('Alice derived shared secret:', {
    length: aliceSharedSecret.length,
    hex: Array.from(new Uint8Array(aliceSharedSecret)).map(b => b.toString(16).padStart(2, '0')).join('')
  });

  // Bob (recipient) derives shared secret
  const bobSharedSecret = await deriveX3DHSharedSecretRecipient({
    senderEKPub: aliceEphemeral.publicKey,
    senderIKPub: aliceBundle.identity_key,
    myIKPriv: bobBundle.identity_key_private,
    mySPKPriv: bobBundle.signed_pre_key_private,
    myOPKPriv: bobBundle.one_time_pre_keys_private[0] // Using first OPK private key
  });

  console.log('Bob derived shared secret:', {
    length: bobSharedSecret.length,
    hex: Array.from(new Uint8Array(bobSharedSecret)).map(b => b.toString(16).padStart(2, '0')).join('')
  });

  // Compare shared secrets
  const secretsMatch = sodium.memcmp(aliceSharedSecret, bobSharedSecret);
  console.log('Shared secrets match:', secretsMatch);

  // Test encryption/decryption with shared secrets
  const testMessage = new TextEncoder().encode('Hello, X3DH!');
  const { ciphertext, nonce } = await encryptWithAESGCM(aliceSharedSecret, testMessage);
  
  try {
    const decrypted = await decryptFile(ciphertext, bobSharedSecret, nonce);
    const decryptedText = new TextDecoder().decode(decrypted);
    console.log('Test message decrypted successfully:', decryptedText);
    console.log('Original message matches decrypted:', decryptedText === 'Hello, X3DH!');
  } catch (error) {
    console.error('Decryption failed:', error);
  }

  return {
    secretsMatch,
    aliceSharedSecret,
    bobSharedSecret
  };
}