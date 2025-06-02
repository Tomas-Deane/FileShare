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
  key: Uint8Array
): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }> {
  await sodium.ready;
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    data,
    null, // no additional data
    null, // no additional data
    nonce,
    key
  );
  return { encrypted, nonce };
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

  console.log('Sender - Input keys:', {
    myIKPriv: {
      length: myIKPriv.length,
      hex: Array.from(myIKPriv).map(b => b.toString(16).padStart(2, '0')).join('')
    },
    myEKPriv: {
      length: myEKPriv.length,
      hex: Array.from(myEKPriv).map(b => b.toString(16).padStart(2, '0')).join('')
    },
    recipientIKPub: {
      length: recipientIKPub.length,
      hex: Array.from(recipientIKPub).map(b => b.toString(16).padStart(2, '0')).join('')
    },
    recipientSPKPub: {
      length: recipientSPKPub.length,
      hex: Array.from(recipientSPKPub).map(b => b.toString(16).padStart(2, '0')).join('')
    },
    recipientOPKPub: {
      length: recipientOPKPub.length,
      hex: Array.from(recipientOPKPub).map(b => b.toString(16).padStart(2, '0')).join('')
    }
  });

  // 1. Verify SPK signature
  const valid = sodium.crypto_sign_verify_detached(
    recipientSPKSignature,
    recipientSPKPub,
    recipientIKPub
  );
  if (!valid) throw new Error('Invalid SPK signature');
  console.log('SPK signature verified successfully');

  try {
    // 2. Convert Ed25519 keys to X25519 for DH
    const myIKPriv_x = sodium.crypto_sign_ed25519_sk_to_curve25519(myIKPriv);
    const myEKPriv_x = sodium.crypto_sign_ed25519_sk_to_curve25519(myEKPriv);
    const recipientIKPub_x = sodium.crypto_sign_ed25519_pk_to_curve25519(recipientIKPub);
    const recipientSPKPub_x = sodium.crypto_sign_ed25519_pk_to_curve25519(recipientSPKPub);
    const recipientOPKPub_x = sodium.crypto_sign_ed25519_pk_to_curve25519(recipientOPKPub);

    console.log('Sender - Converted keys:', {
      myIKPriv_x: {
        length: myIKPriv_x.length,
        hex: Array.from(myIKPriv_x).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      myEKPriv_x: {
        length: myEKPriv_x.length,
        hex: Array.from(myEKPriv_x).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      recipientIKPub_x: {
        length: recipientIKPub_x.length,
        hex: Array.from(recipientIKPub_x).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      recipientSPKPub_x: {
        length: recipientSPKPub_x.length,
        hex: Array.from(recipientSPKPub_x).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      recipientOPKPub_x: {
        length: recipientOPKPub_x.length,
        hex: Array.from(recipientOPKPub_x).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      }
    });

    // 3. Perform DHs
    const DH1 = sodium.crypto_scalarmult(myIKPriv_x, recipientSPKPub_x);  // IK * SPK
    const DH2 = sodium.crypto_scalarmult(myEKPriv_x, recipientIKPub_x);  // EK * IK
    const DH3 = sodium.crypto_scalarmult(myEKPriv_x, recipientSPKPub_x);  // EK * SPK
    const DH4 = sodium.crypto_scalarmult(myEKPriv_x, recipientOPKPub_x);  // EK * OPK

    console.log('Sender - DH results:', {
      DH1: {
        length: DH1.length,
        hex: Array.from(DH1).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      DH2: {
        length: DH2.length,
        hex: Array.from(DH2).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      DH3: {
        length: DH3.length,
        hex: Array.from(DH3).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      DH4: {
        length: DH4.length,
        hex: Array.from(DH4).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      }
    });

    // Add this before the concatenation in both functions
    console.log('DH values to concatenate:', {
      DH1_hex: Array.from(DH1).map((b) => (b as number).toString(16).padStart(2, '0')).join(''),
      DH2_hex: Array.from(DH2).map((b) => (b as number).toString(16).padStart(2, '0')).join(''),
      DH3_hex: Array.from(DH3).map((b) => (b as number).toString(16).padStart(2, '0')).join(''),
      DH4_hex: Array.from(DH4).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
    });

    // 4. Concatenate and hash
    const combined = new Uint8Array(DH1.length + DH2.length + DH3.length + DH4.length);
    combined.set(DH1, 0);
    combined.set(DH2, DH1.length);
    combined.set(DH3, DH1.length + DH2.length);
    combined.set(DH4, DH1.length + DH2.length + DH3.length);

    const sharedSecret = sodium.crypto_generichash(32, combined);
    console.log('Sender - Final shared secret:', {
      length: sharedSecret.length,
      hex: Array.from(sharedSecret).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
    });

    return sharedSecret;

  } catch (error: unknown) {
    console.error('Sender - Key conversion error:', error);
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
  senderSPKPub,
  myIKPriv,
  mySPKPriv,
  myOPKPriv,
}: {
  senderEKPub: Uint8Array,
  senderIKPub: Uint8Array,
  senderSPKPub: Uint8Array,
  myIKPriv: Uint8Array,
  mySPKPriv: Uint8Array,
  myOPKPriv: Uint8Array
}): Promise<Uint8Array> {
  try {
    // Convert Ed25519 keys to X25519
    const senderEKPub_x = sodium.crypto_sign_ed25519_pk_to_curve25519(senderEKPub);
    const senderIKPub_x = sodium.crypto_sign_ed25519_pk_to_curve25519(senderIKPub);
    const senderSPKPub_x = sodium.crypto_sign_ed25519_pk_to_curve25519(senderSPKPub);
    
    const myIKPriv_x = sodium.crypto_sign_ed25519_sk_to_curve25519(myIKPriv);
    const mySPKPriv_x = sodium.crypto_sign_ed25519_sk_to_curve25519(mySPKPriv);
    const myOPKPriv_x = sodium.crypto_sign_ed25519_sk_to_curve25519(myOPKPriv);

    console.log('Recipient - Converted keys:', {
      senderEKPub_x: {
        length: senderEKPub_x.length,
        hex: Array.from(senderEKPub_x).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      senderIKPub_x: {
        length: senderIKPub_x.length,
        hex: Array.from(senderIKPub_x).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      senderSPKPub_x: {
        length: senderSPKPub_x.length,
        hex: Array.from(senderSPKPub_x).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      myIKPriv_x: {
        length: myIKPriv_x.length,
        hex: Array.from(myIKPriv_x).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      mySPKPriv_x: {
        length: mySPKPriv_x.length,
        hex: Array.from(mySPKPriv_x).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      myOPKPriv_x: {
        length: myOPKPriv_x.length,
        hex: Array.from(myOPKPriv_x).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      }
    });

    // DH computations - matching sender's operations exactly
    const DH1 = sodium.crypto_scalarmult(mySPKPriv_x, senderIKPub_x);    // SPK * IK (matches IK * SPK)
    const DH2 = sodium.crypto_scalarmult(myIKPriv_x, senderEKPub_x);     // IK * EK (matches EK * IK)
    const DH3 = sodium.crypto_scalarmult(mySPKPriv_x, senderEKPub_x);    // SPK * EK (matches EK * SPK)
    const DH4 = sodium.crypto_scalarmult(myOPKPriv_x, senderEKPub_x);    // OPK * EK (matches EK * OPK)

    console.log('Recipient - DH results:', {
      DH1: {
        length: DH1.length,
        hex: Array.from(DH1).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      DH2: {
        length: DH2.length,
        hex: Array.from(DH2).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      DH3: {
        length: DH3.length,
        hex: Array.from(DH3).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      },
      DH4: {
        length: DH4.length,
        hex: Array.from(DH4).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
      }
    });

    // Add this before the concatenation in both functions
    console.log('DH values to concatenate:', {
      DH1_hex: Array.from(DH1).map((b) => (b as number).toString(16).padStart(2, '0')).join(''),
      DH2_hex: Array.from(DH2).map((b) => (b as number).toString(16).padStart(2, '0')).join(''),
      DH3_hex: Array.from(DH3).map((b) => (b as number).toString(16).padStart(2, '0')).join(''),
      DH4_hex: Array.from(DH4).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
    });

    // Concatenate DH results in the same order as sender
    const concatenated = new Uint8Array(DH1.length + DH2.length + DH3.length + DH4.length);
    concatenated.set(DH1, 0);
    concatenated.set(DH2, DH1.length);
    concatenated.set(DH3, DH1.length + DH2.length);
    concatenated.set(DH4, DH1.length + DH2.length + DH3.length);

    // Generate final shared secret
    const sharedSecret = sodium.crypto_generichash(32, concatenated);
    console.log('Recipient - Final shared secret:', {
      length: sharedSecret.length,
      hex: Array.from(sharedSecret).map((b) => (b as number).toString(16).padStart(2, '0')).join('')
    });

    return sharedSecret;
  } catch (error) {
    console.error('Error in deriveX3DHSharedSecretRecipient:', error);
    throw error;
  }
}

export async function encryptWithAESGCM(key: Uint8Array, data: Uint8Array) {
  await sodium.ready;
  // Use the correct nonce length for XChaCha20-Poly1305 (24 bytes)
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  console.log('Encryption inputs:', {
    keyLength: key.length,
    dataLength: data.length,
    nonceLength: nonce.length
  });
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    data,
    null, // no additional data
    null, // no additional data
    nonce,
    key
  );
  console.log('Encryption outputs:', {
    ciphertextLength: ciphertext.length,
    nonceLength: nonce.length
  });
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

  // Alice (sender) derives shared secret using deriveX3DHSharedSecret
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

  // Bob (recipient) derives shared secret using deriveX3DHSharedSecretRecipient
  const bobSharedSecret = await deriveX3DHSharedSecretRecipient({
    senderEKPub: aliceEphemeral.publicKey,
    senderIKPub: aliceBundle.identity_key,
    senderSPKPub: bobBundle.signed_pre_key,
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

  if (!secretsMatch) {
    throw new Error('X3DH key exchange failed: Shared secrets do not match');
  }

  // Test encryption/decryption with shared secrets
  const testMessage = new TextEncoder().encode('Hello, X3DH!');
  const { ciphertext, nonce } = await encryptWithAESGCM(aliceSharedSecret, testMessage);
  
  try {
    const decrypted = await decryptFile(ciphertext, bobSharedSecret, nonce);
    const decryptedText = new TextDecoder().decode(decrypted);
    console.log('Test message decrypted successfully:', decryptedText);
    console.log('Original message matches decrypted:', decryptedText === 'Hello, X3DH!');
    
    if (decryptedText !== 'Hello, X3DH!') {
      throw new Error('X3DH encryption/decryption test failed: Message mismatch');
    }
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('X3DH encryption/decryption test failed: ' + (error instanceof Error ? error.message : 'Unknown error'));
  }

  // Test with a larger message
  const largeMessage = new TextEncoder().encode('This is a larger test message to verify X3DH works with bigger data. ' + 
    'It includes multiple sentences and special characters: !@#$%^&*()_+{}[]|\\:;"\'<>,.?/~`');
  const { ciphertext: largeCiphertext, nonce: largeNonce } = await encryptWithAESGCM(aliceSharedSecret, largeMessage);
  
  try {
    const decryptedLarge = await decryptFile(largeCiphertext, bobSharedSecret, largeNonce);
    const decryptedLargeText = new TextDecoder().decode(decryptedLarge);
    console.log('Large message test passed:', decryptedLargeText === new TextDecoder().decode(largeMessage));
    
    if (decryptedLargeText !== new TextDecoder().decode(largeMessage)) {
      throw new Error('X3DH large message test failed: Message mismatch');
    }
  } catch (error) {
    console.error('Large message decryption failed:', error);
    throw new Error('X3DH large message test failed: ' + (error instanceof Error ? error.message : 'Unknown error'));
  }

  console.log('All X3DH tests passed successfully!');
  return {
    secretsMatch,
    aliceSharedSecret,
    bobSharedSecret
  };
}

export async function encryptWithPublicKey(
  data: Uint8Array,
  recipientPublicKey: string
): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }> {
  await sodium.ready;
  const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
  const publicKey = sodium.from_base64(recipientPublicKey);
  
  // Generate ephemeral key pair
  const ephemeralKeyPair = sodium.crypto_box_keypair();
  
  // Encrypt the data
  const encrypted = sodium.crypto_box_easy(
    data,
    nonce,
    publicKey,
    ephemeralKeyPair.privateKey
  );
  
  // Combine ephemeral public key with encrypted data
  const combined = new Uint8Array(ephemeralKeyPair.publicKey.length + encrypted.length);
  combined.set(ephemeralKeyPair.publicKey);
  combined.set(encrypted, ephemeralKeyPair.publicKey.length);
  
  return { encrypted: combined, nonce };
}