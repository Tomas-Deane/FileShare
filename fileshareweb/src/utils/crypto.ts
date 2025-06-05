import sodium from 'libsodium-wrappers-sumo';
import nacl from 'tweetnacl';
import { createHmac } from 'crypto';

// --------------------------------------------------------------------------------
// 1. TYPES & ERRORS
// --------------------------------------------------------------------------------

declare global {
  interface Window {
    crypto: Crypto;
    runX3DHTest: () => Promise<void>;
  }
}

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

// --------------------------------------------------------------------------------
// 3. SALT & PDK (Argon2id)
// --------------------------------------------------------------------------------

export async function generateSalt(): Promise<Uint8Array> {
  try {
    await initSodium();
    // 16‐byte (128‐bit) salt for Argon2id
    return sodium.randombytes_buf(16);
  } catch (err) {
    throw new CryptoError('Failed to generate salt', err);
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
  } catch (err) {
    throw new CryptoError('Failed to derive PDK', err);
  }
}

// --------------------------------------------------------------------------------
// 4. ASYMMETRIC KEY GENERATION & EN/DECRYPTION
// --------------------------------------------------------------------------------

export async function generateKeyPair(): Promise<KeyPair> {
  try {
    await initSodium();
    const kp = sodium.crypto_sign_keypair();
    return { publicKey: kp.publicKey, privateKey: kp.privateKey };
  } catch (err) {
    throw new CryptoError('Failed to generate key pair', err);
  }
}

export async function generateKEK(): Promise<Uint8Array> {
  try {
    await initSodium();
    // Generate 256-bit (32-byte) KEK using libsodium's CSPRNG
    return sodium.randombytes_buf(32);
  } catch (err) {
    throw new CryptoError('Failed to generate KEK', err);
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
      null,
      null,
      nonce,
      pdk
    );
    return { encryptedPrivateKey: encrypted, nonce };
  } catch (err) {
    throw new CryptoError('Failed to encrypt private key', err);
  }
}

export async function decryptPrivateKey(
  encryptedPrivateKey: Uint8Array,
  pdk: Uint8Array,
  nonce: Uint8Array
): Promise<Uint8Array> {
  try {
    await initSodium();
    const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      encryptedPrivateKey,
      null,
      nonce,
      pdk
    );
    if (!decrypted) throw new Error('Decryption returned null');
    return decrypted;
  } catch (err) {
    throw new CryptoError('Failed to decrypt private key', err);
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
      null,
      null,
      nonce,
      pdk
    );
    return { encryptedPrivateKey: encrypted, nonce };
  } catch (err) {
    throw new CryptoError('Failed to encrypt KEK', err);
  }
}

export async function decryptKEK(
  encryptedKek: Uint8Array,
  pdk: Uint8Array,
  nonce: Uint8Array
): Promise<Uint8Array> {
  try {
    await initSodium();
    const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      encryptedKek,
      null,
      nonce,
      pdk
    );
    if (!decrypted) throw new Error('Decryption returned null');
    return decrypted;
  } catch (err) {
    throw new CryptoError('Failed to decrypt KEK', err);
  }
}

export async function signChallenge(
  challenge: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  try {
    await initSodium();
    return sodium.crypto_sign_detached(challenge, privateKey);
  } catch (err) {
    throw new CryptoError('Failed to sign challenge', err);
  }
}

export async function generateFileKey(): Promise<Uint8Array> {
  const key = new Uint8Array(32);
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
    null,
    null,
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
  const decrypted = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    encrypted,
    null,
    nonce,
    key
  );
  if (!decrypted) throw new Error('File decryption returned null');
  return decrypted;
}

// --------------------------------------------------------------------------------
// 6. X3DH KEY BUNDLE GENERATION (FOLLOWING SIGNAL'S PATTERN)
// --------------------------------------------------------------------------------

/**
 * 1. Generate an Ed25519 identity keypair (32-byte pub, 64-byte priv).
 * 2. Derive X25519 identity keypair from Ed25519 (so you can do DH).
 * 3. Generate an X25519 SPK (SIDPreKey), sign its public half using Ed25519 private.
 * 4. Generate N one-time X25519 prekeys.
 *
 * Return value includes:
 *   • identityEd25519Public  (to publish as "pubIK")
 *   • identityEd25519Private (only stored client-side, never sent)
 *   • identityX25519Public   (for X25519 DH)
 *   • identityX25519Private  (for X25519 DH)
 *   • signedPreKeyX25519Public
 *   • signedPreKeyX25519Private
 *   • signedPreKeySignature   (Ed25519 signature over SPK_pub)
 *   • oneTimePreKeysX25519    (array of X25519 pub keys)
 *   • oneTimePreKeysX25519Private (array of X25519 priv keys)
 */
export interface X3DHKeyBundle {
  identityEd25519Public:  Uint8Array;
  identityEd25519Private: Uint8Array;
  identityX25519Public:   Uint8Array;
  identityX25519Private:  Uint8Array;

  signedPreKeyX25519Public:  Uint8Array;
  signedPreKeyX25519Private: Uint8Array;
  signedPreKeySignature:     Uint8Array;

  oneTimePreKeysX25519:        Uint8Array[];
  oneTimePreKeysX25519Private: Uint8Array[];
}

export async function generateX3DHKeys(): Promise<X3DHKeyBundle> {
  await initSodium();

  // 1) Create an Ed25519 identity keypair
  const ed25519KP = sodium.crypto_sign_keypair();
  const identityEd25519Public  = ed25519KP.publicKey;   // 32 bytes
  const identityEd25519Private = ed25519KP.privateKey;  // 64 bytes

  // 2) Convert Ed25519 → X25519 for all DH usage
  //    (libsodium provides helper functions)
  const identityX25519Private = sodium.crypto_sign_ed25519_sk_to_curve25519(
    identityEd25519Private  // Pass the full 64-byte key
  ); // 32 bytes
  const identityX25519Public = sodium.crypto_sign_ed25519_pk_to_curve25519(
    identityEd25519Public
  ); // 32 bytes

  // 3) Generate an X25519 Signed Pre-Key (SPK)
  //    We'll use TweetNaCl's box.keyPair() (which is X25519 under the hood)
  const spkKP = nacl.box.keyPair();
  const signedPreKeyX25519Public  = spkKP.publicKey;    // 32 bytes
  const signedPreKeyX25519Private = spkKP.secretKey;    // 32 bytes

  // 3a) Sign the SPK public with Ed25519 identity-private
  //     (so others can verify that this SPK belongs to your Ed25519 identity)
  const signedPreKeySignature = nacl.sign.detached(
    signedPreKeyX25519Public,
    identityEd25519Private  // Use the full 64-byte private key for signing
  ); // 64 bytes

  // 4) Generate a batch of one-time X25519 prekeys
  const numOPKs = 100;
  const oneTimePreKeysX25519: Uint8Array[] = [];
  const oneTimePreKeysX25519Private: Uint8Array[] = [];
  for (let i = 0; i < numOPKs; i++) {
    const opkPair = nacl.box.keyPair(); // curve25519
    oneTimePreKeysX25519.push(opkPair.publicKey);
    oneTimePreKeysX25519Private.push(opkPair.secretKey);
  }

  return {
    identityEd25519Public,
    identityEd25519Private,
    identityX25519Public,
    identityX25519Private,

    signedPreKeyX25519Public,
    signedPreKeyX25519Private,
    signedPreKeySignature,

    oneTimePreKeysX25519,
    oneTimePreKeysX25519Private
  };
}

// --------------------------------------------------------------------------------
// 7. X3DH SHARED SECRET (SENDER & RECIPIENT)
// --------------------------------------------------------------------------------

/**
 * HKDF-SHA256 (single-block expand).  outputLength ≤ 32.
 */
async function hkdfSha256(
  salt: Uint8Array,
  ikm: Uint8Array,
  outputLength: number
): Promise<Uint8Array> {
  // 1) Extract: PRK = HMAC-SHA256(salt, ikm)
  const key = await window.crypto.subtle.importKey(
    'raw',
    salt,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const prkBuffer = await window.crypto.subtle.sign('HMAC', key, ikm);
  const prk = new Uint8Array(prkBuffer);

  // 2) Expand (single-block): T = HMAC-SHA256(PRK, 0x01)
  const infoAndCounter = new Uint8Array([0x01]);
  const expandKey = await window.crypto.subtle.importKey(
    'raw',
    prk,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const okmBuffer = await window.crypto.subtle.sign('HMAC', expandKey, infoAndCounter);
  const okm = new Uint8Array(okmBuffer);
  return okm.slice(0, outputLength);
}

/**
 * Sender-side X3DH:
 *   • myEd25519Priv    = your Ed25519 identity private (64 bytes)
 *   • myX25519IKPriv   = your X25519 identity private (derived above)
 *   • myEKPriv         = your ephemeral X25519 private (generate fresh via nacl.box.keyPair())
 *   • theirIKEd25519Pub = recipient's Ed25519 identity public
 *   • theirSPKPub      = recipient's X25519 SPK public
 *   • theirSPKSignature = signature over theirSPKPub by their Ed25519 identity pub
 *   • theirOPKPub?     = (optional) recipient's one-time X25519 prekey
 *
 * 1) Verify theirSPKPub signature using nacl.sign.detached.verify( theirSPKPub, theirSPKSignature, theirIKEd25519Pub ).
 * 2) Convert theirIKEd25519Pub → theirIKX25519Pub via sodium.crypto_sign_ed25519_pk_to_curve25519.
 * 3) Do DHs:
 *      dh1 = ECDH(myX25519IKPriv,  theirSPKPub)
 *      dh2 = ECDH(myEKPriv,        theirIKX25519Pub)
 *      dh3 = ECDH(myEKPriv,        theirSPKPub)
 *      dh4 = ECDH(myEKPriv,        theirOPKPub) // or zeros if no OPK
 * 4) Concat dh1 ∥ dh2 ∥ dh3 ∥ dh4 → 128 bytes, then HKDF-SHA256(zeroSalt, concat, 32).
 *
 * Returns { sharedSecret, ekPub } where ekPub = nacl.scalarMult.base(myEKPriv).
 */
export async function deriveX3DHSharedSecret({
  myEd25519Priv,     // 64 bytes
  myEKPriv,          // 32 bytes (ephemeral)
  theirIKEd25519Pub, // 32 bytes
  theirSPKPub,       // 32 bytes
  theirSPKSignature, // 64 bytes
  theirOPKPub,       // optional 32 bytes
}: {
  myEd25519Priv: Uint8Array;
  myEKPriv: Uint8Array;
  theirIKEd25519Pub: Uint8Array;
  theirSPKPub: Uint8Array;
  theirSPKSignature: Uint8Array;
  theirOPKPub?: Uint8Array;
}): Promise<{ sharedSecret: Uint8Array; ekPub: Uint8Array }> {
  await initSodium();

  console.log('deriveX3DHSharedSecret input key sizes:', {
    myEd25519Priv: myEd25519Priv.length,
    myEKPriv: myEKPriv.length,
    theirIKEd25519Pub: theirIKEd25519Pub.length,
    theirSPKPub: theirSPKPub.length,
    theirSPKSignature: theirSPKSignature.length,
    theirOPKPub: theirOPKPub?.length
  });

  // 1) Verify SPK signature
  console.log('Verifying SPK signature...');
  const valid = nacl.sign.detached.verify(
    theirSPKPub,
    theirSPKSignature,
    theirIKEd25519Pub
  );
  if (!valid) {
    throw new Error("Invalid SPK signature: cannot verify sender's SPK");
  }
  console.log('SPK signature verified successfully');

  // 2) Convert their Ed25519 IK → X25519 IK
  console.log('Converting their Ed25519 IK to X25519...');
  const theirX25519IKPub = sodium.crypto_sign_ed25519_pk_to_curve25519(
    theirIKEd25519Pub
  );
  console.log('Their X25519 IK pub length:', theirX25519IKPub.length);

  // 3) Convert our Ed25519 private key to X25519 private key
  console.log('Converting our Ed25519 private key to X25519...');
  console.log('Our Ed25519 private key length:', myEd25519Priv.length);
  let myX25519IKPriv: Uint8Array;
  try {
    myX25519IKPriv = sodium.crypto_sign_ed25519_sk_to_curve25519(
      myEd25519Priv
    );
    console.log('Our X25519 private key length:', myX25519IKPriv.length);
  } catch (err) {
    console.error('Error converting Ed25519 to X25519:', err);
    console.error('Ed25519 private key (first 10 bytes):', 
      Array.from(myEd25519Priv.slice(0, 10)).map(b => b.toString(16).padStart(2, '0')).join('')
    );
    throw err;
  }

  // 4) Perform the four DHs
  console.log('Performing DH operations...');
  const dh1 = nacl.scalarMult(myX25519IKPriv, theirSPKPub);
  const dh2 = nacl.scalarMult(myEKPriv, theirX25519IKPub);
  const dh3 = nacl.scalarMult(myEKPriv, theirSPKPub);
  const dh4 = nacl.scalarMult(
    myEKPriv,
    theirOPKPub || new Uint8Array(32)
  );
  console.log('DH results lengths:', {
    dh1: dh1.length,
    dh2: dh2.length,
    dh3: dh3.length,
    dh4: dh4.length
  });

  // 5) Concat and HKDF
  console.log('Concatenating DH results and running HKDF...');
  const concatDH = new Uint8Array(32 * 4);
  concatDH.set(dh1, 0);
  concatDH.set(dh2, 32);
  concatDH.set(dh3, 64);
  concatDH.set(dh4, 96);
  console.log('Concatenated DH length:', concatDH.length);

  const zeroSalt = new Uint8Array(32);
  const sharedSecret = await hkdfSha256(zeroSalt, concatDH, 32);
  console.log('Generated shared secret length:', sharedSecret.length);

  // 6) Reconstruct EK public
  console.log('Reconstructing EK public key...');
  const ekPub = nacl.scalarMult.base(myEKPriv);
  console.log('EK public key length:', ekPub.length);

  return { sharedSecret, ekPub };
}

/**
 * Recipient-side X3DH:
 *   • myEd25519IKPriv   = your Ed25519 identity private (64 bytes)
 *   • myX25519IKPriv    = your X25519 identity private (32 bytes)
 *   • mySPKPriv         = your X25519 SPK private (32 bytes)
 *   • myOPKPriv?        = your one-time X25519 prekey private (32 bytes or undefined)
 *   • theirIKEd25519Pub = sender's Ed25519 identity public
 *   • theirSPKPub       = sender's X25519 SPK public
 *   • theirEKPub        = sender's ephemeral EK public (32 bytes)
 *
 * 1) Convert your Ed25519 IK → your X25519 IK (if not already done).
 * 2) Optionally verify that the SPKPub you saw is signed by sender's Ed25519 IK. (Usually done client-side at fetch time.)
 * 3) Perform DHs:
 *      dh1 = ECDH(mySPKPriv,  theirIKX25519Pub)
 *      dh2 = ECDH(myX25519IKPriv,  theirEKPub)
 *      dh3 = ECDH(mySPKPriv,  theirEKPub)
 *      dh4 = ECDH(myOPKPriv,  theirEKPub)
 * 4) Concat and HKDF
 */
export async function deriveX3DHSharedSecretRecipient({
  myEd25519IKPriv,  // 64 bytes
  myX25519IKPriv,   // 32 bytes
  mySPKPriv,        // 32 bytes
  myOPKPriv,        // optional 32 bytes
  theirIKEd25519Pub,// 32 bytes
  theirSPKPub,      // 32 bytes
  theirEKPub,       // 32 bytes
}: {
  myEd25519IKPriv: Uint8Array;
  myX25519IKPriv: Uint8Array;
  mySPKPriv: Uint8Array;
  myOPKPriv?: Uint8Array;
  theirIKEd25519Pub: Uint8Array;
  theirSPKPub: Uint8Array;
  theirEKPub: Uint8Array;
}): Promise<Uint8Array> {
  await initSodium();

  // 1) (Optional) Verify SPKPub signature using their Ed25519 IK
  //    [We assume sender did this; but you could re-verify here if you like.]

  // 2) Derive their IK X25519
  const theirX25519IKPub = sodium.crypto_sign_ed25519_pk_to_curve25519(
    theirIKEd25519Pub
  );

  // 3) Perform the four DHs
  const dh1 = nacl.scalarMult(mySPKPriv, theirX25519IKPub);
  const dh2 = nacl.scalarMult(myX25519IKPriv, theirEKPub);
  const dh3 = nacl.scalarMult(mySPKPriv, theirEKPub);
  const dh4 = nacl.scalarMult(
    myOPKPriv || new Uint8Array(32),
    theirEKPub
  );

  // 4) Concat + HKDF
  const concatDH = new Uint8Array(32 * 4);
  concatDH.set(dh1, 0);
  concatDH.set(dh2, 32);
  concatDH.set(dh3, 64);
  concatDH.set(dh4, 96);

  const zeroSalt = new Uint8Array(32);
  return await hkdfSha256(zeroSalt, concatDH, 32);
}

// --------------------------------------------------------------------------------
// 8. X3DH UNIT TEST (OPTIONAL)
// --------------------------------------------------------------------------------

export async function testX3DH(): Promise<void> {
  console.log('--- Starting X3DH Key Exchange Test ---');

  // Alice's bundle
  const aliceBundle = await generateX3DHKeys();
  // Bob's bundle
  const bobBundle = await generateX3DHKeys();

  // Alice's ephemeral (EK)
  const aliceEK = nacl.box.keyPair(); // X25519

  // Alice derives shared secret
  const { sharedSecret: aliceSS, ekPub: aliceEKPub } =
    await deriveX3DHSharedSecret({
      myEd25519Priv: aliceBundle.identityEd25519Private,
      myEKPriv: aliceEK.secretKey,
      theirIKEd25519Pub: bobBundle.identityEd25519Public,
      theirSPKPub: bobBundle.signedPreKeyX25519Public,
      theirSPKSignature: bobBundle.signedPreKeySignature,
      theirOPKPub: bobBundle.oneTimePreKeysX25519[0],
    });

  console.log('Alice shared secret (hex):',
    Array.from(aliceSS).map(b => b.toString(16).padStart(2, '0')).join('')
  );

  // Bob derives shared secret
  const bobSS = await deriveX3DHSharedSecretRecipient({
    myEd25519IKPriv: bobBundle.identityEd25519Private,
    myX25519IKPriv: bobBundle.identityX25519Private,
    mySPKPriv: bobBundle.signedPreKeyX25519Private,
    myOPKPriv: bobBundle.oneTimePreKeysX25519Private[0],
    theirIKEd25519Pub: aliceBundle.identityEd25519Public,
    theirSPKPub: aliceBundle.signedPreKeyX25519Public,
    theirEKPub: aliceEKPub,
  });

  console.log('Bob shared secret (hex):',
    Array.from(bobSS).map(b => b.toString(16).padStart(2, '0')).join('')
  );

  const match = aliceSS.length === bobSS.length &&
    aliceSS.every((b, i) => b === bobSS[i]);

  console.log('Do they match? →', match ? '✅ yes' : '❌ no');
  if (!match) throw new Error('X3DH failed: Shared secrets differ');

  // Quick encrypt/decrypt test using the shared secret as a file key:
  const testMessage = new TextEncoder().encode('Hello, X3DH!');
  const { encrypted, nonce } = await encryptWithXChaCha20Poly(aliceSS, testMessage);
  const decrypted = await decryptFile(encrypted, bobSS, nonce);
  const plaintext = new TextDecoder().decode(decrypted);
  console.log('Decrypted text:', plaintext);
  if (plaintext !== 'Hello, X3DH!') {
    throw new Error('Encrypt/Decrypt test failed');
  }

  console.log('✅ X3DH test passed successfully!');
}

// --------------------------------------------------------------------------------
// 9. OPTIONAL: ENCRYPT WITH SOMEONE'S ED25519-SIGNED X25519 PUBLIC KEY
//    (e.g., "encryptWithPublicKey" that bundles ephemeral key + box_easy)
// --------------------------------------------------------------------------------

export async function encryptWithPublicKey(
  data: Uint8Array,
  recipientEd25519Pub_b64: string
): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }> {
  await sodium.ready;

  // 1) Decode their Ed25519 public from base64
  const theirEd25519Pub = sodium.from_base64(recipientEd25519Pub_b64);

  // 2) Convert Ed25519→X25519 public
  const theirX25519Pub = sodium.crypto_sign_ed25519_pk_to_curve25519(
    theirEd25519Pub
  );

  // 3) Generate ephemeral keypair for NaCl box
  const ephKP = nacl.box.keyPair();
  const nonce = sodium.randombytes_buf(nacl.box.nonceLength);

  // 4) Encrypt using NaCl.box
  const ciphertext = nacl.box(
    data,
    nonce,
    theirX25519Pub,
    ephKP.secretKey
  );

  // 5) Prepend ephemeral public key so the recipient can reconstruct
  const combined = new Uint8Array(ephKP.publicKey.length + ciphertext.length);
  combined.set(ephKP.publicKey, 0);
  combined.set(ciphertext, ephKP.publicKey.length);

  return { encrypted: combined, nonce };
}


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

// Generate an ephemeral X25519 key pair (for use in X3DH, etc.)
export function generateEphemeralKeyPair() {
  return nacl.box.keyPair();
}

// Encrypt data with XChaCha20-Poly1305 (explicit name for clarity)
export async function encryptWithXChaCha20Poly(
  key: Uint8Array,
  data: Uint8Array
): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }> {
  await sodium.ready;
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const encrypted = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    data,
    null,
    null,
    nonce,
    key
  );
  return { encrypted, nonce };
}

