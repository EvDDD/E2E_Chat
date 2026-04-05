/**
 * crypto.js — E2EE Chat Cryptographic Module
 * Implements all 18 functions from the Function Reference
 * Uses WebCrypto API (runs entirely client-side)
 *
 * Mai Đức Duy — 22127084
 */

'use strict';

// ─────────────────────────────────────────────────────────────
//  Utility helpers
// ─────────────────────────────────────────────────────────────

/** ArrayBuffer → Base64 string */
function bufToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

/** Base64 string → Uint8Array */
function b64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

/** hex string → Uint8Array */
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

/** Uint8Array → hex string */
function bufToHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ─────────────────────────────────────────────────────────────
//  MODULE 2 — Key Management
// ─────────────────────────────────────────────────────────────

/**
 * generateKeyPair(passphrase)
 *
 * INPUT : passphrase : string   — user's passphrase to protect PrivKey
 * OUTPUT: { pubKeyB64, encPrivKey }
 *   pubKeyB64  : string (Base64 SPKI)  — safe to send to server
 *   encPrivKey : string (JSON)         — AES-GCM encrypted blob
 *
 * ALGORITHM:
 *   1. WebCrypto RSA-OAEP 2048-bit keygen
 *   2. Export pubKey as SPKI → Base64
 *   3. Derive AES-256 key from passphrase via PBKDF2 (100,000 iter, SHA-256)
 *   4. Encrypt privKey bytes with AES-256-GCM
 *   5. Pack { salt, iv, ciphertext } as JSON string
 */
async function generateKeyPair(passphrase) {
  // 1. Generate RSA-OAEP 2048-bit key pair
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );

  // 2. Export public key as SPKI Base64
  const pubKeyBuf = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const pubKeyB64 = bufToB64(pubKeyBuf);

  // 3. Derive AES key from passphrase using PBKDF2
  const salt         = crypto.getRandomValues(new Uint8Array(16));
  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    passphraseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  // 4. Export private key and encrypt with AES-GCM
  const privKeyBuf   = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const iv           = crypto.getRandomValues(new Uint8Array(12));
  const encPrivBuf   = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    privKeyBuf
  );

  // 5. Pack into a JSON blob (salt + iv + ciphertext all Base64)
  const encPrivKey = JSON.stringify({
    salt:       bufToB64(salt),
    iv:         bufToB64(iv),
    ciphertext: bufToB64(encPrivBuf)
  });

  return { pubKeyB64, encPrivKey };
}

/**
 * decryptPrivateKey(encPrivKey, passphrase)
 *
 * INPUT : encPrivKey : string (JSON from generateKeyPair)
 *         passphrase : string
 * OUTPUT: privateKey : CryptoKey (extractable=false, in memory only)
 *
 * ALGORITHM: reverse of generateKeyPair steps 3–4
 * Note: AES-GCM auth tag automatically detects tamper — wrong passphrase → throws
 */
async function decryptPrivateKey(encPrivKey, passphrase) {
  const { salt, iv, ciphertext } = JSON.parse(encPrivKey);

  // Re-derive AES key with same PBKDF2 parameters
  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64ToBuf(salt), iterations: 100000, hash: 'SHA-256' },
    passphraseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Decrypt private key bytes
  const privKeyBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBuf(iv) },
    aesKey,
    b64ToBuf(ciphertext)
  );

  // Import as non-extractable CryptoKey — stays in memory only
  return crypto.subtle.importKey(
    'pkcs8',
    privKeyBuf,
    { name: 'RSA-PSS', hash: 'SHA-256' }, // imported for signing
    false,
    ['sign']
  );
}

/**
 * importPublicKeyForEncrypt(pubKeyB64)
 * Import Base64 SPKI public key for RSA-OAEP encryption
 */
async function importPublicKeyForEncrypt(pubKeyB64) {
  return crypto.subtle.importKey(
    'spki',
    b64ToBuf(pubKeyB64),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );
}

/**
 * importPublicKeyForVerify(pubKeyB64)
 * Import Base64 SPKI public key for RSA-PSS signature verification
 */
async function importPublicKeyForVerify(pubKeyB64) {
  return crypto.subtle.importKey(
    'spki',
    b64ToBuf(pubKeyB64),
    { name: 'RSA-PSS', hash: 'SHA-256' },
    false,
    ['verify']
  );
}

/**
 * importPrivateKeyForDecrypt(encPrivKey, passphrase)
 * Returns a CryptoKey usable for RSA-OAEP decryption
 */
async function importPrivateKeyForDecrypt(encPrivKey, passphrase) {
  const { salt, iv, ciphertext } = JSON.parse(encPrivKey);

  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64ToBuf(salt), iterations: 100000, hash: 'SHA-256' },
    passphraseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const privKeyBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBuf(iv) },
    aesKey,
    b64ToBuf(ciphertext)
  );

  return crypto.subtle.importKey(
    'pkcs8',
    privKeyBuf,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt']
  );
}

// ─────────────────────────────────────────────────────────────
//  MODULE 3 — Encryption Pipeline
// ─────────────────────────────────────────────────────────────

/**
 * hashPlaintext(plaintext)
 *
 * INPUT : plaintext : string
 * OUTPUT: H         : string (SHA-256 hex, 64 chars)
 *
 * ALGORITHM: SHA-256(UTF8(plaintext))
 * Used in both encryptMessage and decryptMessage (integrity check)
 */
async function hashPlaintext(plaintext) {
  const msgBytes = new TextEncoder().encode(plaintext);
  const hashBuf  = await crypto.subtle.digest('SHA-256', msgBytes);
  return bufToHex(hashBuf);
}

/**
 * encryptAES(plaintext, K, IV)
 *
 * INPUT : plaintext : string
 *         K         : CryptoKey (AES-CBC 256-bit)
 *         IV        : Uint8Array (16 bytes)
 * OUTPUT: C         : string (Base64 ciphertext)
 *
 * ALGORITHM: AES-256-CBC with automatic PKCS#7 padding
 */
async function encryptAES(plaintext, K, IV) {
  const msgBytes  = new TextEncoder().encode(plaintext);
  const cipherBuf = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: IV },
    K,
    msgBytes
  );
  return bufToB64(cipherBuf);
}

/**
 * encryptRSA(K, receiverPubKey)
 *
 * INPUT : K             : CryptoKey (AES-CBC, raw-exportable)
 *         receiverPubKey: CryptoKey (RSA-OAEP public key)
 * OUTPUT: K'            : string (Base64)
 *
 * ALGORITHM: RSA-OAEP encrypt of raw AES key bytes
 * Only receiver with PrivKey_B can decrypt K'
 */
async function encryptRSA(K, receiverPubKey) {
  const rawKey    = await crypto.subtle.exportKey('raw', K);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    receiverPubKey,
    rawKey
  );
  return bufToB64(encrypted);
}

/**
 * signHash(H, senderPrivKey)
 *
 * INPUT : H           : string (hex hash)
 *         senderPrivKey: CryptoKey (RSA-PSS private key)
 * OUTPUT: S           : string (Base64 signature)
 *
 * ALGORITHM: RSA-PSS with SHA-256, saltLength=32
 * Ensures Authentication + Non-repudiation
 */
async function signHash(H, senderPrivKey) {
  const hashBytes = hexToBuf(H);
  const sigBuf    = await crypto.subtle.sign(
    { name: 'RSA-PSS', saltLength: 32 },
    senderPrivKey,
    hashBytes
  );
  return bufToB64(sigBuf);
}

/**
 * encryptMessage(plaintext, receiverPubKey, senderPrivKey)
 *
 * INPUT : plaintext     : string
 *         receiverPubKey: CryptoKey (RSA-OAEP)
 *         senderPrivKey : CryptoKey (RSA-PSS)
 * OUTPUT: packet = { C, encSessionKey (K'), signature (S), hashValue (H), aesIV (IV) }
 *
 * ALGORITHM: Hybrid encryption pipeline
 *   1. H  = SHA-256(M)
 *   2. K  = random AES-256 key, IV = random 16 bytes
 *   3. C  = AES-256-CBC(K, IV, M)
 *   4. K' = RSA-OAEP(receiverPubKey, K)
 *   5. S  = RSA-PSS(senderPrivKey, H)
 */
async function encryptMessage(plaintext, receiverPubKey, senderPrivKey) {
  // Step 1: hash plaintext before encryption
  const H = await hashPlaintext(plaintext);

  // Step 2: generate ephemeral AES session key + IV
  const K = await crypto.subtle.generateKey(
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt']
  );
  const IV = crypto.getRandomValues(new Uint8Array(16));

  // Step 3: encrypt message content with AES
  const C = await encryptAES(plaintext, K, IV);

  // Step 4: encrypt session key with receiver's RSA public key
  const Kprime = await encryptRSA(K, receiverPubKey);

  // Step 5: sign hash with sender's RSA private key
  const S = await signHash(H, senderPrivKey);

  return {
    ciphertext:    C,
    encSessionKey: Kprime,
    signature:     S,
    hashValue:     H,
    aesIV:         bufToB64(IV)
  };
}

// ─────────────────────────────────────────────────────────────
//  MODULE 5 — Decryption Pipeline
// ─────────────────────────────────────────────────────────────

/**
 * decryptRSA(K_enc, receiverPrivKey)
 *
 * INPUT : K_enc         : string (Base64)
 *         receiverPrivKey: CryptoKey (RSA-OAEP private key)
 * OUTPUT: K             : CryptoKey (AES-CBC 256-bit)
 *
 * ALGORITHM: RSA-OAEP decrypt → import as AES key
 */
async function decryptRSA(K_enc, receiverPrivKey) {
  const rawKey = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    receiverPrivKey,
    b64ToBuf(K_enc)
  );
  return crypto.subtle.importKey(
    'raw',
    rawKey,
    { name: 'AES-CBC', length: 256 },
    false,
    ['decrypt']
  );
}

/**
 * decryptAES(C, K, IV)
 *
 * INPUT : C  : string (Base64 ciphertext)
 *         K  : CryptoKey (AES-CBC)
 *         IV : string (Base64)
 * OUTPUT: plaintext : string
 *
 * ALGORITHM: AES-256-CBC decrypt with automatic PKCS#7 unpadding
 */
async function decryptAES(C, K, IV) {
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: b64ToBuf(IV) },
    K,
    b64ToBuf(C)
  );
  return new TextDecoder().decode(plainBuf);
}

/**
 * verifySignature(S, H, senderPubKey)
 *
 * INPUT : S           : string (Base64 signature)
 *         H           : string (hex hash)
 *         senderPubKey: CryptoKey (RSA-PSS public key)
 * OUTPUT: valid       : boolean
 *
 * ALGORITHM: RSA-PSS verify — false means tampered or wrong sender
 */
async function verifySignature(S, H, senderPubKey) {
  return crypto.subtle.verify(
    { name: 'RSA-PSS', saltLength: 32 },
    senderPubKey,
    b64ToBuf(S),
    hexToBuf(H)
  );
}

/**
 * decryptMessage(packet, receiverPrivKey, senderPubKey)
 *
 * INPUT : packet        : { ciphertext, encSessionKey, signature, hashValue, aesIV }
 *         receiverPrivKey: CryptoKey (RSA-OAEP)
 *         senderPubKey  : CryptoKey (RSA-PSS)
 * OUTPUT: { plaintext, isVerified, tamperAlert }
 *
 * ALGORITHM:
 *   1. K  = RSA-OAEP.decrypt(PrivKey_B, K')
 *   2. M  = AES-256-CBC.decrypt(K, IV, C)
 *   3. H' = SHA-256(M)
 *   4. Check H' == H  →  integrity
 *   5. valid = RSA-PSS.verify(PubKey_A, S, H)  →  authentication
 */
async function decryptMessage(packet, receiverPrivKey, senderPubKey) {
  const { ciphertext, encSessionKey, signature, hashValue, aesIV } = packet;

  try {
    // Step 1: recover session key
    const K = await decryptRSA(encSessionKey, receiverPrivKey);

    // Step 2: recover plaintext
    const plaintext = await decryptAES(ciphertext, K, aesIV);

    // Step 3: recompute hash
    const Hcomputed = await hashPlaintext(plaintext);

    // Step 4: integrity check
    const integrityOk = Hcomputed === hashValue;

    // Step 5: signature verification
    const sigValid = await verifySignature(signature, hashValue, senderPubKey);

    const isVerified  = integrityOk && sigValid;
    const tamperAlert = !isVerified;

    return {
      plaintext:   isVerified ? plaintext : null,
      isVerified,
      tamperAlert,
      integrityOk,
      sigValid
    };
  } catch (err) {
    // Decryption failure = tamper or wrong key
    return {
      plaintext:   null,
      isVerified:  false,
      tamperAlert: true,
      integrityOk: false,
      sigValid:    false,
      error:       err.message
    };
  }
}

// Export all functions
window.E2EE = {
  generateKeyPair,
  decryptPrivateKey,
  importPublicKeyForEncrypt,
  importPublicKeyForVerify,
  importPrivateKeyForDecrypt,
  hashPlaintext,
  encryptAES,
  encryptRSA,
  signHash,
  encryptMessage,
  decryptRSA,
  decryptAES,
  verifySignature,
  decryptMessage,
  // utils
  bufToB64,
  b64ToBuf
};
