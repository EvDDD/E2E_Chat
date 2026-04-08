const express = require('express');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
router.use(requireAuth);

// ─────────────────────────────────────────────
//  POST /api/keys
//  Store RSA key pair generated on client
//  Body: { publicKey, privateKey (AES-encrypted) }
// ─────────────────────────────────────────────
router.post('/', (req, res) => {
  const { publicKey, privateKey } = req.body;
  const { userID } = req.user;

  if (!publicKey || !privateKey) {
    return res.status(400).json({ error: 'publicKey và privateKey là bắt buộc' });
  }

  // Revoke any existing active key before inserting new one
  db.prepare(
    "UPDATE key_pairs SET status='revoked', revokedAt=datetime('now'), revokedReason='replaced' WHERE userID=? AND status='active'"
  ).run(userID);

  // Insert new key pair — privateKey is already AES-GCM encrypted by client
  const result = db.prepare(`
    INSERT INTO key_pairs (userID, publicKey, privateKey, status)
    VALUES (?, ?, ?, 'active')
  `).run(userID, publicKey, privateKey);

  res.status(201).json({
    keyID: result.lastInsertRowid,
    status: 'stored',
    message: 'Cặp khóa RSA đã được lưu'
  });
});

// ─────────────────────────────────────────────
//  GET /api/keys/me
//  Get current user's active key info
// ─────────────────────────────────────────────
router.get('/me', (req, res) => {
  const key = db.prepare(
    "SELECT keyID, publicKey, privateKey, createdAt FROM key_pairs WHERE userID=? AND status='active'"
  ).get(req.user.userID);

  if (!key) return res.status(404).json({ error: 'Chưa có khóa' });
  res.json(key);
});

// ─────────────────────────────────────────────
//  GET /api/keys/user/:userID
//  Get another user's active PUBLIC key only
//  (private key is never exposed to other users)
// ─────────────────────────────────────────────
router.get('/user/:targetID', (req, res) => {
  const targetID = parseInt(req.params.targetID);

  const key = db.prepare(
    "SELECT keyID, publicKey, createdAt FROM key_pairs WHERE userID=? AND status='active'"
  ).get(targetID);

  if (!key) return res.status(404).json({ error: 'Người dùng chưa có khóa' });

  // Only return PUBLIC key — never expose private key to other users
  res.json({ keyID: key.keyID, publicKey: key.publicKey, createdAt: key.createdAt });
});

// ─────────────────────────────────────────────
//  POST /api/keys/revoke
//  Revoke current active key
//  Body: { reason? }
// ─────────────────────────────────────────────
router.post('/revoke', (req, res) => {
  const { reason } = req.body;
  const { userID } = req.user;

  const result = db.prepare(`
    UPDATE key_pairs
    SET status='revoked', revokedAt=datetime('now'), revokedReason=?
    WHERE userID=? AND status='active'
  `).run(reason || 'user_requested', userID);

  if (result.changes === 0) {
    return res.status(404).json({ error: 'Không có khóa active để thu hồi' });
  }
  res.json({ message: 'Khóa đã bị thu hồi. Hãy tạo cặp khóa mới.' });
});

// ─────────────────────────────────────────────
//  GET /api/keys/history
//  Get key history for current user
// ─────────────────────────────────────────────
router.get('/history', (req, res) => {
  const keys = db.prepare(`
    SELECT keyID, status, algorithm, keySize, createdAt, revokedAt, revokedReason
    FROM key_pairs WHERE userID=? ORDER BY createdAt DESC
  `).all(req.user.userID);
  res.json(keys);
});

// ─────────────────────────────────────────────
//  GET /api/keys/all
//  Get ALL key pairs for current user (active + revoked)
//  Returns encrypted private key so client can decrypt old messages
// ─────────────────────────────────────────────
router.get('/all', (req, res) => {
  const keys = db.prepare(`
    SELECT keyID, publicKey, privateKey, status, createdAt, revokedAt
    FROM key_pairs WHERE userID=? ORDER BY createdAt DESC
  `).all(req.user.userID);
  res.json(keys);
});

// ─────────────────────────────────────────────
//  GET /api/keys/user/:userID/public-all
//  Get ALL public keys (active + revoked) for a user
//  Used to verify signatures on old messages after key rotation
//  Only returns public keys — private keys are never exposed
// ─────────────────────────────────────────────
router.get('/user/:targetID/public-all', (req, res) => {
  const targetID = parseInt(req.params.targetID);
  const keys = db.prepare(`
    SELECT keyID, publicKey, status, createdAt
    FROM key_pairs WHERE userID=? ORDER BY createdAt DESC
  `).all(targetID);
  res.json(keys);
});

module.exports = router;
