const express = require('express');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
router.use(requireAuth);

// Socket registry is set by server.js after boot
let socketRegistry = null;
router.setSocketRegistry = (registry) => { socketRegistry = registry; };

// ─────────────────────────────────────────────
//  POST /api/messages
//  Send an encrypted message
//  Body: { receiverID, ciphertext, encSessionKey, signature, hashValue, aesIV, receiverKeyID }
// ─────────────────────────────────────────────
router.post('/', (req, res) => {
  const { senderID: _s, ...rest } = req.body; // ignore any senderID from body
  const senderID = req.user.userID;
  const {
    receiverID, ciphertext, encSessionKey, senderEncSessionKey,
    signature, hashValue, aesIV, receiverKeyID
  } = req.body;

  // 1. Validate required fields
  if (!receiverID || !ciphertext || !encSessionKey || !signature || !hashValue || !aesIV || !receiverKeyID) {
    return res.status(400).json({ error: 'Thiếu trường bắt buộc trong gói tin' });
  }
  if (senderID === parseInt(receiverID)) {
    return res.status(400).json({ error: 'Không thể gửi tin nhắn cho chính mình' });
  }

  // 2. Get sender's active key for senderKeyID
  const senderKey = db.prepare(
    "SELECT keyID FROM key_pairs WHERE userID=? AND status='active'"
  ).get(senderID);
  if (!senderKey) {
    return res.status(403).json({ error: 'Sender chưa có khóa active' });
  }

  // 3. Verify receiverKeyID exists and belongs to receiver
  const receiverKey = db.prepare(
    'SELECT keyID FROM key_pairs WHERE keyID=? AND userID=?'
  ).get(receiverKeyID, receiverID);
  if (!receiverKey) {
    return res.status(400).json({ error: 'receiverKeyID không hợp lệ' });
  }

  // 4. Persist to Message Store — server stores encrypted packet, cannot read content
  const result = db.prepare(`
    INSERT INTO messages
      (senderID, receiverID, senderKeyID, receiverKeyID,
       ciphertext, encSessionKey, senderEncSessionKey, signature, hashValue, aesIV, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'sent')
  `).run(senderID, receiverID, senderKey.keyID, receiverKeyID,
         ciphertext, encSessionKey, senderEncSessionKey || null,
         signature, hashValue, aesIV);

  const messageID = result.lastInsertRowid;

  // 5. Real-time delivery via Socket.IO
  let delivered = false;
  if (socketRegistry) {
    const receiverSocket = socketRegistry.get(parseInt(receiverID));
    if (receiverSocket) {
      receiverSocket.emit('new_message', {
        messageID, senderID, receiverID,
        ciphertext, encSessionKey, signature, hashValue, aesIV,
        senderKeyID: senderKey.keyID, receiverKeyID,
        timestamp: new Date().toISOString()
        // Note: senderEncSessionKey is NOT sent to receiver — only sender needs it
      });
      db.prepare(
        "UPDATE messages SET status='delivered' WHERE messageID=?"
      ).run(messageID);
      delivered = true;
    }
  }

  res.status(201).json({
    messageID,
    status: delivered ? 'delivered' : 'sent'
  });
});

// ─────────────────────────────────────────────
//  GET /api/messages/:contactID
//  Load conversation history (paginated)
//  Query: ?page=1&limit=20
// ─────────────────────────────────────────────
router.get('/:contactID', (req, res) => {
  const myID      = req.user.userID;
  const contactID = parseInt(req.params.contactID);
  const page      = Math.max(1, parseInt(req.query.page) || 1);
  const limit     = Math.min(50, parseInt(req.query.limit) || 20);
  const offset    = (page - 1) * limit;

  const messages = db.prepare(`
    SELECT
      m.messageID, m.senderID, m.receiverID,
      m.senderKeyID, m.receiverKeyID,
      m.ciphertext, m.encSessionKey, m.senderEncSessionKey,
      m.signature, m.hashValue, m.aesIV,
      m.timestamp, m.status, m.sigVerified, m.tamperAlert
    FROM messages m
    WHERE (m.senderID=? AND m.receiverID=?)
       OR (m.senderID=? AND m.receiverID=?)
    ORDER BY m.timestamp DESC, m.messageID DESC
    LIMIT ? OFFSET ?
  `).all(myID, contactID, contactID, myID, limit, offset);

  // Mark fetched messages as delivered if receiver is fetching
  const undeliveredIDs = messages
    .filter(m => m.receiverID === myID && m.status === 'sent')
    .map(m => m.messageID);

  if (undeliveredIDs.length > 0) {
    const placeholders = undeliveredIDs.map(() => '?').join(',');
    db.prepare(
      `UPDATE messages SET status='delivered' WHERE messageID IN (${placeholders})`
    ).run(...undeliveredIDs);
  }

  res.json({
    messages: messages.reverse(), // chronological order
    page,
    limit,
    hasMore: messages.length === limit
  });
});

// ─────────────────────────────────────────────
//  PATCH /api/messages/:messageID/verify
//  Client reports verification result after decryption
//  Body: { sigVerified, tamperAlert }
// ─────────────────────────────────────────────
router.patch('/:messageID/verify', (req, res) => {
  const { sigVerified, tamperAlert } = req.body;
  const { messageID } = req.params;
  const myID = req.user.userID;

  // Only receiver can report verification
  const msg = db.prepare(
    'SELECT receiverID, sigVerified, tamperAlert FROM messages WHERE messageID=?'
  ).get(messageID);
  if (!msg || msg.receiverID !== myID) {
    return res.status(403).json({ error: 'Không có quyền' });
  }

  // Always update — especially important when tamperAlert is newly detected
  // even if message was previously marked as verified
  db.prepare(`
    UPDATE messages
    SET sigVerified=?, tamperAlert=?, status='read'
    WHERE messageID=?
  `).run(sigVerified ? 1 : 0, tamperAlert ? 1 : 0, messageID);

  res.json({ updated: true });
});

module.exports = router;
