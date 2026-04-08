const express = require('express');
const db = require('../db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();
router.use(requireAuth);

let socketRegistry = null;
router.setSocketRegistry = (r) => { socketRegistry = r; };

// GET /api/contacts — accepted contacts only
router.get('/', (req, res) => {
  const myID = req.user.userID;
  const contacts = db.prepare(`
    SELECT c.contactID, c.contactUserID, c.cachedKeyID, c.cachedPubKey, c.addedAt,
      u.username, u.displayName, u.status, u.lastSeen,
      kp.keyID AS currentKeyID
    FROM contacts c
    JOIN users u ON u.userID = c.contactUserID
    LEFT JOIN key_pairs kp ON kp.userID = c.contactUserID AND kp.status='active'
    WHERE c.ownerID = ?
    ORDER BY u.username ASC
  `).all(myID);
  res.json(contacts.map(c => ({
    ...c,
    keyMismatch: !!(c.currentKeyID && c.cachedKeyID && c.currentKeyID !== c.cachedKeyID)
  })));
});

// POST /api/contacts/request — send invitation
router.post('/request', (req, res) => {
  const fromUserID = req.user.userID;
  const { toUserID } = req.body;
  if (!toUserID || parseInt(toUserID) === fromUserID)
    return res.status(400).json({ error: 'toUserID không hợp lệ' });

  const target = db.prepare('SELECT userID, username FROM users WHERE userID=?').get(toUserID);
  if (!target) return res.status(404).json({ error: 'Người dùng không tồn tại' });

  const existing = db.prepare('SELECT contactID FROM contacts WHERE ownerID=? AND contactUserID=?').get(fromUserID, toUserID);
  if (existing) return res.status(409).json({ error: 'Đã là liên hệ rồi' });

  const pending = db.prepare("SELECT requestID FROM contact_requests WHERE fromUserID=? AND toUserID=? AND status='pending'").get(fromUserID, toUserID);
  if (pending) return res.status(409).json({ error: 'Lời mời đã được gửi, đang chờ chấp nhận' });

  const result = db.prepare(
    "INSERT INTO contact_requests (fromUserID, toUserID) VALUES (?, ?) ON CONFLICT(fromUserID, toUserID) DO UPDATE SET status='pending', updatedAt=datetime('now')"
  ).run(fromUserID, toUserID);

  const from = db.prepare('SELECT username, displayName FROM users WHERE userID=?').get(fromUserID);
  socketRegistry?.get(parseInt(toUserID))?.emit('contact_request', {
    requestID: result.lastInsertRowid,
    fromUserID, fromUsername: from.username, fromDisplay: from.displayName
  });

  res.status(201).json({ requestID: result.lastInsertRowid, message: `Đã gửi lời mời đến @${target.username}` });
});

// GET /api/contacts/requests/pending — incoming requests
router.get('/requests/pending', (req, res) => {
  const myID = req.user.userID;
  res.json(db.prepare(`
    SELECT cr.requestID, cr.fromUserID, cr.createdAt,
      u.username AS fromUsername, u.displayName AS fromDisplay, u.status AS fromStatus
    FROM contact_requests cr JOIN users u ON u.userID=cr.fromUserID
    WHERE cr.toUserID=? AND cr.status='pending'
    ORDER BY cr.createdAt DESC
  `).all(myID));
});

// GET /api/contacts/requests/sent — outgoing requests
router.get('/requests/sent', (req, res) => {
  const myID = req.user.userID;
  res.json(db.prepare(`
    SELECT cr.requestID, cr.toUserID, cr.status, cr.createdAt,
      u.username AS toUsername, u.displayName AS toDisplay
    FROM contact_requests cr JOIN users u ON u.userID=cr.toUserID
    WHERE cr.fromUserID=?
    ORDER BY cr.createdAt DESC
  `).all(myID));
});

// POST /api/contacts/requests/:id/accept — accept → create BOTH directions
router.post('/requests/:requestID/accept', (req, res) => {
  const myID      = req.user.userID;
  const requestID = parseInt(req.params.requestID);

  const request = db.prepare(
    "SELECT * FROM contact_requests WHERE requestID=? AND toUserID=? AND status='pending'"
  ).get(requestID, myID);
  if (!request) return res.status(404).json({ error: 'Lời mời không tồn tại hoặc đã xử lý' });

  const fromID  = request.fromUserID;
  const myKey   = db.prepare("SELECT keyID, publicKey FROM key_pairs WHERE userID=? AND status='active'").get(myID);
  const fromKey = db.prepare("SELECT keyID, publicKey FROM key_pairs WHERE userID=? AND status='active'").get(fromID);

  // ★ Both directions
  db.prepare('INSERT OR IGNORE INTO contacts (ownerID,contactUserID,cachedKeyID,cachedPubKey) VALUES (?,?,?,?)')
    .run(myID,   fromID, fromKey?.keyID||null, fromKey?.publicKey||null);
  db.prepare('INSERT OR IGNORE INTO contacts (ownerID,contactUserID,cachedKeyID,cachedPubKey) VALUES (?,?,?,?)')
    .run(fromID, myID,   myKey?.keyID||null,   myKey?.publicKey||null);

  db.prepare("UPDATE contact_requests SET status='accepted', updatedAt=datetime('now') WHERE requestID=?").run(requestID);

  const me = db.prepare('SELECT username, displayName FROM users WHERE userID=?').get(myID);
  socketRegistry?.get(fromID)?.emit('contact_accepted', {
    byUserID: myID, byUsername: me.username, byDisplay: me.displayName
  });

  res.json({ message: 'Đã chấp nhận lời mời kết bạn' });
});

// POST /api/contacts/requests/:id/reject
router.post('/requests/:requestID/reject', (req, res) => {
  const myID      = req.user.userID;
  const requestID = parseInt(req.params.requestID);
  const result    = db.prepare(
    "UPDATE contact_requests SET status='rejected', updatedAt=datetime('now') WHERE requestID=? AND toUserID=? AND status='pending'"
  ).run(requestID, myID);
  if (result.changes === 0) return res.status(404).json({ error: 'Lời mời không tồn tại' });
  res.json({ message: 'Đã từ chối lời mời' });
});

// GET /api/contacts/pubkey/:userID
router.get('/pubkey/:targetID', (req, res) => {
  const myID     = req.user.userID;
  const targetID = parseInt(req.params.targetID);
  const currentKey = db.prepare("SELECT keyID, publicKey FROM key_pairs WHERE userID=? AND status='active'").get(targetID);
  if (!currentKey) return res.status(404).json({ error: 'Người dùng chưa có khóa' });
  const contact    = db.prepare('SELECT cachedKeyID, cachedPubKey FROM contacts WHERE ownerID=? AND contactUserID=?').get(myID, targetID);
  const keyChanged = !!(contact && (
    (contact.cachedKeyID && contact.cachedKeyID !== currentKey.keyID) ||
    (contact.cachedPubKey && contact.cachedPubKey !== currentKey.publicKey)
  ));
  if (contact) db.prepare('UPDATE contacts SET cachedKeyID=?,cachedPubKey=? WHERE ownerID=? AND contactUserID=?')
    .run(currentKey.keyID, currentKey.publicKey, myID, targetID);
  res.json({ keyID: currentKey.keyID, publicKey: currentKey.publicKey, keyChanged });
});

// GET /api/contacts/search?q=
router.get('/search', (req, res) => {
  const q    = (req.query.q || '').trim();
  const myID = req.user.userID;
  if (q.length < 2) return res.status(400).json({ error: 'Query phải ít nhất 2 ký tự' });
  res.json(db.prepare(`
    SELECT u.userID, u.username, u.displayName, u.status,
      CASE
        WHEN c.contactID      IS NOT NULL THEN 'contact'
        WHEN cr_out.requestID IS NOT NULL THEN 'request_sent'
        WHEN cr_in.requestID  IS NOT NULL THEN 'request_received'
        ELSE 'none'
      END AS relation
    FROM users u
    LEFT JOIN contacts c             ON c.ownerID=?       AND c.contactUserID=u.userID
    LEFT JOIN contact_requests cr_out ON cr_out.fromUserID=? AND cr_out.toUserID=u.userID AND cr_out.status='pending'
    LEFT JOIN contact_requests cr_in  ON cr_in.toUserID=?  AND cr_in.fromUserID=u.userID  AND cr_in.status='pending'
    WHERE u.username LIKE ? AND u.userID!=?
    LIMIT 20
  `).all(myID, myID, myID, `%${q}%`, myID));
});

// DELETE /api/contacts/:contactUserID
router.delete('/:contactUserID', (req, res) => {
  const myID = req.user.userID;
  const cid  = parseInt(req.params.contactUserID);
  db.prepare('DELETE FROM contacts WHERE ownerID=? AND contactUserID=?').run(myID, cid);
  db.prepare('DELETE FROM contacts WHERE ownerID=? AND contactUserID=?').run(cid, myID);
  res.json({ message: 'Đã xóa liên hệ' });
});

module.exports = router;
