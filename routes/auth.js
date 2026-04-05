const express = require('express');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
const db      = require('../db');
const { JWT_SECRET } = require('../middleware/auth');

const router = express.Router();
const BCRYPT_ROUNDS = 12;
const JWT_EXPIRES   = '24h';

// ─────────────────────────────────────────────
//  POST /api/auth/register
//  Body: { username, email, password, displayName? }
// ─────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { username, email, password, displayName } = req.body;

  // 1. Validate required fields
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'username, email và password là bắt buộc' });
  }
  if (username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: 'username phải từ 3–50 ký tự' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'password phải ít nhất 8 ký tự' });
  }

  // 2. Check uniqueness
  const existingUsername = db.prepare(
    'SELECT userID FROM users WHERE username = ?'
  ).get(username);
  if (existingUsername) {
    return res.status(409).json({ error: 'USERNAME_TAKEN' });
  }

  const existingEmail = db.prepare(
    'SELECT userID FROM users WHERE email = ?'
  ).get(email);
  if (existingEmail) {
    return res.status(409).json({ error: 'EMAIL_EXISTS' });
  }

  try {
    // 3. Hash password — bcrypt embeds salt automatically
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // 4. Insert user
    const insert = db.prepare(`
      INSERT INTO users (username, email, passwordHash, displayName)
      VALUES (?, ?, ?, ?)
    `);
    const result = insert.run(username, email, passwordHash, displayName || username);
    const userID = result.lastInsertRowid;

    // 5. Issue JWT
    const token = jwt.sign({ userID }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    // 6. Return — client will call generateKeyPair after this
    res.status(201).json({
      userID,
      username,
      displayName: displayName || username,
      sessionToken: token,
      message: 'Đăng ký thành công. Hãy tạo cặp khóa RSA.'
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─────────────────────────────────────────────
//  POST /api/auth/login
//  Body: { username, password }
// ─────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username và password là bắt buộc' });
  }

  // 1. Lookup user
  const user = db.prepare(
    'SELECT * FROM users WHERE username = ?'
  ).get(username);
  if (!user) {
    return res.status(401).json({ error: 'USER_NOT_FOUND' });
  }

  try {
    // 2. Verify password — bcrypt extracts embedded salt automatically
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ error: 'WRONG_PASSWORD' });
    }

    // 3. Fetch encrypted private key — server cannot decrypt this
    const keyRow = db.prepare(
      "SELECT keyID, publicKey, privateKey FROM key_pairs WHERE userID = ? AND status = 'active'"
    ).get(user.userID);

    // 4. Update status
    db.prepare(
      "UPDATE users SET status = 'online', lastSeen = datetime('now') WHERE userID = ?"
    ).run(user.userID);

    // 5. Issue JWT
    const token = jwt.sign({ userID: user.userID }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    res.json({
      userID:       user.userID,
      username:     user.username,
      displayName:  user.displayName,
      sessionToken: token,
      // encPrivKey stays AES-GCM encrypted — server never sees the raw key
      encPrivKey:   keyRow ? keyRow.privateKey : null,
      hasKeys:      !!keyRow
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Lỗi server' });
  }
});

// ─────────────────────────────────────────────
//  POST /api/auth/logout
// ─────────────────────────────────────────────
router.post('/logout', require('../middleware/auth').requireAuth, (req, res) => {
  db.prepare(
    "UPDATE users SET status = 'offline', lastSeen = datetime('now') WHERE userID = ?"
  ).run(req.user.userID);
  res.json({ message: 'Đã đăng xuất' });
});

module.exports = router;
