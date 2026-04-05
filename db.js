const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = path.join(__dirname, 'e2ee_chat.db');
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ─────────────────────────────────────────────
//  Schema creation
// ─────────────────────────────────────────────
db.exec(`
  -- ── users ──────────────────────────────────
  CREATE TABLE IF NOT EXISTS users (
    userID        INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL UNIQUE,
    passwordHash  TEXT    NOT NULL,
    displayName   TEXT,
    status        TEXT    NOT NULL DEFAULT 'offline'
                          CHECK(status IN ('online','offline')),
    isVerified    INTEGER NOT NULL DEFAULT 0,
    createdAt     TEXT    NOT NULL DEFAULT (datetime('now')),
    lastSeen      TEXT
  );

  -- ── key_pairs ────────────────────────────────
  CREATE TABLE IF NOT EXISTS key_pairs (
    keyID          INTEGER PRIMARY KEY AUTOINCREMENT,
    userID         INTEGER NOT NULL REFERENCES users(userID) ON DELETE CASCADE,
    publicKey      TEXT    NOT NULL,
    privateKey     TEXT    NOT NULL,
    keySize        INTEGER NOT NULL DEFAULT 2048,
    algorithm      TEXT    NOT NULL DEFAULT 'RSA-OAEP',
    status         TEXT    NOT NULL DEFAULT 'active'
                           CHECK(status IN ('active','revoked')),
    revokedAt      TEXT,
    revokedReason  TEXT,
    createdAt      TEXT    NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_keypairs_user_status
    ON key_pairs(userID, status);

  -- ── contact_requests ─────────────────────────
  -- Lời mời kết bạn — phải được chấp nhận mới tạo contact 2 chiều
  CREATE TABLE IF NOT EXISTS contact_requests (
    requestID   INTEGER PRIMARY KEY AUTOINCREMENT,
    fromUserID  INTEGER NOT NULL REFERENCES users(userID) ON DELETE CASCADE,
    toUserID    INTEGER NOT NULL REFERENCES users(userID) ON DELETE CASCADE,
    status      TEXT    NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','accepted','rejected')),
    createdAt   TEXT    NOT NULL DEFAULT (datetime('now')),
    updatedAt   TEXT,
    UNIQUE(fromUserID, toUserID)
  );
  CREATE INDEX IF NOT EXISTS idx_requests_to ON contact_requests(toUserID, status);

  -- ── messages ─────────────────────────────────
  CREATE TABLE IF NOT EXISTS messages (
    messageID     INTEGER PRIMARY KEY AUTOINCREMENT,
    senderID      INTEGER NOT NULL REFERENCES users(userID),
    receiverID    INTEGER NOT NULL REFERENCES users(userID),
    senderKeyID   INTEGER NOT NULL REFERENCES key_pairs(keyID),
    receiverKeyID INTEGER NOT NULL REFERENCES key_pairs(keyID),
    ciphertext    TEXT    NOT NULL,
    encSessionKey TEXT    NOT NULL,
    signature     TEXT    NOT NULL,
    hashValue     TEXT    NOT NULL,
    aesIV         TEXT    NOT NULL,
    timestamp     TEXT    NOT NULL DEFAULT (datetime('now')),
    status        TEXT    NOT NULL DEFAULT 'sent'
                          CHECK(status IN ('sent','delivered','read')),
    sigVerified   INTEGER NOT NULL DEFAULT 0,
    tamperAlert   INTEGER NOT NULL DEFAULT 0,
    CHECK(senderID != receiverID)
  );
  CREATE INDEX IF NOT EXISTS idx_messages_sender_ts
    ON messages(senderID, timestamp);
  CREATE INDEX IF NOT EXISTS idx_messages_receiver_ts
    ON messages(receiverID, timestamp);
  CREATE INDEX IF NOT EXISTS idx_messages_sender_key
    ON messages(senderKeyID);
  CREATE INDEX IF NOT EXISTS idx_messages_receiver_key
    ON messages(receiverKeyID);

  -- ── contacts ─────────────────────────────────
  CREATE TABLE IF NOT EXISTS contacts (
    contactID     INTEGER PRIMARY KEY AUTOINCREMENT,
    ownerID       INTEGER NOT NULL REFERENCES users(userID) ON DELETE CASCADE,
    contactUserID INTEGER NOT NULL REFERENCES users(userID) ON DELETE CASCADE,
    cachedKeyID   INTEGER REFERENCES key_pairs(keyID),
    cachedPubKey  TEXT,
    addedAt       TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(ownerID, contactUserID),
    CHECK(ownerID != contactUserID)
  );
`);

module.exports = db;
