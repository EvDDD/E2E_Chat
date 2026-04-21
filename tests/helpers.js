/**
 * Test Helpers — Các hàm tiện ích dùng chung cho integration tests.
 * 
 * Giúp tạo user, đăng nhập, tạo key, kết bạn nhanh chóng mà không
 * phải viết lặp lại code setup trong mỗi file test.
 */
const request = require('supertest');
const { app } = require('../expressApp');
const db      = require('../db');

/**
 * Đăng ký user mới và trả về { userID, token }
 */
async function createUser({ username, email, password }) {
  const res = await request(app)
    .post('/api/auth/register')
    .send({ username, email, password });
  return {
    userID: res.body.userID,
    token:  res.body.sessionToken,
    username: res.body.username
  };
}

/**
 * Đăng nhập và trả về { userID, token }
 */
async function loginUser({ username, password }) {
  const res = await request(app)
    .post('/api/auth/login')
    .send({ username, password });
  return {
    userID: res.body.userID,
    token:  res.body.sessionToken,
    username: res.body.username
  };
}

/**
 * Tạo RSA key pair giả cho user (dùng trong test, không phải RSA thật)
 */
async function createKeyForUser(token) {
  const res = await request(app)
    .post('/api/keys')
    .set('Authorization', `Bearer ${token}`)
    .send({
      publicKey:  'TEST_PUBLIC_KEY_BASE64_' + Date.now() + '_' + Math.random(),
      privateKey: JSON.stringify({ salt: 'test', iv: 'test', ciphertext: 'test_' + Date.now() })
    });
  return { keyID: res.body.keyID };
}

/**
 * Tạo quan hệ bạn bè giữa 2 user (gửi lời mời + chấp nhận)
 */
async function makeFriends(tokenA, userA_ID, tokenB, userB_ID) {
  // A gửi lời mời cho B
  const reqRes = await request(app)
    .post('/api/contacts/request')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ toUserID: userB_ID });

  const requestID = reqRes.body.requestID;

  // B chấp nhận
  await request(app)
    .post(`/api/contacts/requests/${requestID}/accept`)
    .set('Authorization', `Bearer ${tokenB}`);

  return requestID;
}

/**
 * Dọn dẹp tất cả dữ liệu test (username bắt đầu bằng "test_")
 */
function cleanupTestData() {
  const testUsers = db.prepare("SELECT userID FROM users WHERE username LIKE 'test_%'").all();
  for (const u of testUsers) {
    db.prepare('DELETE FROM messages WHERE senderID = ? OR receiverID = ?').run(u.userID, u.userID);
    db.prepare('DELETE FROM contacts WHERE ownerID = ? OR contactUserID = ?').run(u.userID, u.userID);
    db.prepare('DELETE FROM contact_requests WHERE fromUserID = ? OR toUserID = ?').run(u.userID, u.userID);
    db.prepare('DELETE FROM key_pairs WHERE userID = ?').run(u.userID);
  }
  db.prepare("DELETE FROM users WHERE username LIKE 'test_%'").run();
}

module.exports = { createUser, loginUser, createKeyForUser, makeFriends, cleanupTestData };
