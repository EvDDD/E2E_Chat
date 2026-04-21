/**
 * Integration Tests — Messages API
 * 
 * Test luồng gửi/nhận tin nhắn: POST, GET (pagination), PATCH (verify).
 */
const request = require('supertest');
const { app } = require('../../expressApp');
const db      = require('../../db');
const { createUser, createKeyForUser, makeFriends, cleanupTestData } = require('../helpers');

let alice, bob, aliceKeyID, bobKeyID;

beforeAll(async () => {
  cleanupTestData();

  alice = await createUser({ username: 'test_msg_alice', email: 'msg_alice@test.com', password: 'Alice@2026' });
  const ak = await createKeyForUser(alice.token);
  aliceKeyID = ak.keyID;

  bob = await createUser({ username: 'test_msg_bob', email: 'msg_bob@test.com', password: 'Bob@2026' });
  const bk = await createKeyForUser(bob.token);
  bobKeyID = bk.keyID;

  // Kết bạn
  await makeFriends(alice.token, alice.userID, bob.token, bob.userID);
});

afterAll(() => { cleanupTestData(); });

// Dữ liệu tin nhắn mẫu (đã mã hóa giả)
function fakeMessage(receiverID, receiverKeyID) {
  return {
    receiverID,
    receiverKeyID,
    ciphertext:    'FAKE_CIPHERTEXT_' + Date.now(),
    encSessionKey: 'FAKE_ENC_SESSION_KEY_' + Date.now(),
    senderEncSessionKey: 'FAKE_SENDER_ENC_' + Date.now(),
    signature:     'FAKE_SIGNATURE_' + Date.now(),
    hashValue:     'a'.repeat(64),  // SHA-256 hex = 64 chars
    aesIV:         'FAKE_IV_' + Date.now()
  };
}

// ═══════════════════════════════════════════════════════
//  POST /api/messages — Gửi tin nhắn
// ═══════════════════════════════════════════════════════
describe('POST /api/messages', () => {

  test('gửi tin nhắn thành công → 201', async () => {
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send(fakeMessage(bob.userID, bobKeyID));

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('messageID');
    expect(['sent', 'delivered']).toContain(res.body.status);
  });

  test('tin nhắn được lưu trong DB với đúng senderKeyID', async () => {
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send(fakeMessage(bob.userID, bobKeyID));

    const msg = db.prepare('SELECT * FROM messages WHERE messageID = ?').get(res.body.messageID);
    expect(msg.senderID).toBe(alice.userID);
    expect(msg.receiverID).toBe(bob.userID);
    expect(msg.senderKeyID).toBe(aliceKeyID);
    expect(msg.receiverKeyID).toBe(bobKeyID);
    expect(msg.senderEncSessionKey).not.toBeNull();  // dual encryption
  });

  test('gửi tin nhắn cho chính mình → 400', async () => {
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send(fakeMessage(alice.userID, aliceKeyID));

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('chính mình');
  });

  test('thiếu trường bắt buộc → 400', async () => {
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({ receiverID: bob.userID });  // thiếu ciphertext, signature, etc.

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Thiếu trường');
  });

  test('receiverKeyID không hợp lệ → 400', async () => {
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send(fakeMessage(bob.userID, 99999));

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('receiverKeyID');
  });

  test('không có token → 401', async () => {
    const res = await request(app)
      .post('/api/messages')
      .send(fakeMessage(bob.userID, bobKeyID));

    expect(res.status).toBe(401);
  });

  test('server không inject senderID từ body (bảo mật)', async () => {
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({ ...fakeMessage(bob.userID, bobKeyID), senderID: 99999 });

    expect(res.status).toBe(201);
    const msg = db.prepare('SELECT senderID FROM messages WHERE messageID = ?').get(res.body.messageID);
    expect(msg.senderID).toBe(alice.userID);
  });

  // ── Thêm test cases ──
  test('Bob gửi tin nhắn cho Alice (chiều ngược)', async () => {
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${bob.token}`)
      .send(fakeMessage(alice.userID, aliceKeyID));
    expect(res.status).toBe(201);
  });

  test('gửi tin nhắn với receiverKeyID của người khác (sai chủ sở hữu) → 400', async () => {
    // Dùng aliceKeyID cho bob là receiver → keyID không thuộc bob
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send(fakeMessage(bob.userID, aliceKeyID));
    expect(res.status).toBe(400);
  });

  test('gửi tin nhắn với body rỗng → 400', async () => {
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({});
    expect(res.status).toBe(400);
  });

  test('gửi tin nhắn thiếu chỉ ciphertext → 400', async () => {
    const msg = fakeMessage(bob.userID, bobKeyID);
    delete msg.ciphertext;
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send(msg);
    expect(res.status).toBe(400);
  });

  test('gửi tin nhắn thiếu chỉ signature → 400', async () => {
    const msg = fakeMessage(bob.userID, bobKeyID);
    delete msg.signature;
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send(msg);
    expect(res.status).toBe(400);
  });

  test('gửi tin cho user không tồn tại (receiverKeyID ko tồn tại) → 400', async () => {
    const msg = fakeMessage(99999, 99999);
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send(msg);
    expect(res.status).toBe(400);
  });
});

// ═══════════════════════════════════════════════════════
//  GET /api/messages/:contactID — Lịch sử tin nhắn (phân trang)
// ═══════════════════════════════════════════════════════
describe('GET /api/messages/:contactID', () => {

  beforeAll(async () => {
    // Gửi thêm tin nhắn để test pagination (đang có ~3 từ test trước)
    for (let i = 0; i < 22; i++) {
      await request(app)
        .post('/api/messages')
        .set('Authorization', `Bearer ${alice.token}`)
        .send(fakeMessage(bob.userID, bobKeyID));
    }
  });

  test('lấy trang 1 → mặc định 20 tin, hasMore = true', async () => {
    const res = await request(app)
      .get(`/api/messages/${bob.userID}?page=1`)
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    expect(res.body.messages.length).toBe(20);
    expect(res.body.page).toBe(1);
    expect(res.body.hasMore).toBe(true);
  });

  test('lấy trang 2 → tin còn lại, hasMore có thể false', async () => {
    const res = await request(app)
      .get(`/api/messages/${bob.userID}?page=2`)
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    expect(res.body.messages.length).toBeGreaterThan(0);
    expect(res.body.page).toBe(2);
  });

  test('custom limit → trả đúng số lượng', async () => {
    const res = await request(app)
      .get(`/api/messages/${bob.userID}?page=1&limit=5`)
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    expect(res.body.messages.length).toBe(5);
    expect(res.body.limit).toBe(5);
  });

  test('tin nhắn trả về theo thứ tự chronological (cũ → mới)', async () => {
    const res = await request(app)
      .get(`/api/messages/${bob.userID}?page=1&limit=5`)
      .set('Authorization', `Bearer ${alice.token}`);

    const msgs = res.body.messages;
    for (let i = 1; i < msgs.length; i++) {
      expect(msgs[i].messageID).toBeGreaterThanOrEqual(msgs[i-1].messageID);
    }
  });

  test('Bob cũng xem được lịch sử chat với Alice', async () => {
    const res = await request(app)
      .get(`/api/messages/${alice.userID}?page=1`)
      .set('Authorization', `Bearer ${bob.token}`);
    expect(res.status).toBe(200);
    expect(res.body.messages.length).toBeGreaterThan(0);
  });

  // ── Thêm test cases ──
  test('page=0 → server coi như page=1 (Math.max)', async () => {
    const res = await request(app)
      .get(`/api/messages/${bob.userID}?page=0`)
      .set('Authorization', `Bearer ${alice.token}`);
    expect(res.status).toBe(200);
    expect(res.body.page).toBe(1);
  });

  test('page âm → server coi như page=1', async () => {
    const res = await request(app)
      .get(`/api/messages/${bob.userID}?page=-5`)
      .set('Authorization', `Bearer ${alice.token}`);
    expect(res.status).toBe(200);
    expect(res.body.page).toBe(1);
  });

  test('page rất lớn → mảng rỗng, hasMore = false', async () => {
    const res = await request(app)
      .get(`/api/messages/${bob.userID}?page=999`)
      .set('Authorization', `Bearer ${alice.token}`);
    expect(res.status).toBe(200);
    expect(res.body.messages.length).toBe(0);
    expect(res.body.hasMore).toBe(false);
  });

  test('limit > 50 → server giới hạn tối đa 50 (Math.min)', async () => {
    const res = await request(app)
      .get(`/api/messages/${bob.userID}?page=1&limit=100`)
      .set('Authorization', `Bearer ${alice.token}`);
    expect(res.status).toBe(200);
    expect(res.body.limit).toBeLessThanOrEqual(50);
  });

  test('response chứa đầy đủ các trường cần thiết', async () => {
    const res = await request(app)
      .get(`/api/messages/${bob.userID}?page=1&limit=1`)
      .set('Authorization', `Bearer ${alice.token}`);
    const msg = res.body.messages[0];
    expect(msg).toHaveProperty('messageID');
    expect(msg).toHaveProperty('senderID');
    expect(msg).toHaveProperty('receiverID');
    expect(msg).toHaveProperty('ciphertext');
    expect(msg).toHaveProperty('encSessionKey');
    expect(msg).toHaveProperty('signature');
    expect(msg).toHaveProperty('timestamp');
  });

  test('không có token → 401', async () => {
    const res = await request(app).get(`/api/messages/${bob.userID}`);
    expect(res.status).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════
//  PATCH /api/messages/:messageID/verify — Cập nhật xác thực
// ═══════════════════════════════════════════════════════
describe('PATCH /api/messages/:messageID/verify', () => {

  let messageID;

  beforeAll(async () => {
    // Alice gửi 1 tin cho Bob
    const res = await request(app)
      .post('/api/messages')
      .set('Authorization', `Bearer ${alice.token}`)
      .send(fakeMessage(bob.userID, bobKeyID));
    messageID = res.body.messageID;
  });

  test('Bob verify tin nhắn → sigVerified=true, tamperAlert=false', async () => {
    const res = await request(app)
      .patch(`/api/messages/${messageID}/verify`)
      .set('Authorization', `Bearer ${bob.token}`)
      .send({ sigVerified: true, tamperAlert: false });

    expect(res.status).toBe(200);
    expect(res.body.updated).toBe(true);

    // Verify trong DB
    const msg = db.prepare('SELECT sigVerified, tamperAlert, status FROM messages WHERE messageID = ?').get(messageID);
    expect(msg.sigVerified).toBe(1);
    expect(msg.tamperAlert).toBe(0);
    expect(msg.status).toBe('read');
  });

  test('Bob report tamper → tamperAlert=true cập nhật dù đã verified', async () => {
    // Bug 4 fix: tamperAlert phải luôn cập nhật được
    const res = await request(app)
      .patch(`/api/messages/${messageID}/verify`)
      .set('Authorization', `Bearer ${bob.token}`)
      .send({ sigVerified: false, tamperAlert: true });

    expect(res.status).toBe(200);

    const msg = db.prepare('SELECT sigVerified, tamperAlert FROM messages WHERE messageID = ?').get(messageID);
    expect(msg.tamperAlert).toBe(1);
    expect(msg.sigVerified).toBe(0);
  });

  test('Alice (sender) không thể verify tin mình gửi → 403', async () => {
    const res = await request(app)
      .patch(`/api/messages/${messageID}/verify`)
      .set('Authorization', `Bearer ${alice.token}`)
      .send({ sigVerified: true, tamperAlert: false });

    expect(res.status).toBe(403);
  });

  test('verify message không tồn tại → 403', async () => {
    const res = await request(app)
      .patch('/api/messages/99999/verify')
      .set('Authorization', `Bearer ${bob.token}`)
      .send({ sigVerified: true, tamperAlert: false });
    expect(res.status).toBe(403);
  });

  // ── Thêm test cases ──
  test('verify không có token → 401', async () => {
    const res = await request(app)
      .patch(`/api/messages/${messageID}/verify`)
      .send({ sigVerified: true, tamperAlert: false });
    expect(res.status).toBe(401);
  });

  test('toggle lại: verify đúng sau khi đã report tamper', async () => {
    await request(app)
      .patch(`/api/messages/${messageID}/verify`)
      .set('Authorization', `Bearer ${bob.token}`)
      .send({ sigVerified: false, tamperAlert: true });

    const res = await request(app)
      .patch(`/api/messages/${messageID}/verify`)
      .set('Authorization', `Bearer ${bob.token}`)
      .send({ sigVerified: true, tamperAlert: false });

    expect(res.status).toBe(200);
    const msg = db.prepare('SELECT sigVerified, tamperAlert FROM messages WHERE messageID = ?').get(messageID);
    expect(msg.sigVerified).toBe(1);
    expect(msg.tamperAlert).toBe(0);
  });
});
