/**
 * Integration Tests — Keys API
 * 
 * Test luồng quản lý khóa RSA: tạo khóa, lấy khóa, thu hồi, lịch sử.
 */
const request = require('supertest');
const { app } = require('../../expressApp');
const db      = require('../../db');
const { createUser, createKeyForUser, cleanupTestData } = require('../helpers');

let alice, aliceKey;

// ─── Setup: tạo user test ───
beforeAll(async () => {
  cleanupTestData();
  alice = await createUser({ username: 'test_key_alice', email: 'key_alice@test.com', password: 'Alice@2026' });
  aliceKey = await createKeyForUser(alice.token);
});

afterAll(() => { cleanupTestData(); });

// ═══════════════════════════════════════════════════════
//  POST /api/keys — Lưu cặp khóa RSA
// ═══════════════════════════════════════════════════════
describe('POST /api/keys', () => {

  test('lưu khóa thành công → 201, trả keyID', async () => {
    const res = await request(app)
      .post('/api/keys')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({
        publicKey:  'NEW_PUB_KEY_' + Date.now(),
        privateKey: JSON.stringify({ salt: 's', iv: 'i', ciphertext: 'c' })
      });

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('keyID');
    expect(res.body.status).toBe('stored');
  });

  test('thiếu publicKey → 400', async () => {
    const res = await request(app)
      .post('/api/keys')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({ privateKey: 'test' });

    expect(res.status).toBe(400);
  });

  test('thiếu privateKey → 400', async () => {
    const res = await request(app)
      .post('/api/keys')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({ publicKey: 'test' });

    expect(res.status).toBe(400);
  });

  test('không có token → 401', async () => {
    const res = await request(app)
      .post('/api/keys')
      .send({ publicKey: 'x', privateKey: 'x' });

    expect(res.status).toBe(401);
  });
});

// ═══════════════════════════════════════════════════════
//  GET /api/keys/me — Lấy khóa active của tôi
// ═══════════════════════════════════════════════════════
describe('GET /api/keys/me', () => {

  test('trả về khóa active hiện tại', async () => {
    const res = await request(app)
      .get('/api/keys/me')
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('keyID');
    expect(res.body).toHaveProperty('publicKey');
    expect(res.body).toHaveProperty('privateKey');  // user xem key của mình → có privateKey
    expect(res.body).toHaveProperty('createdAt');
  });
});

// ═══════════════════════════════════════════════════════
//  GET /api/keys/user/:targetID — Lấy public key của người khác
// ═══════════════════════════════════════════════════════
describe('GET /api/keys/user/:targetID', () => {

  let bob;

  beforeAll(async () => {
    bob = await createUser({ username: 'test_key_bob', email: 'key_bob@test.com', password: 'Bob@2026' });
    await createKeyForUser(bob.token);
  });

  test('trả về publicKey, KHÔNG có privateKey (bảo mật)', async () => {
    const res = await request(app)
      .get(`/api/keys/user/${bob.userID}`)
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('keyID');
    expect(res.body).toHaveProperty('publicKey');
    expect(res.body).not.toHaveProperty('privateKey');  // QUAN TRỌNG: không lộ private key
  });

  test('user không tồn tại → 404', async () => {
    const res = await request(app)
      .get('/api/keys/user/99999')
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════
//  POST /api/keys/revoke — Thu hồi khóa
// ═══════════════════════════════════════════════════════
describe('POST /api/keys/revoke', () => {

  test('thu hồi thành công → key cũ revoked trong DB', async () => {
    // Lấy keyID hiện tại
    const before = await request(app)
      .get('/api/keys/me')
      .set('Authorization', `Bearer ${alice.token}`);
    const oldKeyID = before.body.keyID;

    // Thu hồi
    const res = await request(app)
      .post('/api/keys/revoke')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({ reason: 'test_revoke' });

    expect(res.status).toBe(200);

    // Verify key cũ đã bị revoke trong DB
    const revokedKey = db.prepare('SELECT status, revokedAt, revokedReason FROM key_pairs WHERE keyID = ?').get(oldKeyID);
    expect(revokedKey.status).toBe('revoked');
    expect(revokedKey.revokedAt).not.toBeNull();
    expect(revokedKey.revokedReason).toBe('test_revoke');
  });

  test('thu hồi khi không có key active → 404', async () => {
    // Alice vừa revoke ở test trước → không còn active key
    const res = await request(app)
      .post('/api/keys/revoke')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({});

    expect(res.status).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════
//  GET /api/keys/history — Lịch sử khóa
// ═══════════════════════════════════════════════════════
describe('GET /api/keys/history', () => {

  test('trả về danh sách khóa (cả active lẫn revoked)', async () => {
    // Tạo key mới cho alice (vì đã revoke hết)
    await createKeyForUser(alice.token);

    const res = await request(app)
      .get('/api/keys/history')
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThanOrEqual(2); // ít nhất 1 active + 1 revoked

    // Kiểm tra có cả 2 trạng thái
    const statuses = res.body.map(k => k.status);
    expect(statuses).toContain('active');
    expect(statuses).toContain('revoked');

    // History không chứa privateKey (chỉ metadata)
    expect(res.body[0]).not.toHaveProperty('privateKey');
    expect(res.body[0]).not.toHaveProperty('publicKey');
  });
});

// ═══════════════════════════════════════════════════════
//  GET /api/keys/all — Tất cả khóa (bao gồm encrypted privkey)
// ═══════════════════════════════════════════════════════
describe('GET /api/keys/all', () => {

  test('trả về cả publicKey và privateKey (cho decrypt tin nhắn cũ)', async () => {
    const res = await request(app)
      .get('/api/keys/all')
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body[0]).toHaveProperty('publicKey');
    expect(res.body[0]).toHaveProperty('privateKey');  // user xem key CỦA MÌNH → có privateKey
  });
});

// ═══════════════════════════════════════════════════════
//  GET /api/keys/user/:id/public-all — Public keys của người khác (cả revoked)
// ═══════════════════════════════════════════════════════
describe('GET /api/keys/user/:id/public-all', () => {

  test('trả về danh sách public keys, KHÔNG có privateKey', async () => {
    const res = await request(app)
      .get(`/api/keys/user/${alice.userID}/public-all`)
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThanOrEqual(1);
    expect(res.body[0]).toHaveProperty('publicKey');
    expect(res.body[0]).not.toHaveProperty('privateKey');
  });
});
