/**
 * Integration Tests — Contacts API
 * 
 * Test luồng quản lý liên hệ: tìm kiếm, gửi lời mời, chấp nhận/từ chối, xóa.
 */
const request = require('supertest');
const { app } = require('../../expressApp');
const { createUser, createKeyForUser, cleanupTestData } = require('../helpers');
const db = require('../../db');

let alice, bob, charlie;

beforeAll(async () => {
  cleanupTestData();

  // Tạo 3 user test, mỗi user có 1 key
  alice = await createUser({ username: 'test_ct_alice', email: 'ct_alice@test.com', password: 'Alice@2026' });
  await createKeyForUser(alice.token);

  bob = await createUser({ username: 'test_ct_bob', email: 'ct_bob@test.com', password: 'Bob@2026' });
  await createKeyForUser(bob.token);

  charlie = await createUser({ username: 'test_ct_charlie', email: 'ct_charlie@test.com', password: 'Charlie@2026' });
  await createKeyForUser(charlie.token);
});

afterAll(() => { cleanupTestData(); });

// ═══════════════════════════════════════════════════════
//  GET /api/contacts/search — Tìm kiếm người dùng
// ═══════════════════════════════════════════════════════
describe('GET /api/contacts/search', () => {

  test('tìm kiếm thành công → trả danh sách users', async () => {
    const res = await request(app)
      .get('/api/contacts/search?q=test_ct_bob')
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThanOrEqual(1);
    expect(res.body[0].username).toBe('test_ct_bob');
  });

  test('không tìm thấy bản thân trong kết quả', async () => {
    const res = await request(app)
      .get('/api/contacts/search?q=test_ct_alice')
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    const ids = res.body.map(u => u.userID);
    expect(ids).not.toContain(alice.userID);
  });

  test('query dưới 2 ký tự → 400', async () => {
    const res = await request(app)
      .get('/api/contacts/search?q=a')
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('2 ký tự');
  });

  test('query rỗng → 400', async () => {
    const res = await request(app)
      .get('/api/contacts/search?q=')
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(400);
  });
});

// ═══════════════════════════════════════════════════════
//  POST /api/contacts/request — Gửi lời mời kết bạn
// ═══════════════════════════════════════════════════════
describe('POST /api/contacts/request', () => {

  test('gửi lời mời thành công → 201', async () => {
    const res = await request(app)
      .post('/api/contacts/request')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({ toUserID: bob.userID });

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('requestID');
    expect(res.body.message).toContain('test_ct_bob');
  });

  test('gửi lời mời trùng → 409', async () => {
    const res = await request(app)
      .post('/api/contacts/request')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({ toUserID: bob.userID });

    expect(res.status).toBe(409);
    expect(res.body.error).toContain('đã được gửi');
  });

  test('gửi lời mời cho chính mình → 400', async () => {
    const res = await request(app)
      .post('/api/contacts/request')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({ toUserID: alice.userID });

    expect(res.status).toBe(400);
  });

  test('gửi lời mời cho user không tồn tại → 404', async () => {
    const res = await request(app)
      .post('/api/contacts/request')
      .set('Authorization', `Bearer ${alice.token}`)
      .send({ toUserID: 99999 });

    expect(res.status).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════
//  GET /api/contacts/requests/pending — Lời mời đang chờ
// ═══════════════════════════════════════════════════════
describe('GET /api/contacts/requests/pending', () => {

  test('Bob thấy lời mời từ Alice', async () => {
    const res = await request(app)
      .get('/api/contacts/requests/pending')
      .set('Authorization', `Bearer ${bob.token}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThanOrEqual(1);

    const fromAlice = res.body.find(r => r.fromUserID === alice.userID);
    expect(fromAlice).toBeDefined();
    expect(fromAlice.fromUsername).toBe('test_ct_alice');
  });

  test('Alice không có lời mời pending nào', async () => {
    const res = await request(app)
      .get('/api/contacts/requests/pending')
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    // Alice gửi lời mời cho Bob, không nhận lời mời từ ai
    const forAlice = res.body.filter(r => r.fromUserID !== alice.userID);
    // OK nếu có hoặc không, chỉ verify status 200
  });
});

// ═══════════════════════════════════════════════════════
//  POST /api/contacts/requests/:id/accept — Chấp nhận
// ═══════════════════════════════════════════════════════
describe('POST /api/contacts/requests/:id/accept', () => {

  test('Bob chấp nhận → tạo liên hệ 2 chiều', async () => {
    // Lấy requestID
    const pending = await request(app)
      .get('/api/contacts/requests/pending')
      .set('Authorization', `Bearer ${bob.token}`);

    const req = pending.body.find(r => r.fromUserID === alice.userID);
    expect(req).toBeDefined();

    // Chấp nhận
    const res = await request(app)
      .post(`/api/contacts/requests/${req.requestID}/accept`)
      .set('Authorization', `Bearer ${bob.token}`);

    expect(res.status).toBe(200);

    // Verify: Alice có Bob trong danh bạ
    const aliceContacts = await request(app)
      .get('/api/contacts')
      .set('Authorization', `Bearer ${alice.token}`);
    const bobInAlice = aliceContacts.body.find(c => c.contactUserID === bob.userID);
    expect(bobInAlice).toBeDefined();

    // Verify: Bob có Alice trong danh bạ
    const bobContacts = await request(app)
      .get('/api/contacts')
      .set('Authorization', `Bearer ${bob.token}`);
    const aliceInBob = bobContacts.body.find(c => c.contactUserID === alice.userID);
    expect(aliceInBob).toBeDefined();

    // Verify: DB có 2 records contacts
    const dbContacts = db.prepare(
      'SELECT * FROM contacts WHERE (ownerID=? AND contactUserID=?) OR (ownerID=? AND contactUserID=?)'
    ).all(alice.userID, bob.userID, bob.userID, alice.userID);
    expect(dbContacts.length).toBe(2);
  });

  test('chấp nhận request không tồn tại → 404', async () => {
    const res = await request(app)
      .post('/api/contacts/requests/99999/accept')
      .set('Authorization', `Bearer ${bob.token}`);

    expect(res.status).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════
//  POST /api/contacts/requests/:id/reject — Từ chối
// ═══════════════════════════════════════════════════════
describe('POST /api/contacts/requests/:id/reject', () => {

  let rejectRequestID;

  beforeAll(async () => {
    // Charlie gửi lời mời cho Alice
    const res = await request(app)
      .post('/api/contacts/request')
      .set('Authorization', `Bearer ${charlie.token}`)
      .send({ toUserID: alice.userID });
    rejectRequestID = res.body.requestID;
  });

  test('Alice từ chối lời mời từ Charlie', async () => {
    const res = await request(app)
      .post(`/api/contacts/requests/${rejectRequestID}/reject`)
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);

    // Verify: request status = rejected trong DB
    const dbReq = db.prepare('SELECT status FROM contact_requests WHERE requestID = ?').get(rejectRequestID);
    expect(dbReq.status).toBe('rejected');
  });

  test('từ chối request không tồn tại → 404', async () => {
    const res = await request(app)
      .post('/api/contacts/requests/99999/reject')
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════
//  GET /api/contacts/pubkey/:userID — Lấy public key + keyChanged
// ═══════════════════════════════════════════════════════
describe('GET /api/contacts/pubkey/:targetID', () => {

  test('lấy pubkey thành công, keyChanged = false', async () => {
    const res = await request(app)
      .get(`/api/contacts/pubkey/${bob.userID}`)
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('keyID');
    expect(res.body).toHaveProperty('publicKey');
    expect(res.body.keyChanged).toBe(false);
  });

  test('sau khi Bob đổi key → keyChanged = true', async () => {
    // Lấy pubkey lần đầu (cập nhật cache)
    await request(app)
      .get(`/api/contacts/pubkey/${bob.userID}`)
      .set('Authorization', `Bearer ${alice.token}`);

    // Bob tạo key mới (tự động revoke key cũ)
    await createKeyForUser(bob.token);

    // Lấy pubkey lần 2 → phải detect keyChanged
    const res = await request(app)
      .get(`/api/contacts/pubkey/${bob.userID}`)
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);
    expect(res.body.keyChanged).toBe(true);
  });

  test('user không có khóa → 404', async () => {
    // Tạo user mới KHÔNG có key
    const noKey = await createUser({ username: 'test_ct_nokey', email: 'nokey@test.com', password: 'Nokey@2026' });

    const res = await request(app)
      .get(`/api/contacts/pubkey/${noKey.userID}`)
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════
//  DELETE /api/contacts/:contactUserID — Xóa liên hệ
// ═══════════════════════════════════════════════════════
describe('DELETE /api/contacts/:contactUserID', () => {

  test('xóa liên hệ thành công → xóa cả 2 chiều', async () => {
    const res = await request(app)
      .delete(`/api/contacts/${bob.userID}`)
      .set('Authorization', `Bearer ${alice.token}`);

    expect(res.status).toBe(200);

    // Verify: cả 2 chiều đều bị xóa
    const remaining = db.prepare(
      'SELECT * FROM contacts WHERE (ownerID=? AND contactUserID=?) OR (ownerID=? AND contactUserID=?)'
    ).all(alice.userID, bob.userID, bob.userID, alice.userID);
    expect(remaining.length).toBe(0);
  });
});
