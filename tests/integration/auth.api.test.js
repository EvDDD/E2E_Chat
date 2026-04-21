/**
 * Integration Tests — Authentication API
 * 
 * Test luồng: HTTP Request → Express Router → Database → HTTP Response.
 * Sử dụng Supertest để gửi request trực tiếp vào Express app,
 * KHÔNG cần khởi chạy server thật.
 */
const request = require('supertest');
const { app }  = require('../../expressApp');
const db       = require('../../db');

// ─── Dọn dẹp dữ liệu test sau khi chạy xong ───
afterAll(() => {
  // Xóa tất cả users tạo bởi test (username bắt đầu bằng "test_")
  const testUsers = db.prepare("SELECT userID FROM users WHERE username LIKE 'test_%'").all();
  for (const u of testUsers) {
    db.prepare('DELETE FROM key_pairs WHERE userID = ?').run(u.userID);
    db.prepare('DELETE FROM contacts WHERE ownerID = ? OR contactUserID = ?').run(u.userID, u.userID);
    db.prepare('DELETE FROM contact_requests WHERE fromUserID = ? OR toUserID = ?').run(u.userID, u.userID);
    db.prepare('DELETE FROM messages WHERE senderID = ? OR receiverID = ?').run(u.userID, u.userID);
  }
  db.prepare("DELETE FROM users WHERE username LIKE 'test_%'").run();
});

// ═══════════════════════════════════════════════════════
//  POST /api/auth/register
// ═══════════════════════════════════════════════════════
describe('POST /api/auth/register', () => {

  test('đăng ký thành công → 201, trả về sessionToken và userID', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'test_alice',
        email: 'test_alice@test.com',
        password: 'Alice@2026'
      });

    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('sessionToken');
    expect(res.body).toHaveProperty('userID');
    expect(res.body.username).toBe('test_alice');
    expect(typeof res.body.sessionToken).toBe('string');
    expect(res.body.sessionToken.length).toBeGreaterThan(10);
  });

  test('đăng ký trùng username → 409 USERNAME_TAKEN', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'test_alice',          // đã tồn tại từ test trước
        email: 'test_other@test.com',
        password: 'Other@2026'
      });

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('USERNAME_TAKEN');
  });

  test('đăng ký trùng email → 409 EMAIL_EXISTS', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'test_other',
        email: 'test_alice@test.com',    // đã tồn tại
        password: 'Other@2026'
      });

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('EMAIL_EXISTS');
  });

  test('đăng ký thiếu field → 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'test_incomplete' });

    expect(res.status).toBe(400);
  });

  test('đăng ký username quá ngắn → 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'ab', email: 'x@test.com', password: 'Admin123' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('3–50');
  });

  test('đăng ký username ký tự đặc biệt → 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'test@user', email: 'x@test.com', password: 'Admin123' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('chữ cái');
  });

  test('đăng ký email sai format → 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'test_bad_email', email: 'not-an-email', password: 'Admin123' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Email');
  });

  test('đăng ký password yếu (thiếu chữ hoa) → 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'test_weak', email: 'weak@test.com', password: 'admin123' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('chữ hoa');
  });

  test('đăng ký password quá ngắn → 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'test_short', email: 'short@test.com', password: 'Ab1' });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('8 ký tự');
  });

  test('verify: password trong DB là bcrypt hash, không phải plaintext', async () => {
    const user = db.prepare("SELECT passwordHash FROM users WHERE username = 'test_alice'").get();
    expect(user.passwordHash).toMatch(/^\$2[aby]\$/);   // bcrypt hash pattern
    expect(user.passwordHash).not.toContain('Alice@2026');
  });

  // ── Thêm test cases ──
  test('đăng ký thành công user thứ 2 (không xung đột)', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'test_bob', email: 'test_bob@test.com', password: 'Bob@2026' });
    expect(res.status).toBe(201);
    expect(res.body.username).toBe('test_bob');
  });

  test('đăng ký với body rỗng → 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({});
    expect(res.status).toBe(400);
  });

  test('đăng ký với username giống SQL injection → 400 (chặn bởi validation)', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: "test'; DROP TABLE users;--", email: 'sql@test.com', password: 'Admin123' });
    expect(res.status).toBe(400);
  });

  test('đăng ký password chỉ có số + thường → 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'test_pw2', email: 'pw2@test.com', password: 'abcd1234' });
    expect(res.status).toBe(400);
  });

  test('đăng ký thiếu email → 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'test_no_email', password: 'Admin123' });
    expect(res.status).toBe(400);
  });

  test('đăng ký thiếu password → 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ username: 'test_no_pass', email: 'nopass@test.com' });
    expect(res.status).toBe(400);
  });

  test('displayName mặc định là username nếu không truyền', async () => {
    const user = db.prepare("SELECT displayName FROM users WHERE username = 'test_alice'").get();
    expect(user.displayName).toBe('test_alice');
  });
});

// ═══════════════════════════════════════════════════════
//  POST /api/auth/login
// ═══════════════════════════════════════════════════════
describe('POST /api/auth/login', () => {

  test('đăng nhập đúng → 200, trả về sessionToken', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice', password: 'Alice@2026' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('sessionToken');
    expect(res.body.username).toBe('test_alice');
    expect(res.body).toHaveProperty('userID');
  });

  test('đăng nhập sai password → 401 WRONG_PASSWORD', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice', password: 'WrongPass1' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('WRONG_PASSWORD');
  });

  test('đăng nhập user không tồn tại → 401 USER_NOT_FOUND', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_nobody', password: 'Test1234' });

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('USER_NOT_FOUND');
  });

  test('đăng nhập thiếu password → 400', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice' });

    expect(res.status).toBe(400);
  });

  test('response không chứa password hoặc raw private key', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice', password: 'Alice@2026' });

    expect(res.body).not.toHaveProperty('password');
    expect(res.body).not.toHaveProperty('passwordHash');
    if (res.body.encPrivKey) {
      expect(res.body.encPrivKey).not.toMatch(/^MII/);
    }
  });

  // ── Thêm test cases ──
  test('đăng nhập thiếu username → 400', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ password: 'Alice@2026' });
    expect(res.status).toBe(400);
  });

  test('đăng nhập với body rỗng → 400', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({});
    expect(res.status).toBe(400);
  });

  test('password phân biệt hoa/thường (case sensitive)', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice', password: 'alice@2026' }); // a thường thay vì A hoa
    expect(res.status).toBe(401);
  });

  test('đăng nhập 2 lần → cả 2 token đều hợp lệ', async () => {
    const res1 = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice', password: 'Alice@2026' });
    const res2 = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice', password: 'Alice@2026' });
    // Cả 2 lần đều thành công và trả token
    expect(res1.status).toBe(200);
    expect(res2.status).toBe(200);
    expect(typeof res1.body.sessionToken).toBe('string');
    expect(typeof res2.body.sessionToken).toBe('string');
    expect(res1.body.sessionToken.length).toBeGreaterThan(10);
    expect(res2.body.sessionToken.length).toBeGreaterThan(10);
  });

  test('login đúng → user status = online trong DB', async () => {
    await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice', password: 'Alice@2026' });
    const user = db.prepare("SELECT status FROM users WHERE username = 'test_alice'").get();
    expect(user.status).toBe('online');
  });
});

// ═══════════════════════════════════════════════════════
//  JWT Authentication Middleware
// ═══════════════════════════════════════════════════════
describe('JWT Authentication', () => {

  test('gọi API không có token → 401', async () => {
    const res = await request(app).get('/api/contacts');

    expect(res.status).toBe(401);
    expect(res.body.error).toContain('Authorization');
  });

  test('gọi API với token giả → 401', async () => {
    const res = await request(app)
      .get('/api/contacts')
      .set('Authorization', 'Bearer fake.token.here');

    expect(res.status).toBe(401);
    expect(res.body.error).toContain('invalid');
  });

  test('gọi API với token hợp lệ → 200', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice', password: 'Alice@2026' });
    const token = loginRes.body.sessionToken;
    const res = await request(app)
      .get('/api/contacts')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });

  // ── Thêm test cases ──
  test('Authorization header không có prefix Bearer → 401', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice', password: 'Alice@2026' });
    const res = await request(app)
      .get('/api/contacts')
      .set('Authorization', loginRes.body.sessionToken); // thiếu "Bearer "
    expect(res.status).toBe(401);
  });

  test('Authorization header rỗng → 401', async () => {
    const res = await request(app)
      .get('/api/contacts')
      .set('Authorization', '');
    expect(res.status).toBe(401);
  });

  test('gọi nhiều API khác nhau với cùng token → đều 200', async () => {
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice', password: 'Alice@2026' });
    const token = loginRes.body.sessionToken;

    const r1 = await request(app).get('/api/contacts').set('Authorization', `Bearer ${token}`);
    const r2 = await request(app).get('/api/keys/history').set('Authorization', `Bearer ${token}`);
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
  });
});

// ═══════════════════════════════════════════════════════
//  POST /api/auth/logout
// ═══════════════════════════════════════════════════════
describe('POST /api/auth/logout', () => {

  test('đăng xuất thành công → 200, status offline trong DB', async () => {
    // Đăng nhập trước
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ username: 'test_alice', password: 'Alice@2026' });
    const token = loginRes.body.sessionToken;

    // Đăng xuất
    const res = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);

    // Verify trong DB
    const user = db.prepare("SELECT status FROM users WHERE username = 'test_alice'").get();
    expect(user.status).toBe('offline');
  });

  test('đăng xuất không có token → 401', async () => {
    const res = await request(app).post('/api/auth/logout');
    expect(res.status).toBe(401);
  });
});
