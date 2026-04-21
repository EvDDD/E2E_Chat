/**
 * Unit Tests — Auth Logic (JWT & bcrypt)
 * 
 * Test các hàm bảo mật cơ bản: tạo/verify JWT, hash/compare password.
 */
const jwt    = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { JWT_SECRET } = require('../../middleware/auth');

// ═══════════════════════════════════════════════════════
//  JWT Token
// ═══════════════════════════════════════════════════════
describe('JWT Token', () => {

  test('tạo token hợp lệ chứa userID', () => {
    const token = jwt.sign({ userID: 42 }, JWT_SECRET, { expiresIn: '1h' });
    expect(typeof token).toBe('string');

    const decoded = jwt.verify(token, JWT_SECRET);
    expect(decoded.userID).toBe(42);
  });

  test('verify token với secret sai → throw error', () => {
    const token = jwt.sign({ userID: 1 }, JWT_SECRET);
    expect(() => jwt.verify(token, 'wrong-secret')).toThrow();
  });

  test('token hết hạn → throw TokenExpiredError', () => {
    const token = jwt.sign({ userID: 1 }, JWT_SECRET, { expiresIn: '0s' }); // hết hạn ngay
    expect(() => jwt.verify(token, JWT_SECRET)).toThrow('jwt expired');
  });

  test('token bị sửa đổi → JsonWebTokenError', () => {
    const token = jwt.sign({ userID: 1 }, JWT_SECRET);
    const tampered = token.slice(0, -5) + 'XXXXX'; // sửa 5 ký tự cuối
    expect(() => jwt.verify(tampered, JWT_SECRET)).toThrow();
  });

  test('token chứa đúng payload, không chứa dữ liệu thừa', () => {
    const token = jwt.sign({ userID: 10 }, JWT_SECRET, { expiresIn: '24h' });
    const decoded = jwt.verify(token, JWT_SECRET);
    expect(decoded).toHaveProperty('userID', 10);
    expect(decoded).toHaveProperty('iat');
    expect(decoded).toHaveProperty('exp');
    expect(decoded).not.toHaveProperty('password');
  });
});

// ═══════════════════════════════════════════════════════
//  bcrypt Hashing
// ═══════════════════════════════════════════════════════
describe('bcrypt Password Hashing', () => {

  const password = 'MySecure@Pass123';
  let hash;

  test('hash password thành công', async () => {
    hash = await bcrypt.hash(password, 12);
    expect(typeof hash).toBe('string');
    expect(hash).toMatch(/^\$2[aby]\$/);  // bcrypt format
    expect(hash).not.toBe(password);      // không phải plaintext
    expect(hash.length).toBeGreaterThan(50);
  });

  test('compare password đúng → true', async () => {
    const match = await bcrypt.compare(password, hash);
    expect(match).toBe(true);
  });

  test('compare password sai → false', async () => {
    const match = await bcrypt.compare('WrongPass', hash);
    expect(match).toBe(false);
  });

  test('hash cùng password 2 lần → ra 2 hash khác nhau (salt ngẫu nhiên)', async () => {
    const hash1 = await bcrypt.hash(password, 12);
    const hash2 = await bcrypt.hash(password, 12);
    expect(hash1).not.toBe(hash2);
    // Nhưng cả 2 đều verify đúng
    expect(await bcrypt.compare(password, hash1)).toBe(true);
    expect(await bcrypt.compare(password, hash2)).toBe(true);
  });

  test('hash chứa thông tin round ($2b$12$...)', async () => {
    const h = await bcrypt.hash('test', 12);
    expect(h).toMatch(/^\$2b\$12\$/);  // bcrypt v2b, 12 rounds
  });
});

// ═══════════════════════════════════════════════════════
//  requireAuth middleware logic (unit test through JWT)
// ═══════════════════════════════════════════════════════
describe('Auth middleware logic', () => {

  test('token có userID → req.user.userID trích xuất đúng', () => {
    const token = jwt.sign({ userID: 99 }, JWT_SECRET, { expiresIn: '24h' });
    const payload = jwt.verify(token, JWT_SECRET);
    // Middleware sẽ gán req.user = { userID: payload.userID }
    expect(payload.userID).toBe(99);
  });

  test('Bearer token format: "Bearer <token>" → tách đúng', () => {
    const token = jwt.sign({ userID: 1 }, JWT_SECRET);
    const header = `Bearer ${token}`;

    // Middleware logic: header.slice(7)
    expect(header.startsWith('Bearer ')).toBe(true);
    const extracted = header.slice(7);
    expect(extracted).toBe(token);

    const decoded = jwt.verify(extracted, JWT_SECRET);
    expect(decoded.userID).toBe(1);
  });
});
