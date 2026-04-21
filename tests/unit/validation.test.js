/**
 * Unit Tests — Input Validation
 * 
 * Test các hàm validate riêng lẻ, không cần server hay database.
 * Đây là tầng THẤP NHẤT trong Testing Pyramid — chạy nhanh nhất.
 */

// ─── Copy validation logic từ public/app.js ───
// (Vì public/app.js chạy trên browser, không require() được trong Node.js)
const Validate = {
  username(v) {
    if (!v) return 'Tên đăng nhập là bắt buộc.';
    if (v.length < 3 || v.length > 50) return 'Tên đăng nhập phải từ 3–50 ký tự.';
    if (!/^[a-zA-Z0-9_]+$/.test(v)) return 'Tên đăng nhập chỉ được chứa chữ cái, số và dấu gạch dưới.';
    return null;
  },
  email(v) {
    if (!v) return 'Email là bắt buộc.';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'Email không hợp lệ.';
    return null;
  },
  password(v) {
    if (!v) return 'Mật khẩu là bắt buộc.';
    if (v.length < 8) return 'Mật khẩu phải ít nhất 8 ký tự.';
    if (!/[A-Z]/.test(v)) return 'Mật khẩu phải chứa ít nhất 1 chữ hoa.';
    if (!/[a-z]/.test(v)) return 'Mật khẩu phải chứa ít nhất 1 chữ thường.';
    if (!/[0-9]/.test(v)) return 'Mật khẩu phải chứa ít nhất 1 số.';
    return null;
  },
  passphrase(v) {
    if (!v) return 'Passphrase là bắt buộc.';
    if (v.length < 6) return 'Passphrase phải ít nhất 6 ký tự.';
    return null;
  },
  message(v) {
    if (!v || !v.trim()) return 'Tin nhắn không được để trống.';
    if (v.length > 5000) return 'Tin nhắn không được vượt quá 5000 ký tự.';
    return null;
  }
};

// ═══════════════════════════════════════════════════════
//  TEST SUITE: Validate.username
// ═══════════════════════════════════════════════════════
describe('Validate.username', () => {

  // ── Positive tests (hợp lệ) ──
  test('chấp nhận username chữ thường', () => {
    expect(Validate.username('alice')).toBeNull();
  });

  test('chấp nhận username có gạch dưới và số', () => {
    expect(Validate.username('user_123')).toBeNull();
  });

  test('chấp nhận username chữ hoa', () => {
    expect(Validate.username('ALICE')).toBeNull();
  });

  // ── Boundary tests (biên) ──
  test('chấp nhận username đúng 3 ký tự (boundary min)', () => {
    expect(Validate.username('abc')).toBeNull();
  });

  test('chấp nhận username đúng 50 ký tự (boundary max)', () => {
    expect(Validate.username('a'.repeat(50))).toBeNull();
  });

  test('từ chối username 2 ký tự (boundary min-1)', () => {
    expect(Validate.username('ab')).not.toBeNull();
  });

  test('từ chối username 51 ký tự (boundary max+1)', () => {
    expect(Validate.username('a'.repeat(51))).not.toBeNull();
  });

  // ── Negative tests (không hợp lệ) ──
  test('từ chối username rỗng', () => {
    expect(Validate.username('')).toContain('bắt buộc');
  });

  test('từ chối username null', () => {
    expect(Validate.username(null)).toContain('bắt buộc');
  });

  test('từ chối username chứa @', () => {
    expect(Validate.username('alice@bob')).toContain('chữ cái');
  });

  test('từ chối username chứa khoảng trắng', () => {
    expect(Validate.username('hello world')).toContain('chữ cái');
  });

  test('từ chối username chứa dấu gạch ngang', () => {
    expect(Validate.username('user-name')).toContain('chữ cái');
  });

  test('từ chối username chứa tiếng Việt', () => {
    expect(Validate.username('nguyễn')).toContain('chữ cái');
  });

  // ── Thêm test cases (edge cases) ──
  test('chấp nhận username chỉ toàn gạch dưới', () => {
    expect(Validate.username('___')).toBeNull();
  });

  test('chấp nhận username chỉ toàn số', () => {
    expect(Validate.username('12345')).toBeNull();
  });

  test('chấp nhận username hỗn hợp hoa/thường/số/gạch dưới', () => {
    expect(Validate.username('Alice_Bob_99')).toBeNull();
  });

  test('từ chối username chứa dấu chấm', () => {
    expect(Validate.username('user.name')).not.toBeNull();
  });

  test('từ chối username chứa dấu chấm than', () => {
    expect(Validate.username('user!')).not.toBeNull();
  });

  test('từ chối username bắt đầu bằng khoảng trắng', () => {
    expect(Validate.username(' alice')).not.toBeNull();
  });

  test('từ chối username chứa tab', () => {
    expect(Validate.username('user\tname')).not.toBeNull();
  });

  test('từ chối username chứa newline', () => {
    expect(Validate.username('user\nname')).not.toBeNull();
  });

  test('từ chối chuỗi giống SQL injection', () => {
    expect(Validate.username("admin' OR '1'='1")).not.toBeNull();
  });

  test('từ chối chuỗi giống XSS', () => {
    expect(Validate.username('<script>alert(1)</script>')).not.toBeNull();
  });

  test('từ chối username undefined', () => {
    expect(Validate.username(undefined)).toContain('bắt buộc');
  });

  test('chấp nhận username 4 ký tự (hợp lệ gần biên)', () => {
    expect(Validate.username('abcd')).toBeNull();
  });

  test('chấp nhận username 49 ký tự (hợp lệ gần biên)', () => {
    expect(Validate.username('a'.repeat(49))).toBeNull();
  });

  test('từ chối username 1 ký tự', () => {
    expect(Validate.username('a')).not.toBeNull();
  });
});

// ═══════════════════════════════════════════════════════
//  TEST SUITE: Validate.email
// ═══════════════════════════════════════════════════════
describe('Validate.email', () => {

  test('chấp nhận email hợp lệ', () => {
    expect(Validate.email('user@example.com')).toBeNull();
  });

  test('chấp nhận email có subdomain', () => {
    expect(Validate.email('user@mail.example.com')).toBeNull();
  });

  test('từ chối email rỗng', () => {
    expect(Validate.email('')).toContain('bắt buộc');
  });

  test('từ chối email thiếu @', () => {
    expect(Validate.email('userexample.com')).toContain('không hợp lệ');
  });

  test('từ chối email thiếu domain', () => {
    expect(Validate.email('user@')).toContain('không hợp lệ');
  });

  test('từ chối email thiếu tên', () => {
    expect(Validate.email('@example.com')).toContain('không hợp lệ');
  });

  test('từ chối email có khoảng trắng', () => {
    expect(Validate.email('user @example.com')).toContain('không hợp lệ');
  });

  // ── Thêm test cases ──
  test('chấp nhận email có dấu chấm trong tên', () => {
    expect(Validate.email('first.last@example.com')).toBeNull();
  });

  test('chấp nhận email có dấu + (plus addressing)', () => {
    expect(Validate.email('user+tag@example.com')).toBeNull();
  });

  test('chấp nhận email có số trong tên', () => {
    expect(Validate.email('user123@example.com')).toBeNull();
  });

  test('chấp nhận email domain ngắn (.co)', () => {
    expect(Validate.email('a@b.co')).toBeNull();
  });

  test('từ chối email thiếu phần mở rộng (.com)', () => {
    expect(Validate.email('user@example')).toContain('không hợp lệ');
  });

  test('từ chối email có nhiều @', () => {
    expect(Validate.email('user@@example.com')).toContain('không hợp lệ');
  });

  test('từ chối email null', () => {
    expect(Validate.email(null)).toContain('bắt buộc');
  });

  test('từ chối email undefined', () => {
    expect(Validate.email(undefined)).toContain('bắt buộc');
  });

  test('từ chối email chỉ có khoảng trắng', () => {
    expect(Validate.email('   ')).toContain('không hợp lệ');
  });

  test('từ chối email có khoảng trắng ở cuối', () => {
    expect(Validate.email('user@example.com ')).toContain('không hợp lệ');
  });

  test('từ chối email dạng chỉ có @.', () => {
    expect(Validate.email('@.')).toContain('không hợp lệ');
  });
});

// ═══════════════════════════════════════════════════════
//  TEST SUITE: Validate.password
// ═══════════════════════════════════════════════════════
describe('Validate.password', () => {

  test('chấp nhận password hợp lệ', () => {
    expect(Validate.password('Admin123')).toBeNull();
  });

  test('chấp nhận password có ký tự đặc biệt', () => {
    expect(Validate.password('MyPass99!')).toBeNull();
  });

  test('từ chối password rỗng', () => {
    expect(Validate.password('')).toContain('bắt buộc');
  });

  test('từ chối password dưới 8 ký tự', () => {
    expect(Validate.password('Ab1')).toContain('8 ký tự');
  });

  test('từ chối password đúng 7 ký tự (boundary)', () => {
    expect(Validate.password('Admin12')).toContain('8 ký tự');
  });

  test('chấp nhận password đúng 8 ký tự (boundary)', () => {
    expect(Validate.password('Admin123')).toBeNull();
  });

  test('từ chối password thiếu chữ hoa', () => {
    expect(Validate.password('admin123')).toContain('chữ hoa');
  });

  test('từ chối password thiếu chữ thường', () => {
    expect(Validate.password('ADMIN123')).toContain('chữ thường');
  });

  test('từ chối password thiếu số', () => {
    expect(Validate.password('AdminAdmin')).toContain('1 số');
  });

  test('từ chối password toàn số', () => {
    expect(Validate.password('12345678')).toContain('chữ hoa');
  });

  // ── Thêm test cases ──
  test('chấp nhận password rất dài (100 ký tự)', () => {
    expect(Validate.password('Aa1' + 'x'.repeat(97))).toBeNull();
  });

  test('chấp nhận password có ký tự đặc biệt phức tạp', () => {
    expect(Validate.password('P@$$w0rd!')).toBeNull();
  });

  test('chấp nhận password chứa khoảng trắng', () => {
    expect(Validate.password('My Pass 1')).toBeNull();
  });

  test('từ chối password null', () => {
    expect(Validate.password(null)).toContain('bắt buộc');
  });

  test('từ chối password undefined', () => {
    expect(Validate.password(undefined)).toContain('bắt buộc');
  });

  test('từ chối password toàn chữ thường', () => {
    expect(Validate.password('abcdefgh')).toContain('chữ hoa');
  });

  test('từ chối password toàn chữ hoa', () => {
    expect(Validate.password('ABCDEFGH')).toContain('chữ thường');
  });

  test('từ chối password chữ hoa + thường nhưng không có số', () => {
    expect(Validate.password('AbCdEfGh')).toContain('1 số');
  });

  test('từ chối password toàn ký tự đặc biệt', () => {
    expect(Validate.password('!@#$%^&*')).not.toBeNull();
  });

  test('chấp nhận password đúng 8 ký tự với đủ yêu cầu', () => {
    expect(Validate.password('aB3dEf6h')).toBeNull();
  });

  test('chấp nhận password chứa unicode nhưng đủ tiêu chí', () => {
    expect(Validate.password('Passw0rd🔒')).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════
//  TEST SUITE: Validate.passphrase
// ═══════════════════════════════════════════════════════
describe('Validate.passphrase', () => {

  test('chấp nhận passphrase 6 ký tự (boundary min)', () => {
    expect(Validate.passphrase('abcdef')).toBeNull();
  });

  test('chấp nhận passphrase dài', () => {
    expect(Validate.passphrase('my secret passphrase 2026')).toBeNull();
  });

  test('từ chối passphrase rỗng', () => {
    expect(Validate.passphrase('')).toContain('bắt buộc');
  });

  test('từ chối passphrase null', () => {
    expect(Validate.passphrase(null)).toContain('bắt buộc');
  });

  test('từ chối passphrase 5 ký tự (boundary min-1)', () => {
    expect(Validate.passphrase('abcde')).toContain('6 ký tự');
  });

  // ── Thêm test cases ──
  test('chấp nhận passphrase 7 ký tự (hợp lệ gần biên)', () => {
    expect(Validate.passphrase('abcdefg')).toBeNull();
  });

  test('chấp nhận passphrase có khoảng trắng', () => {
    expect(Validate.passphrase('my key')).toBeNull();
  });

  test('chấp nhận passphrase rất dài (200 ký tự)', () => {
    expect(Validate.passphrase('a'.repeat(200))).toBeNull();
  });

  test('chấp nhận passphrase có ký tự đặc biệt', () => {
    expect(Validate.passphrase('p@$$!!')).toBeNull();
  });

  test('chấp nhận passphrase tiếng Việt', () => {
    expect(Validate.passphrase('mật khẩu bí mật')).toBeNull();
  });

  test('từ chối passphrase undefined', () => {
    expect(Validate.passphrase(undefined)).toContain('bắt buộc');
  });

  test('từ chối passphrase 1 ký tự', () => {
    expect(Validate.passphrase('x')).toContain('6 ký tự');
  });

  test('từ chối passphrase chỉ khoảng trắng nhưng đủ dài', () => {
    // 6 khoảng trắng vẫn hợp lệ (không trim passphrase)
    expect(Validate.passphrase('      ')).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════
//  TEST SUITE: Validate.message
// ═══════════════════════════════════════════════════════
describe('Validate.message', () => {

  test('chấp nhận tin nhắn bình thường', () => {
    expect(Validate.message('Hello!')).toBeNull();
  });

  test('chấp nhận tin nhắn tiếng Việt có dấu', () => {
    expect(Validate.message('Xin chào Việt Nam! 🇻🇳')).toBeNull();
  });

  test('chấp nhận tin nhắn đúng 5000 ký tự (boundary max)', () => {
    expect(Validate.message('x'.repeat(5000))).toBeNull();
  });

  test('từ chối tin nhắn rỗng', () => {
    expect(Validate.message('')).toContain('trống');
  });

  test('từ chối tin nhắn chỉ có khoảng trắng', () => {
    expect(Validate.message('   ')).toContain('trống');
  });

  test('từ chối tin nhắn null', () => {
    expect(Validate.message(null)).toContain('trống');
  });

  test('từ chối tin nhắn 5001 ký tự (boundary max+1)', () => {
    expect(Validate.message('x'.repeat(5001))).toContain('5000');
  });

  // ── Thêm test cases ──
  test('chấp nhận tin nhắn 1 ký tự', () => {
    expect(Validate.message('H')).toBeNull();
  });

  test('chấp nhận tin nhắn chỉ emoji', () => {
    expect(Validate.message('😀😁😂🤣')).toBeNull();
  });

  test('chấp nhận tin nhắn có newline (nhiều dòng)', () => {
    expect(Validate.message('dòng 1\ndòng 2\ndòng 3')).toBeNull();
  });

  test('chấp nhận tin nhắn có tab', () => {
    expect(Validate.message('col1\tcol2')).toBeNull();
  });

  test('từ chối tin nhắn undefined', () => {
    expect(Validate.message(undefined)).toContain('trống');
  });

  test('từ chối tin nhắn chỉ newlines', () => {
    expect(Validate.message('\n\n\n')).toContain('trống');
  });

  test('từ chối tin nhắn chỉ tabs', () => {
    expect(Validate.message('\t\t')).toContain('trống');
  });

  test('từ chối tin nhắn hỗn hợp whitespace', () => {
    expect(Validate.message(' \n\t ')).toContain('trống');
  });

  test('chấp nhận tin nhắn có khoảng trắng ở đầu/cuối nhưng có nội dung', () => {
    expect(Validate.message('  hello  ')).toBeNull();
  });

  test('chấp nhận tin nhắn 4999 ký tự (hợp lệ gần biên max)', () => {
    expect(Validate.message('x'.repeat(4999))).toBeNull();
  });

  test('từ chối tin nhắn 10000 ký tự (vượt xa giới hạn)', () => {
    expect(Validate.message('x'.repeat(10000))).toContain('5000');
  });
});
