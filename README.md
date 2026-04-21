# E2EE Chat Application

**Đồ án cá nhân — Mai Đức Duy — 22127084**

Ứng dụng chat Peer-to-Peer với mã hóa đầu cuối (End-to-End Encryption) sử dụng mô hình Hybrid Encryption (RSA-OAEP + AES-256-GCM + RSA-PSS).

---

## Cài đặt và chạy

```bash
# 1. Cài dependencies
npm install

# 2. Chạy server
npm start
# hoặc chế độ dev (auto-reload)
npm run dev

# 3. Mở trình duyệt
# http://localhost:3000
```

> **Yêu cầu:** Node.js ≥ 18.0

---

## Kiểm thử (Testing)

Dự án sử dụng **Jest** + **Supertest** với 204 test cases tự động.

```bash
# Chạy toàn bộ test
npm test

# Chỉ chạy unit tests
npx jest tests/unit/ --verbose

# Chỉ chạy integration tests
npx jest tests/integration/ --verbose
```

### Tổng quan test suite

| File | Loại | Số test | Mô tả |
|------|------|---------|--------|
| `validation.test.js` | Unit | 84 | Kiểm tra input validation (username, email, password, passphrase, message) |
| `auth.unit.test.js` | Unit | 12 | Kiểm tra JWT token và bcrypt hashing |
| `auth.api.test.js` | Integration | 35 | API đăng ký, đăng nhập, JWT middleware, đăng xuất |
| `keys.api.test.js` | Integration | 11 | API quản lý khóa RSA (tạo, lấy, thu hồi, lịch sử) |
| `contacts.api.test.js` | Integration | 19 | API liên hệ (tìm kiếm, gửi/chấp nhận/từ chối lời mời, xóa) |
| `messages.api.test.js` | Integration | 43 | API tin nhắn (gửi, phân trang, xác thực chữ ký) |

### Kỹ thuật kiểm thử áp dụng

- **Boundary Value Analysis**: Test giá trị biên (min, min-1, max, max+1)
- **Equivalence Partitioning**: Phân lớp đầu vào hợp lệ/không hợp lệ
- **Negative Testing**: Thiếu field, sai format, body rỗng, SQL injection, XSS
- **Security Testing**: Kiểm tra không lộ private key, bcrypt hash, JWT integrity
- **Workflow Testing**: Test luồng hoàn chỉnh (request → accept → chat → verify)

---

## Cấu trúc dự án

```
E2E_Chat/
├── server.js              # HTTP Server + Socket.IO (listen)
├── expressApp.js          # Express app + routes (tách cho testability)
├── db.js                  # SQLite schema + migrations (better-sqlite3, WAL mode)
├── middleware/
│   └── auth.js            # JWT verification middleware
├── routes/
│   ├── auth.js            # POST /api/auth/register|login|logout + input validation
│   ├── keys.js            # GET/POST /api/keys (CRUD + revoke + history)
│   ├── messages.js        # POST/GET/PATCH /api/messages (dual encryption)
│   └── contacts.js        # GET/POST/DELETE /api/contacts (request/accept/reject)
├── public/
│   ├── index.html         # UI (auth screen + chat app) + CSS
│   ├── crypto.js          # WebCrypto API — 18 hàm mật mã
│   └── app.js             # Frontend logic + Socket.IO client + validation
├── tests/
│   ├── helpers.js         # Hàm tiện ích dùng chung cho test
│   ├── unit/
│   │   ├── validation.test.js   # Unit test: input validation (84 tests)
│   │   └── auth.unit.test.js    # Unit test: JWT + bcrypt (12 tests)
│   └── integration/
│       ├── auth.api.test.js     # Integration test: auth API (35 tests)
│       ├── keys.api.test.js     # Integration test: keys API (11 tests)
│       ├── contacts.api.test.js # Integration test: contacts API (19 tests)
│       └── messages.api.test.js # Integration test: messages API (43 tests)
└── e2ee_chat.db           # SQLite database (tự tạo khi chạy)
```

---

## Kiến trúc bảo mật

### Mô hình bảo mật 3 lớp Input Validation

```
HTML5 Attributes (minlength, maxlength, pattern)
        ↓
Frontend JavaScript (Validate object trong app.js)
        ↓
Backend Express (routes/auth.js — defense-in-depth)
```

### Luồng gửi tin nhắn — Dual Encryption (P4 → P5)

```
plaintext M
    │
    ├─ hashPlaintext()   → H  = SHA-256(M)
    │
    ├─ encryptAES()      → C  = AES-256-GCM(K, IV, M)    K = random 256-bit
    │                                                      IV = random 12-byte
    ├─ encryptRSA()      → K'  = RSA-OAEP(PubKey_B, K)   ← cho receiver giải mã
    │                    → K'' = RSA-OAEP(PubKey_A, K)   ← cho sender tự giải mã
    │
    └─ signHash()        → S  = RSA-PSS(PrivKey_A, H, saltLen=32)

Packet gửi đi: { C, K', K'', S, H, IV, senderKeyID, receiverKeyID }
```

### Luồng nhận và giải mã (P6)

```
Packet { C, K', S, H, IV }
    │
    ├─ decryptRSA()      → K  = RSA-OAEP.decrypt(PrivKey_B, K')
    ├─ decryptAES()      → M  = AES-256-GCM.decrypt(K, IV, C)
    ├─ hashPlaintext()   → H' = SHA-256(M)
    │
    ├─ Integrity check:  H' == H  ?  ✓ : ⚠ tamperAlert
    └─ verifySignature() valid = RSA-PSS.verify(PubKey_A, S, H)
```

### Bảo vệ Private Key

```
Khi tạo khóa:
  passphrase → PBKDF2(100,000 iter, SHA-256, salt=random16) → aesKey
  privKey    → AES-256-GCM(aesKey, IV=random12) → encPrivKey

Khi login:
  encPrivKey (từ server) + passphrase → re-derive aesKey → decrypt → CryptoKey in memory
  Server KHÔNG BAO GIỜ thấy privKey dạng plaintext
```

---

## API Endpoints

### Authentication
| Method | Path | Body | Response |
|--------|------|------|----------|
| POST | `/api/auth/register` | `{ username, email, password }` | `201 { userID, username, sessionToken }` |
| POST | `/api/auth/login`    | `{ username, password }` | `200 { userID, username, sessionToken, encPrivKey? }` |
| POST | `/api/auth/logout`   | — (JWT required) | `200 { message }` |

### Key Management
| Method | Path | Mô tả |
|--------|------|-------|
| POST | `/api/keys` | Upload key pair (auto-revoke cũ) |
| GET  | `/api/keys/me` | Lấy khóa active của mình (có privateKey) |
| GET  | `/api/keys/user/:id` | Lấy public key của người khác (KHÔNG có privateKey) |
| POST | `/api/keys/revoke` | Thu hồi khóa active |
| GET  | `/api/keys/history` | Lịch sử khóa (metadata only) |
| GET  | `/api/keys/all` | Tất cả khóa của mình (cho decrypt tin cũ) |
| GET  | `/api/keys/user/:id/public-all` | Tất cả public keys (cho verify chữ ký cũ) |

### Messages
| Method | Path | Mô tả |
|--------|------|-------|
| POST  | `/api/messages` | Gửi gói tin mã hóa |
| GET   | `/api/messages/:contactID?page=1&limit=20` | Lịch sử tin nhắn (phân trang, max 50) |
| PATCH | `/api/messages/:id/verify` | Cập nhật kết quả xác thực chữ ký |

### Contacts
| Method | Path | Mô tả |
|--------|------|-------|
| GET    | `/api/contacts` | Danh sách liên hệ |
| POST   | `/api/contacts/request` | Gửi lời mời kết bạn |
| GET    | `/api/contacts/requests/pending` | Lời mời đang chờ (nhận) |
| GET    | `/api/contacts/requests/sent` | Lời mời đã gửi |
| POST   | `/api/contacts/requests/:id/accept` | Chấp nhận (tạo 2 chiều) |
| POST   | `/api/contacts/requests/:id/reject` | Từ chối |
| GET    | `/api/contacts/pubkey/:id` | Lấy public key + keyChanged detection |
| GET    | `/api/contacts/search?q=` | Tìm kiếm user (min 2 ký tự) |
| DELETE | `/api/contacts/:id` | Xóa liên hệ (cả 2 chiều) |

---

## Socket.IO Events

| Event | Direction | Payload |
|-------|-----------|---------| 
| `new_message` | Server → Client | `{ messageID, senderID, receiverID, ciphertext, encSessionKey, signature, hashValue, aesIV, ... }` |
| `ack`         | Client → Server | `{ messageID }` |
| `typing`      | Client → Server → Client | `{ toUserID }` / `{ fromUserID }` |
| `stop_typing` | Client → Server → Client | `{ toUserID }` / `{ fromUserID }` |
| `contact_request` | Server → Client | `{ requestID, fromUserID, fromUsername }` |
| `contact_accepted` | Server → Client | `{ byUserID, byUsername }` |

---

## Các tính chất bảo mật đảm bảo

| Tính chất | Cơ chế |
|-----------|--------|
| **Confidentiality** | Chỉ người có PrivKey_B mới giải mã được K' → đọc được C |
| **Integrity** | H' = SHA-256(M_decrypted) phải khớp H trong packet |
| **Authentication** | Chữ ký S verify bằng PubKey_A xác nhận đúng sender |
| **Non-repudiation** | S lưu vĩnh viễn cùng senderKeyID — hợp lệ sau khi thu hồi khóa |
| **Forward Secrecy** | Mỗi tin nhắn dùng AES session key K ngẫu nhiên riêng |
| **Server Blind** | Server chỉ lưu ciphertext — không đọc được nội dung |
| **Self-Decryption** | Dual encryption (K'' cho sender) — sender đọc lại tin nhắn đã gửi |
| **Key Change Detection** | So sánh cachedKeyID + cachedPubKey khi fetch public key |
| **Defense-in-Depth** | Validation 3 lớp: HTML5 → Frontend JS → Backend |

---

## Công nghệ sử dụng

| Thành phần | Công nghệ |
|------------|-----------|
| **Runtime** | Node.js |
| **Framework** | Express.js |
| **Database** | SQLite (better-sqlite3, WAL mode) |
| **Real-time** | Socket.IO |
| **Auth** | JWT (jsonwebtoken) + bcrypt |
| **Crypto** | Web Crypto API (RSA-OAEP, RSA-PSS, AES-256-GCM, PBKDF2, SHA-256) |
| **Testing** | Jest + Supertest (204 automated tests) |

---

## Ghi chú triển khai

- **JWT_SECRET**: Đặt biến môi trường `JWT_SECRET` trước khi deploy production
- **HTTPS**: Bắt buộc dùng HTTPS khi deploy thực tế (WebCrypto yêu cầu secure context)
- Database file `e2ee_chat.db` tự tạo lần đầu chạy (WAL mode cho hiệu suất cao)
- `expressApp.js` tách riêng Express setup để hỗ trợ automated testing với Supertest
