# E2EE Chat Application

**Đồ án cá nhân — Mai Đức Duy — 22127084**

Ứng dụng chat Peer-to-Peer với mã hóa đầu cuối (End-to-End Encryption) sử dụng mô hình Hybrid Encryption.

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

## Cấu trúc dự án

```
e2ee-chat/
├── server.js              # Express + Socket.IO server
├── db.js                  # SQLite schema (better-sqlite3)
├── middleware/
│   └── auth.js            # JWT verification middleware
├── routes/
│   ├── auth.js            # POST /api/auth/register|login|logout
│   ├── keys.js            # GET/POST /api/keys
│   ├── messages.js        # POST/GET /api/messages
│   └── contacts.js        # GET/POST /api/contacts
├── public/
│   ├── index.html         # UI (auth screen + chat app)
│   ├── crypto.js          # WebCrypto API — 18 hàm mật mã
│   └── app.js             # Application logic + Socket.IO client
└── e2ee_chat.db           # SQLite database (tự tạo khi chạy)
```

---

## Kiến trúc bảo mật

### Luồng gửi tin nhắn (P4 → P5)

```
plaintext M
    │
    ├─ hashPlaintext()   → H  = SHA-256(M)
    │
    ├─ encryptAES()      → C  = AES-256-CBC(K, IV, M)    K = random 256-bit
    │                                                      IV = random 16-byte
    ├─ encryptRSA()      → K' = RSA-OAEP(PubKey_B, K)
    │
    └─ signHash()        → S  = RSA-PSS(PrivKey_A, H, saltLen=32)

Packet gửi đi: { C, K', S, H, IV }
```

### Luồng nhận và giải mã (P6)

```
Packet { C, K', S, H, IV }
    │
    ├─ decryptRSA()      → K  = RSA-OAEP.decrypt(PrivKey_B, K')
    ├─ decryptAES()      → M  = AES-256-CBC.decrypt(K, IV, C)
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
| Method | Path | Body |
|--------|------|------|
| POST | `/api/auth/register` | `{ username, email, password, displayName? }` |
| POST | `/api/auth/login`    | `{ username, password }` |
| POST | `/api/auth/logout`   | — (JWT required) |

### Key Management
| Method | Path | |
|--------|------|-|
| POST | `/api/keys` | Upload key pair (JWT) |
| GET  | `/api/keys/me` | Get own active key (JWT) |
| GET  | `/api/keys/user/:id` | Get user's public key (JWT) |
| POST | `/api/keys/revoke` | Revoke active key (JWT) |

### Messages
| Method | Path | |
|--------|------|-|
| POST  | `/api/messages` | Send encrypted packet (JWT) |
| GET   | `/api/messages/:contactID?page=1` | Load history (JWT) |
| PATCH | `/api/messages/:id/verify` | Report sig verification (JWT) |

### Contacts
| Method | Path | |
|--------|------|-|
| GET    | `/api/contacts` | List all contacts (JWT) |
| POST   | `/api/contacts` | Add contact (JWT) |
| GET    | `/api/contacts/pubkey/:id` | Get pubkey + mismatch check (JWT) |
| GET    | `/api/contacts/search?q=` | Search users (JWT) |
| DELETE | `/api/contacts/:id` | Remove contact (JWT) |

---

## Socket.IO Events

| Event | Direction | Payload |
|-------|-----------|---------|
| `new_message` | Server → Client | `{ messageID, senderID, receiverID, ciphertext, encSessionKey, signature, hashValue, aesIV, ... }` |
| `ack`         | Client → Server | `{ messageID }` |
| `typing`      | Client → Server | `{ toUserID }` |
| `stop_typing` | Client → Server | `{ toUserID }` |

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

---

## Ghi chú triển khai

- **JWT_SECRET**: Đặt biến môi trường `JWT_SECRET` trước khi deploy production
- **HTTPS**: Bắt buộc dùng HTTPS khi deploy thực tế (WebCrypto yêu cầu secure context)
- Database file `e2ee_chat.db` tự tạo lần đầu chạy
