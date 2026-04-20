/**
 * app.js — E2EE Chat v3 (bugfix edition)
 * Fixed bugs: 1, 2, 4, 5, 6
 */
'use strict';

const State = {
  token:          null,
  userID:         null,
  username:       null,
  displayName:    null,
  encPrivKey:     null,
  privKeySign:    null,
  privKeyDecrypt: null,
  pubKeyB64:      null,
  pubKeyForEncrypt: null,   // Bug 5: CryptoKey for self-encrypt
  keyMap:         {},       // Bug 2: keyID → CryptoKey (decrypt) for all known keys
  currentContact: null,
  contacts:       [],
  messages:       {}
};

// ─────────────────────────────────────────────
//  API helper
// ─────────────────────────────────────────────
async function api(method, path, body=null) {
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(State.token ? { 'Authorization': `Bearer ${State.token}` } : {})
    }
  };
  if (body) opts.body = JSON.stringify(body);
  const res  = await fetch(`/api${path}`, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// ─────────────────────────────────────────────
//  Socket.IO
// ─────────────────────────────────────────────
let socket = null;

function connectSocket() {
  socket = io({ auth: { token: State.token } });
  socket.on('connect',    () => ui.setStatus('online'));
  socket.on('disconnect', () => ui.setStatus('offline'));

  socket.on('new_message', async (packet) => {
    socket.emit('ack', { messageID: packet.messageID });
    let senderPubKey;
    try {
      const kd = await api('GET', `/contacts/pubkey/${packet.senderID}`);
      if (kd.keyChanged) ui.toast('⚠ Public key người gửi đã thay đổi!', 'warn');
      senderPubKey = await E2EE.importPublicKeyForVerify(kd.publicKey);
    } catch { ui.addMessage(packet, null, { tamperAlert:true, isVerified:false }); return; }

    const result = await E2EE.decryptMessage(packet, State.privKeyDecrypt, senderPubKey);
    // Bug 4: always PATCH to update tamperAlert in DB, not just on first verify
    await api('PATCH', `/messages/${packet.messageID}/verify`, {
      sigVerified: result.isVerified, tamperAlert: result.tamperAlert
    }).catch(()=>{});
    ui.addMessage(packet, result.plaintext, result);
    if (State.currentContact?.userID !== packet.senderID) ui.showUnread(packet.senderID);
  });

  socket.on('contact_request',  (d) => ui.onContactRequest(d));
  socket.on('contact_accepted', (d) => ui.onContactAccepted(d));
  socket.on('typing',      ({ fromUserID }) => ui.showTyping(fromUserID));
  socket.on('stop_typing', ({ fromUserID }) => ui.hideTyping(fromUserID));
}

// ─────────────────────────────────────────────
//  Session persistence (JWT in sessionStorage)
// ─────────────────────────────────────────────
function saveSession(token, userID, username, displayName, encPrivKey) {
  sessionStorage.setItem('e2ee_session', JSON.stringify({ token, userID, username, displayName, encPrivKey }));
}

function loadSession() {
  try { return JSON.parse(sessionStorage.getItem('e2ee_session')); } catch { return null; }
}

function clearSession() { sessionStorage.removeItem('e2ee_session'); }

// ─────────────────────────────────────────────
//  Boot
// ─────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  const saved = loadSession();
  if (!saved) { ui.showAuth(); return; }

  Object.assign(State, {
    token:       saved.token,
    userID:      saved.userID,
    username:    saved.username,
    displayName: saved.displayName,
    encPrivKey:  saved.encPrivKey
  });

  ui.showUnlock();
});

// ─────────────────────────────────────────────
//  Auth
// ─────────────────────────────────────────────
// ─── Input Validation Helpers ───
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

async function register(username, email, password, passphrase) {
  ui.setLoading(true);
  try {
    // Client-side validation
    const err = Validate.username(username) || Validate.email(email) || Validate.password(password) || Validate.passphrase(passphrase);
    if (err) throw new Error(err);

    const data = await api('POST', '/auth/register', { username, email, password });
    Object.assign(State, { token: data.sessionToken, userID: data.userID, username: data.username, displayName: data.displayName });

    ui.setLoadingText('Đang tạo cặp khóa RSA-2048...');
    const { pubKeyB64, encPrivKey } = await E2EE.generateKeyPair(passphrase);
    Object.assign(State, { pubKeyB64, encPrivKey });

    await api('POST', '/keys', { publicKey: pubKeyB64, privateKey: encPrivKey });
    await unlockKeys(encPrivKey, passphrase);

    // Unlock all keys + init pubKeyForEncrypt for dual encryption (Bug 5)
    await unlockAllKeys(passphrase);

    saveSession(State.token, State.userID, State.username, State.displayName, encPrivKey);
    connectSocket();
    await loadContacts();
    ui.showApp();
  } catch(err) { ui.showAuthError(err.message); }
  ui.setLoading(false);
}

async function login(username, password, passphrase) {
  ui.setLoading(true);
  try {
    // Client-side validation
    if (!username) throw new Error('Tên đăng nhập là bắt buộc.');
    if (!password) throw new Error('Mật khẩu là bắt buộc.');
    const ppErr = Validate.passphrase(passphrase);
    if (ppErr) throw new Error(ppErr);

    const data = await api('POST', '/auth/login', { username, password });
    Object.assign(State, { token: data.sessionToken, userID: data.userID, username: data.username, displayName: data.displayName, encPrivKey: data.encPrivKey });

    if (!data.hasKeys) throw new Error('Tài khoản chưa có khóa RSA. Hãy đăng ký lại.');

    ui.setLoadingText('Đang giải mã khóa riêng tư...');
    await unlockKeys(data.encPrivKey, passphrase);

    const keyData = await api('GET', '/keys/me');
    State.pubKeyB64 = keyData.publicKey;

    // Bug 2: unlock all historical keys
    await unlockAllKeys(passphrase);

    saveSession(State.token, State.userID, State.username, State.displayName, data.encPrivKey);
    connectSocket();
    await loadContacts();
    ui.showApp();
  } catch(err) { ui.showAuthError(err.message); }
  ui.setLoading(false);
}

// Called from unlock screen after reload
async function unlock(passphrase) {
  const saved = loadSession();
  if (!saved) throw new Error('Không tìm thấy phiên đăng nhập. Vui lòng đăng nhập lại.');

  await unlockKeys(saved.encPrivKey, passphrase);

  const keyData = await api('GET', '/keys/me');
  State.pubKeyB64 = keyData.publicKey;

  // Bug 2: unlock all historical keys
  await unlockAllKeys(passphrase);

  connectSocket();
  await loadContacts();
  ui.showApp();
}

async function unlockKeys(encPrivKey, passphrase) {
  State.privKeySign    = await E2EE.decryptPrivateKey(encPrivKey, passphrase);
  State.privKeyDecrypt = await E2EE.importPrivateKeyForDecrypt(encPrivKey, passphrase);
  // Always re-import pubKeyForEncrypt for dual encryption (must match current pubKeyB64)
  if (State.pubKeyB64) {
    State.pubKeyForEncrypt = await E2EE.importPublicKeyForEncrypt(State.pubKeyB64);
  }
}

/**
 * Bug 2 + 5: Unlock ALL historical keys (active + revoked).
 * Also imports own active pubkey for encryption (Bug 5 dual encrypt).
 */
async function unlockAllKeys(passphrase) {
  State.keyMap = {};
  try {
    const allKeys = await api('GET', '/keys/all');
    for (const k of allKeys) {
      try {
        const privKey = await E2EE.importPrivateKeyForDecrypt(k.privateKey, passphrase);
        State.keyMap[k.keyID] = privKey;
      } catch {
        // Wrong passphrase for this key, or corrupted — skip
        State.keyMap[k.keyID] = null;
      }
    }
    // Bug 5: import own active public key for self-encryption
    if (State.pubKeyB64) {
      State.pubKeyForEncrypt = await E2EE.importPublicKeyForEncrypt(State.pubKeyB64);
    }
  } catch(e) {
    // Non-critical — main keys still work for new messages
    console.warn('unlockAllKeys failed:', e.message);
  }
}

async function logout() {
  try { await api('POST', '/auth/logout'); } catch {}
  socket?.disconnect();
  clearSession();
  Object.assign(State, {
    token:null, userID:null, username:null, encPrivKey:null,
    privKeySign:null, privKeyDecrypt:null, pubKeyB64:null, pubKeyForEncrypt:null,
    keyMap:{}, currentContact:null, contacts:[], messages:{}
  });
  ui.showAuth();
}

// ─────────────────────────────────────────────
//  Contact invitation flow
// ─────────────────────────────────────────────
async function loadContacts() {
  const data = await api('GET', '/contacts');
  State.contacts = data;
  ui.renderContacts(data);
  ui.loadPendingRequests().catch(()=>{});
}

async function sendContactRequest(toUserID) {
  return api('POST', '/contacts/request', { toUserID });
}

async function getPendingRequests() {
  return api('GET', '/contacts/requests/pending');
}

async function acceptRequest(requestID) {
  await api('POST', `/contacts/requests/${requestID}/accept`);
  await loadContacts();
}

async function rejectRequest(requestID) {
  return api('POST', `/contacts/requests/${requestID}/reject`);
}

async function searchUsers(q) {
  return api('GET', `/contacts/search?q=${encodeURIComponent(q)}`);
}

async function openChat(contactUserID) {
  const kd = await api('GET', `/contacts/pubkey/${contactUserID}`);
  if (kd.keyChanged) ui.toast('⚠ Public key liên hệ đã thay đổi! Xác minh danh tính.', 'warn');
  const c = State.contacts.find(x => x.contactUserID === contactUserID);
  State.currentContact = { userID: contactUserID, username: c?.username||`User ${contactUserID}`, pubKeyB64: kd.publicKey, keyID: kd.keyID };
  ui.openChatPanel(State.currentContact);
  await loadHistory(contactUserID, 1);
}

// ─────────────────────────────────────────────
//  Messaging
// ─────────────────────────────────────────────
async function sendMessage(plaintext) {
  if (!State.currentContact) return;
  const msgErr = Validate.message(plaintext);
  if (msgErr) { ui.toast(msgErr, 'warn'); return; }
  try {
    // Bug 1: always re-fetch receiver's latest public key before encrypting
    // (in case they revoked and regenerated their key while chat was open)
    const kd = await api('GET', `/contacts/pubkey/${State.currentContact.userID}`);
    if (kd.keyChanged) {
      ui.toast('⚠ Public key người nhận đã thay đổi, đang dùng khóa mới nhất.', 'warn');
      State.currentContact.pubKeyB64 = kd.publicKey;
      State.currentContact.keyID     = kd.keyID;
    }

    const receiverPubKey = await E2EE.importPublicKeyForEncrypt(kd.publicKey);

    // Bug 5: also encrypt with sender's own pubkey (dual encryption)
    const packet = await E2EE.encryptMessage(
      plaintext, receiverPubKey, State.privKeySign, State.pubKeyForEncrypt
    );

    const result = await api('POST', '/messages', {
      receiverID:    State.currentContact.userID,
      receiverKeyID: kd.keyID,
      ...packet
    });

    // Update keyMap with sender's current key (for decrypting own future history)
    const myKeyData = await api('GET', '/keys/me').catch(() => null);
    if (myKeyData && !State.keyMap[myKeyData.keyID]) {
      try {
        State.keyMap[myKeyData.keyID] = State.privKeyDecrypt;
      } catch {}
    }

    ui.addMessage(
      { messageID: result.messageID, senderID: State.userID, timestamp: new Date().toISOString() },
      plaintext,
      { isVerified:true, tamperAlert:false },
      true
    );
    socket?.emit('stop_typing', { toUserID: State.currentContact.userID });
  } catch(err) { ui.toast('Gửi tin thất bại: '+err.message, 'error'); }
}

async function loadHistory(contactID, page=1) {
  ui.setHistoryLoading(true);
  try {
    const data = await api('GET', `/messages/${contactID}?page=${page}&limit=20`);

    // Fetch ALL public keys of the contact (active + revoked) for signature verification.
    // After key rotation, old messages were signed with the OLD private key,
    // so we need the matching OLD public key to verify — not the current one.
    const contactAllKeys = await api('GET', `/keys/user/${contactID}/public-all`);
    const contactPubKeyMap = {};  // keyID → CryptoKey (for verify)
    for (const k of contactAllKeys) {
      try {
        contactPubKeyMap[k.keyID] = await E2EE.importPublicKeyForVerify(k.publicKey);
      } catch { /* skip corrupt key */ }
    }

    const myID = State.userID;
    const isPaging = page > 1;

    // Bug 6 FIX: when prepending (load more), iterate in reverse order (newest → oldest)
    // because each insertBefore pushes the element to the very top.
    // After all inserts: oldest ends up at top of batch → correct chronological display.
    const msgsToRender = isPaging ? [...data.messages].reverse() : data.messages;

    for (const msg of msgsToRender) {
      if (msg.senderID === myID) {
        // OWN SENT MESSAGES: decrypt using senderEncSessionKey + own historical private key
        let plaintext = null;
        if (msg.senderEncSessionKey) {
          // senderEncSessionKey was encrypted with OUR pubkey at send time.
          // After key rotation, need the OLD private key → lookup by senderKeyID.
          const myPrivKey = State.keyMap[msg.senderKeyID] || State.privKeyDecrypt;
          if (myPrivKey) {
            try {
              const K = await E2EE.decryptRSA(msg.senderEncSessionKey, myPrivKey);
              plaintext = await E2EE.decryptAES(msg.ciphertext, K, msg.aesIV);
            } catch {
              plaintext = null;
            }
          }
        }
        ui.renderHistoryMessage(msg, plaintext, null, true, isPaging);
      } else {
        // RECEIVED MESSAGES: decrypt with own historical private key + verify with sender's historical pubkey
        const privKeyDecrypt = State.keyMap[msg.receiverKeyID] || State.privKeyDecrypt;

        // Use the sender's pubkey that matches senderKeyID (the key used to sign this message)
        const senderPubKey = contactPubKeyMap[msg.senderKeyID] || null;

        let r;
        if (!senderPubKey) {
          // Can't find matching pubkey for verification — still try to decrypt
          try {
            const K = await E2EE.decryptRSA(msg.encSessionKey, privKeyDecrypt);
            const plaintext = await E2EE.decryptAES(msg.ciphertext, K, msg.aesIV);
            r = { plaintext, isVerified: false, tamperAlert: false };
          } catch {
            r = { plaintext: null, isVerified: false, tamperAlert: true };
          }
        } else {
          try {
            r = await E2EE.decryptMessage(msg, privKeyDecrypt, senderPubKey);
          } catch {
            r = { plaintext: null, isVerified: false, tamperAlert: true };
          }
        }

        // Bug 4: always PATCH when tamper detected
        if (r.tamperAlert || !msg.sigVerified) {
          await api('PATCH', `/messages/${msg.messageID}/verify`, {
            sigVerified: r.isVerified,
            tamperAlert: r.tamperAlert
          }).catch(()=>{});
        }
        ui.renderHistoryMessage(msg, r.plaintext, r, false, isPaging);
      }
    }

    // Bug 6: show/hide load-more button correctly
    if (data.hasMore) {
      ui.showLoadMoreBtn(contactID, page + 1);
    } else {
      ui.hideLoadMoreBtn();
    }
  } catch(err) { ui.toast('Tải lịch sử thất bại: '+err.message, 'error'); }
  ui.setHistoryLoading(false);
}

async function revokeAndRegenKey(passphrase, reason) {
  // GUARD: verify passphrase is correct by trying to decrypt current private key first.
  // If wrong passphrase → abort immediately, do NOT revoke the old key.
  try {
    await E2EE.decryptPrivateKey(State.encPrivKey, passphrase);
  } catch {
    throw new Error('Passphrase không đúng. Không thể thu hồi khóa.');
  }

  await api('POST', '/keys/revoke', { reason });
  const { pubKeyB64, encPrivKey } = await E2EE.generateKeyPair(passphrase);
  Object.assign(State, { pubKeyB64, encPrivKey });
  await api('POST', '/keys', { publicKey: pubKeyB64, privateKey: encPrivKey });
  await unlockKeys(encPrivKey, passphrase);
  // Bug 2: refresh keyMap with all keys after regen
  await unlockAllKeys(passphrase);
  saveSession(State.token, State.userID, State.username, State.displayName, encPrivKey);
  ui.toast('Khóa mới đã được tạo và kích hoạt.', 'success');
}

window.App = {
  register, login, unlock, logout,
  sendMessage, loadHistory,
  sendContactRequest, getPendingRequests, acceptRequest, rejectRequest,
  searchUsers, openChat,
  revokeAndRegenKey, loadContacts,
  getState: () => State
};
