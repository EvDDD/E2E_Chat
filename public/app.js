/**
 * app.js — E2EE Chat v3
 * Changes: invitation flow, bidirectional contacts, sessionStorage JWT, reload unlock
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
//  Private key stays in memory only — requires
//  passphrase re-entry on page reload
// ─────────────────────────────────────────────
function saveSession(token, userID, username, displayName, encPrivKey) {
  sessionStorage.setItem('e2ee_session', JSON.stringify({ token, userID, username, displayName, encPrivKey }));
}

function loadSession() {
  try { return JSON.parse(sessionStorage.getItem('e2ee_session')); } catch { return null; }
}

function clearSession() { sessionStorage.removeItem('e2ee_session'); }

// ─────────────────────────────────────────────
//  Boot: check for existing session on page load
// ─────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  const saved = loadSession();
  if (!saved) { ui.showAuth(); return; }

  // Restore token and user info
  Object.assign(State, {
    token:       saved.token,
    userID:      saved.userID,
    username:    saved.username,
    displayName: saved.displayName,
    encPrivKey:  saved.encPrivKey
  });

  // Private key NOT in memory — ask for passphrase
  ui.showUnlock();
});

// ─────────────────────────────────────────────
//  Auth
// ─────────────────────────────────────────────
async function register(username, email, password, passphrase) {
  ui.setLoading(true);
  try {
    const data = await api('POST', '/auth/register', { username, email, password });
    Object.assign(State, { token: data.sessionToken, userID: data.userID, username: data.username, displayName: data.displayName });

    ui.setLoadingText('Đang tạo cặp khóa RSA-2048...');
    const { pubKeyB64, encPrivKey } = await E2EE.generateKeyPair(passphrase);
    Object.assign(State, { pubKeyB64, encPrivKey });

    await api('POST', '/keys', { publicKey: pubKeyB64, privateKey: encPrivKey });
    await unlockKeys(encPrivKey, passphrase);

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
    const data = await api('POST', '/auth/login', { username, password });
    Object.assign(State, { token: data.sessionToken, userID: data.userID, username: data.username, displayName: data.displayName, encPrivKey: data.encPrivKey });

    if (!data.hasKeys) throw new Error('Tài khoản chưa có khóa RSA. Hãy đăng ký lại.');

    ui.setLoadingText('Đang giải mã khóa riêng tư...');
    await unlockKeys(data.encPrivKey, passphrase);

    const keyData = await api('GET', '/keys/me');
    State.pubKeyB64 = keyData.publicKey;

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

  // Re-decrypt private key into memory
  await unlockKeys(saved.encPrivKey, passphrase); // throws if wrong passphrase

  // Restore pubkey
  const keyData = await api('GET', '/keys/me');
  State.pubKeyB64 = keyData.publicKey;

  connectSocket();
  await loadContacts();
  ui.showApp();
}

async function unlockKeys(encPrivKey, passphrase) {
  State.privKeySign    = await E2EE.decryptPrivateKey(encPrivKey, passphrase);
  State.privKeyDecrypt = await E2EE.importPrivateKeyForDecrypt(encPrivKey, passphrase);
}

async function logout() {
  try { await api('POST', '/auth/logout'); } catch {}
  socket?.disconnect();
  clearSession();
  Object.assign(State, { token:null, userID:null, username:null, encPrivKey:null, privKeySign:null, privKeyDecrypt:null, pubKeyB64:null, currentContact:null, contacts:[], messages:{} });
  ui.showAuth();
}

// ─────────────────────────────────────────────
//  Contact invitation flow
// ─────────────────────────────────────────────
async function loadContacts() {
  const data = await api('GET', '/contacts');
  State.contacts = data;
  ui.renderContacts(data);
  // Refresh pending request badge
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
  await loadContacts(); // refresh both sides
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
  if (!State.currentContact || !plaintext.trim()) return;
  try {
    const receiverPubKey = await E2EE.importPublicKeyForEncrypt(State.currentContact.pubKeyB64);
    const packet         = await E2EE.encryptMessage(plaintext, receiverPubKey, State.privKeySign);
    const result         = await api('POST', '/messages', { receiverID: State.currentContact.userID, receiverKeyID: State.currentContact.keyID, ...packet });
    ui.addMessage({ messageID: result.messageID, senderID: State.userID, timestamp: new Date().toISOString() }, plaintext, { isVerified:true, tamperAlert:false }, true);
    socket?.emit('stop_typing', { toUserID: State.currentContact.userID });
  } catch(err) { ui.toast('Gửi tin thất bại: '+err.message, 'error'); }
}

async function loadHistory(contactID, page=1) {
  ui.setHistoryLoading(true);
  try {
    const data = await api('GET', `/messages/${contactID}?page=${page}&limit=20`);
    const kd   = await api('GET', `/contacts/pubkey/${contactID}`);
    const senderPubKey = await E2EE.importPublicKeyForVerify(kd.publicKey);
    for (const msg of data.messages) {
      if (msg.senderID === State.userID) { ui.renderHistoryMessage(msg, null, null, true); }
      else {
        const r = await E2EE.decryptMessage(msg, State.privKeyDecrypt, senderPubKey);
        if (!msg.sigVerified && !msg.tamperAlert) await api('PATCH', `/messages/${msg.messageID}/verify`, { sigVerified:r.isVerified, tamperAlert:r.tamperAlert }).catch(()=>{});
        ui.renderHistoryMessage(msg, r.plaintext, r, false);
      }
    }
    if (data.hasMore) ui.showLoadMoreBtn(contactID, page+1);
  } catch(err) { ui.toast('Tải lịch sử thất bại: '+err.message, 'error'); }
  ui.setHistoryLoading(false);
}

async function revokeAndRegenKey(passphrase, reason) {
  await api('POST', '/keys/revoke', { reason });
  const { pubKeyB64, encPrivKey } = await E2EE.generateKeyPair(passphrase);
  Object.assign(State, { pubKeyB64, encPrivKey });
  await api('POST', '/keys', { publicKey: pubKeyB64, privateKey: encPrivKey });
  await unlockKeys(encPrivKey, passphrase);
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
