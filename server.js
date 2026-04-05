const express   = require('express');
const http      = require('http');
const { Server } = require('socket.io');
const cors      = require('cors');
const path      = require('path');
const jwt       = require('jsonwebtoken');
const db        = require('./db');
const { JWT_SECRET } = require('./middleware/auth');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────
//  Middleware
// ─────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────
//  Socket registry: userID → socket instance
//  Used by messages route for real-time delivery
// ─────────────────────────────────────────────
const socketRegistry = new Map();

// ─────────────────────────────────────────────
//  Routes
// ─────────────────────────────────────────────
const messagesRouter = require('./routes/messages');
const contactsRouter = require('./routes/contacts');
messagesRouter.setSocketRegistry(socketRegistry);
contactsRouter.setSocketRegistry(socketRegistry);

app.use('/api/auth',     require('./routes/auth'));
app.use('/api/keys',     require('./routes/keys'));
app.use('/api/messages', messagesRouter);
app.use('/api/contacts', contactsRouter);

// ─────────────────────────────────────────────
//  Socket.IO — real-time messaging
// ─────────────────────────────────────────────
io.use((socket, next) => {
  // Authenticate socket connection with JWT
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('No token'));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.userID = payload.userID;
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  const userID = socket.userID;

  // Register socket and mark user online
  socketRegistry.set(userID, socket);
  db.prepare("UPDATE users SET status='online', lastSeen=datetime('now') WHERE userID=?").run(userID);

  // Deliver any pending messages that arrived while offline
  const pending = db.prepare(`
    SELECT * FROM messages WHERE receiverID=? AND status='sent'
    ORDER BY timestamp ASC
  `).all(userID);

  for (const msg of pending) {
    socket.emit('new_message', {
      messageID:     msg.messageID,
      senderID:      msg.senderID,
      receiverID:    msg.receiverID,
      senderKeyID:   msg.senderKeyID,
      receiverKeyID: msg.receiverKeyID,
      ciphertext:    msg.ciphertext,
      encSessionKey: msg.encSessionKey,
      signature:     msg.signature,
      hashValue:     msg.hashValue,
      aesIV:         msg.aesIV,
      timestamp:     msg.timestamp
    });
    db.prepare("UPDATE messages SET status='delivered' WHERE messageID=?").run(msg.messageID);
  }

  // Client ACKs delivery
  socket.on('ack', ({ messageID }) => {
    db.prepare("UPDATE messages SET status='delivered' WHERE messageID=?").run(messageID);
  });

  // Typing indicator (forward to contact)
  socket.on('typing', ({ toUserID }) => {
    const target = socketRegistry.get(toUserID);
    if (target) target.emit('typing', { fromUserID: userID });
  });

  socket.on('stop_typing', ({ toUserID }) => {
    const target = socketRegistry.get(toUserID);
    if (target) target.emit('stop_typing', { fromUserID: userID });
  });

  socket.on('disconnect', () => {
    socketRegistry.delete(userID);
    db.prepare("UPDATE users SET status='offline', lastSeen=datetime('now') WHERE userID=?").run(userID);
  });
});

// ─────────────────────────────────────────────
//  Start server
// ─────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`E2EE Chat server running on http://localhost:${PORT}`);
});
