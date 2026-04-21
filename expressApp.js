/**
 * expressApp.js — Express application setup (tách từ server.js)
 * 
 * File này chỉ chứa Express app + routes, KHÔNG có server.listen().
 * Mục đích: cho phép test files import app mà không khởi chạy server thật.
 * 
 * Sử dụng:
 *   - server.js:  require('./expressApp') rồi listen()
 *   - test files: require('./expressApp') rồi dùng Supertest
 */
const express = require('express');
const cors    = require('cors');
const path    = require('path');

const app = express();

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

module.exports = { app, socketRegistry };
