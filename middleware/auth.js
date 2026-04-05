const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'e2ee-chat-secret-change-in-production';

/**
 * Middleware: verify JWT from Authorization header.
 * Attaches decoded { userID } to req.user on success.
 */
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { userID: payload.userID };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token expired or invalid' });
  }
}

module.exports = { requireAuth, JWT_SECRET };
