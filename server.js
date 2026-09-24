const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const db = new Database('trade_data.db');
const JWT_SECRET = 'apna_secret_key_12345';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Database Setup & Auto Migration
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'member'
  );

  CREATE TABLE IF NOT EXISTS trade_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    entry_date TEXT NOT NULL,
    day_name TEXT DEFAULT '',
    buy_val REAL NOT NULL DEFAULT 0,
    sell_val REAL NOT NULL DEFAULT 0,
    total_val REAL NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Safe table migration (Purani database file ke saath compatible banane ke liye)
try { db.exec(`ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'member'`); } catch(e){}
try { db.exec(`ALTER TABLE trade_entries ADD COLUMN day_name TEXT DEFAULT ''`); } catch(e){}
try { db.exec(`ALTER TABLE trade_entries ADD COLUMN script_name TEXT DEFAULT ''`); } catch(e){}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Auth Middleware
function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: 'Login required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Session expired, please login again' });
  }
}

// 1. Register API
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Sabhi fields bharna zaroori hai' });
  }
  try {
    const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    const role = totalUsers === 0 ? 'admin' : 'member';

    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)');
    stmt.run(name, email, hashedPassword, role);
    res.json({ message: `Registration safal raha! (${role.toUpperCase()} Account). Ab login karein.` });
  } catch (err) {
    res.status(400).json({ error: 'Email pehle se register hai.' });
  }
});

// 2. Login API
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: 'Galat email ya password' });
  }
  const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
  res.json({ message: 'Login successful', name: user.name, role: user.role });
});

// 3. Logout API
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

// Helper: Date string se Day Name nikalna
function getDayNameFromDate(dateStr) {
  const dateObj = new Date(dateStr + 'T00:00:00');
  return dateObj.toLocaleDateString('en-US', { weekday: 'long' });
}

// 4. Save Entry API (With try/catch error reporting)
app.post('/api/entries', authMiddleware, (req, res) => {
  try {
    const { entry_date, buy_val, sell_val } = req.body;
    if (!entry_date) return res.status(400).json({ error: 'Date zaroori hai' });

    const buy = parseFloat(buy_val) || 0;
    const sell = parseFloat(sell_val) || 0;
    const total = sell - buy;
    const dayName = getDayNameFromDate(entry_date);

    const stmt = db.prepare(`
      INSERT INTO trade_entries (user_id, entry_date, day_name, script_name, buy_val, sell_val, total_val)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(req.user.id, entry_date, dayName, dayName, buy, sell, total);
    res.json({ success: true, message: 'Data successfully save ho gaya!' });
  } catch (err) {
    console.error('Error saving entry:', err);
    res.status(500).json({ error: 'Database save error: ' + err.message });
  }
});

// 5. Update (Edit) Trade Entry API
app.put('/api/entries/:id', authMiddleware, (req, res) => {
  try {
    const entryId = parseInt(req.params.id, 10);
    const { entry_date, buy_val, sell_val } = req.body;

    const buy = parseFloat(buy_val) || 0;
    const sell = parseFloat(sell_val) || 0;
    const total = sell - buy;
    const dayName = getDayNameFromDate(entry_date);

    let stmt;
    if (req.user.role === 'admin') {
      stmt = db.prepare(`
        UPDATE trade_entries 
        SET entry_date = ?, day_name = ?, buy_val = ?, sell_val = ?, total_val = ?
        WHERE id = ?
      `);
      stmt.run(entry_date, dayName, buy, sell, total, entryId);
    } else {
      stmt = db.prepare(`
        UPDATE trade_entries 
        SET entry_date = ?, day_name = ?, buy_val = ?, sell_val = ?, total_val = ?
        WHERE id = ? AND user_id = ?
      `);
      stmt.run(entry_date, dayName, buy, sell, total, entryId, req.user.id);
    }

    res.json({ success: true, message: 'Entry successfully update ho gayi!' });
  } catch (err) {
    console.error('Error updating entry:', err);
    res.status(500).json({ error: 'Update error: ' + err.message });
  }
});

// 6. Get Entries API
app.get('/api/entries', authMiddleware, (req, res) => {
  let targetUserId = req.user.id;

  if (req.user.role === 'admin' && req.query.member_id) {
    if (req.query.member_id === 'all') {
      const stmt = db.prepare(`
        SELECT trade_entries.*, users.name as user_name 
        FROM trade_entries 
        JOIN users ON trade_entries.user_id = users.id 
        ORDER BY entry_date DESC, trade_entries.id DESC
      `);
      const entries = stmt.all();
      return res.json({ user: req.user, entries });
    } else {
      targetUserId = parseInt(req.query.member_id, 10);
    }
  }

  const stmt = db.prepare(`
    SELECT trade_entries.*, users.name as user_name 
    FROM trade_entries 
    JOIN users ON trade_entries.user_id = users.id 
    WHERE user_id = ? 
    ORDER BY entry_date DESC, trade_entries.id DESC
  `);
  const entries = stmt.all(targetUserId);
  res.json({ user: req.user, entries });
});

// 7. Get All Members List (Sirf Admin ke liye)
app.get('/api/members', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }
  const members = db.prepare('SELECT id, name, email, role FROM users ORDER BY name ASC').all();
  res.json({ members });
});

// 8. Delete Trade Entry API
app.delete('/api/entries/:id', authMiddleware, (req, res) => {
  const entryId = parseInt(req.params.id, 10);
  if (isNaN(entryId)) return res.status(400).json({ error: 'Invalid ID' });

  let stmt;
  if (req.user.role === 'admin') {
    stmt = db.prepare('DELETE FROM trade_entries WHERE id = ?');
    stmt.run(entryId);
  } else {
    stmt = db.prepare('DELETE FROM trade_entries WHERE id = ? AND user_id = ?');
    stmt.run(entryId, req.user.id);
  }

  res.json({ success: true, message: 'Entry delete ho gayi!' });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});