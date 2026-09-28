const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'apna_secret_key_12345';
const OFFICE_SECRET_CODE = 'OFFICE@2026';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Database Setup
const db = new sqlite3.Database('trade_data.db', (err) => {
  if (err) console.error('DB Open Error:', err);
  else console.log('Connected to SQLite database.');
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'member'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS trade_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      entry_date TEXT NOT NULL,
      day_name TEXT DEFAULT '',
      script_name TEXT DEFAULT '',
      buy_val REAL NOT NULL DEFAULT 0,
      sell_val REAL NOT NULL DEFAULT 0,
      total_val REAL NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
});

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

function getDayNameFromDate(dateStr) {
  const dateObj = new Date(dateStr + 'T00:00:00');
  return dateObj.toLocaleDateString('en-US', { weekday: 'long' });
}

// 1. Register API
app.post('/api/register', (req, res) => {
  const { name, email, password, office_code } = req.body;
  if (!name || !email || !password || !office_code) {
    return res.status(400).json({ error: 'Sabhi fields aur Office Code bharna zaroori hai' });
  }

  if (office_code.trim() !== OFFICE_SECRET_CODE) {
    return res.status(403).json({ error: 'Galat Office Passcode!' });
  }

  db.get('SELECT COUNT(*) as count FROM users', async (err, row) => {
    if (err) return res.status(500).json({ error: 'DB Error' });
    const role = row.count === 0 ? 'admin' : 'member';
    const cleanUsername = email.trim().toLowerCase();
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name.trim(), cleanUsername, hashedPassword, role],
      function (insertErr) {
        if (insertErr) {
          return res.status(400).json({ error: 'Yeh User ID / MCX ID pehle se registered hai.' });
        }
        res.json({ message: `Registration safal raha! (${role.toUpperCase()} Account). Ab login karein.` });
      }
    );
  });
});

// 2. Login API
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'User ID aur Password dono dalein' });
  }

  const cleanUsername = email.trim().toLowerCase();
  db.get('SELECT * FROM users WHERE LOWER(email) = ?', [cleanUsername], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Galat User ID ya Password' });
    }
    const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.json({ message: 'Login successful', name: user.name, role: user.role });
  });
});

// 3. Logout API
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

// 4. Save Entry API
app.post('/api/entries', authMiddleware, (req, res) => {
  const { entry_date, buy_val, sell_val } = req.body;
  if (!entry_date) return res.status(400).json({ error: 'Date zaroori hai' });

  const buy = parseFloat(buy_val) || 0;
  const sell = parseFloat(sell_val) || 0;
  const total = buy + sell;
  const dayName = getDayNameFromDate(entry_date);

  db.run(
    `INSERT INTO trade_entries (user_id, entry_date, day_name, script_name, buy_val, sell_val, total_val)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [req.user.id, entry_date, dayName, dayName, buy, sell, total],
    function (err) {
      if (err) return res.status(500).json({ error: 'Save error: ' + err.message });
      res.json({ success: true, message: 'Data successfully save ho gaya!' });
    }
  );
});

// 5. Update Entry API
app.put('/api/entries/:id', authMiddleware, (req, res) => {
  const entryId = parseInt(req.params.id, 10);
  const { entry_date, buy_val, sell_val } = req.body;

  const buy = parseFloat(buy_val) || 0;
  const sell = parseFloat(sell_val) || 0;
  const total = buy + sell;
  const dayName = getDayNameFromDate(entry_date);

  const query = req.user.role === 'admin'
    ? `UPDATE trade_entries SET entry_date = ?, day_name = ?, buy_val = ?, sell_val = ?, total_val = ? WHERE id = ?`
    : `UPDATE trade_entries SET entry_date = ?, day_name = ?, buy_val = ?, sell_val = ?, total_val = ? WHERE id = ? AND user_id = ?`;

  const params = req.user.role === 'admin'
    ? [entry_date, dayName, buy, sell, total, entryId]
    : [entry_date, dayName, buy, sell, total, entryId, req.user.id];

  db.run(query, params, function (err) {
    if (err) return res.status(500).json({ error: 'Update error: ' + err.message });
    res.json({ success: true, message: 'Entry successfully update ho gayi!' });
  });
});

// 6. Get Entries API
app.get('/api/entries', authMiddleware, (req, res) => {
  let query = `
    SELECT trade_entries.*, users.name as user_name 
    FROM trade_entries 
    JOIN users ON trade_entries.user_id = users.id 
    WHERE user_id = ? 
    ORDER BY entry_date DESC, trade_entries.id DESC
  `;
  let params = [req.user.id];

  if (req.user.role === 'admin' && req.query.member_id) {
    if (req.query.member_id === 'all') {
      query = `
        SELECT trade_entries.*, users.name as user_name 
        FROM trade_entries 
        JOIN users ON trade_entries.user_id = users.id 
        ORDER BY entry_date DESC, trade_entries.id DESC
      `;
      params = [];
    } else {
      params = [parseInt(req.query.member_id, 10)];
    }
  }

  db.all(query, params, (err, entries) => {
    if (err) return res.status(500).json({ error: 'Fetch error' });
    res.json({ user: req.user, entries });
  });
});

// 7. Get Members List
app.get('/api/members', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  db.all('SELECT id, name, email as username, role FROM users ORDER BY name ASC', [], (err, members) => {
    if (err) return res.status(500).json({ error: 'Fetch error' });
    res.json({ members });
  });
});

// 8. Delete Entry API
app.delete('/api/entries/:id', authMiddleware, (req, res) => {
  const entryId = parseInt(req.params.id, 10);
  const query = req.user.role === 'admin'
    ? 'DELETE FROM trade_entries WHERE id = ?'
    : 'DELETE FROM trade_entries WHERE id = ? AND user_id = ?';
  const params = req.user.role === 'admin' ? [entryId] : [entryId, req.user.id];

  db.run(query, params, function (err) {
    if (err) return res.status(500).json({ error: 'Delete error' });
    res.json({ success: true, message: 'Entry delete ho gayi!' });
  });
});

// Server Listen (Heroku Dyno Binding)
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server started successfully on port ${PORT}`);
});