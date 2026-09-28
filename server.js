const express = require('express');
const { Pool } = require('pg');
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

// Heroku Postgres Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Database Auto-Setup (PostgreSQL Queries)
async function initDB() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'member'
      );

      CREATE TABLE IF NOT EXISTS trade_entries (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        entry_date TEXT NOT NULL,
        day_name TEXT DEFAULT '',
        script_name TEXT DEFAULT '',
        buy_val NUMERIC NOT NULL DEFAULT 0,
        sell_val NUMERIC NOT NULL DEFAULT 0,
        total_val NUMERIC NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log('PostgreSQL database connected and initialized.');
  } catch (err) {
    console.error('Database connection error:', err);
  }
}
initDB();

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
app.post('/api/register', async (req, res) => {
  const { name, email, password, office_code } = req.body;
  if (!name || !email || !password || !office_code) {
    return res.status(400).json({ error: 'Sabhi fields aur Office Code bharna zaroori hai' });
  }

  if (office_code.trim() !== OFFICE_SECRET_CODE) {
    return res.status(403).json({ error: 'Galat Office Passcode!' });
  }

  try {
    const countRes = await pool.query('SELECT COUNT(*) FROM users');
    const role = parseInt(countRes.rows[0].count, 10) === 0 ? 'admin' : 'member';

    const cleanUsername = email.trim().toLowerCase();
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)',
      [name.trim(), cleanUsername, hashedPassword, role]
    );

    res.json({ message: `Registration safal raha! (${role.toUpperCase()} Account). Ab login karein.` });
  } catch (err) {
    res.status(400).json({ error: 'Yeh User ID / MCX ID pehle se registered hai.' });
  }
});

// 2. Login API
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'User ID aur Password dono dalein' });
  }

  try {
    const cleanUsername = email.trim().toLowerCase();
    const userRes = await pool.query('SELECT * FROM users WHERE LOWER(email) = $1', [cleanUsername]);
    const user = userRes.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Galat User ID ya Password' });
    }

    const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });
    res.json({ message: 'Login successful', name: user.name, role: user.role });
  } catch (err) {
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

// 3. Logout API
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out' });
});

// 4. Save Entry API
app.post('/api/entries', authMiddleware, async (req, res) => {
  try {
    const { entry_date, buy_val, sell_val } = req.body;
    if (!entry_date) return res.status(400).json({ error: 'Date zaroori hai' });

    const buy = parseFloat(buy_val) || 0;
    const sell = parseFloat(sell_val) || 0;
    const total = buy + sell;
    const dayName = getDayNameFromDate(entry_date);

    await pool.query(
      `INSERT INTO trade_entries (user_id, entry_date, day_name, script_name, buy_val, sell_val, total_val)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [req.user.id, entry_date, dayName, dayName, buy, sell, total]
    );

    res.json({ success: true, message: 'Data successfully save ho gaya!' });
  } catch (err) {
    res.status(500).json({ error: 'Save error: ' + err.message });
  }
});

// 5. Update Entry API
app.put('/api/entries/:id', authMiddleware, async (req, res) => {
  try {
    const entryId = parseInt(req.params.id, 10);
    const { entry_date, buy_val, sell_val } = req.body;

    const buy = parseFloat(buy_val) || 0;
    const sell = parseFloat(sell_val) || 0;
    const total = buy + sell;
    const dayName = getDayNameFromDate(entry_date);

    if (req.user.role === 'admin') {
      await pool.query(
        `UPDATE trade_entries SET entry_date = $1, day_name = $2, buy_val = $3, sell_val = $4, total_val = $5 WHERE id = $6`,
        [entry_date, dayName, buy, sell, total, entryId]
      );
    } else {
      await pool.query(
        `UPDATE trade_entries SET entry_date = $1, day_name = $2, buy_val = $3, sell_val = $4, total_val = $5 WHERE id = $6 AND user_id = $7`,
        [entry_date, dayName, buy, sell, total, entryId, req.user.id]
      );
    }

    res.json({ success: true, message: 'Entry successfully update ho gayi!' });
  } catch (err) {
    res.status(500).json({ error: 'Update error: ' + err.message });
  }
});

// 6. Get Entries API
app.get('/api/entries', authMiddleware, async (req, res) => {
  try {
    let result;
    if (req.user.role === 'admin' && req.query.member_id) {
      if (req.query.member_id === 'all') {
        result = await pool.query(`
          SELECT trade_entries.*, users.name as user_name 
          FROM trade_entries 
          JOIN users ON trade_entries.user_id = users.id 
          ORDER BY entry_date DESC, trade_entries.id DESC
        `);
      } else {
        result = await pool.query(`
          SELECT trade_entries.*, users.name as user_name 
          FROM trade_entries 
          JOIN users ON trade_entries.user_id = users.id 
          WHERE trade_entries.user_id = $1
          ORDER BY entry_date DESC, trade_entries.id DESC
        `, [parseInt(req.query.member_id, 10)]);
      }
    } else {
      result = await pool.query(`
        SELECT trade_entries.*, users.name as user_name 
        FROM trade_entries 
        JOIN users ON trade_entries.user_id = users.id 
        WHERE trade_entries.user_id = $1
        ORDER BY entry_date DESC, trade_entries.id DESC
      `, [req.user.id]);
    }

    res.json({ user: req.user, entries: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Fetch error: ' + err.message });
  }
});

// 7. Get Members List
app.get('/api/members', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  try {
    const result = await pool.query('SELECT id, name, email as username, role FROM users ORDER BY name ASC');
    res.json({ members: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Fetch error: ' + err.message });
  }
});

// 8. Delete Entry API
app.delete('/api/entries/:id', authMiddleware, async (req, res) => {
  try {
    const entryId = parseInt(req.params.id, 10);
    if (req.user.role === 'admin') {
      await pool.query('DELETE FROM trade_entries WHERE id = $1', [entryId]);
    } else {
      await pool.query('DELETE FROM trade_entries WHERE id = $1 AND user_id = $2', [entryId, req.user.id]);
    }
    res.json({ success: true, message: 'Entry delete ho gayi!' });
  } catch (err) {
    res.status(500).json({ error: 'Delete error' });
  }
});

// Port & Listen
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server started successfully on port ${PORT}`);
});