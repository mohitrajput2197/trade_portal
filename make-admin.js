const Database = require('better-sqlite3');
const db = new Database('trade_data.db');

// Jisko Admin banana hai uska email yahan likhein:
const targetEmail = 'user_ka_email@gmail.com'; 

const stmt = db.prepare('UPDATE users SET role = "admin" WHERE email = ?');
const result = stmt.run(targetEmail);

if (result.changes > 0) {
  console.log(`✅ Safalta! ${targetEmail} ab ADMIN ban chuka hai.`);
} else {
  console.log(`❌ Error: Is email se koi user nahi mila: ${targetEmail}`);
}