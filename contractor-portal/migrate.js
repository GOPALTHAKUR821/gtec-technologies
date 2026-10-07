require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

async function main() {
  if (!process.env.DATABASE_URL) throw new Error('Set DATABASE_URL before applying migrations.');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined });
  try {
    const sql = fs.readFileSync(path.join(__dirname, 'migrations', '001_initial.sql'), 'utf8');
    await pool.query(sql);
    console.log('Contractor portal migration applied.');
  } finally { await pool.end(); }
}
main().catch(e => { console.error(e.message); process.exitCode = 1; });
