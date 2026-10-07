require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const accounts = [
  ['SENGARTHEKEDAR', 'Sengar Thekedar', 'MASTER', 'INITIAL_MASTER_PASSWORD'],
  ['MDHARIKRISHNA', 'Hari Krishna', 'MD', 'INITIAL_MD_PASSWORD'],
  ['MANAGERDEEP', 'Deep', 'MANAGER', 'INITIAL_MANAGER_PASSWORD'],
  ['SUPERVISORGOPAL', 'Gopal', 'SUPERVISOR', 'INITIAL_SUPERVISOR_PASSWORD']
];
async function main() {
  if (!process.env.DATABASE_URL) throw new Error('Set DATABASE_URL before seeding accounts.');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined });
  try {
    const existing = await pool.query('SELECT login_id FROM cp_users WHERE login_id = ANY($1::text[])', [accounts.map(([login]) => login)]);
    const existingLogins = new Set(existing.rows.map(row => row.login_id));
    const missingAccounts = accounts.filter(([login]) => !existingLogins.has(login));
    if (missingAccounts.length === 0) {
      console.log('Portal role accounts already exist; initial passwords were left unchanged.');
      return;
    }
    for (const [, , , key] of missingAccounts) if (!process.env[key]) throw new Error(`${key} must be set in the private environment to create its account.`);
    if (missingAccounts.some(([, , , key]) => process.env[key].length < 12)) console.warn('At least one initial password is short; each account will be required to change it at first sign in.');
    for (const [login, name, role, key] of missingAccounts) {
      const hash = await bcrypt.hash(process.env[key], 12);
      await pool.query(`INSERT INTO cp_users(login_id,display_name,role,password_hash,must_change_password) VALUES($1,$2,$3,$4,true)
        ON CONFLICT(login_id) DO NOTHING`, [login, name, role, hash]);
    }
    console.log(`${missingAccounts.length} missing portal role account(s) were created. Existing accounts and passwords were left unchanged.`);
  } finally { await pool.end(); }
}
main().catch(e => { console.error(e.message); process.exitCode = 1; });
