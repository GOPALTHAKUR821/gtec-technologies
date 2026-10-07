require('dotenv').config();
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { Pool } = require('pg');

const env = process.env;
if (!env.DATABASE_URL) {
  console.error('Local database URL was not provided by pglite-server.');
  process.exit(1);
}

function run(file) {
  const result = spawnSync(process.execPath, [path.join(__dirname, file)], { stdio: 'inherit', env });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status || 1);
}

async function main() {
  run('migrate.js');
  const pool = new Pool({ connectionString: env.DATABASE_URL });
  let userCount;
  try {
    const { rows } = await pool.query('SELECT count(*)::int AS total FROM cp_users');
    userCount = rows[0].total;
  } finally {
    await pool.end();
  }
  if (userCount === 0) run('seed.js');
  else console.log('Local portal accounts already exist; keeping their current passwords.');

  const port = Number(env.PORT) || 3100;
  if (!env.NEXT_PUBLIC_APP_URL || env.NEXT_PUBLIC_APP_URL.includes('your-domain.example')) {
    env.NEXT_PUBLIC_APP_URL = `http://127.0.0.1:${port}`;
  }
  const app = require('../server');
  const server = app.listen(port, '127.0.0.1', () => {
    console.log(`M/S ANDE HI ANDE portal running at http://127.0.0.1:${port}/portal`);
    console.log('Local PostgreSQL data is stored in contractor-portal/local-data.');
  });
  function shutdown() {
    server.close(() => process.exit(0));
  }
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}

main().catch(error => {
  console.error(error.message);
  process.exit(1);
});
