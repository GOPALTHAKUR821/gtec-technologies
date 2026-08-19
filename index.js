// Vercel entrypoint.
// All persistent application data is stored in Supabase; no SQLite file is used in production.
module.exports = require('./server.js');
