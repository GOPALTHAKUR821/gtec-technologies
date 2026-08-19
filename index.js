// Vercel entrypoint for the existing Express server.
// Vercel's deployment filesystem is read-only, so redirect the SQLite
// database file to /tmp before loading server.js. /tmp is writable.
const path = require('path');

const originalJoin = path.join;
path.join = function (...parts) {
  if (parts[parts.length - 1] === 'gtec.sqlite') {
    return '/tmp/gtec.sqlite';
  }
  return originalJoin.apply(path, parts);
};

const app = require('./server.js');

module.exports = app;
