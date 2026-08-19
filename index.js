// Vercel entrypoint for the existing Express server.
// Vercel's deployment filesystem is read-only, so redirect the SQLite
// database file to /tmp before loading server.js. /tmp is writable.
const path = require('path');
const express = require('express');

const originalJoin = path.join;
path.join = function (...parts) {
  if (parts[parts.length - 1] === 'gtec.sqlite') {
    return '/tmp/gtec.sqlite';
  }
  return originalJoin.apply(path, parts);
};

// /admin.html is now a real login entry point. After successful login the
// browser goes to /admin.html?panel=1, which loads the existing dashboard.
const originalStatic = express.static;
express.static = function (root, options) {
  const middleware = originalStatic(root, options);

  return function (req, res, next) {
    if (
      req.path === '/admin.html' &&
      req.query.panel !== '1'
    ) {
      return res.sendFile(
        path.join(root, 'admin-login.html')
      );
    }

    return middleware(req, res, next);
  };
};

const app = require('./server.js');

module.exports = app;
