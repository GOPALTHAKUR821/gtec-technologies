require('dotenv').config();
const express = require('express');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

app.get('/healthz', (_req, res) => res.status(200).type('text/plain').send('ok'));
app.use('/portal', (req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob: https:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
    'Cache-Control': 'no-store'
  });
  next();
});

app.use('/portal/api', require('./api'));
const publicDir = path.join(__dirname, 'public');
const page = path.join(publicDir, 'index.html');
app.get(['/portal', '/portal/'], (_req, res) => res.sendFile(page));
app.get(['/portal/join', '/portal/verify/:employeeId'], (_req, res) => res.sendFile(page));
app.use('/portal', express.static(publicDir, { index: 'index.html', maxAge: 0 }));
app.get('/', (_req, res) => res.redirect(302, '/portal'));
app.use((_req, res) => res.status(404).type('text/plain').send('Not found'));

const port = Number(process.env.PORT) || 3000;
app.listen(port, '0.0.0.0', () => console.log(`Contractor portal listening on ${port}`));
