const express = require('express');
const path = require('path');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://sflhhuedxszpfuvocssc.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_PUBLISHABLE_KEY || process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNmbGhodWVkeHN6cGZ1dm9jc3NjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODcwNzg0OTksImV4cCI6MjEwMjY1NDQ5OX0.D_4JW2yDlDS5-AwGXhKyU19CLjsMf-XbZu73xA0fIok';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });

app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use((req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/admin.html' || req.path === '/track-order.html') {
    res.set({ 'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate', Pragma: 'no-cache', Expires: '0' });
  }
  next();
});
app.use(express.static(PUBLIC, { index: false, maxAge: 0 }));

function clean(v, max = 500) { return String(v ?? '').trim().slice(0, max); }
function errorResponse(res, error) {
  const message = error?.message || 'Server error';
  const status = /login required/i.test(message) ? 401 : /not found/i.test(message) ? 404 : /invalid|required|cart is empty/i.test(message) ? 400 : 500;
  return res.status(status).json({ error: message });
}
async function rpc(action, payload = {}) { const { data, error } = await supabase.rpc('gtec_api', { p_action: action, p_payload: payload }); if (error) throw error; return data || {}; }
function tokenFrom(req) { return String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim(); }
async function auth(req, res, next) { try { const token = tokenFrom(req); if (!token) return res.status(401).json({ error: 'Admin login required' }); await rpc('me', { token }); req.adminToken = token; next(); } catch (e) { errorResponse(res, e); } }

app.post('/api/login', async (req, res) => { try { res.json(await rpc('login', { username: clean(req.body?.username, 100), password: String(req.body?.password || '') })); } catch (e) { errorResponse(res, e); } });
app.post('/api/logout', auth, async (req, res) => { try { await rpc('logout', { token: req.adminToken }); res.json({ ok: true }); } catch (e) { errorResponse(res, e); } });
app.get('/api/admin/me', auth, (req, res) => res.json({ ok: true }));
app.get('/api/products', async (req, res) => { try { res.json(await rpc('products')); } catch (e) { errorResponse(res, e); } });
app.get('/api/admin/products', auth, async (req, res) => { try { res.json(await rpc('admin_products', { token: req.adminToken })); } catch (e) { errorResponse(res, e); } });
app.post('/api/admin/products', auth, async (req, res) => { try { res.json(await rpc('create_product', { token: req.adminToken, ...(req.body || {}) })); } catch (e) { errorResponse(res, e); } });
app.put('/api/admin/products/:id', auth, async (req, res) => { try { res.json(await rpc('update_product', { token: req.adminToken, id: req.params.id, ...(req.body || {}) })); } catch (e) { errorResponse(res, e); } });
app.delete('/api/admin/products/:id', auth, async (req, res) => { try { res.json(await rpc('delete_product', { token: req.adminToken, id: req.params.id })); } catch (e) { errorResponse(res, e); } });
app.post('/api/orders', async (req, res) => { try { res.json(await rpc('create_order', req.body || {})); } catch (e) { errorResponse(res, e); } });
app.post('/api/track-order', async (req, res) => { try { res.json(await rpc('track_order', { ...(req.body || {}), userAgent: clean(req.headers['user-agent'], 500) })); } catch (e) { errorResponse(res, e); } });
app.get('/api/admin/orders', auth, async (req, res) => { try { res.json(await rpc('admin_orders', { token: req.adminToken })); } catch (e) { errorResponse(res, e); } });
app.get('/api/admin/tracking-stats', auth, async (req, res) => { try { res.json(await rpc('tracking_stats', { token: req.adminToken })); } catch (e) { errorResponse(res, e); } });
app.patch('/api/admin/orders/:id', auth, async (req, res) => { try { res.json(await rpc('update_order', { token: req.adminToken, id: req.params.id, status: req.body?.status, ewayNumber: req.body?.ewayNumber, courierCompany: req.body?.courierCompany })); } catch (e) { errorResponse(res, e); } });
app.delete('/api/admin/orders', auth, async (req, res) => { try { res.json(await rpc('delete_orders', { token: req.adminToken, ids: Array.isArray(req.body?.ids) ? req.body.ids : [] })); } catch (e) { errorResponse(res, e); } });

app.get('/track-order', (req, res) => res.sendFile(path.join(PUBLIC, 'track-order.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(PUBLIC, 'admin.html')));
app.use((req, res) => res.sendFile(path.join(PUBLIC, 'index.html')));

module.exports = app;
if (require.main === module) app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
