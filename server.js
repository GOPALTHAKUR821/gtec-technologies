const express = require('express');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');

// Vercel functions have a read-only deployment filesystem.  Do NOT use
// better-sqlite3/WAL here.  A small JSON store in /tmp keeps the function
// alive and, most importantly, avoids the native SQLite crash that was
// returning HTML 500 pages to the admin login.
const DATA_FILE = process.env.VERCEL
  ? '/tmp/gtec-data.json'
  : path.join(ROOT, 'gtec-data.json');

app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

app.use((req, res, next) => {
  if (req.path.startsWith('/api/') || req.path === '/admin.html') {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});

app.use(express.static(PUBLIC, { index: false, maxAge: 0 }));

function cleanText(value, max = 500) {
  return String(value ?? '').trim().slice(0, max);
}

function defaultProducts() {
  return [
    ['DS-2CE16D0T-ITPFS','HIKVISION','Camera','2MP Audio Bullet','DS-2CE16D0T-ITPFS',1179,10,'2MP • Audio • IR Bullet',''],
    ['brand-DS-2CE76D0T-ITPFS','HIKVISION','Camera','2MP Audio Turret','DS-2CE76D0T-ITPFS',800,10,'2MP • Audio • IR Turret',''],
    ['brand-DS-7108NI-Q1-M','HIKVISION','NVR','8CH NVR','DS-7108NI-Q1/M',4900,10,'8CH Network Video Recorder',''],
    ['brand-HDCVI-Full-Color-Series','DAHUA','Camera','2MP Full-Color Bullet','HDCVI Full-Color Series',3850,10,'2MP • Full Color • Starlight',''],
    ['brand-NVR1108HS-S3-H','DAHUA','NVR','8CH NVR','NVR1108HS-S3/H',5599,10,'8CH Network Video Recorder',''],
    ['brand-NVR4208-8P-Series','DAHUA','NVR','8CH PoE NVR','NVR4208-8P Series',0,10,'8CH • 8 PoE Ports • WizSense',''],
    ['CP-UNC-TA21L3C-Q','CP PLUS','Camera','2MP IP Bullet Camera','CP-UNC-TA21L3C-Q',2850,10,'2MP • IR • PoE • IP67',''],
    ['CP-UNC-DA41L3C-D-Q','CP PLUS','Camera','4MP IP Dome Camera','CP-UNC-DA41L3C-D-Q',3000,10,'4MP • IR • Mic • PoE',''],
    ['CP-UVR-0801F1V-I','CP PLUS','DVR','8CH DVR','CP-UVR-0801F1V-I',4500,10,'8CH • H.265 • HDMI/VGA',''],
    ['CP-ANW-HPU8H2-N12','CP PLUS','PoE Switch','8CH PoE Switch','CP-ANW-HPU8H2-N12',1265,10,'8 PoE + 2 Uplink • 120W',''],
    ['brand-UNV-IPC-Series','UNV','Camera','Network Cameras','UNV IPC Series',0,10,'2MP / 4MP / 5MP / 8MP • IP cameras',''],
    ['brand-UNV-NVR-Series','UNV','NVR','Network Recorders','UNV NVR Series',0,10,'4CH / 8CH / 16CH / 32CH+',''],
    ['brand-Tiandy-Network-Camera-Series','TIANDY','Camera','IP Camera Range','Tiandy Network Camera Series',0,10,'Starlight • Full Color • Smart IR',''],
    ['brand-Tiandy-NVR-Series','TIANDY','NVR','NVR Range','Tiandy NVR Series',0,10,'4CH / 8CH / 16CH / 32CH+',''],
    ['brand-Prama-CCTV-Series','PRAMA','Camera','Security Camera Range','Prama CCTV Series',0,10,'HD / IP cameras • Multiple resolutions',''],
    ['brand-Prama-DVR-NVR-Series','PRAMA','NVR','Recorder Range','Prama DVR / NVR Series',0,10,'Multiple channel and storage options','']
  ].map(x => ({
    id:x[0], brand:x[1], category:x[2], name:x[3], model:x[4], price:x[5], stock:x[6], specs:x[7], image:x[8], created_at:new Date().toISOString()
  }));
}

function initialState() {
  return {
    admins: [{ id:1, username:'GOPALTHAKUR821', password_hash:bcrypt.hashSync('GOPAL@5467', 10) }],
    sessions: {},
    products: defaultProducts(),
    orders: [],
    tracking_checks: []
  };
}

function loadState() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (parsed && Array.isArray(parsed.products) && Array.isArray(parsed.orders)) {
        parsed.admins = Array.isArray(parsed.admins) && parsed.admins.length ? parsed.admins : initialState().admins;
        parsed.sessions = parsed.sessions && typeof parsed.sessions === 'object' ? parsed.sessions : {};
        parsed.tracking_checks = Array.isArray(parsed.tracking_checks) ? parsed.tracking_checks : [];
        return parsed;
      }
    }
  } catch (e) {
    console.error('Data load warning:', e.message);
  }
  const fresh = initialState();
  saveState(fresh);
  return fresh;
}

function saveState(state) {
  try {
    const dir = path.dirname(DATA_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive:true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(state), 'utf8');
  } catch (e) {
    console.error('Data save warning:', e.message);
  }
}

let state = loadState();

function ensureAdmin() {
  let admin = state.admins.find(a => a.username === 'GOPALTHAKUR821');
  if (!admin) {
    admin = { id:1, username:'GOPALTHAKUR821', password_hash:bcrypt.hashSync('GOPAL@5467', 10) };
    state.admins.push(admin);
    saveState(state);
  }
}
ensureAdmin();

function auth(req, res, next) {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  const session = token ? state.sessions[token] : null;
  if (!session || Number(session.expires_at) <= Date.now()) {
    if (token) delete state.sessions[token];
    return res.status(401).json({ error:'Admin login required' });
  }
  req.adminId = session.admin_id;
  next();
}

function productPayload(body, existing = {}) {
  return {
    brand: cleanText(body.brand ?? existing.brand, 100),
    category: cleanText(body.category ?? existing.category ?? 'Camera', 80),
    name: cleanText(body.name ?? existing.name, 200),
    model: cleanText(body.model ?? existing.model, 160),
    price: Math.max(0, Number(body.price ?? existing.price ?? 0) || 0),
    stock: Math.max(0, Math.floor(Number(body.stock ?? existing.stock ?? 0) || 0)),
    specs: cleanText(body.specs ?? existing.specs, 500),
    image: cleanText(body.image ?? existing.image, 12000000)
  };
}

function delivery(pin, city) {
  pin = String(pin || '').replace(/\D/g, '').slice(0, 6);
  city = String(city || '').toLowerCase();
  if (pin.length !== 6) return null;
  if (pin.startsWith('204') || city.includes('hathras')) return 50;
  if (['202','281','282','283'].some(p => pin.startsWith(p))) return 70;
  if (/^(20|21|22|23|24|25|26|27|28)/.test(pin)) return 90;
  if (['110','121','122','201','203'].some(p => pin.startsWith(p))) return 120;
  if (/^(14|16|17|18|30)/.test(pin)) return 150;
  return 200;
}

function trackingLabel(status) {
  return ({
    New:'Order received',
    Contacted:'Customer contacted',
    Confirmed:'Order confirmed / processing',
    Dispatched:'Parcel dispatched / in transit',
    Delivered:'Parcel delivered',
    Cancelled:'Order cancelled'
  })[status] || status;
}

app.post('/api/login', (req, res) => {
  try {
    const username = cleanText(req.body?.username, 100);
    const password = String(req.body?.password || '');
    const admin = state.admins.find(a => a.username === username);
    if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
      return res.status(401).json({ error:'Invalid username or password' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    state.sessions[token] = { admin_id:admin.id, expires_at:Date.now() + 7*24*60*60*1000 };
    saveState(state);
    return res.json({ token });
  } catch (e) {
    console.error('LOGIN_ERROR', e);
    return res.status(500).json({ error:'Login server error' });
  }
});

app.post('/api/logout', auth, (req, res) => {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  delete state.sessions[token];
  saveState(state);
  res.json({ ok:true });
});

app.get('/api/admin/me', auth, (req, res) => res.json({ ok:true }));

app.get('/api/products', (req, res) => res.json({ products:state.products }));

app.get('/api/admin/products', auth, (req, res) => res.json({ products:state.products }));

app.post('/api/admin/products', auth, (req, res) => {
  const product = productPayload(req.body || {});
  if (!product.brand || !product.name || !product.model) return res.status(400).json({ error:'Brand, product name and model are required.' });
  let id = cleanText(req.body?.id, 160) || ('prod-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex'));
  if (state.products.some(p => p.id === id)) id = 'prod-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
  const row = { id, ...product, created_at:new Date().toISOString() };
  state.products.unshift(row);
  saveState(state);
  res.json({ ok:true, product:row });
});

app.put('/api/admin/products/:id', auth, (req, res) => {
  const id = cleanText(req.params.id, 160);
  const index = state.products.findIndex(p => p.id === id);
  if (index < 0) return res.status(404).json({ error:'Product not found.' });
  const product = productPayload(req.body || {}, state.products[index]);
  if (!product.brand || !product.name || !product.model) return res.status(400).json({ error:'Brand, product name and model are required.' });
  state.products[index] = { ...state.products[index], ...product };
  saveState(state);
  res.json({ ok:true, product:state.products[index] });
});

app.delete('/api/admin/products/:id', auth, (req, res) => {
  const id = cleanText(req.params.id, 160);
  const before = state.products.length;
  state.products = state.products.filter(p => p.id !== id);
  if (state.products.length === before) return res.status(404).json({ error:'Product not found.' });
  saveState(state);
  res.json({ ok:true });
});

app.post('/api/orders', (req, res) => {
  try {
    const body = req.body || {};
    const items = Array.isArray(body.items) ? body.items : [];
    if (!items.length) return res.status(400).json({ error:'Cart is empty' });
    if (!body.name || !body.phone || !body.address || !body.city || !body.pin) return res.status(400).json({ error:'Delivery details required' });
    const deliveryCharge = delivery(body.pin, body.city);
    if (deliveryCharge === null) return res.status(400).json({ error:'Invalid PIN' });

    let subtotal = 0, qty = 0;
    const products = items.map(item => {
      const price = Number(item.price) || 0;
      const quantity = Math.max(1, Number(item.qty) || 1);
      subtotal += price * quantity;
      qty += quantity;
      return `${quantity} × ${cleanText(item.name,180)} (${cleanText(item.productId,100)}) @ ₹${price.toLocaleString('en-IN')}`;
    }).join('; ');

    const id = 'GTEC-' + Date.now() + '-' + crypto.randomBytes(2).toString('hex').toUpperCase();
    const date = new Date().toLocaleString('en-IN');
    const total = subtotal + deliveryCharge;
    const normalizedPhone = cleanText(body.phone,50).replace(/\D/g,'');
    const statusUpdatedAt = new Date().toISOString();
    const order = {
      id,date,name:cleanText(body.name,150),phone:normalizedPhone,address:cleanText(body.address,500),city:cleanText(body.city,100),pin:cleanText(body.pin,10),products,qty,
      installation:cleanText(body.installation,50) || 'No',payment:cleanText(body.payment,30),utr:cleanText(body.utr,100),status:'New',subtotal,delivery_charge:deliveryCharge,total,
      shipping_from:'Kailora Chauraha, Hathras Jn, UP 204102',status_updated_at:statusUpdatedAt,last_tracking_check_at:null
    };
    state.orders.unshift(order);
    saveState(state);
    res.json({ ok:true, order:{ id,date,subtotal,deliveryCharge,total,status:'New',statusUpdatedAt } });
  } catch (e) {
    console.error('ORDER_ERROR', e);
    res.status(500).json({ error:'Order server error' });
  }
});

app.post('/api/track-order', (req, res) => {
  const phone = cleanText(req.body?.phone,50).replace(/\D/g,'');
  if (phone.length < 10) return res.status(400).json({ error:'Enter the same 10-digit contact number used for the order.' });
  const rows = state.orders.filter(o => o.phone === phone).map(o => ({
    id:o.id,date:o.date,products:o.products,qty:o.qty,payment:o.payment,status:o.status,subtotal:o.subtotal,
    deliveryCharge:o.delivery_charge,total:o.total,shippingFrom:o.shipping_from,statusUpdatedAt:o.status_updated_at,
    lastTrackingCheckAt:o.last_tracking_check_at,trackingLabel:trackingLabel(o.status)
  }));
  const checkedAt = new Date().toISOString();
  const requestId = 'TRK-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
  if (!rows.length) {
    state.tracking_checks.push({ phone,order_id:null,checked_at:checkedAt,user_agent:cleanText(req.headers['user-agent'],500),request_id:requestId });
  } else {
    for (const order of rows) {
      state.tracking_checks.push({ phone,order_id:order.id,checked_at:checkedAt,user_agent:cleanText(req.headers['user-agent'],500),request_id:requestId });
      const original = state.orders.find(o => o.id === order.id);
      if (original) original.last_tracking_check_at = checkedAt;
    }
  }
  saveState(state);
  res.json({ ok:true, phoneLast4:phone.slice(-4), orders:rows, checkedAt });
});

app.get('/api/admin/orders', auth, (req, res) => {
  const orders = state.orders.map(o => ({
    id:o.id,date:o.date,name:o.name,phone:o.phone,address:o.address,city:o.city,pin:o.pin,products:o.products,qty:o.qty,installation:o.installation,payment:o.payment,utr:o.utr,status:o.status,subtotal:o.subtotal,deliveryCharge:o.delivery_charge,total:o.total,shippingFrom:o.shipping_from,statusUpdatedAt:o.status_updated_at,lastTrackingCheckAt:o.last_tracking_check_at,
    trackingCheckCount:state.tracking_checks.filter(t => t.order_id === o.id).length
  }));
  res.json({ orders });
});

app.get('/api/admin/tracking-stats', auth, (req, res) => {
  const byPhoneMap = {};
  for (const t of state.tracking_checks) {
    if (!byPhoneMap[t.phone]) byPhoneMap[t.phone] = { phone:t.phone, requestIds:new Set(), orders:new Set(), lastCheckedAt:t.checked_at };
    const x = byPhoneMap[t.phone];
    x.requestIds.add(t.request_id);
    if (t.order_id) x.orders.add(t.order_id);
    if (t.checked_at > x.lastCheckedAt) x.lastCheckedAt = t.checked_at;
  }
  const byPhone = Object.values(byPhoneMap).sort((a,b)=>String(b.lastCheckedAt).localeCompare(String(a.lastCheckedAt))).map(x => ({ phone:x.phone,totalChecks:x.requestIds.size,ordersChecked:x.orders.size,lastCheckedAt:x.lastCheckedAt }));
  const byOrderMap = {};
  for (const t of state.tracking_checks) if (t.order_id) {
    const key=t.order_id+'|'+t.phone;
    if (!byOrderMap[key]) byOrderMap[key]={order_id:t.order_id,phone:t.phone,checkCount:0,lastCheckedAt:t.checked_at};
    byOrderMap[key].checkCount++;
    if (t.checked_at > byOrderMap[key].lastCheckedAt) byOrderMap[key].lastCheckedAt=t.checked_at;
  }
  const byOrder=Object.values(byOrderMap).sort((a,b)=>String(b.lastCheckedAt).localeCompare(String(a.lastCheckedAt)));
  res.json({ byPhone, byOrder });
});

app.patch('/api/admin/orders/:id', auth, (req, res) => {
  const allowed=['New','Contacted','Confirmed','Dispatched','Delivered','Cancelled'];
  if (!allowed.includes(req.body?.status)) return res.status(400).json({ error:'Invalid status' });
  const order=state.orders.find(o=>o.id===req.params.id);
  if (!order) return res.status(404).json({ error:'Order not found' });
  const now=new Date().toISOString();
  order.status=req.body.status;
  order.status_updated_at=now;
  saveState(state);
  res.json({ ok:true,status:order.status,statusUpdatedAt:now });
});

app.delete('/api/admin/orders', auth, (req, res) => {
  const ids=Array.isArray(req.body?.ids)?req.body.ids.map(x=>cleanText(x,100)):[];
  state.orders=state.orders.filter(o=>!ids.includes(o.id));
  state.tracking_checks=state.tracking_checks.filter(t=>!ids.includes(t.order_id));
  saveState(state);
  res.json({ ok:true });
});

// Always return JSON for unknown API routes. This prevents the frontend from
// trying to parse Vercel/Express HTML error pages as JSON.
app.use('/api', (req, res) => res.status(404).json({ error:'API route not found' }));
app.use((err, req, res, next) => {
  console.error('UNHANDLED_ERROR', err);
  if (req.path.startsWith('/api/')) return res.status(500).json({ error:'Server error' });
  next(err);
});

app.use((req, res) => res.sendFile(path.join(PUBLIC,'index.html')));

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}
