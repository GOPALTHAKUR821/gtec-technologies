const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
fs.mkdirSync(path.join(PUBLIC, 'uploads'), { recursive: true });

app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));
app.use((req,res,next)=>{ if(req.path.startsWith('/api/') || req.path==='/admin.html'){ res.set('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate'); res.set('Pragma','no-cache'); } next(); });
app.use(express.static(PUBLIC));

const db = new Database(path.join(ROOT, 'gtec.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, admin_id INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS products(
 id TEXT PRIMARY KEY, brand TEXT NOT NULL, category TEXT NOT NULL, name TEXT NOT NULL,
 model TEXT NOT NULL, price REAL NOT NULL DEFAULT 0, stock INTEGER NOT NULL DEFAULT 0,
 specs TEXT DEFAULT '', image TEXT DEFAULT '', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders(
 id TEXT PRIMARY KEY, date TEXT NOT NULL, name TEXT NOT NULL, phone TEXT NOT NULL,
 address TEXT NOT NULL, city TEXT NOT NULL, pin TEXT NOT NULL, products TEXT NOT NULL,
 qty INTEGER NOT NULL, installation TEXT, payment TEXT NOT NULL, utr TEXT, status TEXT NOT NULL,
 subtotal REAL NOT NULL, delivery_charge REAL NOT NULL, total REAL NOT NULL, shipping_from TEXT NOT NULL
);
`);

// Tracking + status audit tables. Safe migrations for existing installations.
function ensureColumn(table, column, definition){
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(x=>x.name);
  if(!cols.includes(column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}
ensureColumn('orders','status_updated_at','TEXT');
ensureColumn('orders','last_tracking_check_at','TEXT');
db.exec(`
CREATE TABLE IF NOT EXISTS tracking_checks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,
  order_id TEXT,
  checked_at TEXT NOT NULL,
  user_agent TEXT DEFAULT '',
  request_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tracking_checks_phone ON tracking_checks(phone);
CREATE INDEX IF NOT EXISTS idx_tracking_checks_order ON tracking_checks(order_id);
CREATE INDEX IF NOT EXISTS idx_tracking_checks_request ON tracking_checks(request_id);
`);
ensureColumn('tracking_checks','request_id','TEXT');
db.prepare("UPDATE orders SET status_updated_at=COALESCE(status_updated_at,date) WHERE status_updated_at IS NULL OR status_updated_at='' ").run();

const ADMIN_USER = 'GOPALTHAKUR821';
const ADMIN_PASS = 'GOPAL@5467';
if (!db.prepare('SELECT id FROM admins WHERE username=?').get(ADMIN_USER)) {
  db.prepare('INSERT INTO admins(username,password_hash) VALUES(?,?)').run(ADMIN_USER, bcrypt.hashSync(ADMIN_PASS, 12));
}

// The original visible catalog is seeded once. Existing rows are never overwritten,
// so anything already edited in the admin portal stays edited.
const defaults = [
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
];
const seed = db.prepare(`INSERT OR IGNORE INTO products
(id,brand,category,name,model,price,stock,specs,image,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?)`);
for (const p of defaults) seed.run(...p, new Date().toISOString());

function cleanText(v, max=500){ return String(v ?? '').trim().slice(0,max); }
function productPayload(body, existing={}) {
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
function auth(req,res,next){
  const token=(req.headers.authorization||'').replace(/^Bearer\s+/,'').trim();
  const s=db.prepare('SELECT * FROM sessions WHERE token=? AND expires_at>?').get(token,Date.now());
  if(!s) return res.status(401).json({error:'Admin login required'});
  req.adminId=s.admin_id; next();
}

app.post('/api/login',(req,res)=>{
  const username=cleanText(req.body?.username,100), password=String(req.body?.password||'');
  const a=db.prepare('SELECT * FROM admins WHERE username=?').get(username);
  if(!a || !bcrypt.compareSync(password,a.password_hash)) return res.status(401).json({error:'Invalid username or password'});
  const token=crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions(token,admin_id,expires_at) VALUES(?,?,?)').run(token,a.id,Date.now()+7*24*60*60*1000);
  res.json({token});
});
app.post('/api/logout',auth,(req,res)=>{const t=(req.headers.authorization||'').replace(/^Bearer\s+/,'').trim();db.prepare('DELETE FROM sessions WHERE token=?').run(t);res.json({ok:true});});
app.get('/api/admin/me',auth,(req,res)=>res.json({ok:true}));

// Public catalog.
app.get('/api/products',(req,res)=>res.json({products:db.prepare('SELECT * FROM products ORDER BY created_at DESC').all()}));

// Admin catalog: explicitly protected and returns a clear response for the UI.
app.get('/api/admin/products',auth,(req,res)=>res.json({products:db.prepare('SELECT * FROM products ORDER BY created_at DESC').all()}));
app.post('/api/admin/products',auth,(req,res)=>{
  const p=productPayload(req.body||{});
  if(!p.brand||!p.name||!p.model) return res.status(400).json({error:'Brand, product name and model are required.'});
  let id=cleanText(req.body?.id,160) || ('prod-'+Date.now()+'-'+crypto.randomBytes(3).toString('hex'));
  if(db.prepare('SELECT id FROM products WHERE id=?').get(id)) id='prod-'+Date.now()+'-'+crypto.randomBytes(4).toString('hex');
  db.prepare(`INSERT INTO products(id,brand,category,name,model,price,stock,specs,image,created_at)
              VALUES(?,?,?,?,?,?,?,?,?,?)`).run(id,p.brand,p.category,p.name,p.model,p.price,p.stock,p.specs,p.image,new Date().toISOString());
  res.json({ok:true,product:db.prepare('SELECT * FROM products WHERE id=?').get(id)});
});
app.put('/api/admin/products/:id',auth,(req,res)=>{
  const id=cleanText(req.params.id,160), existing=db.prepare('SELECT * FROM products WHERE id=?').get(id);
  if(!existing) return res.status(404).json({error:'Product not found.'});
  const p=productPayload(req.body||{},existing);
  if(!p.brand||!p.name||!p.model) return res.status(400).json({error:'Brand, product name and model are required.'});
  db.prepare(`UPDATE products SET brand=?,category=?,name=?,model=?,price=?,stock=?,specs=?,image=? WHERE id=?`)
    .run(p.brand,p.category,p.name,p.model,p.price,p.stock,p.specs,p.image,id);
  res.json({ok:true,product:db.prepare('SELECT * FROM products WHERE id=?').get(id)});
});
app.delete('/api/admin/products/:id',auth,(req,res)=>{
  const id=cleanText(req.params.id,160); const r=db.prepare('DELETE FROM products WHERE id=?').run(id);
  if(!r.changes)return res.status(404).json({error:'Product not found.'}); res.json({ok:true});
});

function delivery(pin,city){
  pin=String(pin||'').replace(/\D/g,'').slice(0,6);city=String(city||'').toLowerCase();
  if(pin.length!==6)return null;
  if(pin.startsWith('204')||city.includes('hathras'))return 50;
  if(['202','281','282','283'].some(x=>pin.startsWith(x)))return 70;
  if(/^(20|21|22|23|24|25|26|27|28)/.test(pin))return 90;
  if(['110','121','122','201','203'].some(x=>pin.startsWith(x)))return 120;
  if(/^(14|16|17|18|30)/.test(pin))return 150;
  return 200;
}
app.post('/api/orders',(req,res)=>{
  const b=req.body||{},items=Array.isArray(b.items)?b.items:[];
  if(!items.length)return res.status(400).json({error:'Cart is empty'});
  if(!b.name||!b.phone||!b.address||!b.city||!b.pin)return res.status(400).json({error:'Delivery details required'});
  const dc=delivery(b.pin,b.city);if(dc===null)return res.status(400).json({error:'Invalid PIN'});
  let subtotal=0,qty=0;
  const products=items.map(x=>{const price=Number(x.price)||0,q=Math.max(1,Number(x.qty)||1);subtotal+=price*q;qty+=q;return `${q} × ${cleanText(x.name,180)} (${cleanText(x.productId,100)}) @ ₹${price.toLocaleString('en-IN')}`}).join('; ');
  const id='GTEC-'+Date.now(),date=new Date().toLocaleString('en-IN'),total=subtotal+dc;
  const normalizedPhone = cleanText(b.phone,50).replace(/\D/g,'');
  const statusUpdatedAt = new Date().toISOString();
  db.prepare(`INSERT INTO orders(id,date,name,phone,address,city,pin,products,qty,installation,payment,utr,status,subtotal,delivery_charge,total,shipping_from,status_updated_at,last_tracking_check_at)
  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id,date,cleanText(b.name,150),normalizedPhone,cleanText(b.address,500),cleanText(b.city,100),cleanText(b.pin,10),products,qty,cleanText(b.installation,50)||'No',cleanText(b.payment,30),cleanText(b.utr,100),'New',subtotal,dc,total,'Kailora Chauraha, Hathras Jn, UP 204102',statusUpdatedAt,null);
  res.json({ok:true,order:{id,date,subtotal,deliveryCharge:dc,total,status:'New',statusUpdatedAt}});
});

function trackingLabel(status){
  return ({New:'Order received',Contacted:'Customer contacted',Confirmed:'Order confirmed / processing',Dispatched:'Parcel dispatched / in transit',Delivered:'Parcel delivered',Cancelled:'Order cancelled'})[status] || status;
}

// Customer tracking by the exact mobile number used on the order.
app.post('/api/track-order',(req,res)=>{
  const phone=cleanText(req.body?.phone,50).replace(/\D/g,'');
  if(phone.length<10)return res.status(400).json({error:'Enter the same 10-digit contact number used for the order.'});
  const rows=db.prepare(`SELECT id,date,products,qty,payment,status,subtotal,delivery_charge AS deliveryCharge,total,shipping_from AS shippingFrom,status_updated_at AS statusUpdatedAt,last_tracking_check_at AS lastTrackingCheckAt FROM orders WHERE phone=? ORDER BY rowid DESC`).all(phone);
  const checkedAt=new Date().toISOString();
  const requestId='TRK-'+Date.now()+'-'+crypto.randomBytes(4).toString('hex');
  const log=db.prepare('INSERT INTO tracking_checks(phone,order_id,checked_at,user_agent,request_id) VALUES(?,?,?,?,?)');
  const tx=db.transaction((items)=>{
    if(!items.length) log.run(phone,null,checkedAt,cleanText(req.headers['user-agent'],500),requestId);
    for(const o of items){
      log.run(phone,o.id,checkedAt,cleanText(req.headers['user-agent'],500),requestId);
      db.prepare('UPDATE orders SET last_tracking_check_at=? WHERE id=?').run(checkedAt,o.id);
    }
  });
  tx(rows);
  res.json({ok:true,phoneLast4:phone.slice(-4),orders:rows.map(o=>({...o,trackingLabel:trackingLabel(o.status)})),checkedAt});
});

app.get('/api/admin/orders',auth,(req,res)=>{
  const rows=db.prepare(`SELECT o.id,o.date,o.name,o.phone,o.address,o.city,o.pin,o.products,o.qty,o.installation,o.payment,o.utr,o.status,
    o.subtotal,o.delivery_charge AS deliveryCharge,o.total,o.shipping_from AS shippingFrom,o.status_updated_at AS statusUpdatedAt,
    o.last_tracking_check_at AS lastTrackingCheckAt,COALESCE(tc.check_count,0) AS trackingCheckCount
    FROM orders o LEFT JOIN (SELECT order_id,COUNT(*) AS check_count FROM tracking_checks GROUP BY order_id) tc ON tc.order_id=o.id
    ORDER BY o.rowid DESC`).all();
  res.json({orders:rows});
});

app.get('/api/admin/tracking-stats',auth,(req,res)=>{
  const byPhone=db.prepare(`SELECT phone,COUNT(DISTINCT request_id) AS totalChecks,COUNT(DISTINCT order_id) AS ordersChecked,MAX(checked_at) AS lastCheckedAt FROM tracking_checks GROUP BY phone ORDER BY lastCheckedAt DESC`).all();
  const byOrder=db.prepare(`SELECT order_id,phone,COUNT(*) AS checkCount,MAX(checked_at) AS lastCheckedAt FROM tracking_checks WHERE order_id IS NOT NULL GROUP BY order_id,phone ORDER BY lastCheckedAt DESC`).all();
  res.json({byPhone,byOrder});
});

app.patch('/api/admin/orders/:id',auth,(req,res)=>{
  const allowed=['New','Contacted','Confirmed','Dispatched','Delivered','Cancelled'];
  if(!allowed.includes(req.body?.status))return res.status(400).json({error:'Invalid status'});
  const now=new Date().toISOString();
  const r=db.prepare('UPDATE orders SET status=?,status_updated_at=? WHERE id=?').run(req.body.status,now,req.params.id);
  if(!r.changes)return res.status(404).json({error:'Order not found'});res.json({ok:true,status:req.body.status,statusUpdatedAt:now});
});
app.delete('/api/admin/orders',auth,(req,res)=>{
  const ids=Array.isArray(req.body?.ids)?req.body.ids:[];const del=db.prepare('DELETE FROM orders WHERE id=?');
  db.transaction(xs=>xs.forEach(id=>del.run(cleanText(id,100))))(ids);res.json({ok:true});
});

app.get('*',(req,res)=>res.sendFile(path.join(PUBLIC,'index.html')));
app.listen(PORT,()=>console.log(`G TEC TECHNOLOGEIES running at http://localhost:${PORT}`));
