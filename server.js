const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC = path.join(__dirname, 'public');

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://sflhhuedxszpfuvocssc.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || '';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY || 'missing-key', { auth:{ persistSession:false, autoRefreshToken:false } });

if (!SUPABASE_KEY) console.error('SUPABASE_SERVICE_ROLE_KEY is missing');

app.use(cors());
app.use(express.json({ limit:'20mb' }));
app.use(express.urlencoded({ extended:true, limit:'20mb' }));
app.use((req,res,next)=>{ if(req.path.startsWith('/api/') || req.path==='/admin.html'){ res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate'); res.setHeader('Pragma','no-cache'); res.setHeader('Expires','0'); } next(); });
app.use(express.static(PUBLIC,{index:false,maxAge:0}));

const defaults=[
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

function cleanText(v,max=500){return String(v??'').trim().slice(0,max);}
function fail(res,status,error){return res.status(status).json({error});}

async function bootstrap(){
 if(!SUPABASE_KEY)return;
 const {data:admins,error:aerr}=await supabase.from('admins').select('id,username,password_hash').eq('username','GOPALTHAKUR821').limit(1);
 if(aerr){console.error('ADMIN_BOOTSTRAP',aerr.message);return;}
 if(!admins?.length){const {error}=await supabase.from('admins').insert({username:'GOPALTHAKUR821',password_hash:bcrypt.hashSync('GOPAL@5467',12)});if(error)console.error('ADMIN_SEED',error.message);}
 const {count,error:cerr}=await supabase.from('products').select('id',{count:'exact',head:true});
 if(!cerr&&Number(count)===0){const rows=defaults.map(p=>({id:p[0],brand:p[1],category:p[2],name:p[3],model:p[4],price:p[5],stock:p[6],specs:p[7],image:p[8],created_at:new Date().toISOString()}));const {error}=await supabase.from('products').insert(rows);if(error)console.error('PRODUCT_SEED',error.message);}
}

function productPayload(body,existing={}){return{brand:cleanText(body.brand??existing.brand,100),category:cleanText(body.category??existing.category??'Camera',80),name:cleanText(body.name??existing.name,200),model:cleanText(body.model??existing.model,160),price:Math.max(0,Number(body.price??existing.price??0)||0),stock:Math.max(0,Math.floor(Number(body.stock??existing.stock??0)||0)),specs:cleanText(body.specs??existing.specs,500),image:cleanText(body.image??existing.image,12000000)};}

async function auth(req,res,next){try{const token=String(req.headers.authorization||'').replace(/^Bearer\s+/i,'').trim();if(!token)return fail(res,401,'Admin login required');const {data,error}=await supabase.from('sessions').select('*').eq('token',token).gt('expires_at',Date.now()).maybeSingle();if(error||!data)return fail(res,401,'Admin login required');req.adminId=data.admin_id;next();}catch(e){console.error('AUTH_ERROR',e);return fail(res,500,'Authentication server error');}}

app.post('/api/login',async(req,res)=>{try{const username=cleanText(req.body?.username,100);const password=String(req.body?.password||'');const {data:admin,error}=await supabase.from('admins').select('*').eq('username',username).maybeSingle();if(error)return fail(res,500,'Database error');if(!admin||!bcrypt.compareSync(password,admin.password_hash))return fail(res,401,'Invalid username or password');const token=crypto.randomBytes(32).toString('hex');const {error:se}=await supabase.from('sessions').insert({token,admin_id:admin.id,expires_at:Date.now()+7*24*60*60*1000});if(se){console.error('SESSION_ERROR',se.message);return fail(res,500,'Unable to create login session');}res.json({token});}catch(e){console.error('LOGIN_ERROR',e);return fail(res,500,'Login server error');}});
app.post('/api/logout',auth,async(req,res)=>{const token=String(req.headers.authorization||'').replace(/^Bearer\s+/i,'').trim();await supabase.from('sessions').delete().eq('token',token);res.json({ok:true});});
app.get('/api/admin/me',auth,(req,res)=>res.json({ok:true}));

app.get('/api/products',async(req,res)=>{const {data,error}=await supabase.from('products').select('*').order('created_at',{ascending:false});if(error)return fail(res,500,'Unable to load products');res.json({products:data||[]});});
app.get('/api/admin/products',auth,async(req,res)=>{const {data,error}=await supabase.from('products').select('*').order('created_at',{ascending:false});if(error)return fail(res,500,'Unable to load products');res.json({products:data||[]});});
app.post('/api/admin/products',auth,async(req,res)=>{const product=productPayload(req.body||{});if(!product.brand||!product.name||!product.model)return fail(res,400,'Brand, product name and model are required.');let id=cleanText(req.body?.id,160)||('prod-'+Date.now()+'-'+crypto.randomBytes(3).toString('hex'));const chk=await supabase.from('products').select('id').eq('id',id).maybeSingle();if(chk.data)id='prod-'+Date.now()+'-'+crypto.randomBytes(4).toString('hex');const row={id,...product,created_at:new Date().toISOString()};const {data,error}=await supabase.from('products').insert(row).select().single();if(error)return fail(res,500,'Unable to create product');res.json({ok:true,product:data});});
app.put('/api/admin/products/:id',auth,async(req,res)=>{const id=cleanText(req.params.id,160);const found=await supabase.from('products').select('*').eq('id',id).maybeSingle();if(!found.data)return fail(res,404,'Product not found.');const product=productPayload(req.body||{},found.data);if(!product.brand||!product.name||!product.model)return fail(res,400,'Brand, product name and model are required.');const {data,error}=await supabase.from('products').update(product).eq('id',id).select().single();if(error)return fail(res,500,'Unable to update product');res.json({ok:true,product:data});});
app.delete('/api/admin/products/:id',auth,async(req,res)=>{const id=cleanText(req.params.id,160);const {data,error}=await supabase.from('products').delete().eq('id',id).select('id');if(error)return fail(res,500,'Unable to delete product');if(!data?.length)return fail(res,404,'Product not found.');res.json({ok:true});});

function delivery(pin,city){pin=String(pin||'').replace(/\D/g,'').slice(0,6);city=String(city||'').toLowerCase();if(pin.length!==6)return null;if(pin.startsWith('204')||city.includes('hathras'))return 50;if(['202','281','282','283'].some(p=>pin.startsWith(p)))return 70;if(/^(20|21|22|23|24|25|26|27|28)/.test(pin))return 90;if(['110','121','122','201','203'].some(p=>pin.startsWith(p)))return 120;if(/^(14|16|17|18|30)/.test(pin))return 150;return 200;}

app.post('/api/orders',async(req,res)=>{try{const b=req.body||{},items=Array.isArray(b.items)?b.items:[];if(!items.length)return fail(res,400,'Cart is empty');if(!b.name||!b.phone||!b.address||!b.city||!b.pin)return fail(res,400,'Delivery details required');const dc=delivery(b.pin,b.city);if(dc===null)return fail(res,400,'Invalid PIN');let subtotal=0,qty=0;const products=items.map(x=>{const price=Number(x.price)||0,q=Math.max(1,Number(x.qty)||1);subtotal+=price*q;qty+=q;return `${q} × ${cleanText(x.name,180)} (${cleanText(x.productId,100)}) @ ₹${price.toLocaleString('en-IN')}`;}).join('; ');const id='GTEC-'+Date.now()+'-'+crypto.randomBytes(2).toString('hex').toUpperCase();const date=new Date().toLocaleString('en-IN');const total=subtotal+dc;const updated=new Date().toISOString();const row={id,date,name:cleanText(b.name,150),phone:cleanText(b.phone,50).replace(/\D/g,''),address:cleanText(b.address,500),city:cleanText(b.city,100),pin:cleanText(b.pin,10),products,qty,installation:cleanText(b.installation,50)||'No',payment:cleanText(b.payment,30),utr:cleanText(b.utr,100),status:'New',subtotal,delivery_charge:dc,total,shipping_from:'Kailora Chauraha, Hathras Jn, UP 204102',status_updated_at:updated,last_tracking_check_at:null};const {error}=await supabase.from('orders').insert(row);if(error){console.error('ORDER_DB_ERROR',error.message);return fail(res,500,'Unable to save order');}res.json({ok:true,order:{id,date,subtotal,deliveryCharge:dc,total,status:'New',statusUpdatedAt:updated}});}catch(e){console.error('ORDER_ERROR',e);return fail(res,500,'Order server error');}});

function trackingLabel(s){return({New:'Order received',Contacted:'Customer contacted',Confirmed:'Order confirmed / processing',Dispatched:'Parcel dispatched / in transit',Delivered:'Parcel delivered',Cancelled:'Order cancelled'})[s]||s;}
app.post('/api/track-order',async(req,res)=>{try{const phone=cleanText(req.body?.phone,50).replace(/\D/g,'');if(phone.length<10)return fail(res,400,'Enter the same 10-digit contact number used for the order.');const {data:orders,error}=await supabase.from('orders').select('id,date,products,qty,payment,status,subtotal,delivery_charge,total,shipping_from,status_updated_at,last_tracking_check_at').eq('phone',phone).order('id',{ascending:false});if(error)return fail(res,500,'Unable to track order');const checkedAt=new Date().toISOString(),requestId='TRK-'+Date.now()+'-'+crypto.randomBytes(4).toString('hex');for(const o of orders||[]){await supabase.from('tracking_checks').insert({phone,order_id:o.id,checked_at:checkedAt,user_agent:cleanText(req.headers['user-agent'],500),request_id:requestId});await supabase.from('orders').update({last_tracking_check_at:checkedAt}).eq('id',o.id);}if(!orders?.length)await supabase.from('tracking_checks').insert({phone,order_id:null,checked_at:checkedAt,user_agent:cleanText(req.headers['user-agent'],500),request_id:requestId});res.json({ok:true,phoneLast4:phone.slice(-4),checkedAt,orders:(orders||[]).map(o=>({...o,deliveryCharge:o.delivery_charge,shippingFrom:o.shipping_from,statusUpdatedAt:o.status_updated_at,lastTrackingCheckAt:o.last_tracking_check_at,trackingLabel:trackingLabel(o.status)}))});}catch(e){console.error('TRACK_ERROR',e);return fail(res,500,'Tracking server error');}});

app.get('/api/admin/orders',auth,async(req,res)=>{const {data:orders,error}=await supabase.from('orders').select('*').order('id',{ascending:false});if(error)return fail(res,500,'Unable to load orders');const {data:checks}=await supabase.from('tracking_checks').select('order_id');const counts={};for(const c of checks||[])if(c.order_id)counts[c.order_id]=(counts[c.order_id]||0)+1;res.json({orders:(orders||[]).map(o=>({...o,deliveryCharge:o.delivery_charge,shippingFrom:o.shipping_from,statusUpdatedAt:o.status_updated_at,lastTrackingCheckAt:o.last_tracking_check_at,trackingCheckCount:counts[o.id]||0}))});});
app.get('/api/admin/tracking-stats',auth,async(req,res)=>{const {data,error}=await supabase.from('tracking_checks').select('*').order('checked_at',{ascending:false});if(error)return fail(res,500,'Unable to load tracking stats');const phones={},orders={};for(const x of data||[]){if(!phones[x.phone])phones[x.phone]={phone:x.phone,totalChecks:0,ordersChecked:new Set(),lastCheckedAt:x.checked_at};phones[x.phone].totalChecks++;if(x.order_id)phones[x.phone].ordersChecked.add(x.order_id);if(x.order_id){const k=x.order_id+'|'+x.phone;if(!orders[k])orders[k]={order_id:x.order_id,phone:x.phone,checkCount:0,lastCheckedAt:x.checked_at};orders[k].checkCount++;}}res.json({byPhone:Object.values(phones).map(x=>({phone:x.phone,totalChecks:x.totalChecks,ordersChecked:x.ordersChecked.size,lastCheckedAt:x.lastCheckedAt})),byOrder:Object.values(orders)});});
app.patch('/api/admin/orders/:id',auth,async(req,res)=>{const allowed=['New','Contacted','Confirmed','Dispatched','Delivered','Cancelled'];if(!allowed.includes(req.body?.status))return fail(res,400,'Invalid status');const now=new Date().toISOString();const {data,error}=await supabase.from('orders').update({status:req.body.status,status_updated_at:now}).eq('id',req.params.id).select('id,status,status_updated_at').maybeSingle();if(error)return fail(res,500,'Unable to update order');if(!data)return fail(res,404,'Order not found');res.json({ok:true,status:data.status,statusUpdatedAt:data.status_updated_at});});
app.delete('/api/admin/orders',auth,async(req,res)=>{const ids=Array.isArray(req.body?.ids)?req.body.ids.map(x=>cleanText(x,100)).filter(Boolean):[];if(!ids.length)return res.json({ok:true});const {error}=await supabase.from('orders').delete().in('id',ids);if(error)return fail(res,500,'Unable to delete orders');res.json({ok:true});});

app.use((req,res)=>res.sendFile(path.join(PUBLIC,'index.html')));
module.exports=app;
if(require.main===module)app.listen(PORT,()=>console.log(`Server running on port ${PORT}`));
bootstrap().catch(e=>console.error('BOOTSTRAP_ERROR',e));
