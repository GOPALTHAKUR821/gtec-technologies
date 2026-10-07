const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs/promises');
const path = require('path');

const router = express.Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined, max: 5, idleTimeoutMillis: 10000 });
const ROLES = ['MASTER', 'MD', 'MANAGER', 'SUPERVISOR'];
const role = (...allowed) => (req, res, next) => req.user && (req.user.role === 'MASTER' || allowed.includes(req.user.role)) ? next() : res.status(403).json({ error: 'You do not have permission to perform this action.' });
const clean = (value, max = 500) => String(value ?? '').trim().slice(0, max);
const validContactNumber = value => /^[+0-9().\s-]{7,25}$/.test(value) && (value.match(/\d/g) || []).length >= 7 && (value.match(/\d/g) || []).length <= 15;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const cookieName = 'aha_session';
const fileUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1 }, fileFilter: (_req, file, cb) => cb(null, ['image/jpeg','image/png','image/webp','application/pdf'].includes(file.mimetype)) });
const hasRemoteStorage = () => !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY && process.env.CONTRACTOR_STORAGE_BUCKET);
const localUploadRoot = path.resolve(process.env.CONTRACTOR_LOCAL_STORAGE_DIR || path.join(__dirname, 'local-data', 'uploads'));
function localUploadPath(objectKey) {
  const filePath = path.resolve(localUploadRoot, ...String(objectKey).split(/[\\/]+/));
  if (!filePath.startsWith(localUploadRoot + path.sep)) throw new Error('Invalid local file reference.');
  return filePath;
}
const storage = () => {
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY || !process.env.CONTRACTOR_STORAGE_BUCKET) throw new Error('Private file storage is not configured.');
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } }).storage;
};
const cookieOpts = { httpOnly: true, secure: process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true', sameSite: 'strict', path: '/', maxAge: 8 * 60 * 60 * 1000 };
const audit = (req, action, type, id, details = {}) => pool.query('INSERT INTO cp_audit_logs(user_id,action,record_type,record_id,ip_address,details) VALUES($1,$2,$3,$4,$5,$6)', [req.user?.id || null, action, type || null, id || null, req.ip || null, JSON.stringify(details)]).catch(() => {});
function error(res, e) {
  if (e instanceof multer.MulterError) return res.status(e.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: e.code === 'LIMIT_FILE_SIZE' ? 'File size must be 5 MB or smaller.' : 'The uploaded file was rejected.' });
  if (e.code === '23505') return res.status(409).json({ error: 'This record already exists.' });
  if (e.code === '23503' || e.code === '23514') return res.status(400).json({ error: 'The submitted information is invalid.' });
  console.error('Contractor portal request failed:', e.message);
  return res.status(500).json({ error: 'The request could not be completed.' });
}
router.use(async (req, res, next) => {
  try {
    if (!process.env.DATABASE_URL) return res.status(503).json({ error: 'Portal database is not configured.' });
    req.cookies = Object.fromEntries(String(req.headers.cookie || '').split(';').map(v => v.trim()).filter(Boolean).map(v => { const i=v.indexOf('='); return [decodeURIComponent(v.slice(0,i)), decodeURIComponent(v.slice(i+1))]; }));
    const token = req.cookies?.[cookieName];
    if (token) {
      const { rows } = await pool.query('SELECT u.id,u.login_id,u.display_name,u.role,u.must_change_password,s.csrf_token FROM cp_sessions s JOIN cp_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now() AND u.active=true', [sha(token)]);
      if (rows[0]) { req.user = rows[0]; req.sessionCsrf = rows[0].csrf_token; }
    }
    next();
  } catch (e) { error(res, e); }
});
router.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && req.path !== '/login' && req.path !== '/join') {
    const origin = req.get('origin');
    const host = req.get('host');
    if (origin && new URL(origin).host !== host) return res.status(403).json({ error: 'Request origin rejected.' });
    const csrf = req.get('x-csrf-token');
    if (!req.user || !csrf || csrf !== req.sessionCsrf) return res.status(403).json({ error: 'Invalid request token.' });
  }
  next();
});
router.use((req,res,next)=>req.user?.must_change_password&&!['/session','/password','/logout'].includes(req.path)?res.status(403).json({error:'Change your initial password to continue.'}):next());
router.post('/login', async (req, res) => {
  const login = clean(req.body?.loginId, 80).toUpperCase();
  const password = String(req.body?.password || '');
  const key = sha(`${req.ip || 'unknown'}:${login}`);
  try {
    const { rows: limits } = await pool.query('SELECT failures,blocked_until FROM cp_login_attempts WHERE key_hash=$1', [key]);
    if (limits[0]?.blocked_until && new Date(limits[0].blocked_until) > new Date()) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
    const { rows } = await pool.query('SELECT id,login_id,display_name,role,password_hash,must_change_password FROM cp_users WHERE login_id=$1 AND active=true', [login]);
    const valid = rows[0] ? await bcrypt.compare(password, rows[0].password_hash) : await bcrypt.compare(password, '$2a$12$C6UzMDM.H6dfI/f/IKcEe.0p4UJC6h7lWAKV8QJXqT9aS5jQnIdVm');
    if (!rows[0] || !valid) {
      await pool.query(`INSERT INTO cp_login_attempts(key_hash,failures,blocked_until) VALUES($1,1,NULL) ON CONFLICT(key_hash) DO UPDATE SET failures=cp_login_attempts.failures+1, blocked_until=CASE WHEN cp_login_attempts.failures+1>=5 THEN now()+interval '15 minutes' ELSE NULL END, updated_at=now()`, [key]);
      await audit({ ...req, user: null }, 'LOGIN_FAILED', 'user', login);
      return res.status(401).json({ error: 'Login ID or password is incorrect.' });
    }
    await pool.query('DELETE FROM cp_login_attempts WHERE key_hash=$1', [key]);
    const token = crypto.randomBytes(32).toString('base64url'); const csrf = crypto.randomBytes(24).toString('base64url');
    await pool.query('INSERT INTO cp_sessions(token_hash,user_id,csrf_token,expires_at) VALUES($1,$2,$3,now()+interval \'8 hours\')', [sha(token), rows[0].id, csrf]);
    res.cookie(cookieName, token, cookieOpts);
    await audit({ ...req, user: rows[0] }, 'LOGIN', 'user', rows[0].id);
    res.json({ user: { id: rows[0].id, loginId: rows[0].login_id, name: rows[0].display_name, role: rows[0].role, mustChangePassword: rows[0].must_change_password }, csrf });
  } catch (e) { error(res, e); }
});
router.post('/logout', (req, res) => { if (!req.user) return res.status(401).json({ error: 'Login required.' }); pool.query('DELETE FROM cp_sessions WHERE token_hash=$1', [sha(req.cookies[cookieName])]).then(() => { res.clearCookie(cookieName, { ...cookieOpts, maxAge: undefined }); audit(req, 'LOGOUT', 'user', req.user.id); res.json({ ok: true }); }).catch(e => error(res, e)); });
router.get('/session', (req, res) => req.user ? pool.query('SELECT csrf_token FROM cp_sessions WHERE token_hash=$1', [sha(req.cookies[cookieName])]).then(({ rows }) => res.json({ user: { id: req.user.id, loginId: req.user.login_id, name: req.user.display_name, role: req.user.role, mustChangePassword:req.user.must_change_password }, csrf: rows[0]?.csrf_token })) : res.status(401).json({ error: 'Login required.' }));
router.get('/leadership', async (_req,res)=>{try{const{rows}=await pool.query('SELECT id,display_name,title,contact_number,sort_order,photo_asset,photo_file_id FROM cp_leadership WHERE active=true ORDER BY sort_order,created_at');res.json(rows.map(p=>({...p,photoUrl:p.photo_file_id?`${_req.baseUrl}/leadership/${p.id}/photo`:`${_req.baseUrl.replace(/\/api$/,'')}/assets/${encodeURIComponent(p.photo_asset)}`})));}catch(e){error(res,e);}});
router.get('/leadership/:id/photo', async(req,res)=>{try{if(!uuidPattern.test(req.params.id))return res.status(404).json({error:'Photo not found.'});const{rows}=await pool.query('SELECT f.object_key,f.mime_type FROM cp_leadership l JOIN cp_files f ON f.id=l.photo_file_id WHERE l.id=$1 AND l.active=true AND f.mime_type LIKE $2',[req.params.id,'image/%']);if(!rows[0])return res.status(404).json({error:'Photo not found.'});if(hasRemoteStorage()){const{data,error:e}=await storage().from(process.env.CONTRACTOR_STORAGE_BUCKET).createSignedUrl(rows[0].object_key,300);if(e)throw e;return res.redirect(302,data.signedUrl);}res.set({'Content-Type':rows[0].mime_type,'Cache-Control':'public, max-age=60','X-Content-Type-Options':'nosniff'});res.sendFile(localUploadPath(rows[0].object_key),e=>{if(e&&!res.headersSent)error(res,e);});}catch(e){error(res,e);}});
router.post('/leadership',role('MASTER'),async(req,res)=>{try{const b=req.body||{},displayName=clean(b.displayName,120),title=clean(b.title,120),contactNumber=clean(b.contactNumber,25),photoFileId=String(b.photoFileId||'');if(!displayName||!title||!validContactNumber(contactNumber)||!uuidPattern.test(photoFileId))return res.status(400).json({error:'Enter a name, position, valid contact number and upload a profile photo.'});const{rows:files}=await pool.query('SELECT id FROM cp_files WHERE id=$1 AND uploaded_by=$2 AND mime_type LIKE $3',[photoFileId,req.user.id,'image/%']);if(!files[0])return res.status(400).json({error:'Upload a valid image before saving this profile.'});const{rows}=await pool.query('INSERT INTO cp_leadership(display_name,title,contact_number,sort_order,photo_file_id,created_by,updated_by) VALUES($1,$2,$3,(SELECT COALESCE(MAX(sort_order),0)+10 FROM cp_leadership),$4,$5,$5) RETURNING id,display_name,title,contact_number',[displayName,title,contactNumber,photoFileId,req.user.id]);await audit(req,'LEADERSHIP_CREATED','leadership',rows[0].id,{displayName});res.status(201).json(rows[0]);}catch(e){error(res,e);}});
router.patch('/leadership/:id',role('MASTER'),async(req,res)=>{try{if(!uuidPattern.test(req.params.id))return res.status(404).json({error:'Profile not found.'});const{rows:existingRows}=await pool.query('SELECT id,photo_asset,photo_file_id FROM cp_leadership WHERE id=$1 AND active=true',[req.params.id]);if(!existingRows[0])return res.status(404).json({error:'Profile not found.'});const b=req.body||{},displayName=clean(b.displayName,120),title=clean(b.title,120),contactNumber=clean(b.contactNumber,25);if(!displayName||!title||!validContactNumber(contactNumber))return res.status(400).json({error:'Enter a name, position and a valid contact number.'});let photoFileId=existingRows[0].photo_file_id,photoAsset=existingRows[0].photo_asset;if(b.photoFileId){photoFileId=String(b.photoFileId);if(!uuidPattern.test(photoFileId))return res.status(400).json({error:'Upload a valid profile photo.'});const{rows:files}=await pool.query('SELECT id FROM cp_files WHERE id=$1 AND uploaded_by=$2 AND mime_type LIKE $3',[photoFileId,req.user.id,'image/%']);if(!files[0])return res.status(400).json({error:'Upload a valid image before saving this profile.'});photoAsset=null;}const{rows}=await pool.query('UPDATE cp_leadership SET display_name=$1,title=$2,contact_number=$3,photo_file_id=$4,photo_asset=$5,updated_by=$6,updated_at=now() WHERE id=$7 RETURNING id,display_name,title,contact_number',[displayName,title,contactNumber,photoFileId,photoAsset,req.user.id,req.params.id]);await audit(req,'LEADERSHIP_UPDATED','leadership',rows[0].id,{displayName});res.json(rows[0]);}catch(e){error(res,e);}});
router.delete('/leadership/:id',role('MASTER'),async(req,res)=>{try{if(!uuidPattern.test(req.params.id))return res.status(404).json({error:'Profile not found.'});const{rows}=await pool.query('DELETE FROM cp_leadership WHERE id=$1 RETURNING id,display_name',[req.params.id]);if(!rows[0])return res.status(404).json({error:'Profile not found.'});await audit(req,'LEADERSHIP_DELETED','leadership',rows[0].id,{displayName:rows[0].display_name});res.json({ok:true});}catch(e){error(res,e);}});
router.post('/password', async(req,res)=>{if(!req.user)return res.status(401).json({error:'Login required.'});try{const current=String(req.body?.current||'');const{rows}=await pool.query('SELECT password_hash FROM cp_users WHERE id=$1',[req.user.id]);if(!await bcrypt.compare(current,rows[0].password_hash))return res.status(400).json({error:'Current password is incorrect.'});const next=String(req.body?.next||'');if(next.length<12)return res.status(400).json({error:'Use at least 12 characters for your new password.'});if(next===current)return res.status(400).json({error:'Choose a different password.'});await pool.query('UPDATE cp_users SET password_hash=$1,must_change_password=false WHERE id=$2',[await bcrypt.hash(next,12),req.user.id]);await pool.query('DELETE FROM cp_sessions WHERE user_id=$1 AND token_hash<>$2',[req.user.id,sha(req.cookies[cookieName])]);await audit(req,'PASSWORD_CHANGED','user',req.user.id);res.json({ok:true});}catch(e){error(res,e);}});
router.post('/uploads', role('MANAGER','SUPERVISOR','MD'), fileUpload.single('file'), async(req,res)=>{
  try {
    if(!req.file)return res.status(400).json({error:'Select a JPEG, PNG, WebP or PDF file under 5 MB.'});
    const category=clean(req.body?.category,30);if(!['worker-photo','report-attachment'].includes(category))return res.status(400).json({error:'Choose a valid upload category.'});
    if(category==='worker-photo'&&!req.file.mimetype.startsWith('image/'))return res.status(400).json({error:'Worker photos must be an image.'});
    const ext=({ 'image/jpeg':'jpg','image/png':'png','image/webp':'webp','application/pdf':'pdf' })[req.file.mimetype];
    const data=req.file.buffer;const valid=req.file.mimetype==='image/jpeg'?data[0]===0xff&&data[1]===0xd8&&data[2]===0xff:req.file.mimetype==='image/png'?data.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])):req.file.mimetype==='image/webp'?data.subarray(0,4).toString()==='RIFF'&&data.subarray(8,12).toString()==='WEBP':data.subarray(0,5).toString()==='%PDF-';if(!valid)return res.status(400).json({error:'File contents do not match the selected file type.'});
    const key=`${category}/${crypto.randomUUID()}.${ext}`;
    let signedUrl;
    if(hasRemoteStorage()){
      const store=storage();const bucket=process.env.CONTRACTOR_STORAGE_BUCKET;
      const {error:uploadError}=await store.from(bucket).upload(key,req.file.buffer,{contentType:req.file.mimetype,upsert:false});if(uploadError)throw uploadError;
      const {data:signed,error:signedError}=await store.from(bucket).createSignedUrl(key,300);if(signedError)throw signedError;signedUrl=signed.signedUrl;
    }else{
      const destination=localUploadPath(key);await fs.mkdir(path.dirname(destination),{recursive:true});await fs.writeFile(destination,req.file.buffer,{flag:'wx'});
    }
    const name=clean(req.file.originalname,120).replace(/[\\/\x00-\x1f]/g,'_');const {rows}=await pool.query('INSERT INTO cp_files(object_key,original_name,mime_type,size_bytes,uploaded_by) VALUES($1,$2,$3,$4,$5) RETURNING id',[key,name,req.file.mimetype,req.file.size,req.user.id]);
    if(!hasRemoteStorage())signedUrl=`${req.baseUrl}/files/${rows[0].id}/content`;
    await audit(req,'FILE_UPLOADED','file',rows[0].id,{category,mimeType:req.file.mimetype,size:req.file.size});res.status(201).json({id:rows[0].id,signedUrl});
  }catch(e){error(res,e);}
});
router.get('/files/:id/sign', role('MANAGER','SUPERVISOR','MD'), async(req,res)=>{try{const{rows}=await pool.query('SELECT object_key FROM cp_files WHERE id=$1',[req.params.id]);if(!rows[0])return res.status(404).json({error:'File not found.'});if(!hasRemoteStorage())return res.json({url:`${req.baseUrl}/files/${req.params.id}/content`});const{data,error:e}=await storage().from(process.env.CONTRACTOR_STORAGE_BUCKET).createSignedUrl(rows[0].object_key,300);if(e)throw e;res.json({url:data.signedUrl});}catch(e){error(res,e);}});
router.get('/files/:id/content', role(...ROLES), async(req,res)=>{try{const{rows}=await pool.query('SELECT object_key,mime_type FROM cp_files WHERE id=$1',[req.params.id]);if(!rows[0])return res.status(404).json({error:'File not found.'});if(hasRemoteStorage()){const{data,error:e}=await storage().from(process.env.CONTRACTOR_STORAGE_BUCKET).createSignedUrl(rows[0].object_key,300);if(e)throw e;return res.redirect(302,data.signedUrl);}res.set({'Content-Type':rows[0].mime_type,'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'});res.sendFile(localUploadPath(rows[0].object_key),e=>{if(e&&!res.headersSent)error(res,e);});}catch(e){error(res,e);}});
router.get('/users', role('MASTER'),async(req,res)=>{try{const{rows}=await pool.query('SELECT id,login_id,display_name,role,active,created_at FROM cp_users ORDER BY display_name');res.json(rows);}catch(e){error(res,e);}});
router.get('/audit',role('MASTER'),async(req,res)=>{try{const{rows}=await pool.query('SELECT a.id,a.action,a.record_type,a.record_id,a.details,a.ip_address,a.created_at,u.display_name FROM cp_audit_logs a LEFT JOIN cp_users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 300');res.json(rows);}catch(e){error(res,e);}});
router.post('/users', role('MASTER'),async(req,res)=>{try{const b=req.body||{};if(!ROLES.includes(b.role)||String(b.password||'').length<12)return res.status(400).json({error:'Choose a valid role and a password of at least 12 characters.'});const{rows}=await pool.query('INSERT INTO cp_users(login_id,display_name,role,password_hash) VALUES($1,$2,$3,$4) RETURNING id,login_id,display_name,role,active',[clean(b.loginId,80).toUpperCase(),clean(b.name,120),b.role,await bcrypt.hash(b.password,12)]);await audit(req,'USER_CREATED','user',rows[0].id,{role:b.role});res.status(201).json(rows[0]);}catch(e){error(res,e);}});
router.patch('/users/:id', role('MASTER'),async(req,res)=>{try{const{rows}=await pool.query('UPDATE cp_users SET active=$1 WHERE id=$2 AND id<>$3 RETURNING id,login_id,active',[!!req.body?.active,req.params.id,req.user.id]);if(!rows[0])return res.status(404).json({error:'User not found or cannot deactivate your current account.'});await audit(req,'USER_ACCESS_CHANGED','user',req.params.id,{active:!!req.body?.active});res.json(rows[0]);}catch(e){error(res,e);}});

router.get('/dashboard', role(...ROLES), async (req, res) => {
  try {
    const [{ rows: totals }, { rows: today }, { rows: pending }, { rows: reports }] = await Promise.all([
      pool.query(`SELECT count(*) FILTER(WHERE md_approval_status='APPROVED' AND active)::int active, count(*)::int total FROM cp_workers`),
      pool.query(`SELECT status,count(*)::int count FROM cp_attendance WHERE day=CURRENT_DATE GROUP BY status`),
      pool.query(`SELECT count(*) FILTER(WHERE manager_verification_status='PENDING')::int manager,count(*) FILTER(WHERE manager_verification_status='APPROVED' AND md_approval_status='PENDING')::int md FROM cp_workers`),
      pool.query('SELECT p.id,p.report_date,p.site,p.description,p.progress_percent,u.display_name submitted_by FROM cp_progress_reports p JOIN cp_users u ON u.id=p.submitted_by ORDER BY p.created_at DESC LIMIT 5')
    ]);
    const dashboard = { totals: totals[0], today: Object.fromEntries(today.map(x => [x.status, x.count])), pending: pending[0], recentReports: reports };
    if (req.user.role === 'MASTER') {
      const { rows: recentActivity } = await pool.query(`
        SELECT a.id, a.action, a.created_at,
          COALESCE(actor.display_name,
            CASE WHEN a.action='WORKER_JOINED' THEN 'Worker self-registration'
                 WHEN a.action='LOGIN_FAILED' THEN 'Unknown account'
                 ELSE 'System' END) AS actor,
          CASE
            WHEN a.record_type='worker' THEN w.full_name
            WHEN a.record_type='attendance' THEN attendance_worker.full_name
            WHEN a.record_type='user' AND a.action IN ('USER_CREATED','USER_ACCESS_CHANGED') THEN target_user.display_name
            WHEN a.record_type='progress_report' THEN report.site
            WHEN a.record_type='id_card' THEN card_worker.full_name
            WHEN a.record_type='file' THEN uploaded_file.original_name
            ELSE NULL
          END AS subject,
          CASE WHEN a.action='ATTENDANCE_SAVED' THEN
            concat_ws(' · ',
              COALESCE(NULLIF(a.details->>'status',''), attendance.status),
              to_char(COALESCE(NULLIF(a.details->>'day','')::date, attendance.day), 'DD Mon YYYY'))
            ELSE NULL END AS detail
        FROM cp_audit_logs a
        LEFT JOIN cp_users actor ON actor.id=a.user_id
        LEFT JOIN cp_users target_user ON a.record_type='user' AND target_user.id::text=a.record_id
        LEFT JOIN cp_workers w ON a.record_type='worker' AND w.id::text=a.record_id
        LEFT JOIN cp_attendance attendance ON a.record_type='attendance' AND attendance.id::text=a.record_id
        LEFT JOIN cp_workers attendance_worker ON attendance_worker.id=attendance.worker_id
        LEFT JOIN cp_progress_reports report ON a.record_type='progress_report' AND report.id::text=a.record_id
        LEFT JOIN cp_id_cards card ON a.record_type='id_card' AND card.id::text=a.record_id
        LEFT JOIN cp_workers card_worker ON card_worker.id=card.worker_id
        LEFT JOIN cp_files uploaded_file ON a.record_type='file' AND uploaded_file.id::text=a.record_id
        ORDER BY a.created_at DESC LIMIT 40`);
      dashboard.recentActivity = recentActivity;
    }
    res.json(dashboard);
  } catch (e) { error(res, e); }
});
router.get('/workers', role('MD','MANAGER','SUPERVISOR'), async (req, res) => {
  try {
    const q = `%${clean(req.query.q, 100)}%`; const state = clean(req.query.status, 20);
    const { rows } = await pool.query(`SELECT id,employee_id,full_name,mobile,designation,department,joining_date,photo_key,manager_verification_status,md_approval_status,active,created_at FROM cp_workers WHERE (full_name ILIKE $1 OR coalesce(employee_id,'') ILIKE $1 OR mobile ILIKE $1 OR coalesce(designation,'') ILIKE $1 OR coalesce(department,'') ILIKE $1) AND ($2='' OR manager_verification_status=$2 OR md_approval_status=$2) AND ($3='' OR department=$3) AND ($4='' OR active=nullif($4,'')::boolean) AND ($5::date IS NULL OR joining_date >= $5::date) AND ($6::date IS NULL OR joining_date <= $6::date) ORDER BY created_at DESC LIMIT 500`, [q,state,clean(req.query.department,100),clean(req.query.active,5),req.query.from||null,req.query.to||null]);
    if(hasRemoteStorage()){const store=storage();for(const w of rows)if(w.photo_key){const{data}=await store.from(process.env.CONTRACTOR_STORAGE_BUCKET).createSignedUrl(w.photo_key,300);w.photoUrl=data?.signedUrl||null}}
    else for(const w of rows)if(w.photo_key)w.photoUrl=`${req.baseUrl}/workers/${encodeURIComponent(w.id)}/photo`;
    res.json(rows);
  } catch (e) { error(res, e); }
});
router.get('/workers/:id/photo', role('MD'), async(req,res)=>{try{const{rows}=await pool.query('SELECT f.object_key,f.mime_type FROM cp_workers w JOIN cp_files f ON f.object_key=w.photo_key WHERE w.id=$1 AND f.mime_type LIKE $2',[req.params.id,'image/%']);if(!rows[0])return res.status(404).json({error:'Worker photo was not found.'});if(hasRemoteStorage()){const{data,error:e}=await storage().from(process.env.CONTRACTOR_STORAGE_BUCKET).createSignedUrl(rows[0].object_key,300);if(e)throw e;return res.redirect(302,data.signedUrl);}res.set({'Content-Type':rows[0].mime_type,'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'});res.sendFile(localUploadPath(rows[0].object_key),e=>{if(e&&!res.headersSent)error(res,e);});}catch(e){error(res,e);}});
router.get('/workers/pending', role('MANAGER','SUPERVISOR'), async (req,res) => { try { const { rows } = await pool.query(`SELECT id,full_name,fathers_name,mobile,address,date_of_birth,created_at,manager_verification_status FROM cp_workers WHERE manager_verification_status='PENDING' ORDER BY created_at`); res.json(rows); } catch(e){error(res,e);} });
router.post('/joining-codes', role('MANAGER'), async (req, res) => {
  try {
    const code = crypto.randomBytes(9).toString('hex').toUpperCase(); const days = Math.max(1,Math.min(90,Number(req.body?.validDays)||7));
    const { rows } = await pool.query('INSERT INTO cp_joining_codes(code_hash,code_hint,created_by,expires_at) VALUES($1,$2,$3,now()+($4::text||\' days\')::interval) RETURNING id,created_at,expires_at,status', [sha(code), `••${code.slice(-2)}`,req.user.id,days]);
    await audit(req,'JOINING_CODE_CREATED','joining_code',rows[0].id); res.status(201).json({ ...rows[0], code });
  } catch(e){error(res,e);}
});
router.get('/joining-codes', role('MANAGER'), async (req,res) => { try { const { rows }=await pool.query('SELECT id,code_hint,created_at,expires_at,status,used_at FROM cp_joining_codes ORDER BY created_at DESC LIMIT 200');res.json(rows); } catch(e){error(res,e);} });
router.post('/join', async (req,res) => {
  const b=req.body||{};const code=clean(b.code,30).toUpperCase();
  const ipKey=sha(`join:${req.ip||'unknown'}`);
  try {
    const {rows:attempts}=await pool.query('SELECT failures,blocked_until FROM cp_login_attempts WHERE key_hash=$1',[ipKey]);if(attempts[0]?.blocked_until&&new Date(attempts[0].blocked_until)>new Date())return res.status(429).json({error:'Too many attempts. Try again later.'});
    const cx=await pool.connect();
    try { await cx.query('BEGIN'); const {rows:c}=await cx.query('SELECT id FROM cp_joining_codes WHERE code_hash=$1 AND status=\'ACTIVE\' AND used_at IS NULL AND expires_at>now() FOR UPDATE',[sha(code)]); if(!c[0]) { await cx.query('ROLLBACK');await pool.query(`INSERT INTO cp_login_attempts(key_hash,failures) VALUES($1,1) ON CONFLICT(key_hash) DO UPDATE SET failures=cp_login_attempts.failures+1,blocked_until=CASE WHEN cp_login_attempts.failures+1>=5 THEN now()+interval '15 minutes' ELSE NULL END,updated_at=now()`,[ipKey]); return res.status(400).json({error:'Joining code is invalid, expired, or already used.'}); }
      const values=[clean(b.fullName,120),clean(b.fathersName,120),clean(b.mobile,20),clean(b.address,500),b.dateOfBirth,c[0].id];
      if(values.some((v,i)=>i<4&&!v)||!/^\d{10,15}$/.test(values[2])||!/^\d{4}-\d{2}-\d{2}$/.test(String(values[4]||''))) { await cx.query('ROLLBACK'); return res.status(400).json({error:'Complete all required fields with a valid mobile number and date of birth.'}); }
      const {rows:w}=await cx.query(`INSERT INTO cp_workers(full_name,fathers_name,mobile,address,date_of_birth,joining_code_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,full_name,manager_verification_status`,values);
      await cx.query('UPDATE cp_joining_codes SET used_at=now(),status=\'USED\' WHERE id=$1',[c[0].id]);await cx.query('DELETE FROM cp_login_attempts WHERE key_hash=$1',[ipKey]);await cx.query('COMMIT'); await audit({ ...req,user:null },'WORKER_JOINED','worker',w[0].id);res.status(201).json({status:'PENDING VERIFICATION',name:w[0].full_name});
    } catch(e){await cx.query('ROLLBACK');throw e;} finally{cx.release();}
  } catch(e){error(res,e);}
});
router.post('/workers/:id/manager-decision', role('MANAGER'), async (req,res) => {
  const approve=req.body?.decision==='approve';const reason=clean(req.body?.reason,500);
  if(!approve&&!reason)return res.status(400).json({error:'A rejection reason is required.'});
  try {const {rows}=await pool.query(`UPDATE cp_workers SET manager_verification_status=$1,manager_rejection_reason=$2,manager_verified_by=$3,manager_verified_at=now() WHERE id=$4 AND manager_verification_status='PENDING' RETURNING id`,[approve?'APPROVED':'REJECTED',approve?null:reason,req.user.id,req.params.id]);if(!rows[0])return res.status(404).json({error:'Pending worker was not found.'});await audit(req,approve?'WORKER_MANAGER_APPROVED':'WORKER_MANAGER_REJECTED','worker',req.params.id,{reason});res.json({ok:true});}catch(e){error(res,e);}
});
router.patch('/workers/:id/profile', role('MD'), async (req,res) => {
  try {const b=req.body||{};let photoKey=null;if(b.photoFileId){const{rows:f}=await pool.query("SELECT object_key FROM cp_files WHERE id=$1 AND uploaded_by=$2 AND mime_type LIKE 'image/%'",[b.photoFileId,req.user.id]);if(!f[0])return res.status(400).json({error:'Photo upload was not found for this account.'});photoKey=f[0].object_key;}const {rows}=await pool.query(`UPDATE cp_workers SET designation=coalesce(nullif($1,''),designation),department=coalesce(nullif($2,''),department),photo_key=coalesce($3,photo_key),full_name=coalesce(nullif($4,''),full_name),fathers_name=coalesce(nullif($5,''),fathers_name),mobile=coalesce(nullif($6,''),mobile),address=coalesce(nullif($7,''),address) WHERE id=$8 AND manager_verification_status='APPROVED' RETURNING id`,[clean(b.designation,100),clean(b.department,100),photoKey,clean(b.fullName,120),clean(b.fathersName,120),clean(b.mobile,20),clean(b.address,500),req.params.id]);if(!rows[0])return res.status(404).json({error:'Manager approved worker was not found.'});await audit(req,'WORKER_PROFILE_UPDATED','worker',req.params.id);res.json({ok:true});}catch(e){error(res,e);}
});
router.post('/workers/:id/final-approval', role('MD'), async (req,res) => {
  try {const cx=await pool.connect();try {await cx.query('BEGIN');const {rows}=await cx.query(`UPDATE cp_workers SET md_approval_status='APPROVED',joining_date=CURRENT_DATE WHERE id=$1 AND manager_verification_status='APPROVED' AND md_approval_status='PENDING' AND designation IS NOT NULL RETURNING employee_id,full_name`,[req.params.id]);if(!rows[0]){await cx.query('ROLLBACK');return res.status(400).json({error:'Complete designation and Manager approval are required.'});}await cx.query('INSERT INTO cp_id_cards(worker_id,generated_by) VALUES($1,$2)',[req.params.id,req.user.id]);await cx.query('COMMIT');await audit(req,'WORKER_MD_APPROVED','worker',req.params.id);res.json(rows[0]);}catch(e){await cx.query('ROLLBACK');throw e;}finally{cx.release();}}catch(e){error(res,e);}
});
router.patch('/workers/:id/status', role('MD'), async (req,res) => {try{const active=!!req.body?.active;const {rowCount}=await pool.query('UPDATE cp_workers SET active=$1 WHERE id=$2 AND employee_id IS NOT NULL',[active,req.params.id]);if(!rowCount)return res.status(404).json({error:'Worker not found.'});await pool.query('UPDATE cp_id_cards SET active=$1,revoked_at=CASE WHEN $1 THEN NULL ELSE now() END WHERE worker_id=$2',[active,req.params.id]);await audit(req,active?'WORKER_ACTIVATED':'WORKER_DEACTIVATED','worker',req.params.id);res.json({ok:true});}catch(e){error(res,e);}});

router.get('/attendance', role('SUPERVISOR'), async(req,res)=>{try{const{rows}=await pool.query(`SELECT a.id,w.employee_id,w.full_name,w.department,a.day,a.status,a.remarks,u.display_name entered_by,a.created_at FROM cp_attendance a JOIN cp_workers w ON w.id=a.worker_id JOIN cp_users u ON u.id=a.entered_by WHERE a.day BETWEEN coalesce($1::date,CURRENT_DATE-30) AND coalesce($2::date,CURRENT_DATE) AND ($3='' OR a.status=$3) AND ($4='' OR w.department=$4) AND ($5='' OR w.id::text=$5 OR w.employee_id=$5 OR w.full_name ILIKE '%'||$5||'%') ORDER BY a.day DESC,w.full_name`,[req.query.from||null,req.query.to||null,clean(req.query.status,20),clean(req.query.department,100),clean(req.query.worker,100)]);res.json(rows);}catch(e){error(res,e);}});
router.post('/attendance', role('SUPERVISOR'), async(req,res)=>{try{const b=req.body||{};const {rows}=await pool.query(`INSERT INTO cp_attendance(worker_id,day,status,remarks,entered_by) SELECT id,$2,$3,$4,$5 FROM cp_workers WHERE id=$1 AND md_approval_status='APPROVED' AND active=true ON CONFLICT(worker_id,day) DO UPDATE SET status=excluded.status,remarks=excluded.remarks,entered_by=excluded.entered_by,created_at=now() RETURNING id`,[b.workerId,b.day,b.status,clean(b.remarks,500),req.user.id]);if(!rows[0])return res.status(400).json({error:'Select an active, approved worker.'});await audit(req,'ATTENDANCE_SAVED','attendance',rows[0].id,{day:b.day,status:b.status});res.json({ok:true});}catch(e){error(res,e);}});
router.get('/attendance/monthly', role('SUPERVISOR'), async(req,res)=>{try{const month=Number(req.query.month)||new Date().getMonth()+1;const year=Number(req.query.year)||new Date().getFullYear();const{rows}=await pool.query(`SELECT w.employee_id,w.full_name,w.department,coalesce(json_object_agg(extract(day from a.day)::int,a.status) FILTER(WHERE a.id IS NOT NULL),'{}'::json) attendance FROM cp_workers w LEFT JOIN cp_attendance a ON a.worker_id=w.id AND extract(month from a.day)=$1 AND extract(year from a.day)=$2 WHERE w.md_approval_status='APPROVED' AND w.active=true AND ($3='' OR w.department=$3) AND ($4='' OR w.employee_id ILIKE '%'||$4||'%' OR w.full_name ILIKE '%'||$4||'%') GROUP BY w.id ORDER BY w.full_name`,[month,year,clean(req.query.department,100),clean(req.query.worker,100)]);res.json({days:new Date(year,month,0).getDate(),rows});}catch(e){error(res,e);}});
router.post('/progress', role('SUPERVISOR'), async(req,res)=>{try{const b=req.body||{};const fileIds=Array.isArray(b.attachmentFileIds)?[...new Set(b.attachmentFileIds)].slice(0,5):[];if(fileIds.some(x=>! /^[0-9a-f-]{36}$/i.test(String(x))))return res.status(400).json({error:'Attachment reference is invalid.'});let keys=[];if(fileIds.length){const{rows:f}=await pool.query("SELECT id,object_key FROM cp_files WHERE id=ANY($1::uuid[]) AND uploaded_by=$2 AND object_key LIKE 'report-attachment/%'",[fileIds,req.user.id]);if(f.length!==fileIds.length)return res.status(400).json({error:'An attachment was not uploaded for this account.'});keys=f.map(x=>x.object_key)}const{rows}=await pool.query(`INSERT INTO cp_progress_reports(report_date,site,description,completed,progress_percent,issues,materials,remarks,submitted_by,attachment_keys) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,[b.date,clean(b.site,120),clean(b.description,2000),clean(b.completed,2000),Number(b.progressPercent),clean(b.issues,1000),clean(b.materials,1000),clean(b.remarks,1000),req.user.id,JSON.stringify(keys)]);await audit(req,'PROGRESS_REPORT_CREATED','progress_report',rows[0].id);res.status(201).json({id:rows[0].id});}catch(e){error(res,e);}});
router.get('/progress', role(...ROLES), async(req,res)=>{try{const{rows}=await pool.query(`SELECT p.id,p.report_date,p.site,p.description,p.completed,p.progress_percent,p.issues,p.materials,p.remarks,p.attachment_keys,u.display_name submitted_by FROM cp_progress_reports p JOIN cp_users u ON u.id=p.submitted_by WHERE p.report_date BETWEEN coalesce($1::date,'1900-01-01') AND coalesce($2::date,'2999-12-31') AND ($3='' OR p.site ILIKE '%'||$3||'%') AND ($4='' OR u.display_name ILIKE '%'||$4||'%') ORDER BY p.report_date DESC LIMIT 1000`,[req.query.from||null,req.query.to||null,clean(req.query.site,100),clean(req.query.submittedBy,100)]);if(hasRemoteStorage()){const store=storage();for(const r of rows){r.attachmentUrls=[];for(const key of r.attachment_keys||[]){const{data}=await store.from(process.env.CONTRACTOR_STORAGE_BUCKET).createSignedUrl(key,300);if(data?.signedUrl)r.attachmentUrls.push(data.signedUrl)}}}else{for(const r of rows){r.attachmentUrls=[];const keys=r.attachment_keys||[];if(keys.length){const{rows:files}=await pool.query('SELECT id,object_key FROM cp_files WHERE object_key=ANY($1::text[])',[keys]);r.attachmentUrls=files.map(f=>`${req.baseUrl}/files/${f.id}/content`)}}}res.json(rows);}catch(e){error(res,e);}});
router.get('/id-cards', role('MD'),async(req,res)=>{try{const{rows}=await pool.query('SELECT DISTINCT ON (w.id) c.id card_id,c.active card_active,c.generated_at,w.id worker_id,w.employee_id,w.full_name,w.designation,w.department,w.joining_date,w.active,w.photo_key FROM cp_id_cards c JOIN cp_workers w ON w.id=c.worker_id WHERE w.employee_id IS NOT NULL ORDER BY w.id,c.generated_at DESC');if(hasRemoteStorage()){const store=storage();for(const w of rows)if(w.photo_key){const{data}=await store.from(process.env.CONTRACTOR_STORAGE_BUCKET).createSignedUrl(w.photo_key,300);w.photoUrl=data?.signedUrl||null}}else for(const w of rows)if(w.photo_key)w.photoUrl=`${req.baseUrl}/workers/${encodeURIComponent(w.worker_id)}/photo`;res.json(rows);}catch(e){error(res,e);}});
router.post('/id-cards/:workerId/regenerate',role('MD'),async(req,res)=>{try{const cx=await pool.connect();try{await cx.query('BEGIN');const{rows}=await cx.query('SELECT id FROM cp_workers WHERE id=$1 AND employee_id IS NOT NULL AND active=true',[req.params.workerId]);if(!rows[0]){await cx.query('ROLLBACK');return res.status(404).json({error:'Active approved worker not found.'});}await cx.query('UPDATE cp_id_cards SET active=false,revoked_at=now() WHERE worker_id=$1 AND active=true',[req.params.workerId]);const{rows:c}=await cx.query('INSERT INTO cp_id_cards(worker_id,generated_by) VALUES($1,$2) RETURNING id',[req.params.workerId,req.user.id]);await cx.query('COMMIT');await audit(req,'ID_CARD_REGENERATED','id_card',c[0].id);res.json({ok:true});}catch(e){await cx.query('ROLLBACK');throw e;}finally{cx.release();}}catch(e){error(res,e);}});
router.post('/id-cards/:workerId/revoke',role('MD'),async(req,res)=>{try{const{rows}=await pool.query('UPDATE cp_id_cards SET active=false,revoked_at=now() WHERE worker_id=$1 AND active=true RETURNING id',[req.params.workerId]);if(!rows.length)return res.status(404).json({error:'Active card not found.'});await audit(req,'ID_CARD_REVOKED','id_card',rows[0].id);res.json({ok:true});}catch(e){error(res,e);}});
router.get('/id-cards/:workerId', role('MD'),async(req,res)=>{try{const{rows}=await pool.query('SELECT c.id card_id,c.active card_active,w.employee_id,w.full_name,w.designation,w.department,w.joining_date,w.active,w.photo_key FROM cp_id_cards c JOIN cp_workers w ON w.id=c.worker_id WHERE w.id=$1 AND c.active=true AND w.active=true ORDER BY c.generated_at DESC LIMIT 1',[req.params.workerId]);if(!rows[0])return res.status(404).json({error:'Active ID card not found.'});const QRCode=require('qrcode');const url=`${process.env.NEXT_PUBLIC_APP_URL||`${req.protocol}://${req.get('host')}`}/portal/verify/${encodeURIComponent(rows[0].employee_id)}`;let photoUrl=null;if(rows[0].photo_key){if(hasRemoteStorage()){const{data}=await storage().from(process.env.CONTRACTOR_STORAGE_BUCKET).createSignedUrl(rows[0].photo_key,300);photoUrl=data?.signedUrl||null}else photoUrl=`${req.baseUrl}/workers/${encodeURIComponent(req.params.workerId)}/photo`}res.json({...rows[0],photoUrl,verificationUrl:url,qrDataUrl:await QRCode.toDataURL(url,{margin:1,width:180})});}catch(e){error(res,e);}});
router.get('/verify/:employeeId', async(req,res)=>{try{const{rows}=await pool.query(`SELECT w.employee_id,w.full_name,w.designation,w.department,w.active,c.active card_active FROM cp_workers w JOIN cp_id_cards c ON c.worker_id=w.id WHERE w.employee_id=$1 ORDER BY c.generated_at DESC LIMIT 1`,[clean(req.params.employeeId,30)]);if(!rows[0]||!rows[0].active||!rows[0].card_active)return res.status(404).json({verified:false});res.json({verified:true,company:'M/S ANDE HI ANDE CONTRACTOR',employeeId:rows[0].employee_id,name:rows[0].full_name,designation:rows[0].designation,department:rows[0].department});}catch(e){error(res,e);}});

router.use((e,req,res,next)=>error(res,e));

module.exports = router;
