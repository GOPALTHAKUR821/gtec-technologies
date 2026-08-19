const express = require('express');
const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors());

app.use(express.json({
  limit: '20mb'
}));

app.use(express.urlencoded({
  extended: true,
  limit: '20mb'
}));

app.use((req, res, next) => {
  if (
    req.path.startsWith('/api/') ||
    req.path === '/admin.html'
  ) {
    res.setHeader(
      'Cache-Control',
      'no-store, no-cache, must-revalidate, proxy-revalidate'
    );

    res.setHeader(
      'Pragma',
      'no-cache'
    );

    res.setHeader(
      'Expires',
      '0'
    );
  }

  next();
});

app.use(express.static(PUBLIC, {
  index: false,
  maxAge: 0
}));

// ============================================================
// DATABASE
// ============================================================

const dbPath = path.join(ROOT, 'gtec.sqlite');

const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS admins(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions(
    token TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS products(
    id TEXT PRIMARY KEY,
    brand TEXT NOT NULL,
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    model TEXT NOT NULL,
    price REAL NOT NULL DEFAULT 0,
    stock INTEGER NOT NULL DEFAULT 0,
    specs TEXT DEFAULT '',
    image TEXT DEFAULT '',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS orders(
    id TEXT PRIMARY KEY,
    date TEXT NOT NULL,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT NOT NULL,
    city TEXT NOT NULL,
    pin TEXT NOT NULL,
    products TEXT NOT NULL,
    qty INTEGER NOT NULL,
    installation TEXT,
    payment TEXT NOT NULL,
    utr TEXT,
    status TEXT NOT NULL,
    subtotal REAL NOT NULL,
    delivery_charge REAL NOT NULL,
    total REAL NOT NULL,
    shipping_from TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS tracking_checks(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    order_id TEXT,
    checked_at TEXT NOT NULL,
    user_agent TEXT DEFAULT '',
    request_id TEXT NOT NULL DEFAULT ''
  );

  CREATE INDEX IF NOT EXISTS idx_tracking_checks_phone
    ON tracking_checks(phone);

  CREATE INDEX IF NOT EXISTS idx_tracking_checks_order
    ON tracking_checks(order_id);

  CREATE INDEX IF NOT EXISTS idx_tracking_checks_request
    ON tracking_checks(request_id);
`);

// ============================================================
// SAFE MIGRATIONS
// ============================================================

function ensureColumn(table, column, definition) {
  const columns = db
    .prepare(`PRAGMA table_info(${table})`)
    .all()
    .map(row => row.name);

  if (!columns.includes(column)) {
    db.exec(
      `ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`
    );
  }
}

ensureColumn(
  'orders',
  'status_updated_at',
  'TEXT'
);

ensureColumn(
  'orders',
  'last_tracking_check_at',
  'TEXT'
);

ensureColumn(
  'tracking_checks',
  'request_id',
  'TEXT'
);

db.prepare(`
  UPDATE orders
  SET status_updated_at = COALESCE(
    NULLIF(status_updated_at, ''),
    date
  )
  WHERE status_updated_at IS NULL
     OR status_updated_at = ''
`).run();

// ============================================================
// HELPERS
// ============================================================

function cleanText(value, max = 500) {
  return String(value ?? '')
    .trim()
    .slice(0, max);
}

function makeId(prefix) {
  return (
    prefix +
    '-' +
    Date.now() +
    '-' +
    crypto.randomBytes(4).toString('hex')
  );
}

function normalizePhone(value) {
  return cleanText(value, 50)
    .replace(/\D/g, '');
}

// ============================================================
// ADMIN ACCOUNT
// ============================================================

const ADMIN_USER = 'GOPALTHAKUR821';
const ADMIN_PASS = 'GOPAL@5467';

const adminExists = db
  .prepare(
    'SELECT id FROM admins WHERE username = ?'
  )
  .get(ADMIN_USER);

if (!adminExists) {
  db.prepare(`
    INSERT INTO admins(
      username,
      password_hash
    )
    VALUES(?, ?)
  `).run(
    ADMIN_USER,
    bcrypt.hashSync(ADMIN_PASS, 12)
  );
}

// ============================================================
// DEFAULT PRODUCTS
// ============================================================

const defaults = [
  [
    'DS-2CE16D0T-ITPFS',
    'HIKVISION',
    'Camera',
    '2MP Audio Bullet',
    'DS-2CE16D0T-ITPFS',
    1179,
    10,
    '2MP • Audio • IR Bullet',
    ''
  ],

  [
    'brand-DS-2CE76D0T-ITPFS',
    'HIKVISION',
    'Camera',
    '2MP Audio Turret',
    'DS-2CE76D0T-ITPFS',
    800,
    10,
    '2MP • Audio • IR Turret',
    ''
  ],

  [
    'brand-DS-7108NI-Q1-M',
    'HIKVISION',
    'NVR',
    '8CH NVR',
    'DS-7108NI-Q1/M',
    4900,
    10,
    '8CH Network Video Recorder',
    ''
  ],

  [
    'brand-HDCVI-Full-Color-Series',
    'DAHUA',
    'Camera',
    '2MP Full-Color Bullet',
    'HDCVI Full-Color Series',
    3850,
    10,
    '2MP • Full Color • Starlight',
    ''
  ],

  [
    'brand-NVR1108HS-S3-H',
    'DAHUA',
    'NVR',
    '8CH NVR',
    'NVR1108HS-S3/H',
    5599,
    10,
    '8CH Network Video Recorder',
    ''
  ],

  [
    'brand-NVR4208-8P-Series',
    'DAHUA',
    'NVR',
    '8CH PoE NVR',
    'NVR4208-8P Series',
    0,
    10,
    '8CH • 8 PoE Ports • WizSense',
    ''
  ],

  [
    'CP-UNC-TA21L3C-Q',
    'CP PLUS',
    'Camera',
    '2MP IP Bullet Camera',
    'CP-UNC-TA21L3C-Q',
    2850,
    10,
    '2MP • IR • PoE • IP67',
    ''
  ],

  [
    'CP-UNC-DA41L3C-D-Q',
    'CP PLUS',
    'Camera',
    '4MP IP Dome Camera',
    'CP-UNC-DA41L3C-D-Q',
    3000,
    10,
    '4MP • IR • Mic • PoE',
    ''
  ],

  [
    'CP-UVR-0801F1V-I',
    'CP PLUS',
    'DVR',
    '8CH DVR',
    'CP-UVR-0801F1V-I',
    4500,
    10,
    '8CH • H.265 • HDMI/VGA',
    ''
  ],

  [
    'CP-ANW-HPU8H2-N12',
    'CP PLUS',
    'PoE Switch',
    '8CH PoE Switch',
    'CP-ANW-HPU8H2-N12',
    1265,
    10,
    '8 PoE + 2 Uplink • 120W',
    ''
  ],

  [
    'brand-UNV-IPC-Series',
    'UNV',
    'Camera',
    'Network Cameras',
    'UNV IPC Series',
    0,
    10,
    '2MP / 4MP / 5MP / 8MP • IP cameras',
    ''
  ],

  [
    'brand-UNV-NVR-Series',
    'UNV',
    'NVR',
    'Network Recorders',
    'UNV NVR Series',
    0,
    10,
    '4CH / 8CH / 16CH / 32CH+',
    ''
  ],

  [
    'brand-Tiandy-Network-Camera-Series',
    'TIANDY',
    'Camera',
    'IP Camera Range',
    'Tiandy Network Camera Series',
    0,
    10,
    'Starlight • Full Color • Smart IR',
    ''
  ],

  [
    'brand-Tiandy-NVR-Series',
    'TIANDY',
    'NVR',
    'NVR Range',
    'Tiandy NVR Series',
    0,
    10,
    '4CH / 8CH / 16CH / 32CH+',
    ''
  ],

  [
    'brand-Prama-CCTV-Series',
    'PRAMA',
    'Camera',
    'Security Camera Range',
    'Prama CCTV Series',
    0,
    10,
    'HD / IP cameras • Multiple resolutions',
    ''
  ],

  [
    'brand-Prama-DVR-NVR-Series',
    'PRAMA',
    'NVR',
    'Recorder Range',
    'Prama DVR / NVR Series',
    0,
    10,
    'Multiple channel and storage options',
    ''
  ]
];

const seedProduct = db.prepare(`
  INSERT OR IGNORE INTO products(
    id,
    brand,
    category,
    name,
    model,
    price,
    stock,
    specs,
    image,
    created_at
  )
  VALUES(?,?,?,?,?,?,?,?,?,?)
`);

for (const product of defaults) {
  seedProduct.run(
    ...product,
    new Date().toISOString()
  );
}

// ============================================================
// PRODUCT PAYLOAD
// ============================================================

function productPayload(body, existing = {}) {
  return {
    brand: cleanText(
      body.brand ?? existing.brand,
      100
    ),

    category: cleanText(
      body.category ??
      existing.category ??
      'Camera',
      80
    ),

    name: cleanText(
      body.name ?? existing.name,
      200
    ),

    model: cleanText(
      body.model ?? existing.model,
      160
    ),

    price: Math.max(
      0,
      Number(
        body.price ??
        existing.price ??
        0
      ) || 0
    ),

    stock: Math.max(
      0,
      Math.floor(
        Number(
          body.stock ??
          existing.stock ??
          0
        ) || 0
      )
    ),

    specs: cleanText(
      body.specs ??
      existing.specs,
      500
    ),

    image: cleanText(
      body.image ??
      existing.image,
      12000000
    )
  };
}

// ============================================================
// AUTH
// ============================================================

function auth(req, res, next) {
  const header =
    req.headers.authorization || '';

  const token = header
    .replace(/^Bearer\s+/i, '')
    .trim();

  if (!token) {
    return res.status(401).json({
      error: 'Admin login required'
    });
  }

  const session = db
    .prepare(`
      SELECT *
      FROM sessions
      WHERE token = ?
        AND expires_at > ?
    `)
    .get(
      token,
      Date.now()
    );

  if (!session) {
    return res.status(401).json({
      error: 'Admin login required'
    });
  }

  req.adminId = session.admin_id;
  req.sessionToken = token;

  next();
}

// ============================================================
// LOGIN
// ============================================================

app.post('/api/login', (req, res) => {
  try {
    const username = cleanText(
      req.body?.username,
      100
    );

    const password = String(
      req.body?.password || ''
    );

    const admin = db
      .prepare(`
        SELECT *
        FROM admins
        WHERE username = ?
      `)
      .get(username);

    if (
      !admin ||
      !bcrypt.compareSync(
        password,
        admin.password_hash
      )
    ) {
      return res.status(401).json({
        error: 'Invalid username or password'
      });
    }

    const token = crypto
      .randomBytes(32)
      .toString('hex');

    const expiresAt =
      Date.now() +
      7 * 24 * 60 * 60 * 1000;

    db.prepare(`
      INSERT INTO sessions(
        token,
        admin_id,
        expires_at
      )
      VALUES(?,?,?)
    `).run(
      token,
      admin.id,
      expiresAt
    );

    res.json({
      ok: true,
      token,
      expiresAt
    });

  } catch (error) {
    console.error('LOGIN ERROR:', error);

    res.status(500).json({
      error: 'Login server error'
    });
  }
});

// ============================================================
// LOGOUT
// ============================================================

app.post(
  '/api/logout',
  auth,
  (req, res) => {
    db.prepare(`
      DELETE FROM sessions
      WHERE token = ?
    `).run(req.sessionToken);

    res.json({
      ok: true
    });
  }
);

// ============================================================
// CHECK ADMIN SESSION
// ============================================================

app.get(
  '/api/admin/me',
  auth,
  (req, res) => {
    res.json({
      ok: true,
      adminId: req.adminId
    });
  }
);

// ============================================================
// PUBLIC PRODUCTS
// ============================================================

app.get(
  '/api/products',
  (req, res) => {
    try {
      const products = db
        .prepare(`
          SELECT *
          FROM products
          ORDER BY rowid DESC
        `)
        .all();

      res.json({
        ok: true,
        products
      });

    } catch (error) {
      console.error(
        'PRODUCT LOAD ERROR:',
        error
      );

      res.status(500).json({
        error: 'Products load failed'
      });
    }
  }
);

// ============================================================
// ADMIN PRODUCTS - GET
// ============================================================

app.get(
  '/api/admin/products',
  auth,
  (req, res) => {
    try {
      const products = db
        .prepare(`
          SELECT *
          FROM products
          ORDER BY rowid DESC
        `)
        .all();

      res.json({
        ok: true,
        products
      });

    } catch (error) {
      console.error(
        'ADMIN PRODUCTS ERROR:',
        error
      );

      res.status(500).json({
        error: 'Products load failed'
      });
    }
  }
);

// ============================================================
// ADMIN PRODUCTS - ADD
// ============================================================

app.post(
  '/api/admin/products',
  auth,
  (req, res) => {
    try {
      const product =
        productPayload(
          req.body || {}
        );

      if (
        !product.brand ||
        !product.name ||
        !product.model
      ) {
        return res.status(400).json({
          error:
            'Brand, product name and model are required.'
        });
      }

      let id =
        cleanText(
          req.body?.id,
          160
        ) || makeId('prod');

      const alreadyExists =
        db
          .prepare(
            'SELECT id FROM products WHERE id = ?'
          )
          .get(id);

      if (alreadyExists) {
        id = makeId('prod');
      }

      db.prepare(`
        INSERT INTO products(
          id,
          brand,
          category,
          name,
          model,
          price,
          stock,
          specs,
          image,
          created_at
        )
        VALUES(?,?,?,?,?,?,?,?,?,?)
      `).run(
        id,
        product.brand,
        product.category,
        product.name,
        product.model,
        product.price,
        product.stock,
        product.specs,
        product.image,
        new Date().toISOString()
      );

      const saved =
        db
          .prepare(
            'SELECT * FROM products WHERE id = ?'
          )
          .get(id);

      res.json({
        ok: true,
        product: saved
      });

    } catch (error) {
      console.error(
        'ADD PRODUCT ERROR:',
        error
      );

      res.status(500).json({
        error: 'Product add failed'
      });
    }
  }
);

// ============================================================
// ADMIN PRODUCTS - UPDATE
// ============================================================

app.put(
  '/api/admin/products/:id',
  auth,
  (req, res) => {
    try {
      const id =
        cleanText(
          req.params.id,
          160
        );

      const existing =
        db
          .prepare(
            'SELECT * FROM products WHERE id = ?'
          )
          .get(id);

      if (!existing) {
        return res.status(404).json({
          error: 'Product not found.'
        });
      }

      const product =
        productPayload(
          req.body || {},
          existing
        );

      if (
        !product.brand ||
        !product.name ||
        !product.model
      ) {
        return res.status(400).json({
          error:
            'Brand, product name and model are required.'
        });
      }

      db.prepare(`
        UPDATE products
        SET
          brand = ?,
          category = ?,
          name = ?,
          model = ?,
          price = ?,
          stock = ?,
          specs = ?,
          image = ?
        WHERE id = ?
      `).run(
        product.brand,
        product.category,
        product.name,
        product.model,
        product.price,
        product.stock,
        product.specs,
        product.image,
        id
      );

      const updated =
        db
          .prepare(
            'SELECT * FROM products WHERE id = ?'
          )
          .get(id);

      res.json({
        ok: true,
        product: updated
      });

    } catch (error) {
      console.error(
        'UPDATE PRODUCT ERROR:',
        error
      );

      res.status(500).json({
        error: 'Product update failed'
      });
    }
  }
);

// ============================================================
// ADMIN PRODUCTS - DELETE
// ============================================================

app.delete(
  '/api/admin/products/:id',
  auth,
  (req, res) => {
    try {
      const id =
        cleanText(
          req.params.id,
          160
        );

      const result =
        db
          .prepare(
            'DELETE FROM products WHERE id = ?'
          )
          .run(id);

      if (!result.changes) {
        return res.status(404).json({
          error: 'Product not found.'
        });
      }

      res.json({
        ok: true
      });

    } catch (error) {
      console.error(
        'DELETE PRODUCT ERROR:',
        error
      );

      res.status(500).json({
        error: 'Product delete failed'
      });
    }
  }
);

// ============================================================
// DELIVERY
// ============================================================

function delivery(pin, city) {
  pin = String(pin || '')
    .replace(/\D/g, '')
    .slice(0, 6);

  city = String(city || '')
    .toLowerCase();

  if (pin.length !== 6) {
    return null;
  }

  if (
    pin.startsWith('204') ||
    city.includes('hathras')
  ) {
    return 50;
  }

  if (
    ['202', '281', '282', '283']
      .some(prefix =>
        pin.startsWith(prefix)
      )
  ) {
    return 70;
  }

  if (
    /^(20|21|22|23|24|25|26|27|28)/.test(pin)
  ) {
    return 90;
  }

  if (
    ['110', '121', '122', '201', '203']
      .some(prefix =>
        pin.startsWith(prefix)
      )
  ) {
    return 120;
  }

  if (
    /^(14|16|17|18|30)/.test(pin)
  ) {
    return 150;
  }

  return 200;
}

// ============================================================
// CREATE ORDER
// ============================================================

app.post(
  '/api/orders',
  (req, res) => {
    try {
      const body =
        req.body || {};

      const items =
        Array.isArray(body.items)
          ? body.items
          : [];

      if (!items.length) {
        return res.status(400).json({
          error: 'Cart is empty'
        });
      }

      if (
        !body.name ||
        !body.phone ||
        !body.address ||
        !body.city ||
        !body.pin
      ) {
        return res.status(400).json({
          error:
            'Delivery details required'
        });
      }

      const deliveryCharge =
        delivery(
          body.pin,
          body.city
        );

      if (deliveryCharge === null) {
        return res.status(400).json({
          error: 'Invalid PIN'
        });
      }

      let subtotal = 0;
      let qty = 0;

      const products =
        items.map(item => {
          const price =
            Number(item.price) || 0;

          const quantity =
            Math.max(
              1,
              Number(item.qty) || 1
            );

          subtotal +=
            price * quantity;

          qty += quantity;

          return (
            `${quantity} × ` +
            `${cleanText(
              item.name,
              180
            )} ` +
            `(${cleanText(
              item.productId,
              100
            )}) ` +
            `@ ₹${price.toLocaleString(
              'en-IN'
            )}`
          );
        }).join('; ');

      const id =
        makeId('GTEC');

      const date =
        new Date().toLocaleString(
          'en-IN'
        );

      const total =
        subtotal +
        deliveryCharge;

      const normalizedPhone =
        normalizePhone(
          body.phone
        );

      const statusUpdatedAt =
        new Date().toISOString();

      db.prepare(`
        INSERT INTO orders(
          id,
          date,
          name,
          phone,
          address,
          city,
          pin,
          products,
          qty,
          installation,
          payment,
          utr,
          status,
          subtotal,
          delivery_charge,
          total,
          shipping_from,
          status_updated_at,
          last_tracking_check_at
        )
        VALUES(
          ?,?,?,?,?,?,?,?,?,?,
          ?,?,?,?,?,?,?,?,?
        )
      `).run(
        id,
        date,
        cleanText(
          body.name,
          150
        ),
        normalizedPhone,
        cleanText(
          body.address,
          500
        ),
        cleanText(
          body.city,
          100
        ),
        cleanText(
          body.pin,
          10
        ),
        products,
        qty,
        cleanText(
          body.installation,
          50
        ) || 'No',
        cleanText(
          body.payment,
          30
        ),
        cleanText(
          body.utr,
          100
        ),
        'New',
        subtotal,
        deliveryCharge,
        total,
        'Kailora Chauraha, Hathras Jn, UP 204102',
        statusUpdatedAt,
        null
      );

      res.json({
        ok: true,

        order: {
          id,
          date,
          subtotal,
          deliveryCharge,
          total,
          status: 'New',
          statusUpdatedAt
        }
      });

    } catch (error) {
      console.error(
        'CREATE ORDER ERROR:',
        error
      );

      res.status(500).json({
        error: 'Order creation failed'
      });
    }
  }
);

// ============================================================
// TRACKING LABEL
// ============================================================

function trackingLabel(status) {
  const labels = {
    New: 'Order received',

    Contacted:
      'Customer contacted',

    Confirmed:
      'Order confirmed / processing',

    Dispatched:
      'Parcel dispatched / in transit',

    Delivered:
      'Parcel delivered',

    Cancelled:
      'Order cancelled'
  };

  return labels[status] || status;
}

// ============================================================
// CUSTOMER TRACKING
// ============================================================

app.post(
  '/api/track-order',
  (req, res) => {
    try {
      const phone =
        normalizePhone(
          req.body?.phone
        );

      if (phone.length < 10) {
        return res.status(400).json({
          error:
            'Enter the same 10-digit contact number used for the order.'
        });
      }

      const rows =
        db.prepare(`
          SELECT
            id,
            date,
            products,
            qty,
            payment,
            status,
            subtotal,
            delivery_charge AS deliveryCharge,
            total,
            shipping_from AS shippingFrom,
            status_updated_at AS statusUpdatedAt,
            last_tracking_check_at AS lastTrackingCheckAt
          FROM orders
          WHERE phone = ?
          ORDER BY rowid DESC
        `).all(phone);

      const checkedAt =
        new Date().toISOString();

      const requestId =
        makeId('TRK');

      const log =
        db.prepare(`
          INSERT INTO tracking_checks(
            phone,
            order_id,
            checked_at,
            user_agent,
            request_id
          )
          VALUES(?,?,?,?,?)
        `);

      const transaction =
        db.transaction(orderRows => {

          if (!orderRows.length) {
            log.run(
              phone,
              null,
              checkedAt,
              cleanText(
                req.headers['user-agent'],
                500
              ),
              requestId
            );
          }

          for (const order of orderRows) {

            log.run(
              phone,
              order.id,
              checkedAt,
              cleanText(
                req.headers['user-agent'],
                500
              ),
              requestId
            );

            db.prepare(`
              UPDATE orders
              SET last_tracking_check_at = ?
              WHERE id = ?
            `).run(
              checkedAt,
              order.id
            );
          }
        });

      transaction(rows);

      res.json({
        ok: true,

        phoneLast4:
          phone.slice(-4),

        orders:
          rows.map(order => ({
            ...order,
            trackingLabel:
              trackingLabel(
                order.status
              )
          })),

        checkedAt
      });

    } catch (error) {
      console.error(
        'TRACKING ERROR:',
        error
      );

      res.status(500).json({
        error:
          'Tracking server error'
      });
    }
  }
);

// ============================================================
// ADMIN ORDERS
// ============================================================

app.get(
  '/api/admin/orders',
  auth,
  (req, res) => {
    try {
      const rows =
        db.prepare(`
          SELECT
            o.id,
            o.date,
            o.name,
            o.phone,
            o.address,
            o.city,
            o.pin,
            o.products,
            o.qty,
            o.installation,
            o.payment,
            o.utr,
            o.status,
            o.subtotal,
            o.delivery_charge AS deliveryCharge,
            o.total,
            o.shipping_from AS shippingFrom,
            o.status_updated_at AS statusUpdatedAt,
            o.last_tracking_check_at AS lastTrackingCheckAt,

            COALESCE(
              tc.check_count,
              0
            ) AS trackingCheckCount

          FROM orders o

          LEFT JOIN (
            SELECT
              order_id,
              COUNT(*) AS check_count

            FROM tracking_checks

            WHERE order_id IS NOT NULL

            GROUP BY order_id
          ) tc

          ON tc.order_id = o.id

          ORDER BY o.rowid DESC
        `)
        .all();

      res.json({
        ok: true,
        orders: rows
      });

    } catch (error) {
      console.error(
        'ADMIN ORDERS ERROR:',
        error
      );

      res.status(500).json({
        error:
          'Orders load failed'
      });
    }
  }
);

// ============================================================
// TRACKING STATS
// ============================================================

app.get(
  '/api/admin/tracking-stats',
  auth,
  (req, res) => {
    try {
      const byPhone =
        db.prepare(`
          SELECT
            phone,

            COUNT(
              DISTINCT request_id
            ) AS totalChecks,

            COUNT(
              DISTINCT order_id
            ) AS ordersChecked,

            MAX(checked_at)
              AS lastCheckedAt

          FROM tracking_checks

          GROUP BY phone

          ORDER BY lastCheckedAt DESC
        `).all();

      const byOrder =
        db.prepare(`
          SELECT
            order_id,
            phone,
            COUNT(*) AS checkCount,
            MAX(checked_at)
              AS lastCheckedAt

          FROM tracking_checks

          WHERE order_id IS NOT NULL

          GROUP BY
            order_id,
            phone

          ORDER BY lastCheckedAt DESC
        `).all();

      res.json({
        ok: true,
        byPhone,
        byOrder
      });

    } catch (error) {
      console.error(
        'TRACKING STATS ERROR:',
        error
      );

      res.status(500).json({
        error:
          'Tracking stats load failed'
      });
    }
  }
);

// ============================================================
// UPDATE ORDER STATUS
// ============================================================

app.patch(
  '/api/admin/orders/:id',
  auth,
  (req, res) => {
    try {
      const allowed = [
        'New',
        'Contacted',
        'Confirmed',
        'Dispatched',
        'Delivered',
        'Cancelled'
      ];

      const status =
        req.body?.status;

      if (!allowed.includes(status)) {
        return res.status(400).json({
          error: 'Invalid status'
        });
      }

      const now =
        new Date().toISOString();

      const result =
        db.prepare(`
          UPDATE orders
          SET
            status = ?,
            status_updated_at = ?
          WHERE id = ?
        `).run(
          status,
          now,
          req.params.id
        );

      if (!result.changes) {
        return res.status(404).json({
          error: 'Order not found'
        });
      }

      res.json({
        ok: true,
        status,
        statusUpdatedAt: now
      });

    } catch (error) {
      console.error(
        'ORDER STATUS ERROR:',
        error
      );

      res.status(500).json({
        error:
          'Order status update failed'
      });
    }
  }
);

// ============================================================
// DELETE ORDERS
// ============================================================

app.delete(
  '/api/admin/orders',
  auth,
  (req, res) => {
    try {
      const ids =
        Array.isArray(
          req.body?.ids
        )
          ? req.body.ids
          : [];

      const deleteOrder =
        db.prepare(`
          DELETE FROM orders
          WHERE id = ?
        `);

      const transaction =
        db.transaction(orderIds => {

          for (const id of orderIds) {
            deleteOrder.run(
              cleanText(
                id,
                100
              )
            );
          }

        });

      transaction(ids);

      res.json({
        ok: true
      });

    } catch (error) {
      console.error(
        'DELETE ORDERS ERROR:',
        error
      );

      res.status(500).json({
        error:
          'Orders delete failed'
      });
    }
  }
);

// ============================================================
// HEALTH CHECK
// ============================================================

app.get(
  '/api/health',
  (req, res) => {
    res.json({
      ok: true,
      server: 'GTEC',
      time: new Date().toISOString()
    });
  }
);

// ============================================================
// FRONTEND ROUTING
// ============================================================

// Admin page ko directly serve karo
app.get(
  '/admin.html',
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC,
        'admin.html'
      )
    );
  }
);

// Main website
app.get(
  '/',
  (req, res) => {
    res.sendFile(
      path.join(
        PUBLIC,
        'index.html'
      )
    );
  }
);

// Frontend fallback
app.use((req, res) => {

  if (
    req.path.startsWith('/api/')
  ) {
    return res.status(404).json({
      error: 'API endpoint not found'
    });
  }

  res.sendFile(
    path.join(
      PUBLIC,
      'index.html'
    )
  );
});

// ============================================================
// EXPORT
// ============================================================

module.exports = app;

// ============================================================
// LOCAL SERVER
// ============================================================

if (require.main === module) {

  app.listen(
    PORT,
    '0.0.0.0',
    () => {

      console.log(
        `GTEC server running on port ${PORT}`
      );

      console.log(
        `Admin username: ${ADMIN_USER}`
      );

      console.log(
        `Admin password: ${ADMIN_PASS}`
      );

    }
  );
}
