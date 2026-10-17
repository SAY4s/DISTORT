'use strict';
/* DISTORT – storefront + admin API. Zero dependencies, Node >= 18. */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = __dirname;
const PUB = path.join(ROOT, 'public');
const DATA = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT, 'data');
const UP = path.join(DATA, 'uploads');
const DB_FILE = path.join(DATA, 'db.json');
const ADMIN_FILE = path.join(DATA, 'admin.json');
const ENV_PASS = process.env.ADMIN_PASSWORD || '';
const PUBLIC_CORS = process.env.CORS_ORIGIN || '*';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
fs.mkdirSync(UP, { recursive: true });

/* ---------- storage ---------- */
const DEFAULT_TEXTS = JSON.parse(fs.readFileSync(path.join(ROOT, 'default-texts.json'), 'utf8'));
let db;
if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
else { db = JSON.parse(fs.readFileSync(path.join(ROOT, 'seed.json'), 'utf8')); save(); }
db.texts = db.texts || { fa: {}, en: {} };
function save() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 1));
  fs.renameSync(tmp, DB_FILE);
}

/* ---------- auth ---------- */
const sha = s => crypto.createHash('sha256').update(String(s)).digest();
function hashPass(p, salt) { return crypto.scryptSync(p, salt, 32).toString('hex'); }
if (!ENV_PASS && !fs.existsSync(ADMIN_FILE)) {
  const pass = crypto.randomBytes(9).toString('base64url');
  const salt = crypto.randomBytes(16).toString('hex');
  fs.writeFileSync(ADMIN_FILE, JSON.stringify({ salt, hash: hashPass(pass, salt) }));
  console.log('\n  ┌──────────────────────────────────────────────┐');
  console.log('  │  First run: admin password was generated      │');
  console.log('  │  Password:  ' + pass.padEnd(34) + '│');
  console.log('  │  Change it in Settings after you sign in.     │');
  console.log('  └──────────────────────────────────────────────┘\n');
}
function checkPassword(p) {
  if (typeof p !== 'string' || !p || p.length > 200) return false;
  if (ENV_PASS) return crypto.timingSafeEqual(sha(p), sha(ENV_PASS));
  const a = JSON.parse(fs.readFileSync(ADMIN_FILE, 'utf8'));
  return crypto.timingSafeEqual(Buffer.from(hashPass(p, a.salt), 'hex'), Buffer.from(a.hash, 'hex'));
}
const sessions = new Map(); // token -> expiry
const SESSION_MS = 12 * 3600e3;
const fails = new Map();    // ip -> {n, until}
const clientIp = req => (TRUST_PROXY && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress) || '?';
function authed(req) {
  const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization || '');
  if (!m) return false;
  const exp = sessions.get(m[1]);
  if (!exp) return false;
  if (exp < Date.now()) { sessions.delete(m[1]); return false; }
  return m[1];
}

/* ---------- helpers ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp', '.gif': 'image/gif', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8' };
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = m => new HttpError(400, m);
function send(res, status, body, headers = {}) {
  const isObj = typeof body === 'object' && !Buffer.isBuffer(body);
  res.writeHead(status, Object.assign({ 'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' }, headers));
  res.end(isObj ? JSON.stringify(body) : body);
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > limit) { reject(new HttpError(413, 'حجم درخواست زیاد است')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch { reject(bad('JSON نامعتبر است')); } });
    req.on('error', reject);
  });
}
const str = (v, max, label, required = true) => {
  v = v == null ? '' : String(v).trim();
  if (required && !v) throw bad(label + ' الزامی است');
  if (v.length > max) throw bad(label + ' حداکثر ' + max + ' کاراکتر باشد');
  return v;
};
const int = (v, min, max, label) => {
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw bad(label + ' باید عدد صحیح بین ' + min + ' و ' + max + ' باشد');
  return n;
};
const slug = s => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 30);
const HEX = /^#[0-9a-f]{6}$/i;
const SHAPES = ['hoodie', 'crewneck', 'tshirt'];
const MOTIFS = ['gaming', 'pinterest', 'music', 'cinema', 'anime', 'misc'];
const IMG_URL = /^\/uploads\/[a-f0-9]{32}\.(png|jpg|webp|gif)$/;
const uniqueId = (list, base, prefix) => {
  let id = slug(base) || prefix + Date.now().toString(36), i = 2, cand = id;
  while (list.some(x => x.id === cand)) cand = id + '-' + i++;
  return cand;
};
const imgExists = u => IMG_URL.test(u) && fs.existsSync(path.join(UP, path.basename(u)));
function referencedImages() {
  const s = new Set(db.products.flatMap(p => p.images || []));
  if (db.settings.logo) s.add(db.settings.logo);
  return s;
}
function dropImages(urls) {
  const ref = referencedImages();
  urls.filter(u => IMG_URL.test(u) && !ref.has(u)).forEach(u => { try { fs.unlinkSync(path.join(UP, path.basename(u))); } catch {} });
}

/* ---------- validators ---------- */
const V = {
  types(b, ex) {
    return { id: ex ? ex.id : null, fa: str(b.fa, 60, 'نام فارسی'), en: str(b.en, 60, 'نام انگلیسی'),
      shape: SHAPES.includes(b.shape) ? b.shape : (() => { throw bad('شکل لباس نامعتبر است'); })() };
  },
  styles(b, ex) {
    let g = null;
    if (Array.isArray(b.g) && b.g.length === 2) { if (!b.g.every(c => HEX.test(c))) throw bad('رنگ گرادیان نامعتبر است'); g = b.g; }
    return { id: ex ? ex.id : null, fa: str(b.fa, 60, 'نام فارسی'), en: str(b.en, 60, 'نام انگلیسی'),
      motif: MOTIFS.includes(b.motif) ? b.motif : (() => { throw bad('طرح نمادین نامعتبر است'); })(), g };
  },
  colors(b, ex) {
    if (!HEX.test(b.h || '')) throw bad('کد رنگ نامعتبر است');
    return { id: ex ? ex.id : null, fa: str(b.fa, 40, 'نام فارسی رنگ'), en: str(b.en, 40, 'نام انگلیسی رنگ'), h: b.h.toLowerCase() };
  },
  products(b, ex) {
    if (!db.types.some(t => t.id === b.type)) throw bad('نوع لباس نامعتبر است');
    if (!db.styles.some(s => s.id === b.style)) throw bad('سبک طرح نامعتبر است');
    const colors = [...new Set(Array.isArray(b.colors) ? b.colors : [])];
    if (!colors.length) throw bad('حداقل یک رنگ انتخاب کنید');
    if (!colors.every(id => db.colors.some(c => c.id === id))) throw bad('رنگ نامعتبر است');
    const price = int(b.price, 0, 1e10, 'قیمت');
    let oldPrice = null;
    if (b.oldPrice !== '' && b.oldPrice != null) { oldPrice = int(b.oldPrice, 0, 1e10, 'قیمت قبل از تخفیف'); if (oldPrice <= price) throw bad('قیمت قبل از تخفیف باید بیشتر از قیمت فعلی باشد'); }
    const out = [...new Set(Array.isArray(b.outOfStock) ? b.outOfStock : [])];
    if (!out.every(s => db.settings.sizes.includes(s))) throw bad('سایز نامعتبر است');
    const images = Array.isArray(b.images) ? b.images : [];
    if (images.length > 8) throw bad('حداکثر ۸ تصویر مجاز است');
    if (!images.every(imgExists)) throw bad('یکی از تصاویر نامعتبر است');
    let createdAt = Number(b.createdAt); if (!Number.isFinite(createdAt) || createdAt <= 0) createdAt = ex ? ex.createdAt : Date.now();
    return { id: ex ? ex.id : null, code: str(b.code, 24, 'کد محصول', false), fa: str(b.fa, 120, 'نام فارسی'), en: str(b.en, 120, 'نام انگلیسی'),
      type: b.type, style: b.style, price, oldPrice, colors, outOfStock: out, sold: int(b.sold || 0, 0, 1e9, 'تعداد فروش'), createdAt,
      descFa: str(b.descFa, 2000, 'توضیحات فارسی', false), descEn: str(b.descEn, 2000, 'توضیحات انگلیسی', false),
      images, published: b.published !== false };
  }
};
const IN_USE = {
  types: id => db.products.filter(p => p.type === id).length,
  styles: id => db.products.filter(p => p.style === id).length,
  colors: id => db.products.filter(p => p.colors.includes(id)).length,
  products: () => 0
};

function publicPayload() {
  const { logo, sizes, sizeGuide } = db.settings;
  return { settings: { logo, sizes, sizeGuide }, texts: db.texts, types: db.types, styles: db.styles, colors: db.colors,
    products: db.products.filter(p => p.published) };
}

function validateTexts(body) {
  const out = { fa: {}, en: {} };
  for (const lang of ['fa', 'en']) {
    const src = body[lang] || {};
    if (typeof src !== 'object') throw bad('ساختار متن‌ها نامعتبر است');
    for (const [k, v] of Object.entries(src)) {
      const def = DEFAULT_TEXTS[lang][k];
      if (def === undefined) throw bad('کلید ناشناخته: ' + k);
      if (v === null || v === '' || JSON.stringify(v) === JSON.stringify(def)) continue;
      if (Array.isArray(def)) {
        if (!Array.isArray(v) || v.length > 40) throw bad('مقدار لیستی نامعتبر: ' + k);
        const isPair = Array.isArray(def[0]);
        out[lang][k] = v.map(x => isPair
          ? (Array.isArray(x) && x.length === 2 ? [str(x[0], 400, k), str(x[1], 2000, k)] : (() => { throw bad('جفت سؤال/پاسخ نامعتبر'); })())
          : str(x, 200, k)).filter(x => isPair ? true : x);
      } else {
        if (typeof v !== 'string') throw bad('مقدار نامعتبر: ' + k);
        out[lang][k] = str(v, 2000, k);
      }
    }
  }
  return out;
}

/* ---------- API ---------- */
async function api(req, res, url) {
  const p = url.pathname, m = req.method;
  const cors = { 'Access-Control-Allow-Origin': PUBLIC_CORS, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET, OPTIONS' };
  if (m === 'OPTIONS') return send(res, 204, '', cors);
  if (p === '/api/public' && m === 'GET') return send(res, 200, publicPayload(), Object.assign({ 'Cache-Control': 'no-store' }, cors));

  if (p === '/api/admin/login' && m === 'POST') {
    const ip = clientIp(req), f = fails.get(ip) || { n: 0, until: 0 };
    if (f.until > Date.now()) throw new HttpError(429, 'تلاش‌های ناموفق زیاد بود؛ چند دقیقه بعد دوباره امتحان کنید');
    const b = await readBody(req, 10e3);
    if (!checkPassword(b.password)) {
      f.n++; if (f.n >= 5) { f.until = Date.now() + 5 * 60e3; f.n = 0; } fails.set(ip, f);
      throw new HttpError(401, 'رمز عبور اشتباه است');
    }
    fails.delete(ip);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, Date.now() + SESSION_MS);
    return send(res, 200, { token });
  }
  if (!p.startsWith('/api/admin/')) throw new HttpError(404, 'پیدا نشد');
  const token = authed(req);
  if (!token) throw new HttpError(401, 'نیاز به ورود');
  if (p === '/api/admin/logout' && m === 'POST') { sessions.delete(token); return send(res, 200, { ok: true }); }

  if (p === '/api/admin/all' && m === 'GET')
    return send(res, 200, { types: db.types, styles: db.styles, colors: db.colors, products: db.products, texts: db.texts, defaults: DEFAULT_TEXTS, settings: db.settings, envPassword: !!ENV_PASS });
  if (p === '/api/admin/export' && m === 'GET')
    return send(res, 200, JSON.stringify(db, null, 1), { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': 'attachment; filename="distort-backup-' + new Date().toISOString().slice(0, 10) + '.json"' });

  if (p === '/api/admin/texts' && m === 'PUT') { db.texts = validateTexts(await readBody(req, 1e6)); save(); return send(res, 200, { ok: true, texts: db.texts }); }

  if (p === '/api/admin/settings' && m === 'PUT') {
    const b = await readBody(req, 1e6), s = db.settings;
    if (b.logo !== undefined) { if (b.logo !== null && !imgExists(b.logo)) throw bad('لوگوی نامعتبر'); const old = s.logo; s.logo = b.logo; if (old && old !== b.logo) { save(); dropImages([old]); } }
    if (b.sizes !== undefined) {
      if (!Array.isArray(b.sizes) || !b.sizes.length || b.sizes.length > 12) throw bad('فهرست سایزها نامعتبر است');
      s.sizes = [...new Set(b.sizes.map(x => str(x, 6, 'سایز')))];
      db.products.forEach(pr => { pr.outOfStock = pr.outOfStock.filter(z => s.sizes.includes(z)); });
    }
    if (b.sizeGuide !== undefined) {
      if (!Array.isArray(b.sizeGuide) || b.sizeGuide.length > 12) throw bad('جدول اندازه نامعتبر است');
      s.sizeGuide = b.sizeGuide.map(r => [str(r[0], 6, 'سایز'), int(r[1], 0, 500, 'عرض'), int(r[2], 0, 500, 'قد')]);
    }
    save(); return send(res, 200, { ok: true, settings: s });
  }

  if (p === '/api/admin/password' && m === 'POST') {
    if (ENV_PASS) throw bad('رمز از طریق متغیر محیطی ADMIN_PASSWORD تنظیم شده و از اینجا قابل تغییر نیست');
    const b = await readBody(req, 10e3);
    if (!checkPassword(b.current)) throw new HttpError(401, 'رمز فعلی اشتباه است');
    if (typeof b.next !== 'string' || b.next.length < 8 || b.next.length > 100) throw bad('رمز جدید باید حداقل ۸ کاراکتر باشد');
    const salt = crypto.randomBytes(16).toString('hex');
    fs.writeFileSync(ADMIN_FILE, JSON.stringify({ salt, hash: hashPass(b.next, salt) }));
    sessions.clear(); const t = crypto.randomBytes(32).toString('hex'); sessions.set(t, Date.now() + SESSION_MS);
    return send(res, 200, { ok: true, token: t });
  }

  if (p === '/api/admin/upload' && m === 'POST') {
    const b = await readBody(req, 8e6);
    const mm = /^data:image\/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/=]+)$/.exec(b.dataUrl || '');
    if (!mm) throw bad('فقط تصاویر PNG، JPG، WEBP و GIF مجاز است');
    const buf = Buffer.from(mm[2], 'base64');
    if (buf.length > 5 * 1024 * 1024) throw bad('حجم تصویر حداکثر ۵ مگابایت باشد');
    let ext = null;
    if (buf.slice(0, 4).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47]))) ext = 'png';
    else if (buf.slice(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))) ext = 'jpg';
    else if (buf.slice(0, 4).toString('latin1') === 'GIF8') ext = 'gif';
    else if (buf.slice(0, 4).toString('latin1') === 'RIFF' && buf.slice(8, 12).toString('latin1') === 'WEBP') ext = 'webp';
    if (!ext) throw bad('محتوای فایل با فرمت تصویر مطابقت ندارد');
    const name = crypto.randomBytes(16).toString('hex') + '.' + ext;
    fs.writeFileSync(path.join(UP, name), buf);
    return send(res, 200, { url: '/uploads/' + name });
  }

  const cm = /^\/api\/admin\/(types|styles|colors|products)(?:\/([^/]+))?$/.exec(p);
  const rm = /^\/api\/admin\/(types|styles|colors)\/reorder$/.exec(p);
  if (rm && m === 'POST') {
    const col = rm[1], b = await readBody(req, 1e5);
    if (!Array.isArray(b.ids) || b.ids.length !== db[col].length || !b.ids.every(id => db[col].some(x => x.id === id))) throw bad('ترتیب نامعتبر است');
    db[col] = b.ids.map(id => db[col].find(x => x.id === id)); save(); return send(res, 200, { ok: true });
  }
  if (cm) {
    const col = cm[1], id = cm[2];
    if (m === 'POST' && !id) {
      const b = await readBody(req, 1e5), item = V[col](b, null);
      if (col === 'products') { item.id = 'p' + (db.nextProductId++); item.code = item.code || 'DS-' + String(db.nextProductId - 1).padStart(4, '0'); if (db.products.some(x => x.code === item.code)) throw bad('این کد محصول قبلاً استفاده شده'); }
      else item.id = uniqueId(db[col], b.id || b.en, col[0]);
      db[col].push(item); save(); return send(res, 201, item);
    }
    const idx = db[col].findIndex(x => x.id === id);
    if (idx < 0) throw new HttpError(404, 'پیدا نشد');
    if (m === 'PUT') {
      const ex = db[col][idx], item = V[col](await readBody(req, 1e5), ex);
      if (col === 'products') { item.code = item.code || ex.code; if (db.products.some(x => x.code === item.code && x.id !== ex.id)) throw bad('این کد محصول قبلاً استفاده شده'); }
      db[col][idx] = item; save();
      if (col === 'products') dropImages((ex.images || []).filter(u => !item.images.includes(u)));
      return send(res, 200, item);
    }
    if (m === 'DELETE') {
      const n = IN_USE[col](id);
      if (n) throw new HttpError(409, 'این مورد در ' + n + ' محصول استفاده شده؛ ابتدا آن محصولات را تغییر دهید');
      if (col !== 'products' && db[col].length <= 1) throw bad('حداقل یک مورد باید باقی بماند');
      const [gone] = db[col].splice(idx, 1); save();
      if (col === 'products') dropImages(gone.images || []);
      return send(res, 200, { ok: true });
    }
  }
  throw new HttpError(404, 'پیدا نشد');
}

/* ---------- static ---------- */
function serveFile(res, file, headers = {}) {
  fs.readFile(file, (err, buf) => {
    if (err) return send(res, 404, 'Not found');
    send(res, 200, buf, Object.assign({ 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' }, headers));
  });
}
function serveStatic(req, res, url) {
  let p = decodeURIComponent(url.pathname);
  if (p.startsWith('/uploads/')) {
    const name = path.basename(p);
    if (!/^[a-f0-9]{32}\.(png|jpg|webp|gif)$/.test(name)) return send(res, 404, 'Not found');
    return serveFile(res, path.join(UP, name), { 'Cache-Control': 'public, max-age=31536000, immutable', 'Access-Control-Allow-Origin': PUBLIC_CORS });
  }
  if (p === '/admin') { res.writeHead(301, { Location: '/admin/' }); return res.end(); }
  if (p.endsWith('/')) p += 'index.html';
  const file = path.normalize(path.join(PUB, p));
  if (!file.startsWith(PUB + path.sep) || file.split(path.sep).some(s => s.startsWith('.'))) return send(res, 404, 'Not found');
  const h = { 'Cache-Control': file.endsWith('.html') ? 'no-cache' : 'public, max-age=3600' };
  if (p.startsWith('/admin/')) {
    h['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'";
    h['X-Frame-Options'] = 'DENY'; h['Cache-Control'] = 'no-store';
  }
  serveFile(res, file, h);
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
    serveStatic(req, res, url);
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { error: e.message });
    console.error(e); send(res, 500, { error: 'خطای داخلی سرور' });
  }
}).listen(PORT, HOST, () => console.log(`DISTORT running → store: http://localhost:${PORT}/   admin: http://localhost:${PORT}/admin/`));
