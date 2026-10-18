#!/usr/bin/env python3
"""DISTORT - storefront + admin API. Python 3.8+, standard library only.

Run:  python server.py        (Windows: py server.py)
Same data files and same API as server.js, so you can use either one.
"""
import base64
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

PORT = int(os.environ.get("PORT", "3000"))
HOST = os.environ.get("HOST", "127.0.0.1")
ROOT = os.path.dirname(os.path.abspath(__file__))
PUB = os.path.join(ROOT, "public")
DATA = os.path.abspath(os.environ["DATA_DIR"]) if os.environ.get("DATA_DIR") else os.path.join(ROOT, "data")
UP = os.path.join(DATA, "uploads")
DB_FILE = os.path.join(DATA, "db.json")
ADMIN_FILE = os.path.join(DATA, "admin.json")
ENV_PASS = os.environ.get("ADMIN_PASSWORD", "")
PUBLIC_CORS = os.environ.get("CORS_ORIGIN", "*")
TRUST_PROXY = os.environ.get("TRUST_PROXY") == "1"
os.makedirs(UP, exist_ok=True)

LOCK = threading.RLock()


def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json_atomic(path, obj, indent=1):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=indent)
    os.replace(tmp, path)


# ---------- storage ----------
DEFAULT_TEXTS = read_json(os.path.join(ROOT, "default-texts.json"))
if os.path.exists(DB_FILE):
    db = read_json(DB_FILE)
else:
    db = read_json(os.path.join(ROOT, "seed.json"))
    write_json_atomic(DB_FILE, db)
db.setdefault("texts", {"fa": {}, "en": {}})

# one-time upgrade: products saved before per-product specs existed get the sample texts (only untouched seed products) or empty fields
_SPEC = ("fabricFa", "fabricEn", "printFa", "printEn", "careFa", "careEn")
_seed_products = read_json(os.path.join(ROOT, "seed.json"))["products"]
_changed = False
for _p in db["products"]:
    if "fabricFa" in _p:
        continue
    _sp = next((x for x in _seed_products if x["id"] == _p["id"] and x["fa"] == _p["fa"]), None)
    for _k in _SPEC:
        _p[_k] = (_sp or {}).get(_k) or ""
    _changed = True


def save():
    write_json_atomic(DB_FILE, db)


def migrate_specs():
    """products saved before per-product specs existed get the new fields (sample text only for untouched sample products)"""
    keys = ["fabricFa", "fabricEn", "printFa", "printEn", "careFa", "careEn"]
    try:
        seed = read_json(os.path.join(ROOT, "seed.json"))
    except Exception:
        seed = {"products": []}
    sp = {x["id"]: x for x in seed.get("products", [])}
    changed = False
    for pr in db["products"]:
        if all(k not in pr for k in keys):
            sd = sp.get(pr["id"])
            same = bool(sd) and sd.get("fa") == pr.get("fa") and sd.get("en") == pr.get("en")
            for k in keys:
                pr[k] = sd.get(k, "") if same else ""
            changed = True
        else:
            for k in keys:
                if k not in pr:
                    pr[k] = ""
                    changed = True
    if changed:
        save()


migrate_specs()


if _changed:
    save()


# ---------- auth ----------
def hash_pass(p, salt):
    # salt is a hex string used as text, exactly like server.js, so admin.json works with both servers
    return hashlib.scrypt(p.encode("utf-8"), salt=salt.encode("utf-8"), n=16384, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024).hex()


if not ENV_PASS and not os.path.exists(ADMIN_FILE):
    _pass = secrets.token_urlsafe(9)
    _salt = secrets.token_hex(16)
    with open(ADMIN_FILE, "w", encoding="utf-8") as f:
        json.dump({"salt": _salt, "hash": hash_pass(_pass, _salt)}, f)
    print("\n  +----------------------------------------------+")
    print("  |  First run: admin password was generated      |")
    print("  |  Password:  " + _pass.ljust(34) + "|")
    print("  |  Change it in Settings after you sign in.     |")
    print("  +----------------------------------------------+\n")


def check_password(p):
    if not isinstance(p, str) or not p or len(p) > 200:
        return False
    if ENV_PASS:
        return hmac.compare_digest(hashlib.sha256(p.encode()).digest(), hashlib.sha256(ENV_PASS.encode()).digest())
    a = read_json(ADMIN_FILE)
    return hmac.compare_digest(hash_pass(p, a["salt"]), a["hash"])


SESSIONS = {}          # token -> expiry (seconds)
SESSION_S = 12 * 3600
FAILS = {}             # ip -> [count, until]
TOKEN_RE = re.compile(r"^Bearer ([a-f0-9]{64})$")


def authed(headers):
    m = TOKEN_RE.match(headers.get("Authorization", ""))
    if not m:
        return None
    exp = SESSIONS.get(m.group(1))
    if not exp:
        return None
    if exp < time.time():
        SESSIONS.pop(m.group(1), None)
        return None
    return m.group(1)


# ---------- helpers ----------
class HttpError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status
        self.msg = msg


def bad(msg):
    return HttpError(400, msg)


def s_(v, mx, label, required=True):
    v = "" if v is None else str(v).strip()
    if required and not v:
        raise bad(label + " الزامی است")
    if len(v) > mx:
        raise bad("%s حداکثر %d کاراکتر باشد" % (label, mx))
    return v


def i_(v, mn, mx, label):
    try:
        if isinstance(v, bool):
            raise ValueError
        n = float(v)
        if not n.is_integer():
            raise ValueError
        n = int(n)
    except (TypeError, ValueError):
        raise bad("%s باید عدد صحیح بین %d و %d باشد" % (label, mn, mx))
    if n < mn or n > mx:
        raise bad("%s باید عدد صحیح بین %d و %d باشد" % (label, mn, mx))
    return n


def slug(s):
    return re.sub(r"^-+|-+$", "", re.sub(r"[^a-z0-9]+", "-", str(s or "").lower()))[:30]


HEX = re.compile(r"^#[0-9a-f]{6}$", re.I)
SHAPES = ["hoodie", "crewneck", "tshirt"]
MOTIFS = ["gaming", "pinterest", "music", "cinema", "anime", "misc"]
IMG_URL = re.compile(r"^/uploads/[a-f0-9]{32}\.(png|jpg|webp|gif)$")
IMG_NAME = re.compile(r"^[a-f0-9]{32}\.(png|jpg|webp|gif)$")


def unique_id(lst, base, prefix):
    i0 = slug(base) or prefix + str(int(time.time() * 1000))
    cand, n = i0, 2
    while any(x["id"] == cand for x in lst):
        cand = "%s-%d" % (i0, n)
        n += 1
    return cand


def img_exists(u):
    return isinstance(u, str) and bool(IMG_URL.match(u)) and os.path.exists(os.path.join(UP, os.path.basename(u)))


def referenced_images():
    s = set()
    for p in db["products"]:
        s.update(p.get("images") or [])
    for col in ("types", "styles"):
        for x in db[col]:
            if x.get("image"):
                s.add(x["image"])
    if db["settings"].get("logo"):
        s.add(db["settings"]["logo"])
    return s


def drop_images(urls):
    ref = referenced_images()
    for u in urls:
        if isinstance(u, str) and IMG_URL.match(u) and u not in ref:
            try:
                os.unlink(os.path.join(UP, os.path.basename(u)))
            except OSError:
                pass


# ---------- validators ----------
def opt_img(v):
    if v is None or v == "":
        return None
    if not img_exists(v):
        raise bad("تصویر نامعتبر است")
    return v


def v_types(b, ex):
    if b.get("shape") not in SHAPES:
        raise bad("شکل لباس نامعتبر است")
    return {"id": ex["id"] if ex else None, "fa": s_(b.get("fa"), 60, "نام فارسی"), "en": s_(b.get("en"), 60, "نام انگلیسی"), "shape": b["shape"], "image": opt_img(b.get("image"))}


def v_styles(b, ex):
    g = None
    bg = b.get("g")
    if isinstance(bg, list) and len(bg) == 2:
        if not all(isinstance(c, str) and HEX.match(c) for c in bg):
            raise bad("رنگ گرادیان نامعتبر است")
        g = bg
    if b.get("motif") not in MOTIFS:
        raise bad("طرح نمادین نامعتبر است")
    return {"id": ex["id"] if ex else None, "fa": s_(b.get("fa"), 60, "نام فارسی"), "en": s_(b.get("en"), 60, "نام انگلیسی"), "motif": b["motif"], "g": g, "image": opt_img(b.get("image"))}


def v_colors(b, ex):
    h = b.get("h")
    if not isinstance(h, str) or not HEX.match(h):
        raise bad("کد رنگ نامعتبر است")
    return {"id": ex["id"] if ex else None, "fa": s_(b.get("fa"), 40, "نام فارسی رنگ"), "en": s_(b.get("en"), 40, "نام انگلیسی رنگ"), "h": h.lower()}


def uniq(seq):
    out = []
    for x in seq:
        if x not in out:
            out.append(x)
    return out


def v_products(b, ex):
    if not any(t["id"] == b.get("type") for t in db["types"]):
        raise bad("نوع لباس نامعتبر است")
    if not any(t["id"] == b.get("style") for t in db["styles"]):
        raise bad("سبک طرح نامعتبر است")
    colors = uniq(b["colors"] if isinstance(b.get("colors"), list) else [])
    if not colors:
        raise bad("حداقل یک رنگ انتخاب کنید")
    if not all(any(c["id"] == cid for c in db["colors"]) for cid in colors):
        raise bad("رنگ نامعتبر است")
    price = i_(b.get("price"), 0, 10 ** 10, "قیمت")
    old = None
    if b.get("oldPrice") not in ("", None):
        old = i_(b["oldPrice"], 0, 10 ** 10, "قیمت قبل از تخفیف")
        if old <= price:
            raise bad("قیمت قبل از تخفیف باید بیشتر از قیمت فعلی باشد")
    out = uniq(b["outOfStock"] if isinstance(b.get("outOfStock"), list) else [])
    if not all(z in db["settings"]["sizes"] for z in out):
        raise bad("سایز نامعتبر است")
    images = b["images"] if isinstance(b.get("images"), list) else []
    if len(images) > 8:
        raise bad("حداکثر ۸ تصویر مجاز است")
    if not all(img_exists(u) for u in images):
        raise bad("یکی از تصاویر نامعتبر است")
    try:
        created = float(b.get("createdAt"))
        if not created > 0 or created != created or created in (float("inf"),):
            raise ValueError
        created = int(created)
    except (TypeError, ValueError):
        created = ex["createdAt"] if ex else int(time.time() * 1000)
    return {
        "id": ex["id"] if ex else None, "code": s_(b.get("code"), 24, "کد محصول", False),
        "fa": s_(b.get("fa"), 120, "نام فارسی"), "en": s_(b.get("en"), 120, "نام انگلیسی"),
        "type": b["type"], "style": b["style"], "price": price, "oldPrice": old, "colors": colors, "outOfStock": out,
        "sold": i_(b.get("sold") or 0, 0, 10 ** 9, "تعداد فروش"), "createdAt": created,
        "descFa": s_(b.get("descFa"), 2000, "توضیحات فارسی", False), "descEn": s_(b.get("descEn"), 2000, "توضیحات انگلیسی", False),
        "fabricFa": s_(b.get("fabricFa"), 1000, "جنس پارچه (فارسی)", False), "fabricEn": s_(b.get("fabricEn"), 1000, "جنس پارچه (انگلیسی)", False),
        "printFa": s_(b.get("printFa"), 1000, "مشخصات چاپ (فارسی)", False), "printEn": s_(b.get("printEn"), 1000, "مشخصات چاپ (انگلیسی)", False),
        "careFa": s_(b.get("careFa"), 1000, "راهنمای نگهداری (فارسی)", False), "careEn": s_(b.get("careEn"), 1000, "راهنمای نگهداری (انگلیسی)", False),
        "images": images, "published": b.get("published") is not False,
    }


VALIDATE = {"types": v_types, "styles": v_styles, "colors": v_colors, "products": v_products}
IN_USE = {
    "types": lambda i: sum(1 for p in db["products"] if p["type"] == i),
    "styles": lambda i: sum(1 for p in db["products"] if p["style"] == i),
    "colors": lambda i: sum(1 for p in db["products"] if i in p["colors"]),
    "products": lambda i: 0,
}


def public_payload():
    st = db["settings"]
    return {"settings": {"logo": st.get("logo"), "sizes": st["sizes"], "sizeGuide": st.get("sizeGuide")}, "texts": db["texts"],
            "types": db["types"], "styles": db["styles"], "colors": db["colors"],
            "products": [p for p in db["products"] if p.get("published")]}


def validate_texts(body):
    out = {"fa": {}, "en": {}}
    for lang in ("fa", "en"):
        src = body.get(lang) or {}
        if not isinstance(src, dict):
            raise bad("ساختار متن‌ها نامعتبر است")
        for k, v in src.items():
            default = DEFAULT_TEXTS[lang].get(k)
            if default is None:
                raise bad("کلید ناشناخته: " + k)
            if v is None or v == "" or json.dumps(v, sort_keys=True) == json.dumps(default, sort_keys=True):
                continue
            if isinstance(default, list):
                if not isinstance(v, list) or len(v) > 40:
                    raise bad("مقدار لیستی نامعتبر: " + k)
                is_pair = bool(default) and isinstance(default[0], list)
                items = []
                for x in v:
                    if is_pair:
                        if isinstance(x, list) and len(x) == 2:
                            items.append([s_(x[0], 400, k), s_(x[1], 2000, k)])
                        else:
                            raise bad("جفت سؤال/پاسخ نامعتبر")
                    else:
                        t = s_(x, 200, k)
                        if t:
                            items.append(t)
                out[lang][k] = items
            else:
                if not isinstance(v, str):
                    raise bad("مقدار نامعتبر: " + k)
                out[lang][k] = s_(v, 8000 if k.startswith('pg_') else 2000, k)
    return out


def sniff_image(buf):
    if buf[:4] == b"\x89PNG":
        return "png"
    if buf[:3] == b"\xff\xd8\xff":
        return "jpg"
    if buf[:4] == b"GIF8":
        return "gif"
    if buf[:4] == b"RIFF" and buf[8:12] == b"WEBP":
        return "webp"
    return None


# ---------- API ----------
def handle_api(h, method, path, read_body):
    """Returns (status, payload, extra_headers). payload: dict/list -> JSON, bytes/str -> raw."""
    cors = {"Access-Control-Allow-Origin": PUBLIC_CORS, "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Allow-Methods": "GET, OPTIONS"}
    if method == "OPTIONS":
        return 204, "", cors
    if path == "/api/public" and method == "GET":
        with LOCK:
            return 200, public_payload(), dict(cors, **{"Cache-Control": "no-store"})

    if path == "/api/admin/login" and method == "POST":
        ip = client_ip(h)
        f = FAILS.get(ip, [0, 0])
        if f[1] > time.time():
            raise HttpError(429, "تلاش‌های ناموفق زیاد بود؛ چند دقیقه بعد دوباره امتحان کنید")
        b = read_body(10_000)
        if not check_password(b.get("password")):
            f[0] += 1
            if f[0] >= 5:
                f[1] = time.time() + 300
                f[0] = 0
            FAILS[ip] = f
            raise HttpError(401, "رمز عبور اشتباه است")
        FAILS.pop(ip, None)
        token = secrets.token_hex(32)
        SESSIONS[token] = time.time() + SESSION_S
        return 200, {"token": token}, {}

    if not path.startswith("/api/admin/"):
        raise HttpError(404, "پیدا نشد")
    token = authed(h.headers)
    if not token:
        raise HttpError(401, "نیاز به ورود")

    with LOCK:
        if path == "/api/admin/logout" and method == "POST":
            SESSIONS.pop(token, None)
            return 200, {"ok": True}, {}

        if path == "/api/admin/all" and method == "GET":
            return 200, {"types": db["types"], "styles": db["styles"], "colors": db["colors"], "products": db["products"], "texts": db["texts"],
                         "defaults": DEFAULT_TEXTS, "settings": db["settings"], "envPassword": bool(ENV_PASS)}, {}

        if path == "/api/admin/export" and method == "GET":
            return 200, json.dumps(db, ensure_ascii=False, indent=1), {
                "Content-Type": "application/json; charset=utf-8",
                "Content-Disposition": 'attachment; filename="distort-backup-%s.json"' % time.strftime("%Y-%m-%d")}

        if path == "/api/admin/texts" and method == "PUT":
            db["texts"] = validate_texts(read_body(1_000_000))
            save()
            return 200, {"ok": True, "texts": db["texts"]}, {}

        if path == "/api/admin/settings" and method == "PUT":
            b, s = read_body(1_000_000), db["settings"]
            if "logo" in b:
                if b["logo"] is not None and not img_exists(b["logo"]):
                    raise bad("لوگوی نامعتبر")
                old = s.get("logo")
                s["logo"] = b["logo"]
                if old and old != b["logo"]:
                    save()
                    drop_images([old])
            if "sizes" in b:
                sz = b["sizes"]
                if not isinstance(sz, list) or not sz or len(sz) > 12:
                    raise bad("فهرست سایزها نامعتبر است")
                s["sizes"] = uniq([s_(x, 6, "سایز") for x in sz])
                for pr in db["products"]:
                    pr["outOfStock"] = [z for z in pr["outOfStock"] if z in s["sizes"]]
            if "sizeGuide" in b:
                g = b["sizeGuide"]
                if not isinstance(g, list) or len(g) > 12:
                    raise bad("جدول اندازه نامعتبر است")
                rows = []
                for r in g:
                    if not isinstance(r, list) or len(r) < 3:
                        raise bad("جدول اندازه نامعتبر است")
                    rows.append([s_(r[0], 6, "سایز"), i_(r[1], 0, 500, "عرض"), i_(r[2], 0, 500, "قد")])
                s["sizeGuide"] = rows
            save()
            return 200, {"ok": True, "settings": s}, {}

        if path == "/api/admin/password" and method == "POST":
            if ENV_PASS:
                raise bad("رمز از طریق متغیر محیطی ADMIN_PASSWORD تنظیم شده و از اینجا قابل تغییر نیست")
            b = read_body(10_000)
            if not check_password(b.get("current")):
                raise bad("رمز فعلی اشتباه است")
            nxt = b.get("next")
            if not isinstance(nxt, str) or len(nxt) < 8 or len(nxt) > 100:
                raise bad("رمز جدید باید حداقل ۸ کاراکتر باشد")
            salt = secrets.token_hex(16)
            write_json_atomic(ADMIN_FILE, {"salt": salt, "hash": hash_pass(nxt, salt)}, indent=None)
            SESSIONS.clear()
            t = secrets.token_hex(32)
            SESSIONS[t] = time.time() + SESSION_S
            return 200, {"ok": True, "token": t}, {}

        if path == "/api/admin/upload" and method == "POST":
            b = read_body(8_000_000)
            m = re.match(r"^data:image/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/=]+)$", b.get("dataUrl") or "")
            if not m:
                raise bad("فقط تصاویر PNG، JPG، WEBP و GIF مجاز است")
            try:
                buf = base64.b64decode(m.group(2), validate=True)
            except Exception:
                raise bad("محتوای فایل با فرمت تصویر مطابقت ندارد")
            if len(buf) > 5 * 1024 * 1024:
                raise bad("حجم تصویر حداکثر ۵ مگابایت باشد")
            ext = sniff_image(buf)
            if not ext:
                raise bad("محتوای فایل با فرمت تصویر مطابقت ندارد")
            name = secrets.token_hex(16) + "." + ext
            with open(os.path.join(UP, name), "wb") as f:
                f.write(buf)
            return 200, {"url": "/uploads/" + name}, {}

        rm = re.match(r"^/api/admin/(types|styles|colors)/reorder$", path)
        cm = re.match(r"^/api/admin/(types|styles|colors|products)(?:/([^/]+))?$", path)
        if rm and method == "POST":
            col, b = rm.group(1), read_body(100_000)
            ids = b.get("ids")
            if not isinstance(ids, list) or len(ids) != len(db[col]) or not all(any(x["id"] == i for x in db[col]) for i in ids):
                raise bad("ترتیب نامعتبر است")
            db[col] = [next(x for x in db[col] if x["id"] == i) for i in ids]
            save()
            return 200, {"ok": True}, {}
        if cm:
            col, ident = cm.group(1), cm.group(2)
            if method == "POST" and not ident:
                b = read_body(100_000)
                item = VALIDATE[col](b, None)
                if col == "products":
                    n = db["nextProductId"]
                    db["nextProductId"] = n + 1
                    item["id"] = "p%d" % n
                    item["code"] = item["code"] or "DS-%04d" % n
                    if any(x["code"] == item["code"] for x in db["products"]):
                        db["nextProductId"] = n
                        raise bad("این کد محصول قبلاً استفاده شده")
                else:
                    item["id"] = unique_id(db[col], b.get("id") or b.get("en"), col[0])
                db[col].append(item)
                save()
                return 201, item, {}
            idx = next((k for k, x in enumerate(db[col]) if x["id"] == ident), -1)
            if idx < 0:
                raise HttpError(404, "پیدا نشد")
            if method == "PUT":
                ex = db[col][idx]
                item = VALIDATE[col](read_body(100_000), ex)
                if col == "products":
                    item["code"] = item["code"] or ex["code"]
                    if any(x["code"] == item["code"] and x["id"] != ex["id"] for x in db["products"]):
                        raise bad("این کد محصول قبلاً استفاده شده")
                db[col][idx] = item
                save()
                if col == "products":
                    drop_images([u for u in (ex.get("images") or []) if u not in item["images"]])
                elif ex.get("image") and ex.get("image") != item.get("image"):
                    drop_images([ex["image"]])
                return 200, item, {}
            if method == "DELETE":
                n = IN_USE[col](ident)
                if n:
                    raise HttpError(409, "این مورد در %d محصول استفاده شده؛ ابتدا آن محصولات را تغییر دهید" % n)
                if col != "products" and len(db[col]) <= 1:
                    raise bad("حداقل یک مورد باید باقی بماند")
                gone = db[col].pop(idx)
                save()
                if col == "products":
                    drop_images(gone.get("images") or [])
                elif gone.get("image"):
                    drop_images([gone["image"]])
                return 200, {"ok": True}, {}
    raise HttpError(404, "پیدا نشد")


def client_ip(h):
    if TRUST_PROXY and h.headers.get("X-Forwarded-For"):
        return h.headers["X-Forwarded-For"].split(",")[0].strip()
    return h.client_address[0]


ADMIN_CSP = ("default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; "
             "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
         ".json": "application/json; charset=utf-8", ".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp",
         ".gif": "image/gif", ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8"}


class Handler(BaseHTTPRequestHandler):
    server_version = "DISTORT"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quiet
        pass

    # --- response helpers
    def send_out(self, status, body=b"", headers=None, head=False):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            ctype = "application/json; charset=utf-8"
        elif isinstance(body, str):
            body = body.encode("utf-8")
            ctype = "text/plain; charset=utf-8"
        else:
            ctype = "application/octet-stream"
        hdrs = {"Content-Type": ctype, "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin"}
        hdrs.update(headers or {})
        self.send_response(status)
        for k, v in hdrs.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head and status != 204:
            self.wfile.write(body)

    def read_body(self, limit):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise HttpError(413, "حجم درخواست زیاد است")
        raw = self.rfile.read(n) if n else b""
        self._body_read = True
        if not raw:
            return {}
        try:
            v = json.loads(raw.decode("utf-8"))
        except Exception:
            raise bad("JSON نامعتبر است")
        if not isinstance(v, dict):
            raise bad("JSON نامعتبر است")
        return v

    def dispatch(self, method):
        self._body_read = False
        try:
            path = urlsplit(self.path).path
            if path.startswith("/api/"):
                status, payload, hdr = handle_api(self, method, path, self.read_body)
                return self.send_out(status, payload, hdr)
            if method not in ("GET", "HEAD"):
                return self.send_out(405, "Method not allowed")
            self.serve_static(path, method == "HEAD")
        except HttpError as e:
            self.drain()
            self.send_out(e.status, {"error": e.msg})
        except Exception as e:  # noqa
            self.drain()
            print("ERROR", repr(e))
            self.send_out(500, {"error": "خطای داخلی سرور"})

    def drain(self):
        # keep the keep-alive connection usable after an early error
        if not getattr(self, "_body_read", True):
            try:
                n = int(self.headers.get("Content-Length") or 0)
                if 0 < n <= 10_000_000:
                    self.rfile.read(n)
            except Exception:
                self.close_connection = True

    def serve_static(self, path, head):
        p = unquote(path)
        if p.startswith("/uploads/"):
            name = os.path.basename(p)
            if not IMG_NAME.match(name):
                return self.send_out(404, "Not found", head=head)
            return self.send_file(os.path.join(UP, name), {"Cache-Control": "public, max-age=31536000, immutable",
                                                           "Access-Control-Allow-Origin": PUBLIC_CORS}, head)
        if p == "/admin":
            self.send_response(301)
            self.send_header("Location", "/admin/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if p.endswith("/"):
            p += "index.html"
        f = os.path.normpath(os.path.join(PUB, p.lstrip("/")))
        parts = f[len(PUB):].split(os.sep) if f.startswith(PUB + os.sep) else None
        if parts is None or any(s.startswith(".") for s in parts):
            return self.send_out(404, "Not found", head=head)
        h = {"Cache-Control": "no-cache" if f.endswith(".html") else "public, max-age=3600"}
        if p.startswith("/admin/"):
            h.update({"Content-Security-Policy": ADMIN_CSP, "X-Frame-Options": "DENY", "Cache-Control": "no-store"})
        self.send_file(f, h, head)

    def send_file(self, f, headers, head):
        if not os.path.isfile(f):
            return self.send_out(404, "Not found", head=head)
        with open(f, "rb") as fh:
            buf = fh.read()
        ext = os.path.splitext(f)[1].lower()
        ctype = TYPES.get(ext) or mimetypes.guess_type(f)[0] or "application/octet-stream"
        self.send_out(200, buf, dict(headers, **{"Content-Type": ctype}), head)

    def do_GET(self): self.dispatch("GET")
    def do_HEAD(self): self.dispatch("HEAD")
    def do_POST(self): self.dispatch("POST")
    def do_PUT(self): self.dispatch("PUT")
    def do_DELETE(self): self.dispatch("DELETE")
    def do_OPTIONS(self): self.dispatch("OPTIONS")


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    srv.daemon_threads = True
    print("DISTORT running -> store: http://localhost:%d/   admin: http://localhost:%d/admin/" % (PORT, PORT))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
