#!/usr/bin/env python3
"""WorkWatch server: serves the app and keeps everything in a SQLite database.

Run:   python3 server.py          then open http://localhost:8000
Data:  workwatch.db (next to this file). Override with WORKWATCH_DB=/path/to/file.db
Needs only Python 3.8+ (standard library, no installs).
"""
import base64, hashlib, hmac, json, os, re, secrets, sqlite3, sys, threading, time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("WORKWATCH_DB", os.path.join(BASE, "workwatch.db"))
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8000"))
SESSION_HOURS = 12
MAX_BODY = 6 * 1024 * 1024
MAX_IMAGE = 2_500_000

# Demo accounts (hackathon). Passcodes are stored hashed in the database.
DEPTS = [
    ("Engineering Unit – Civil", "civil@26"),
    ("Engineering Unit – Electrical", "elec@26"),
    ("IT & Network Services", "it@26"),
    ("Hostel Office", "hostel@26"),
]
BASE_CONTRACTORS = [
    ("C01", "Sri Murugan Constructions", "murugan@26"),
    ("C02", "Kaveri Builders", "kaveri@26"),
    ("C03", "BrightWay Electricals", "bright@26"),
    ("C04", "Aqua Infra Works", "aqua@26"),
    ("C05", "FiberLink Networks", "fiber@26"),
]
STATUSES = ("planned", "ongoing", "review", "completed")

LOCK = threading.RLock()
CONN = None
FAILS = {}  # ip -> [timestamps of failed logins]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------ database
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY, role TEXT NOT NULL, ref TEXT NOT NULL, name TEXT,
  salt BLOB NOT NULL, pass_hash BLOB NOT NULL, created_at TEXT, UNIQUE(role, ref));
CREATE TABLE IF NOT EXISTS public_users(
  email TEXT PRIMARY KEY, first_login TEXT, last_login TEXT, login_count INTEGER);
CREATE TABLE IF NOT EXISTS login_events(
  id INTEGER PRIMARY KEY, at TEXT, role TEXT, ref TEXT, ok INTEGER, ip TEXT);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY, role TEXT, ref TEXT, created_at REAL, expires_at REAL);
CREATE TABLE IF NOT EXISTS projects(
  code TEXT PRIMARY KEY, seq INTEGER, data TEXT NOT NULL, rev INTEGER NOT NULL,
  updated_at TEXT, updated_by TEXT);
CREATE TABLE IF NOT EXISTS contractors(
  id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at TEXT);
CREATE TABLE IF NOT EXISTS applications(
  id TEXT PRIMARY KEY, seq INTEGER, dept TEXT, status TEXT, data TEXT NOT NULL,
  salt BLOB, pass_hash BLOB, created_at TEXT, decided_at TEXT, decided_by TEXT,
  reason TEXT, contractor_id TEXT);
CREATE TABLE IF NOT EXISTS contractor_log(
  id INTEGER PRIMARY KEY, at TEXT, dept TEXT, by TEXT, text TEXT);
CREATE TABLE IF NOT EXISTS uploads(
  id TEXT PRIMARY KEY, mime TEXT, size INTEGER, data BLOB, owner_role TEXT,
  owner_ref TEXT, created_at TEXT);
"""


def hash_pass(password, salt=None):
    salt = salt or os.urandom(16)
    return salt, hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)


def check_pass(password, salt, pass_hash):
    _, h = hash_pass(password, salt)
    return hmac.compare_digest(h, pass_hash)


def init_db():
    global CONN
    CONN = sqlite3.connect(DB_PATH, check_same_thread=False)
    CONN.row_factory = sqlite3.Row
    CONN.execute("PRAGMA journal_mode=WAL")
    CONN.execute("PRAGMA foreign_keys=ON")
    CONN.executescript(SCHEMA)
    for dept, pw in DEPTS:
        add_account("dept", dept, dept, pw, replace=False)
    for cid, name, pw in BASE_CONTRACTORS:
        add_account("contractor", cid, name, pw, replace=False)
    if not meta_get("seeded"):
        seed_projects()
    CONN.commit()


def meta_get(key):
    r = CONN.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return r["value"] if r else None


def add_account(role, ref, name, password=None, replace=True, salt=None, pass_hash=None):
    if pass_hash is None:
        salt, pass_hash = hash_pass(password)
    verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
    CONN.execute(
        f"{verb} INTO accounts(role,ref,name,salt,pass_hash,created_at) VALUES(?,?,?,?,?,?)",
        (role, ref, name, salt, pass_hash, now_iso()),
    )


def seed_projects():
    path = os.path.join(BASE, "seed_projects.json")
    with open(path, encoding="utf-8") as f:
        seed = json.load(f)
    for i, p in enumerate(seed):
        CONN.execute(
            "INSERT OR REPLACE INTO projects(code,seq,data,rev,updated_at,updated_by) VALUES(?,?,?,?,?,?)",
            (p["code"], i + 1, json.dumps(p, ensure_ascii=False), 1, now_iso(), "seed"),
        )
    CONN.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('seeded',?)", (now_iso(),))


def all_projects():
    rows = CONN.execute("SELECT code,data,rev FROM projects ORDER BY seq").fetchall()
    return [json.loads(r["data"]) for r in rows], {r["code"]: r["rev"] for r in rows}


def extra_contractors():
    return [json.loads(r["data"]) for r in CONN.execute("SELECT data FROM contractors ORDER BY id")]


def log_contractor(dept, by, text):
    CONN.execute(
        "INSERT INTO contractor_log(at,dept,by,text) VALUES(?,?,?,?)", (now_iso(), dept, by, text)
    )


# ------------------------------------------------------------------ sessions
def new_session(role, ref):
    token = secrets.token_urlsafe(32)
    t = time.time()
    CONN.execute(
        "INSERT INTO sessions(token,role,ref,created_at,expires_at) VALUES(?,?,?,?,?)",
        (token, role, ref, t, t + SESSION_HOURS * 3600),
    )
    CONN.execute("DELETE FROM sessions WHERE expires_at<?", (t,))
    return token


def session_of(handler):
    h = handler.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    r = CONN.execute(
        "SELECT role,ref FROM sessions WHERE token=? AND expires_at>?", (h[7:], time.time())
    ).fetchone()
    return {"role": r["role"], "ref": r["ref"]} if r else None


def log_login(role, ref, ok, ip):
    CONN.execute(
        "INSERT INTO login_events(at,role,ref,ok,ip) VALUES(?,?,?,?,?)",
        (now_iso(), role, ref, 1 if ok else 0, ip),
    )


# ------------------------------------------------------------ project saving
LIST_KEYS = {
    "faq": lambda x: x.get("id"),
    "delayClaims": lambda x: x.get("id"),
    "feedback": lambda x: json.dumps([x.get("at"), x.get("stars"), x.get("text"), x.get("img")]),
    "history": lambda x: json.dumps([x.get("d"), x.get("t"), x.get("by")]),
    "released": lambda x: json.dumps([x.get("d"), x.get("amt"), x.get("note")]),
}
ALLOWED = {
    "public": {"faq", "feedback"},
    "contractor": {"stage", "updated", "history", "delayClaims", "faq", "status", "completion"},
    "dept": None,  # everything except the protected keys below
}
DEPT_PROTECTED = {"code", "dept", "faq", "feedback"}


def clean_text(v, n):
    return str(v or "")[:n]


def merge_item(key, cur, item, role):
    """Existing list entries are never deleted. Only specific fields may change."""
    if key == "faq":
        out = dict(cur)
        try:
            out["me2"] = max(int(cur.get("me2", 0)), min(int(item.get("me2", 0)), int(cur.get("me2", 0)) + 1))
        except (TypeError, ValueError):
            pass
        if role == "contractor" and item.get("a") and len(str(item["a"]).strip()) >= 1:
            out["a"] = clean_text(item["a"], 400)
            out["answeredAt"] = clean_text(item.get("answeredAt"), 12)
        return out
    if key == "delayClaims" and role == "dept":
        out = dict(cur)
        if item.get("status") in ("approved", "rejected"):
            out["status"] = item["status"]
            out["okDays"] = item.get("okDays", out.get("okDays"))
            out["reason"] = clean_text(item.get("reason"), 200)
        return out
    return cur


def new_item(key, item, role, project):
    if not isinstance(item, dict):
        return None
    if key == "faq" and role == "public":
        return {
            "id": clean_text(item.get("id"), 24) or "Q" + secrets.token_hex(4),
            "topic": clean_text(item.get("topic"), 40) or "Other",
            "q": clean_text(item.get("q"), 300),
            "a": None,
            "at": clean_text(item.get("at"), 12),
            "me2": 0,
        }
    if key == "feedback" and role == "public" and project.get("status") == "completed":
        stars = item.get("stars")
        if not isinstance(stars, int) or not 1 <= stars <= 5:
            return None
        img = item.get("img")
        if img is not None and not (isinstance(img, str) and img.startswith("/api/uploads/")):
            img = None
        return {"stars": stars, "text": clean_text(item.get("text"), 240), "at": clean_text(item.get("at"), 12), "img": img}
    if key == "history" and role in ("contractor", "dept"):
        return {
            "d": clean_text(item.get("d"), 12), "t": clean_text(item.get("t"), 400),
            "by": clean_text(item.get("by"), 80), **({"kind": item["kind"]} if item.get("kind") in ("approval", "funds") and role == "dept" else {}),
        }
    if key == "delayClaims" and role == "contractor":
        return {
            "id": clean_text(item.get("id"), 24) or "DC" + secrets.token_hex(4),
            "type": clean_text(item.get("type"), 60), "days": int(item.get("days") or 0),
            "text": clean_text(item.get("text"), 200), "status": "pending", "at": clean_text(item.get("at"), 12),
        }
    if key == "released" and role == "dept":
        try:
            amt = float(item.get("amt"))
        except (TypeError, ValueError):
            return None
        return {"d": clean_text(item.get("d"), 12), "amt": amt, "note": clean_text(item.get("note"), 60)}
    return None


def merge_list(key, existing, incoming, role, project):
    kf = LIST_KEYS[key]
    out = list(existing or [])
    idx = {kf(x): i for i, x in enumerate(out)}
    for item in incoming or []:
        if not isinstance(item, dict):
            continue
        k = kf(item)
        if k in idx:
            out[idx[k]] = merge_item(key, out[idx[k]], item, role)
        else:
            n = new_item(key, item, role, project)
            if n is not None:
                out.append(n)
                idx[kf(n)] = len(out) - 1
    return out


def apply_changes(cur, fields, sess):
    """Return (new_project, error). Enforces what each role may change."""
    role, ref = sess["role"], sess["ref"]
    p = json.loads(json.dumps(cur))
    # ownership
    if role == "dept" and p.get("dept") != ref:
        return None, "This project belongs to another department."
    if role == "contractor" and p.get("cid") != ref:
        return None, "This project is assigned to another contractor."
    allowed = ALLOWED[role]
    for key, val in fields.items():
        if role == "dept":
            if key in DEPT_PROTECTED or key.startswith("_"):
                continue
        elif key not in allowed:
            return None, f"Not allowed to change '{key}'."
        if key in LIST_KEYS:
            if not isinstance(val, list):
                return None, f"'{key}' must be a list."
            p[key] = merge_list(key, p.get(key, []), val, role, p)
            continue
        if role == "contractor":
            if key == "status":
                if not (p.get("status") == "ongoing" and val == "review"):
                    return None, "Contractors can only submit ongoing work for verification."
            elif key == "completion":
                if not (isinstance(val, dict) and val.get("status") == "pending"):
                    return None, "Invalid completion submission."
                val = {"status": "pending", "submittedAt": clean_text(val.get("submittedAt"), 12)}
            elif key == "stage":
                if not isinstance(val, int) or not 0 <= val <= 3:
                    return None, "Invalid stage."
            elif key == "updated":
                val = clean_text(val, 12)
        if role == "dept" and key == "status" and val not in STATUSES:
            return None, "Invalid status."
        p[key] = val
    return p, None


def create_project(data, sess):
    if sess["role"] != "dept":
        return None, "Only a department can create projects."
    p = dict(data)
    code = clean_text(p.get("code"), 20)
    if not re.fullmatch(r"WW-\d\d-\d{3}", code):
        return None, "Invalid project code."
    if CONN.execute("SELECT 1 FROM projects WHERE code=?", (code,)).fetchone():
        return None, "That project code already exists. Please try saving again."
    if not clean_text(p.get("title"), 90).strip():
        return None, "A project needs a title."
    p["dept"] = sess["ref"]
    p["status"] = "planned"
    for k in ("released", "delayClaims", "faq", "feedback"):
        p[k] = []
    p["history"] = [h for h in (p.get("history") or []) if isinstance(h, dict)][:5]
    return p, None


def save_projects(sess, changes):
    saved, rejected, revs = [], [], {}
    for ch in changes:
        code = clean_text(ch.get("code"), 20)
        row = CONN.execute("SELECT data,rev FROM projects WHERE code=?", (code,)).fetchone()
        if row is None:
            if not ch.get("isNew") or not isinstance(ch.get("project"), dict):
                rejected.append({"code": code, "reason": "Unknown project."})
                continue
            p, err = create_project(ch["project"], sess)
            if err:
                rejected.append({"code": code, "reason": err})
                continue
            seq = (CONN.execute("SELECT COALESCE(MAX(seq),0) m FROM projects").fetchone()["m"]) + 1
            CONN.execute(
                "INSERT INTO projects(code,seq,data,rev,updated_at,updated_by) VALUES(?,?,?,?,?,?)",
                (code, seq, json.dumps(p, ensure_ascii=False), 1, now_iso(), f"{sess['role']}:{sess['ref']}"),
            )
            saved.append(code)
            revs[code] = 1
            continue
        fields = ch.get("fields")
        if not isinstance(fields, dict):
            rejected.append({"code": code, "reason": "Nothing to save."})
            continue
        cur = json.loads(row["data"])
        p, err = apply_changes(cur, fields, sess)
        if err:
            rejected.append({"code": code, "reason": err})
            continue
        if p != cur:
            rev = row["rev"] + 1
            CONN.execute(
                "UPDATE projects SET data=?,rev=?,updated_at=?,updated_by=? WHERE code=?",
                (json.dumps(p, ensure_ascii=False), rev, now_iso(), f"{sess['role']}:{sess['ref']}", code),
            )
            revs[code] = rev
        else:
            revs[code] = row["rev"]
        saved.append(code)
    return {"ok": True, "saved": saved, "rejected": rejected, "revs": revs}


# -------------------------------------------------------------- applications
APP_FIELDS = ["name", "spec", "lclass", "lno", "lexp", "iexp", "tax", "phone", "email"]


def app_public(r, with_refs=True):
    d = json.loads(r["data"])
    d.update({"id": r["id"], "status": r["status"], "dept": r["dept"], "reason": r["reason"],
              "by": r["decided_by"], "decidedAt": (r["decided_at"] or "")[:10], "contractorId": r["contractor_id"]})
    if not with_refs:
        for k in ("refs", "tax", "phone", "email", "lno"):
            d.pop(k, None)
    return d


def submit_application(b):
    def s(k, n=120):
        return clean_text(b.get(k), n).strip()

    data = {k: s(k) for k in APP_FIELDS}
    if len(data["name"]) < 3 or not data["spec"] or not data["lno"] or not data["tax"]:
        return None, "Please fill in all the business details."
    if not re.fullmatch(r"\d{4}-\d\d-\d\d", data["lexp"]) or not re.fullmatch(r"\d{4}-\d\d-\d\d", data["iexp"]):
        return None, "Licence and insurance dates are required."
    if not re.fullmatch(r"\S+@\S+\.\S+", data["email"]):
        return None, "Enter a valid office email."
    dept = s("dept", 80)
    if dept not in [d for d, _ in DEPTS]:
        return None, "Choose the department that will verify you."
    pw = str(b.get("pass") or "")
    if len(pw) < 6:
        return None, "Choose a passcode of at least 6 characters."
    try:
        data["est"] = int(b.get("est"))
        data["staff"] = int(b.get("staff"))
    except (TypeError, ValueError):
        return None, "Enter the year established and team size."
    refs = b.get("refs") if isinstance(b.get("refs"), dict) else {}
    data["refs"] = {str(k)[:20]: clean_text(v, 200) for k, v in refs.items()}
    data["certs"] = [clean_text(c, 80) for c in (b.get("certs") or [])][:10]
    data["at"] = clean_text(b.get("at"), 12) or now_iso()[:10]
    low = data["name"].lower()
    names = [n.lower() for _, n, _ in BASE_CONTRACTORS] + [json.loads(r["data"])["name"].lower() for r in CONN.execute("SELECT data FROM contractors")]
    if low in names:
        return None, "A contractor with this name is already registered."
    for r in CONN.execute("SELECT data FROM applications WHERE status!='rejected'"):
        d = json.loads(r["data"])
        if d["name"].lower() == low or d["lno"].lower() == data["lno"].lower():
            return None, "An application with this name or licence number already exists."
    seq = CONN.execute("SELECT COALESCE(MAX(seq),0) m FROM applications").fetchone()["m"] + 1
    app_id = "APP-%03d" % seq
    salt, ph = hash_pass(pw)
    CONN.execute(
        "INSERT INTO applications(id,seq,dept,status,data,salt,pass_hash,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (app_id, seq, dept, "pending", json.dumps(data, ensure_ascii=False), salt, ph, now_iso()),
    )
    log_contractor(dept, "Applicant", f"New application from {data['name']} ({app_id}).")
    return {"id": app_id, "dept": dept}, None


def decide_application(sess, b):
    if sess["role"] != "dept":
        return None, "Only a department can decide applications."
    r = CONN.execute("SELECT * FROM applications WHERE id=?", (clean_text(b.get("id"), 20),)).fetchone()
    if r is None or r["status"] != "pending":
        return None, "This application is no longer pending."
    if r["dept"] != sess["ref"]:
        return None, f"Only {r['dept']} can verify this contractor."
    dept = sess["ref"]
    d = json.loads(r["data"])
    if b.get("action") == "reject":
        why = clean_text(b.get("reason"), 140).strip()
        if len(why) < 5:
            return None, "Add a reason for declining."
        CONN.execute(
            "UPDATE applications SET status='rejected',reason=?,decided_at=?,decided_by=?,salt=NULL,pass_hash=NULL WHERE id=?",
            (why, now_iso(), dept, r["id"]),
        )
        log_contractor(dept, dept, f"Declined {d['name']} ({r['id']}): {why}")
        return {"ok": True}, None
    if b.get("action") != "approve":
        return None, "Unknown action."
    c = b.get("contractor")
    if not isinstance(c, dict) or not isinstance(c.get("verification"), dict):
        return None, "Missing verification details."
    n = 0
    for (cid,) in CONN.execute("SELECT id FROM contractors").fetchall():
        n = max(n, int(cid[1:]))
    for cid, _, _ in BASE_CONTRACTORS:
        n = max(n, int(cid[1:]))
    cid = "C%02d" % (n + 1)
    c["id"] = cid
    c["name"], c["speciality"] = d["name"], d["spec"]
    CONN.execute("INSERT INTO contractors(id,data,created_at) VALUES(?,?,?)", (cid, json.dumps(c, ensure_ascii=False), now_iso()))
    add_account("contractor", cid, d["name"], salt=r["salt"], pass_hash=r["pass_hash"])
    CONN.execute(
        "UPDATE applications SET status='approved',contractor_id=?,decided_at=?,decided_by=?,salt=NULL,pass_hash=NULL WHERE id=?",
        (cid, now_iso(), dept, r["id"]),
    )
    log_contractor(dept, dept, f"Verified and approved {d['name']} ({r['id']}) as {cid}.")
    return {"ok": True, "contractor": c}, None


# --------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "WorkWatch/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (datetime.now().strftime("%H:%M:%S"), fmt % args))

    # helpers
    def send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def err(self, status, msg):
        self.send_json({"error": msg}, status)

    def read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, UnicodeDecodeError):
            return None

    def ip(self):
        return self.client_address[0]

    # routing
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        if path in ("/", "/index.html"):
            return self.static_index()
        if path.startswith("/api/uploads/"):
            return self.get_upload(path.rsplit("/", 1)[1])
        if not path.startswith("/api/"):
            return self.err(404, "Not found")
        with LOCK:
            try:
                self.route_get(path, parse_qs(u.query))
            except Exception as e:  # noqa
                CONN.rollback()
                self.log_message("ERROR %r", e)
                self.err(500, "Server error")

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return self.err(404, "Not found")
        body = self.read_json()
        if body is None or not isinstance(body, dict):
            return self.err(400, "Invalid or too large request body.")
        with LOCK:
            try:
                self.route_post(path, body)
                CONN.commit()
            except Exception as e:  # noqa
                CONN.rollback()
                self.log_message("ERROR %r", e)
                self.err(500, "Server error")

    def static_index(self):
        with open(os.path.join(BASE, "static", "index.html"), "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def get_upload(self, uid):
        with LOCK:
            r = CONN.execute("SELECT mime,data FROM uploads WHERE id=?", (uid,)).fetchone()
        if not r:
            return self.err(404, "Not found")
        self.send_response(200)
        self.send_header("Content-Type", r["mime"])
        self.send_header("Content-Length", str(len(r["data"])))
        self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(r["data"])

    def route_get(self, path, qs):
        if path == "/api/bootstrap":
            projects, revs = all_projects()
            return self.send_json({"projects": projects, "revs": revs, "contractors": extra_contractors()})
        if path == "/api/projects":
            projects, revs = all_projects()
            return self.send_json({"projects": projects, "revs": revs})
        if path == "/api/me":
            s = session_of(self)
            return self.send_json(s) if s else self.err(401, "Not logged in")
        if path == "/api/applications":
            aid = (qs.get("id") or [""])[0].strip().upper()
            if aid:  # public status check
                r = CONN.execute("SELECT * FROM applications WHERE id=?", (aid,)).fetchone()
                if not r:
                    return self.err(404, "No application found with that ID.")
                d = json.loads(r["data"])
                return self.send_json({"id": r["id"], "name": d["name"], "status": r["status"], "dept": r["dept"],
                                       "at": d.get("at"), "decidedAt": (r["decided_at"] or "")[:10], "by": r["decided_by"], "reason": r["reason"]})
            s = session_of(self)
            if not s or s["role"] != "dept":
                return self.err(401, "Department login required.")
            rows = CONN.execute("SELECT * FROM applications ORDER BY seq").fetchall()
            mine = [app_public(r) for r in rows if r["dept"] == s["ref"]]
            others = sum(1 for r in rows if r["dept"] != s["ref"] and r["status"] == "pending")
            lg = CONN.execute("SELECT at,dept,by,text FROM contractor_log WHERE dept=? ORDER BY id DESC LIMIT 40", (s["ref"],)).fetchall()
            return self.send_json({"apps": mine, "othersPending": others,
                                   "log": [{"d": x["at"][:10], "t": x["text"], "by": x["by"], "dept": x["dept"]} for x in lg]})
        return self.err(404, "Not found")

    def route_post(self, path, b):
        ip = self.ip()
        if path == "/api/login":
            return self.login(b, ip)
        if path == "/api/applications":
            res, e = submit_application(b)
            return self.err(400, e) if e else self.send_json(res)
        sess = session_of(self)
        if not sess:
            return self.err(401, "Please log in again.")
        if path == "/api/logout":
            tok = self.headers.get("Authorization", "")[7:]
            CONN.execute("DELETE FROM sessions WHERE token=?", (tok,))
            return self.send_json({"ok": True})
        if path == "/api/projects/save":
            ch = b.get("changes")
            if not isinstance(ch, list) or len(ch) > 200:
                return self.err(400, "Invalid changes.")
            return self.send_json(save_projects(sess, [c for c in ch if isinstance(c, dict)]))
        if path == "/api/upload":
            return self.upload(sess, b)
        if path == "/api/applications/decide":
            res, e = decide_application(sess, b)
            return self.err(400, e) if e else self.send_json(res)
        if path == "/api/reset":
            if sess["role"] != "dept":
                return self.err(403, "Only a department login can reset the database.")
            return self.reset(sess)
        return self.err(404, "Not found")

    def login(self, b, ip):
        t = time.time()
        FAILS[ip] = [x for x in FAILS.get(ip, []) if t - x < 300]
        if len(FAILS[ip]) >= 8:
            return self.err(429, "Too many failed attempts. Please wait a few minutes.")
        role = b.get("role")
        if role == "public":
            em = clean_text(b.get("email"), 120).strip().lower()
            if not re.fullmatch(r"[a-z0-9._%+-]{6,}@gmail\.com", em):
                return self.err(400, "Enter a valid Gmail address ending in @gmail.com.")
            CONN.execute(
                "INSERT INTO public_users(email,first_login,last_login,login_count) VALUES(?,?,?,1) "
                "ON CONFLICT(email) DO UPDATE SET last_login=excluded.last_login, login_count=login_count+1",
                (em, now_iso(), now_iso()),
            )
            log_login("public", em, True, ip)
            return self.send_json({"token": new_session("public", em), "role": "public", "id": em})
        if role in ("contractor", "dept"):
            ref = clean_text(b.get("id"), 120)
            r = CONN.execute("SELECT * FROM accounts WHERE role=? AND ref=?", (role, ref)).fetchone()
            if r is None or not check_pass(str(b.get("pass") or ""), r["salt"], r["pass_hash"]):
                FAILS[ip].append(t)
                log_login(role, ref, False, ip)
                CONN.commit()
                return self.err(401, "Incorrect passcode for this " + ("contractor." if role == "contractor" else "department."))
            log_login(role, ref, True, ip)
            return self.send_json({"token": new_session(role, ref), "role": role, "id": ref})
        return self.err(400, "Unknown role.")

    def upload(self, sess, b):
        m = re.fullmatch(r"data:(image/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)", str(b.get("dataUrl") or ""))
        if not m:
            return self.err(400, "Please upload a JPG, PNG or WebP image.")
        raw = base64.b64decode(m.group(2))
        if len(raw) > MAX_IMAGE:
            return self.err(400, "That image is too large.")
        uid = secrets.token_hex(10)
        CONN.execute(
            "INSERT INTO uploads(id,mime,size,data,owner_role,owner_ref,created_at) VALUES(?,?,?,?,?,?,?)",
            (uid, m.group(1), len(raw), raw, sess["role"], sess["ref"], now_iso()),
        )
        return self.send_json({"url": "/api/uploads/" + uid})

    def reset(self, sess):
        for t in ("projects", "contractors", "applications", "contractor_log", "uploads"):
            CONN.execute(f"DELETE FROM {t}")
        keep = [c for c, _, _ in BASE_CONTRACTORS]
        CONN.execute(
            "DELETE FROM accounts WHERE role='contractor' AND ref NOT IN (%s)" % ",".join("?" * len(keep)), keep
        )
        CONN.execute("DELETE FROM sessions WHERE role='contractor' AND ref NOT IN (%s)" % ",".join("?" * len(keep)), keep)
        seed_projects()
        projects, revs = all_projects()
        return self.send_json({"ok": True, "projects": projects, "revs": revs})


def main():
    init_db()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"WorkWatch running at http://{'localhost' if HOST == '127.0.0.1' else HOST}:{PORT}")
    print(f"Database: {DB_PATH}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
