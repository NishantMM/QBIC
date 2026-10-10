#!/usr/bin/env python3
"""WorkWatch backend: standard library only (no requirements.txt needed).

Implements every endpoint that index.html calls:
  GET  /health, /api/bootstrap, /api/me, /api/projects, /api/applications, /uploads/<file>
  POST /api/login, /api/logout, /api/projects/save, /api/upload,
       /api/applications, /api/applications/decide, /api/reset

Data lives in memory and is saved to DATA_DIR/state.json. On Render's free plan the
disk is ephemeral, so data resets to seed_projects.json when the service restarts.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("PORT", 8000))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(BASE_DIR, "data"))
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
STATE_FILE = os.path.join(DATA_DIR, "state.json")
SEED_FILE = os.path.join(BASE_DIR, "seed_projects.json")

SESSION_TTL = 12 * 3600
MAX_BODY = 4_000_000
MAX_IMAGE = 1_500_000

# ---- demo accounts (same values as the front end shows) ----
DEPT_PASS = {
    "Engineering Unit – Civil": "civil@26",
    "Engineering Unit – Electrical": "elec@26",
    "IT & Network Services": "it@26",
    "Hostel Office": "hostel@26",
}
CON_PASS = {
    "C01": "murugan@26",
    "C02": "kaveri@26",
    "C03": "bright@26",
    "C04": "aqua@26",
    "C05": "fiber@26",
}
BASE_CONTRACTOR_NAMES = {
    "sri murugan constructions", "kaveri builders", "brightway electricals",
    "aqua infra works", "fiberlink networks",
}
GMAIL = re.compile(r"^[a-z0-9._%+-]+@gmail\.com$", re.I)

LOCK = threading.RLock()
SESSIONS = {}  # token -> {role, ref, exp}


def today():
    return time.strftime("%Y-%m-%d")


def pw_hash(p):
    return hashlib.sha256(("workwatch:" + p).encode("utf-8")).hexdigest()


def same(a, b):
    return hmac.compare_digest(str(a).encode("utf-8"), str(b).encode("utf-8"))


# ---------------------------------------------------------------- state
def load_seed():
    with open(SEED_FILE, encoding="utf-8") as f:
        seed = json.load(f)
    return {
        "projects": {p["code"]: p for p in seed},
        "revs": {p["code"]: 1 for p in seed},
        "apps": [],
        "contractors": [],
        "con_pass": {},
        "log": [],
        "next_con": 6,
        "next_app": 1,
    }


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            s = json.load(f)
        if isinstance(s, dict) and "projects" in s:
            return s
    except (OSError, ValueError):
        pass
    return load_seed()


S = load_state()


def save_state():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(S, f)
        os.replace(tmp, STATE_FILE)
    except OSError as e:
        print("Could not save state:", e, file=sys.stderr)


class ApiError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status
        self.msg = msg


def need(user, *roles):
    if not user:
        raise ApiError(401, "Please log in again.")
    if roles and user["role"] not in roles:
        raise ApiError(403, "This action is not allowed for your account type.")


def project_list():
    return list(S["projects"].values())


# ---------------------------------------------------------------- handler
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ---- low level helpers
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Cache-Control", "no-store")

    def _send(self, status, obj, head=False):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        if not head:
            self.wfile.write(body)

    def _user(self):
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer "):
            s = SESSIONS.get(h[7:])
            if s and s["exp"] > time.time():
                return s
        return None

    def _read_json(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ApiError(413, "Request too large.")
        raw = self.rfile.read(n) if n else b""
        if not raw:
            return {}
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ApiError(400, "Invalid request.")
        return data

    def _base_url(self):
        env = os.environ.get("PUBLIC_URL")
        if env:
            return env.rstrip("/")
        proto = self.headers.get("X-Forwarded-Proto", "http")
        return "%s://%s" % (proto, self.headers.get("Host", "localhost"))

    # ---- HTTP verbs
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self._cors()
        self.end_headers()

    def do_HEAD(self):  # uptime monitors often use HEAD
        self._send(200, {"status": "ok"}, head=True)

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def _route(self, method):
        try:
            url = urlparse(self.path)
            body = self._read_json() if method == "POST" else {}
            if method == "GET" and url.path.startswith("/uploads/"):
                self._serve_upload(url.path[len("/uploads/"):])
                return
            with LOCK:
                result = self._dispatch(method, url.path, parse_qs(url.query), body)
            self._send(200, result)
        except ApiError as e:
            self._send(e.status, {"error": e.msg})
        except ValueError:
            self._send(400, {"error": "Invalid request body."})
        except Exception:
            traceback.print_exc()
            self._send(500, {"error": "Server error. Please try again."})

    # ---- routing
    def _dispatch(self, method, path, q, b):
        user = self._user()
        key = (method, path.rstrip("/") or "/")

        if key in (("GET", "/"), ("GET", "/health"), ("GET", "/api/health")):
            return {"status": "ok", "service": "WorkWatch"}

        if key == ("GET", "/api/bootstrap"):
            return {"projects": project_list(), "revs": S["revs"], "contractors": S["contractors"]}

        if key == ("POST", "/api/login"):
            return self._login(b)

        if key == ("POST", "/api/logout"):
            h = self.headers.get("Authorization", "")
            SESSIONS.pop(h[7:], None)
            return {"ok": True}

        if key == ("GET", "/api/me"):
            need(user)
            return {"role": user["role"], "ref": user["ref"]}

        if key == ("GET", "/api/projects"):
            need(user)
            return {"projects": project_list(), "revs": S["revs"]}

        if key == ("POST", "/api/projects/save"):
            need(user)
            return self._save_projects(user, b)

        if key == ("POST", "/api/upload"):
            need(user)
            return self._upload(b)

        if key == ("POST", "/api/applications"):
            return self._apply(b)

        if key == ("GET", "/api/applications"):
            if q.get("id"):
                return self._app_status(q["id"][0])
            need(user, "dept")
            mine = [self._pub_app(a) for a in S["apps"] if a["dept"] == user["ref"]]
            others = sum(1 for a in S["apps"] if a["status"] == "pending" and a["dept"] != user["ref"])
            return {"apps": mine, "othersPending": others, "log": list(reversed(S["log"]))[:50]}

        if key == ("POST", "/api/applications/decide"):
            need(user, "dept")
            return self._decide(user, b)

        if key == ("POST", "/api/reset"):
            need(user, "dept")
            return self._reset()

        raise ApiError(404, "Endpoint not found.")

    # ---- auth
    def _login(self, b):
        role = b.get("role")
        if role == "public":
            email = str(b.get("email", "")).strip().lower()
            if not GMAIL.match(email) or len(email.split("@")[0]) < 6:
                raise ApiError(400, "Enter a valid Gmail address ending in @gmail.com.")
            ref = email
        elif role == "contractor":
            cid, pw = str(b.get("id", "")), str(b.get("pass", ""))
            if cid in CON_PASS:
                ok = same(pw, CON_PASS[cid])
            elif any(c.get("id") == cid for c in S["contractors"]):
                ok = same(pw_hash(pw), S["con_pass"].get(cid, ""))
            else:
                raise ApiError(401, "Unknown contractor.")
            if not ok:
                raise ApiError(401, "Incorrect passcode for this contractor.")
            ref = cid
        elif role == "dept":
            dept, pw = str(b.get("id", "")), str(b.get("pass", ""))
            if dept not in DEPT_PASS or not same(pw, DEPT_PASS[dept]):
                raise ApiError(401, "Incorrect passcode for this department.")
            ref = dept
        else:
            raise ApiError(400, "Unknown login type.")
        token = secrets.token_hex(24)
        SESSIONS[token] = {"role": role, "ref": ref, "exp": time.time() + SESSION_TTL}
        return {"token": token, "role": role, "id": ref}

    # ---- projects
    def _save_projects(self, user, b):
        changes = b.get("changes")
        if not isinstance(changes, list):
            raise ApiError(400, "Invalid request.")
        role, ref = user["role"], user["ref"]
        allowed_by_role = {
            "public": {"faq", "feedback"},
            "contractor": {"faq", "stage", "updated", "history", "delayClaims", "status", "completion"},
        }
        rejected = []
        for ch in changes:
            code = ch.get("code") if isinstance(ch, dict) else None
            try:
                if ch.get("isNew"):
                    p = ch.get("project")
                    if role != "dept":
                        raise ApiError(403, "Only a department can create projects.")
                    if not isinstance(p, dict) or p.get("code") != code or p.get("dept") != ref:
                        raise ApiError(403, "You can only create projects for your own department.")
                    if code in S["projects"]:
                        raise ApiError(409, "Project code already exists.")
                    S["projects"][code] = p
                    S["revs"][code] = 1
                    continue
                p = S["projects"].get(code)
                if not p:
                    raise ApiError(404, "Unknown project.")
                fields = ch.get("fields")
                if not isinstance(fields, dict):
                    raise ApiError(400, "Invalid change.")
                if role == "dept":
                    if p.get("dept") != ref:
                        raise ApiError(403, "That project belongs to another department.")
                    bad = set(fields) & {"code", "dept"}
                else:
                    if role == "contractor" and p.get("cid") != ref:
                        raise ApiError(403, "That project is not assigned to you.")
                    bad = set(fields) - allowed_by_role[role]
                    if role == "contractor" and "status" in fields and fields["status"] != "review":
                        raise ApiError(403, "Only the department can change the status.")
                    if role == "public":
                        self._check_public_edit(p, fields)
                if bad:
                    raise ApiError(403, "Not permitted to change: " + ", ".join(sorted(bad)))
                p.update(fields)
                S["revs"][code] = S["revs"].get(code, 0) + 1
            except ApiError as e:
                rejected.append({"code": code, "reason": e.msg})
        save_state()
        return {"revs": S["revs"], "rejected": rejected}

    @staticmethod
    def _check_public_edit(p, fields):
        """Residents may add questions/feedback and vote, not rewrite answers or history."""
        if "feedback" in fields:
            old, new = p.get("feedback", []), fields["feedback"]
            if not isinstance(new, list) or new[:len(old)] != old:
                raise ApiError(403, "Existing feedback cannot be changed.")
        if "faq" in fields:
            old, new = p.get("faq", []), fields["faq"]
            if not isinstance(new, list) or len(new) < len(old):
                raise ApiError(403, "Existing questions cannot be removed.")
            byid = {x.get("id"): x for x in new if isinstance(x, dict)}
            for o in old:
                n = byid.get(o.get("id"))
                if not n or n.get("a") != o.get("a") or n.get("q") != o.get("q"):
                    raise ApiError(403, "Only the contractor can answer questions.")

    # ---- uploads
    def _upload(self, b):
        m = re.match(r"^data:image/(jpeg|png|webp|gif);base64,(.+)$", str(b.get("dataUrl", "")), re.S)
        if not m:
            raise ApiError(400, "Please upload a JPG, PNG, WebP or GIF image.")
        try:
            raw = base64.b64decode(m.group(2), validate=False)
        except Exception:
            raise ApiError(400, "That image could not be read.")
        if len(raw) > MAX_IMAGE:
            raise ApiError(413, "Image is too large.")
        ext = {"jpeg": "jpg"}.get(m.group(1), m.group(1))
        name = secrets.token_hex(8) + "." + ext
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        with open(os.path.join(UPLOAD_DIR, name), "wb") as f:
            f.write(raw)
        return {"url": self._base_url() + "/uploads/" + name}

    def _serve_upload(self, name):
        if not re.match(r"^[a-f0-9]{16}\.(jpg|png|webp|gif)$", name):
            raise ApiError(404, "Not found.")
        try:
            with open(os.path.join(UPLOAD_DIR, name), "rb") as f:
                data = f.read()
        except OSError:
            raise ApiError(404, "Not found.")
        ctype = {"jpg": "image/jpeg", "png": "image/png", "webp": "image/webp", "gif": "image/gif"}[name.rsplit(".", 1)[1]]
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "public, max-age=86400")
        self.end_headers()
        self.wfile.write(data)

    # ---- contractor applications
    @staticmethod
    def _pub_app(a):
        return {k: v for k, v in a.items() if k != "pass_hash"}

    def _apply(self, b):
        g = lambda k: str(b.get(k, "")).strip()
        name, dept = g("name"), g("dept")
        if len(name) < 3:
            raise ApiError(400, "Enter your business name.")
        if dept not in DEPT_PASS:
            raise ApiError(400, "Choose the department that will verify you.")
        if len(str(b.get("pass", ""))) < 6:
            raise ApiError(400, "Choose a passcode of at least 6 characters.")
        low = name.lower()
        if low in BASE_CONTRACTOR_NAMES or any(c["name"].lower() == low for c in S["contractors"]):
            raise ApiError(409, "A contractor with this name is already registered.")
        refs = b.get("refs") if isinstance(b.get("refs"), dict) else {}
        certs = b.get("certs") if isinstance(b.get("certs"), list) else []
        app_id = "APP-%03d" % S["next_app"]
        S["next_app"] += 1
        S["apps"].append({
            "id": app_id, "status": "pending", "at": g("at") or today(), "dept": dept, "name": name,
            "spec": g("spec"), "lclass": g("lclass"), "lno": g("lno"), "lexp": g("lexp"), "iexp": g("iexp"),
            "tax": g("tax"), "est": b.get("est"), "staff": b.get("staff"),
            "certs": [str(c)[:80] for c in certs][:10], "phone": g("phone"), "email": g("email"),
            "refs": {str(k)[:20]: str(v)[:200] for k, v in refs.items()},
            "pass_hash": pw_hash(str(b["pass"])),
        })
        save_state()
        return {"id": app_id}

    def _app_status(self, app_id):
        a = next((x for x in S["apps"] if x["id"].upper() == app_id.strip().upper()), None)
        if not a:
            raise ApiError(404, "No application found with that ID.")
        return {k: a.get(k) for k in ("name", "status", "dept", "at", "decidedAt", "by", "reason")}

    def _decide(self, user, b):
        a = next((x for x in S["apps"] if x["id"] == b.get("id")), None)
        if not a or a["status"] != "pending":
            raise ApiError(400, "This application is no longer pending.")
        if a["dept"] != user["ref"]:
            raise ApiError(403, "Only %s can verify this contractor." % a["dept"])
        action = b.get("action")
        if action == "reject":
            reason = str(b.get("reason", "")).strip()
            if len(reason) < 5:
                raise ApiError(400, "Add a reason for declining.")
            a.update(status="rejected", reason=reason, by=user["ref"], decidedAt=today())
            S["log"].append({"d": today(), "t": "Declined %s (%s): %s" % (a["name"], a["id"], reason), "by": user["ref"]})
            save_state()
            return {"ok": True}
        if action == "approve":
            c = b.get("contractor")
            if not isinstance(c, dict):
                raise ApiError(400, "Missing contractor details.")
            low = a["name"].lower()
            if low in BASE_CONTRACTOR_NAMES or any(x["name"].lower() == low for x in S["contractors"]):
                raise ApiError(409, "A contractor with this name is already registered.")
            cid = "C%02d" % S["next_con"]
            S["next_con"] += 1
            c["id"] = cid
            c.setdefault("records", [])
            S["contractors"].append(c)
            S["con_pass"][cid] = a["pass_hash"]
            a.update(status="approved", by=user["ref"], decidedAt=today(), contractorId=cid)
            S["log"].append({"d": today(), "t": "Approved %s (%s) as %s." % (a["name"], a["id"], cid), "by": user["ref"]})
            save_state()
            return {"contractor": c}
        raise ApiError(400, "Unknown action.")

    # ---- reset
    def _reset(self):
        try:
            for f in os.listdir(UPLOAD_DIR):
                os.remove(os.path.join(UPLOAD_DIR, f))
        except OSError:
            pass
        S.clear()
        S.update(load_seed())
        save_state()
        return {"projects": project_list(), "revs": S["revs"]}


def run():
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("WorkWatch server running on port %d" % PORT)
    sys.stdout.flush()
    httpd.serve_forever()


if __name__ == "__main__":
    run()
