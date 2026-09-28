"""
Cybersecurity layer.

1. Device authentication (drone, handhelds, ESP32)
   Every request from a field device carries
       X-Device-Id, X-Timestamp (unix s), X-Nonce, X-Signature
   where X-Signature = HMAC-SHA256(device_secret,
       "<timestamp>\\n<nonce>\\n<METHOD>\\n<path>\\n<sha256(body) hex>")
   -> forged packets (wrong/unknown key), altered bodies and replayed packets
      (old timestamp or reused nonce) are rejected and logged.
   Secrets are per device (data/devices.json). Phones get theirs by pairing
   with a one-time 6-digit code shown on the Control Unit.

2. Operator accounts (data/users.json): PBKDF2-SHA256 password hashes, roles
   VIEWER < OPERATOR < SUPERVISOR, lockout after repeated failures, per-IP rate
   limits on login and pairing.

3. Capability URLs for evidence images, so a handheld can show an evidence
   frame without the image directory being open to anyone on the network.
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time

from . import config

ROLES = {"VIEWER": 0, "OPERATOR": 1, "SUPERVISOR": 2}
REPLAY_WINDOW_S = 90          # max clock difference / packet age accepted
NONCE_TTL_S = 300


def _now():
    return time.time()


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body or b"").hexdigest()


def canonical(ts, nonce, method, path, body_sha):
    return f"{ts}\n{nonce}\n{method.upper()}\n{path}\n{body_sha}"


def sign(secret_hex, ts, nonce, method, path, body: bytes):
    msg = canonical(ts, nonce, method, path, body_hash(body))
    return hmac.new(bytes.fromhex(secret_hex), msg.encode(), hashlib.sha256).hexdigest()


class Security:
    def __init__(self, data_dir, log=print):
        self.dir = data_dir
        os.makedirs(os.path.join(data_dir, "keys"), exist_ok=True)
        self.log = log
        self.lock = threading.RLock()
        self.devices_path = os.path.join(data_dir, "devices.json")
        self.users_path = os.path.join(data_dir, "users.json")
        self.mode = config.SECURITY_MODE        # enforce | monitor | off
        self.devices = {}
        self._devices_mtime = 0
        self._load_devices()
        self.users = {}
        self._load_users()
        self.nonces = {}                        # nonce -> time seen
        self.pair_codes = {}                    # code -> {device_id, expires, by}
        self.fail = {}                          # username -> [count, locked_until]
        self.rate = {}                          # (bucket, ip) -> [window_start, count]
        self.events = []                        # recent security events for the dashboard
        self.stats = {}                         # device_id -> {ok, rejected, last_reason, last_ok}
        self.on_event = None                    # callback(kind, detail) -> audit + bus
        self.server_key = self._key_file("server.key", 32)
        self.flask_secret = self._key_file("flask_secret.key", 32)

    # ------------------------------------------------------------ files
    def _key_file(self, name, n):
        p = os.path.join(self.dir, "keys", name)
        if not os.path.exists(p):
            with open(p, "wb") as f:
                f.write(secrets.token_bytes(n))
        with open(p, "rb") as f:
            return f.read()

    def _load_devices(self):
        if os.path.exists(self.devices_path):
            self._devices_mtime = os.path.getmtime(self.devices_path)
            with open(self.devices_path) as f:
                self.devices = json.load(f)

    def _save_devices(self):
        tmp = self.devices_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.devices, f, indent=2)
        os.replace(tmp, self.devices_path)
        self._devices_mtime = os.path.getmtime(self.devices_path)

    def _device(self, device_id):
        # pick up devices provisioned by the simulators / tools while running
        if os.path.exists(self.devices_path) and os.path.getmtime(self.devices_path) != self._devices_mtime:
            self._load_devices()
        d = self.devices.get(device_id)
        return d if d and not d.get("revoked") else None

    # ------------------------------------------------------------ events
    def event(self, level, kind, detail, device_id=None, ip=None):
        e = {"t": time.strftime("%Y-%m-%dT%H:%M:%S"), "level": level, "kind": kind, "detail": detail,
             "device_id": device_id, "ip": ip}
        with self.lock:
            self.events = ([e] + self.events)[:200]
        if self.on_event:
            try:
                self.on_event(e)
            except Exception as ex:
                self.log(f"[security] event hook failed: {ex}")
        return e

    # ------------------------------------------------------------ device provisioning
    def provision(self, device_id, dtype="HANDHELD", by="SYSTEM"):
        device_id = device_id.strip().upper()
        with self.lock:
            self._load_devices()
            secret = secrets.token_hex(32)
            self.devices[device_id] = {"secret": secret, "type": dtype, "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                       "by": by, "revoked": False}
            self._save_devices()
        self.event("info", "DEVICE_PROVISIONED", f"{device_id} ({dtype}) by {by}", device_id)
        return secret

    def revoke(self, device_id, by):
        with self.lock:
            self._load_devices()
            if device_id not in self.devices:
                return False
            self.devices[device_id]["revoked"] = True
            self._save_devices()
        self.event("warn", "DEVICE_REVOKED", f"{device_id} revoked by {by}", device_id)
        return True

    def device_list(self):
        self._device("")      # refresh
        out = []
        for k, v in self.devices.items():
            s = self.stats.get(k, {})
            out.append({"device_id": k, "type": v.get("type"), "created": v.get("created"), "revoked": v.get("revoked"),
                        "fingerprint": hashlib.sha256(bytes.fromhex(v["secret"])).hexdigest()[:12],
                        "ok": s.get("ok", 0), "rejected": s.get("rejected", 0), "last_reason": s.get("last_reason"),
                        "last_ok": s.get("last_ok")})
        return out

    def new_pair_code(self, device_id, by):
        code = f"{secrets.randbelow(1000000):06d}"
        with self.lock:
            now = _now()
            self.pair_codes = {c: v for c, v in self.pair_codes.items() if v["expires"] > now}
            self.pair_codes[code] = {"device_id": device_id.strip().upper(), "expires": now + 300, "by": by}
        self.event("info", "PAIR_CODE", f"pairing code issued for {device_id} by {by} (valid 5 min)", device_id)
        return code

    def pair(self, device_id, code, ip):
        device_id = (device_id or "").strip().upper()
        with self.lock:
            p = self.pair_codes.get(code)
            if not p or p["expires"] < _now() or p["device_id"] != device_id:
                self.event("warn", "PAIR_FAILED", f"bad or expired pairing code for {device_id}", device_id, ip)
                return None
            del self.pair_codes[code]
        return self.provision(device_id, "HANDHELD", by=f"pairing ({p['by']})")

    # ------------------------------------------------------------ request verification
    def _stat(self, device_id, ok, reason=None):
        s = self.stats.setdefault(device_id or "?", {"ok": 0, "rejected": 0})
        if ok:
            s["ok"] += 1
            s["last_ok"] = time.strftime("%H:%M:%S")
        else:
            s["rejected"] += 1
            s["last_reason"] = reason

    def verify(self, method, path, body, headers, ip=None, query=None):
        """
        Returns (ok, device_id, reason). In monitor mode failures are reported
        but ok stays True, so nothing breaks while devices are being set up.
        """
        if self.mode == "off":
            return True, headers.get("X-Device-Id"), "security off"
        q = query or {}
        dev = headers.get("X-Device-Id") or q.get("dev")
        ts = headers.get("X-Timestamp") or q.get("ts")
        nonce = headers.get("X-Nonce") or q.get("nonce")
        sig = headers.get("X-Signature") or q.get("sig")
        reason = None
        if not (dev and ts and nonce and sig):
            reason = "unsigned request"
        else:
            d = self._device(dev)
            if not d:
                reason = f"unknown or revoked device {dev}"
            else:
                try:
                    age = abs(_now() - float(ts))
                except ValueError:
                    age = 1e9
                expect = sign(d["secret"], ts, nonce, method, path, body)
                if not hmac.compare_digest(expect, str(sig)):
                    reason = "bad signature (forged or altered message)"
                elif age > REPLAY_WINDOW_S:
                    reason = f"stale timestamp ({age:.0f}s old): replay blocked"
                else:
                    with self.lock:
                        now = _now()
                        if len(self.nonces) > 20000:
                            self.nonces = {n: t for n, t in self.nonces.items() if now - t < NONCE_TTL_S}
                        if nonce in self.nonces:
                            reason = "nonce reused: replay blocked"
                        else:
                            self.nonces[nonce] = now
        if reason is None:
            self._stat(dev, True)
            return True, dev, "ok"
        self._stat(dev, False, reason)
        self._reject_event(dev, reason, path, ip)
        return self.mode == "monitor", dev, reason

    _last_reject = {}

    def _reject_event(self, dev, reason, path, ip):
        key = (dev, reason, path)
        now = _now()
        if now - self._last_reject.get(key, 0) < 10:       # don't flood the log with identical rejections
            return
        self._last_reject[key] = now
        lvl = "warn" if self.mode == "monitor" else "bad"
        self.event(lvl, "PACKET_REJECTED" if self.mode == "enforce" else "PACKET_UNVERIFIED",
                   f"{reason} · {path}", dev, ip)

    # ------------------------------------------------------------ capability URLs
    def signed_url(self, path, ttl=24 * 3600):
        exp = int(_now() + ttl)
        tok = hmac.new(self.server_key, f"{path}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]
        return f"{path}?exp={exp}&tok={tok}"

    def check_url(self, path, exp, tok):
        try:
            if int(exp) < _now():
                return False
        except (TypeError, ValueError):
            return False
        want = hmac.new(self.server_key, f"{path}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]
        return hmac.compare_digest(want, tok or "")

    # ------------------------------------------------------------ users
    def _load_users(self):
        if os.path.exists(self.users_path):
            with open(self.users_path) as f:
                self.users = json.load(f)
        if not self.users:
            # first start: default accounts (change them with tools/set_password.py)
            self.set_user("supervisor", "Supervisor@123", "SUPERVISOR", "Duty Supervisor", save=False)
            self.set_user("operator", "Operator@123", "OPERATOR", "Control Room Operator", save=False)
            self.set_user("viewer", "Viewer@123", "VIEWER", "Observer", save=False)
            self._save_users()
            self.log("[security] created default accounts: supervisor / Supervisor@123, operator / Operator@123, "
                     "viewer / Viewer@123  (change with: python tools/set_password.py)")

    def _save_users(self):
        with open(self.users_path, "w") as f:
            json.dump(self.users, f, indent=2)

    @staticmethod
    def _hash(password, salt, iterations=200_000):
        return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations).hex()

    def set_user(self, username, password, role, name=None, save=True):
        salt = secrets.token_hex(16)
        self.users[username] = {"name": name or username, "role": role, "salt": salt, "iterations": 200_000,
                                "hash": self._hash(password, salt)}
        if save:
            self._save_users()

    def login(self, username, password, ip):
        username = (username or "").strip().lower()
        with self.lock:
            f = self.fail.get(username, [0, 0])
            if f[1] > _now():
                self.event("bad", "LOGIN_LOCKED", f"login attempt for locked account '{username}'", ip=ip)
                return None, f"account locked for {int(f[1] - _now())} s after repeated failures"
        u = self.users.get(username)
        ok = u and hmac.compare_digest(self._hash(password or "", u["salt"], u["iterations"]), u["hash"])
        with self.lock:
            if not ok:
                f = self.fail.get(username, [0, 0])
                f[0] += 1
                if f[0] >= 5:
                    f = [0, _now() + 120]
                    self.event("bad", "ACCOUNT_LOCKED", f"'{username}' locked for 120 s after 5 failed logins", ip=ip)
                else:
                    self.event("warn", "LOGIN_FAILED", f"failed login for '{username}'", ip=ip)
                self.fail[username] = f
                return None, "wrong username or password"
            self.fail.pop(username, None)
        self.event("info", "LOGIN", f"{username} ({u['role']}) signed in", ip=ip)
        return {"username": username, "name": u["name"], "role": u["role"]}, None

    # ------------------------------------------------------------ rate limiting
    def allow(self, bucket, ip, limit, window=60):
        with self.lock:
            now = _now()
            w = self.rate.get((bucket, ip))
            if not w or now - w[0] > window:
                self.rate[(bucket, ip)] = [now, 1]
                return True
            w[1] += 1
            if w[1] > limit:
                if w[1] == limit + 1:
                    self.event("bad", "RATE_LIMITED", f"too many {bucket} requests from {ip}", ip=ip)
                return False
            return True

    def summary(self):
        return {"mode": self.mode, "devices": self.device_list(), "events": self.events[:60],
                "users": [{"username": k, "name": v["name"], "role": v["role"]} for k, v in self.users.items()]}
