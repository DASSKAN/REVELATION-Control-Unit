"""
SQLite storage for runs, detection events, alerts, devices and zones,
plus a hash-chained audit log.

Every audit row stores sha256(prev_hash + canonical_json(payload)). Changing
or deleting any earlier row breaks the chain, which /api/audit/verify detects.
This is the tamper-evidence layer; anchoring the latest hash to a blockchain
later only needs the value returned by `latest_hash()`.
"""
import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    start_time  TEXT NOT NULL,
    end_time    TEXT,
    status      TEXT NOT NULL,            -- ACTIVE | ALERT | COMPLETED
    operator    TEXT,
    notes       TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id    TEXT UNIQUE,
    run_id        TEXT NOT NULL,
    device_id     TEXT NOT NULL,
    device_type   TEXT NOT NULL,          -- DRONE | HANDHELD
    timestamp     TEXT NOT NULL,
    received_at   TEXT NOT NULL,
    detection     TEXT NOT NULL,
    threat_level  TEXT NOT NULL,
    confidence    REAL NOT NULL,
    latitude      REAL,
    longitude     REAL,
    zone          TEXT,
    battery       REAL,
    evidence_ref  TEXT,
    alert_id      TEXT,
    raw           TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id      TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    source_device TEXT NOT NULL,
    source_type   TEXT NOT NULL,
    detection     TEXT NOT NULL,
    threat_level  TEXT NOT NULL,
    confidence    REAL NOT NULL,
    latitude      REAL,
    longitude     REAL,
    geo_method    TEXT,                   -- PROJECTED | DRONE_POSITION | DEVICE_GPS | NONE
    zone          TEXT,
    evidence_ref  TEXT,
    evidence_sha256 TEXT,
    description   TEXT,
    status        TEXT NOT NULL,          -- NEW | DISPATCHED | ACKNOWLEDGED | EN_ROUTE | ON_SCENE | RESOLVED | DISMISSED
    assigned_to   TEXT,
    resolution    TEXT,
    updated_at    TEXT NOT NULL,
    history       TEXT NOT NULL           -- JSON list of {t, status, by, note}
);
CREATE TABLE IF NOT EXISTS zones (
    zone_id   TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    kind      TEXT NOT NULL,              -- RESTRICTED
    polygon   TEXT NOT NULL               -- JSON [[x,y],...] normalised 0..1 image coords
);
CREATE TABLE IF NOT EXISTS audit (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    ref_id     TEXT,
    payload    TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    msg_id     TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    sender     TEXT NOT NULL,
    target     TEXT NOT NULL,             -- ALL or a handheld device_id
    priority   TEXT NOT NULL,             -- INFO | URGENT
    text       TEXT NOT NULL,
    acks       TEXT NOT NULL              -- JSON {device_id: time}
);
CREATE TABLE IF NOT EXISTS ai_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    run_id  TEXT,
    cam_id  TEXT,
    level   TEXT NOT NULL,
    text    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS counters (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
"""

GENESIS = "0" * 64


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.lock = threading.RLock()
        self.on_audit = None
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    # columns added after the first release; ALTER keeps existing databases working
    NEW_COLUMNS = {
        "alerts": {"dispatched_to": "TEXT", "escalations": "INTEGER DEFAULT 0", "backup": "INTEGER DEFAULT 0",
                   "camera": "TEXT", "clip_ref": "TEXT"},
        "zones": {"cam_id": "TEXT"},
    }

    def _migrate(self):
        for table, cols in self.NEW_COLUMNS.items():
            have = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            for c, typ in cols.items():
                if c not in have:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {c} {typ}")

    # ------------------------------------------------------------ helpers
    def _q(self, sql, args=(), one=False):
        with self.lock:
            cur = self.conn.execute(sql, args)
            rows = cur.fetchall()
        rows = [dict(r) for r in rows]
        return (rows[0] if rows else None) if one else rows

    def _x(self, sql, args=()):
        with self.lock:
            self.conn.execute(sql, args)
            self.conn.commit()

    def next_id(self, prefix, width=4):
        with self.lock:
            row = self.conn.execute("SELECT value FROM counters WHERE name=?", (prefix,)).fetchone()
            val = (row["value"] if row else 0) + 1
            self.conn.execute(
                "INSERT INTO counters(name,value) VALUES(?,?) "
                "ON CONFLICT(name) DO UPDATE SET value=excluded.value", (prefix, val))
            self.conn.commit()
        return f"{prefix}_{val:0{width}d}"

    # ------------------------------------------------------------ audit chain
    def audit(self, kind, ref_id, payload):
        with self.lock:
            last = self.conn.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS
            ts = now_iso()
            body = _canon({"ts": ts, "kind": kind, "ref_id": ref_id, "payload": payload})
            h = hashlib.sha256((prev + body).encode()).hexdigest()
            self.conn.execute(
                "INSERT INTO audit(ts,kind,ref_id,payload,prev_hash,hash) VALUES(?,?,?,?,?,?)",
                (ts, kind, ref_id, _canon(payload), prev, h))
            self.conn.commit()
        if self.on_audit:
            self.on_audit(kind, ref_id, h)      # every audit entry also goes into the blockchain ledger
        return h

    def verify_audit(self):
        prev = GENESIS
        rows = self._q("SELECT * FROM audit ORDER BY seq")
        for r in rows:
            body = _canon({"ts": r["ts"], "kind": r["kind"], "ref_id": r["ref_id"],
                           "payload": json.loads(r["payload"])})
            h = hashlib.sha256((prev + body).encode()).hexdigest()
            if r["prev_hash"] != prev or r["hash"] != h:
                return {"ok": False, "broken_at_seq": r["seq"], "entries": len(rows)}
            prev = h
        return {"ok": True, "entries": len(rows), "latest_hash": prev}

    def latest_hash(self):
        r = self._q("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1", one=True)
        return r["hash"] if r else GENESIS

    # ------------------------------------------------------------ runs
    def active_run(self):
        return self._q("SELECT * FROM runs WHERE status IN ('ACTIVE','ALERT') "
                       "ORDER BY start_time DESC LIMIT 1", one=True)

    def start_run(self, operator=None, notes=None):
        run_id = self.next_id("RUN", 3)
        self._x("INSERT INTO runs(run_id,start_time,status,operator,notes) VALUES(?,?,?,?,?)",
                (run_id, now_iso(), "ACTIVE", operator, notes))
        self.audit("RUN_START", run_id, {"operator": operator, "notes": notes})
        return self.get_run(run_id)

    def end_run(self, run_id):
        self._x("UPDATE runs SET status='COMPLETED', end_time=? WHERE run_id=?", (now_iso(), run_id))
        self.audit("RUN_END", run_id, {})
        return self.get_run(run_id)

    def set_run_status(self, run_id, status):
        self._x("UPDATE runs SET status=? WHERE run_id=?", (status, run_id))

    def get_run(self, run_id):
        return self._q("SELECT * FROM runs WHERE run_id=?", (run_id,), one=True)

    def list_runs(self, limit=20):
        return self._q("SELECT * FROM runs ORDER BY start_time DESC LIMIT ?", (limit,))

    # ------------------------------------------------------------ events
    def has_message(self, message_id):
        return self._q("SELECT 1 FROM events WHERE message_id=?", (message_id,), one=True) is not None

    def add_event(self, ev):
        cols = ["message_id", "run_id", "device_id", "device_type", "timestamp", "received_at",
                "detection", "threat_level", "confidence", "latitude", "longitude", "zone",
                "battery", "evidence_ref", "alert_id", "raw"]
        ev = dict(ev)
        ev.setdefault("received_at", now_iso())
        vals = [ev.get(c) for c in cols]
        self._x(f"INSERT INTO events({','.join(cols)}) VALUES({','.join('?' * len(cols))})", vals)
        payload = {k: ev.get(k) for k in cols if k != "raw"}
        self.audit("EVENT", ev.get("message_id"), payload)

    def list_events(self, run_id=None, limit=100):
        if run_id:
            return self._q("SELECT * FROM events WHERE run_id=? ORDER BY id DESC LIMIT ?", (run_id, limit))
        return self._q("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))

    # ------------------------------------------------------------ alerts
    def create_alert(self, a):
        a = dict(a)
        a["alert_id"] = self.next_id("ALT")
        t = now_iso()
        a.setdefault("status", "NEW")
        a["created_at"] = a["updated_at"] = t
        a["history"] = json.dumps([{"t": t, "status": a["status"], "by": a["source_device"], "note": "created"}])
        cols = ["alert_id", "run_id", "created_at", "source_device", "source_type", "detection",
                "threat_level", "confidence", "latitude", "longitude", "geo_method", "zone",
                "evidence_ref", "evidence_sha256", "description", "status", "assigned_to",
                "resolution", "updated_at", "history", "dispatched_to", "camera", "clip_ref"]
        self._x(f"INSERT INTO alerts({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                [a.get(c) for c in cols])
        self.audit("ALERT_CREATED", a["alert_id"], {k: a.get(k) for k in cols if k != "history"})
        return self.get_alert(a["alert_id"])

    def update_alert(self, alert_id, status=None, by=None, note=None, **fields):
        a = self.get_alert(alert_id)
        if not a:
            return None
        hist = a["history"]
        t = now_iso()
        if status:
            fields["status"] = status
        fields["updated_at"] = t
        hist.append({"t": t, "status": status or a["status"], "by": by, "note": note})
        fields["history"] = json.dumps(hist)
        sets = ",".join(f"{k}=?" for k in fields)
        self._x(f"UPDATE alerts SET {sets} WHERE alert_id=?", list(fields.values()) + [alert_id])
        self.audit("ALERT_UPDATE", alert_id, {"status": status, "by": by, "note": note,
                                              **{k: v for k, v in fields.items() if k not in ("history",)}})
        return self.get_alert(alert_id)

    def get_alert(self, alert_id):
        a = self._q("SELECT * FROM alerts WHERE alert_id=?", (alert_id,), one=True)
        if a:
            a["history"] = json.loads(a["history"])
        return a

    def list_alerts(self, statuses=None, limit=50):
        if statuses:
            qs = ",".join("?" * len(statuses))
            rows = self._q(f"SELECT * FROM alerts WHERE status IN ({qs}) ORDER BY created_at DESC LIMIT ?",
                           (*statuses, limit))
        else:
            rows = self._q("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,))
        for r in rows:
            r["history"] = json.loads(r["history"])
        return rows

    # ------------------------------------------------------------ zones
    def list_zones(self, cam_id=None):
        rows = self._q("SELECT * FROM zones") if cam_id is None else \
            self._q("SELECT * FROM zones WHERE cam_id=? OR cam_id IS NULL", (cam_id,))
        for r in rows:
            r["polygon"] = json.loads(r["polygon"])
        return rows

    def save_zone(self, name, polygon, kind="RESTRICTED", cam_id=None):
        zid = self.next_id("ZONE", 2)
        self._x("INSERT INTO zones(zone_id,name,kind,polygon,cam_id) VALUES(?,?,?,?,?)",
                (zid, name, kind, json.dumps(polygon), cam_id))
        self.audit("ZONE_ADD", zid, {"name": name, "polygon": polygon})
        return zid

    def delete_zones(self, cam_id=None):
        if cam_id:
            self._x("DELETE FROM zones WHERE cam_id=?", (cam_id,))
        else:
            self._x("DELETE FROM zones")
        self.audit("ZONES_CLEARED", None, {})

    # ------------------------------------------------------------ operator messages
    def add_message(self, sender, target, priority, text):
        mid = self.next_id("BC")
        self._x("INSERT INTO messages(msg_id,created_at,sender,target,priority,text,acks) VALUES(?,?,?,?,?,?,?)",
                (mid, now_iso(), sender, target, priority, text, "{}"))
        self.audit("MESSAGE", mid, {"sender": sender, "target": target, "priority": priority, "text": text})
        return self.get_message(mid)

    def get_message(self, mid):
        m = self._q("SELECT * FROM messages WHERE msg_id=?", (mid,), one=True)
        if m:
            m["acks"] = json.loads(m["acks"])
        return m

    def ack_message(self, mid, device_id):
        m = self.get_message(mid)
        if not m:
            return None
        m["acks"][device_id] = now_iso()
        self._x("UPDATE messages SET acks=? WHERE msg_id=?", (json.dumps(m["acks"]), mid))
        self.audit("MESSAGE_ACK", mid, {"device_id": device_id})
        return self.get_message(mid)

    def list_messages(self, limit=30):
        rows = self._q("SELECT * FROM messages ORDER BY created_at DESC LIMIT ?", (limit,))
        for r in rows:
            r["acks"] = json.loads(r["acks"])
        return rows

    # ------------------------------------------------------------ AI observations (what the detector saw)
    def add_ai_log(self, run_id, cam_id, level, text):
        self._x("INSERT INTO ai_log(ts,run_id,cam_id,level,text) VALUES(?,?,?,?,?)",
                (now_iso(), run_id, cam_id, level, text))

    def list_ai_log(self, run_id):
        return self._q("SELECT * FROM ai_log WHERE run_id=? ORDER BY id", (run_id,))

    def run_rows(self, table, run_id, order="rowid"):
        return self._q(f"SELECT * FROM {table} WHERE run_id=? ORDER BY {order}", (run_id,))

    def messages_between(self, start, end):
        end = end or "9999"
        rows = self._q("SELECT * FROM messages WHERE created_at>=? AND created_at<=? ORDER BY created_at", (start, end))
        for r in rows:
            r["acks"] = json.loads(r["acks"])
        return rows

    def audit_between(self, start, end):
        end = end or "9999"
        return self._q("SELECT * FROM audit WHERE ts>=? AND ts<=? ORDER BY seq", (start, end))
