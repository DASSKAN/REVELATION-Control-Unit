"""
The Control Unit's core: validates field messages, tracks device health,
creates alerts, dispatches them to RPF handhelds and records everything.

Alert lifecycle
    NEW ─(operator confirms, or auto for HIGH)─> DISPATCHED (to nearest unit, a chosen unit, or ALL)
    DISPATCHED ─(no ACK within ESCALATE_AFTER_S)─> DISPATCHED + ESCALATED (re-sent to ALL, siren restarts)
    DISPATCHED ─(officer)─> ACKNOWLEDGED ─> EN_ROUTE ─> ON_SCENE
    any open ─(operator "request backup")─> visible to ALL units as backup call
    ON_SCENE ─(handheld verification scan)─> CLEARED | CONFIRMED_THREAT
    any open ─(operator)─> DISMISSED
"""
import hashlib
import os
import threading
import time
from datetime import datetime

import cv2

from . import config, geo
from .db import now_iso

REQUIRED = ["device_id", "device_type", "run_id", "timestamp", "detection", "threat_level", "confidence"]
DEVICE_TYPES = {"DRONE", "HANDHELD"}
LEVELS = {"NONE", "NORMAL", "LOW", "MEDIUM", "HIGH"}
OPEN_STATUSES = ["NEW", "DISPATCHED", "ACKNOWLEDGED", "EN_ROUTE", "ON_SCENE"]
OFFICER_ACTIONS = {"ACK": "ACKNOWLEDGED", "EN_ROUTE": "EN_ROUTE", "ON_SCENE": "ON_SCENE"}
MESSAGE_PRIORITIES = {"INFO", "URGENT"}


def visible_to(a, device_id):
    """Should this alert show on this handheld?"""
    if a.get("status") in (None, "NEW"):
        return False
    if a.get("assigned_to") == device_id:
        return True
    if a.get("assigned_to") and not a.get("backup"):
        return False          # someone else has it and no backup was requested
    return a.get("dispatched_to") in (None, "", "ALL", device_id) or bool(a.get("backup"))


def _ts(iso):
    return datetime.fromisoformat(iso).timestamp()


class ValidationError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


class Hub:
    def __init__(self, store, bus, log=print):
        self.store = store
        self.bus = bus
        self.log = log
        self.lock = threading.RLock()
        self.drones = {}      # device_id -> telemetry dict + meta
        self.handhelds = {}   # device_id -> heartbeat dict + meta
        self.errors = []      # recent rejected packets (shown on dashboard)
        self.ledger = None    # set by the server: blockchain ledger for evidence hashes
        self.url_signer = None  # set by the server: capability URLs for evidence images
        os.makedirs(config.EVIDENCE_DIR, exist_ok=True)
        threading.Thread(target=self._health_loop, daemon=True, name="health").start()

    # ================================================================ runs
    def start_run(self, operator=None, notes=None):
        cur = self.store.active_run()
        if cur:
            raise ValidationError(f"run {cur['run_id']} is already active", 409)
        run = self.store.start_run(operator, notes)
        self.bus.publish("run", run)
        return run

    def end_run(self, run_id=None):
        cur = self.store.active_run()
        if not cur or (run_id and run_id != cur["run_id"]):
            raise ValidationError("no such active run", 404)
        self.close_open_alerts(cur["run_id"], "run ended: closed automatically")
        run = self.store.end_run(cur["run_id"])
        self.bus.publish("run", run)
        return run

    def close_open_alerts(self, run_id=None, note="closed"):
        """Close alerts still open at the end of a run (or left over from finished runs at start-up)."""
        active = self.store.active_run()
        n = 0
        for a in self.store.list_alerts(OPEN_STATUSES, 500):
            if run_id is not None and a["run_id"] != run_id:
                continue
            if run_id is None and active and a["run_id"] == active["run_id"]:
                continue        # at start-up, keep alerts of a run that is still active
            a = self.store.update_alert(a["alert_id"], "CLOSED", by="SYSTEM", note=note)
            self.bus.publish("alert", self._alert_view(a))
            n += 1
        return n

    def _refresh_run_status(self):
        run = self.store.active_run()
        if not run:
            return
        open_high = [a for a in self.store.list_alerts(OPEN_STATUSES, 200)
                     if a["run_id"] == run["run_id"] and a["threat_level"] == "HIGH"]
        status = "ALERT" if open_high else "ACTIVE"
        if status != run["status"]:
            self.store.set_run_status(run["run_id"], status)
            self.bus.publish("run", self.store.get_run(run["run_id"]))

    # ================================================================ validation
    def _reject(self, reason, payload, code=400):
        entry = {"t": now_iso(), "reason": reason, "device_id": (payload or {}).get("device_id")}
        self.errors = ([entry] + self.errors)[:50]
        self.bus.publish("packet_rejected", entry)
        self.log(f"[reject] {reason}")
        raise ValidationError(reason, code)

    def validate(self, msg, expect_type=None):
        if not isinstance(msg, dict):
            self._reject("body is not a JSON object", None)
        missing = [k for k in REQUIRED if msg.get(k) in (None, "")]
        if missing:
            self._reject(f"missing required field(s): {', '.join(missing)}", msg)
        if msg["device_type"] not in DEVICE_TYPES:
            self._reject(f"device_type must be one of {sorted(DEVICE_TYPES)}", msg)
        if expect_type and msg["device_type"] != expect_type:
            self._reject(f"device_type must be {expect_type} on this endpoint", msg)
        if str(msg["threat_level"]).upper() not in LEVELS:
            self._reject(f"threat_level must be one of {sorted(LEVELS)}", msg)
        try:
            c = float(msg["confidence"])
            if not 0 <= c <= 1:
                raise ValueError
        except (TypeError, ValueError):
            self._reject("confidence must be a number between 0 and 1", msg)
        try:
            datetime.fromisoformat(str(msg["timestamp"]).replace("Z", "+00:00"))
        except ValueError:
            self._reject("timestamp must be ISO-8601", msg)
        for k in ("latitude", "longitude"):
            if msg.get(k) is not None:
                try:
                    float(msg[k])
                except (TypeError, ValueError):
                    self._reject(f"{k} must be a number", msg)
        run = self.store.active_run()
        if not run:
            self._reject("no active inspection run", msg, 409)
        if msg["run_id"] != run["run_id"]:
            self._reject(f"run_id {msg['run_id']} is not the active run ({run['run_id']})", msg, 409)
        return run

    # ================================================================ handheld
    def ingest_handheld(self, msg):
        """POST /api/handheld/data  (protocol section 07 envelope)."""
        self.validate(msg, "HANDHELD")
        mid = msg.get("message_id")
        if mid and self.store.has_message(mid):
            return {"status": "duplicate", "message_id": mid}
        if not mid:
            mid = self.store.next_id("MSG", 5)
        level = str(msg["threat_level"]).upper()
        ev = {
            "message_id": mid, "run_id": msg["run_id"], "device_id": msg["device_id"],
            "device_type": "HANDHELD", "timestamp": msg["timestamp"], "detection": msg["detection"],
            "threat_level": level, "confidence": float(msg["confidence"]),
            "latitude": msg.get("latitude"), "longitude": msg.get("longitude"),
            "zone": msg.get("zone"), "battery": msg.get("battery"),
            "evidence_ref": msg.get("evidence_ref"), "alert_id": msg.get("alert_id"), "raw": str(msg),
        }
        self.store.add_event(ev)
        self._touch_handheld(msg)
        self.bus.publish("event", {k: v for k, v in ev.items() if k != "raw"})
        result = {"status": "accepted", "message_id": mid, "threat_level": level}

        if msg.get("alert_id"):
            # verification scan for a dispatched alert
            a = self.store.get_alert(msg["alert_id"])
            if a:
                new_status = "CONFIRMED_THREAT" if level == "HIGH" else "CLEARED"
                a = self.store.update_alert(
                    a["alert_id"], new_status, by=msg["device_id"],
                    note=f"handheld scan: {msg['detection']} ({float(msg['confidence']):.2f})",
                    resolution=f"{msg['detection']} / {level} / {float(msg['confidence']):.2f}",
                    assigned_to=a["assigned_to"] or msg["device_id"])
                self.bus.publish("alert", self._alert_view(a))
                result["alert"] = a["alert_id"]
                result["alert_status"] = new_status
        elif level == "HIGH":
            a = self._create_alert({
                "run_id": msg["run_id"], "source_device": msg["device_id"], "source_type": "HANDHELD",
                "detection": msg["detection"], "threat_level": "HIGH",
                "confidence": float(msg["confidence"]),
                "latitude": msg.get("latitude"), "longitude": msg.get("longitude"),
                "geo_method": "DEVICE_GPS" if msg.get("latitude") is not None else "NONE",
                "zone": msg.get("zone"), "evidence_ref": msg.get("evidence_ref"),
                "description": f"Handheld {msg['device_id']} reported {msg['detection']}",
            })
            result["alert"] = a["alert_id"]
        self._refresh_run_status()
        return result

    def handheld_heartbeat(self, hb):
        if not hb.get("device_id"):
            raise ValidationError("device_id required")
        self._touch_handheld(hb)
        pending = [self._alert_view(a) for a in self.store.list_alerts(
            ["DISPATCHED", "ACKNOWLEDGED", "EN_ROUTE", "ON_SCENE"], 20)
            if visible_to(a, hb["device_id"])]
        msgs = [m for m in self.store.list_messages(20)
                if m["target"] in ("ALL", hb["device_id"]) and hb["device_id"] not in m["acks"]
                and time.time() - _ts(m["created_at"]) < 1800]
        run = self.store.active_run()
        return {"run_id": run["run_id"] if run else None, "alerts": pending, "messages": msgs,
                "server_time": now_iso()}

    def _touch_handheld(self, m):
        with self.lock:
            h = self.handhelds.setdefault(m["device_id"], {"device_id": m["device_id"]})
            for k in ("officer", "latitude", "longitude", "battery", "accuracy"):
                if m.get(k) is not None:
                    h[k] = m[k]
            was_online = h.get("online")
            h["last_seen"] = time.time()
            h["online"] = True
        if not was_online:
            self.bus.publish("handheld", self._hh_view(h))
        elif m.get("latitude") is not None:
            self.bus.publish("handheld", self._hh_view(h))

    def _hh_view(self, h):
        v = dict(h)
        v["age_s"] = round(time.time() - h.get("last_seen", 0), 1)
        return v

    def officer_action(self, alert_id, device_id, action, note=None):
        a = self.store.get_alert(alert_id)
        if not a:
            raise ValidationError("unknown alert", 404)
        if action == "BACKUP":
            # another officer answering a backup call; the alert stays with its owner
            if not a["backup"]:
                raise ValidationError("no backup was requested for this alert", 409)
            a = self.store.update_alert(alert_id, None, by=device_id, note="responding as backup")
            self.bus.publish("alert", self._alert_view(a))
            return a
        status = OFFICER_ACTIONS.get(action)
        if not status:
            raise ValidationError(f"action must be one of {sorted(OFFICER_ACTIONS) + ['BACKUP']}")
        if a["status"] not in OPEN_STATUSES or a["status"] == "NEW":
            raise ValidationError(f"alert is {a['status']}", 409)
        if a["assigned_to"] and a["assigned_to"] != device_id:
            raise ValidationError(f"alert already taken by {a['assigned_to']}", 409)
        a = self.store.update_alert(alert_id, status, by=device_id, note=note, assigned_to=device_id)
        self.bus.publish("alert", self._alert_view(a))
        return a

    # ================================================================ drone
    def ingest_telemetry(self, t):
        """POST /api/drone/telemetry — expected at 2 Hz as the drone heartbeat."""
        if not t.get("device_id"):
            raise ValidationError("device_id required")
        with self.lock:
            d = self.drones.setdefault(t["device_id"], {"device_id": t["device_id"], "lost_packets": 0,
                                                         "received": 0})
            seq = t.get("seq")
            if seq is not None and d.get("seq") is not None and seq > d["seq"] + 1:
                d["lost_packets"] += seq - d["seq"] - 1
            if seq is not None:
                d["seq"] = seq
            for k in ("latitude", "longitude", "alt_agl", "heading", "gimbal_pitch", "speed",
                      "battery", "mode", "zone"):
                if t.get(k) is not None:
                    d[k] = t[k]
            d["received"] += 1
            d["last_seen"] = time.time()
            d["link"] = "OK"
            low = d.get("battery") is not None and d["battery"] <= config.LOW_BATTERY_PCT
        if low and not d.get("low_batt_warned"):
            d["low_batt_warned"] = True
            self.bus.publish("warning", {"device_id": d["device_id"], "text": f"Low battery {d['battery']}%"})
        self.bus.publish("telemetry", self._drone_view(d))
        return {"status": "ok"}

    def _drone_view(self, d):
        v = dict(d)
        v["age_s"] = round(time.time() - d.get("last_seen", 0), 2)
        return v

    def drone_state(self, device_id):
        with self.lock:
            d = self.drones.get(device_id)
            return dict(d) if d else None

    def new_evidence_ref(self, rule):
        return f"{self.store.next_id('MSG', 5)}_{rule.lower()}"

    def raise_ai_alert(self, finding, frame_annot, frame_raw, geo_result, drone, cam=None, ev_ref=None,
                       clip_ref=None):
        """Called by the video pipeline when a rule fires."""
        run = self.store.active_run()
        if not run:
            return None
        cam = cam or {}
        tr = finding["track"]
        ev_ref = ev_ref or self.new_evidence_ref(finding["rule"])
        mid = ev_ref.split("_")[0] + "_" + ev_ref.split("_")[1]
        path = os.path.join(config.EVIDENCE_DIR, ev_ref + ".jpg")
        cv2.imwrite(path, frame_annot, [cv2.IMWRITE_JPEG_QUALITY, 90])
        # keep the untouched frame too; the hash covers the raw frame
        raw_path = os.path.join(config.EVIDENCE_DIR, ev_ref + "_raw.jpg")
        cv2.imwrite(raw_path, frame_raw, [cv2.IMWRITE_JPEG_QUALITY, 95])
        with open(raw_path, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        if self.ledger:
            self.ledger.add_file("EVIDENCE", ev_ref + ".jpg", path)
            self.ledger.add_file("EVIDENCE_RAW", ev_ref + "_raw.jpg", raw_path)

        if geo_result:
            lat, lon, rng = geo_result
            method = "PROJECTED"
        elif cam.get("lat") is not None:
            lat, lon, rng = cam["lat"], cam["lon"], None
            method = "CAMERA_POSITION"
        elif drone and drone.get("latitude") is not None:
            lat, lon, rng = float(drone["latitude"]), float(drone["longitude"]), None
            method = "DRONE_POSITION"
        else:
            lat = lon = rng = None
            method = "NONE"
        zone = (drone or {}).get("zone") or tr.state.get("in_zone") or config.DEFAULT_ZONE
        drone_id = (drone or {}).get("device_id") or cam.get("id") or config.VIDEO_DRONE_ID

        self.store.add_event({
            "message_id": mid, "run_id": run["run_id"], "device_id": drone_id, "device_type": "DRONE",
            "timestamp": now_iso(), "detection": finding["rule"], "threat_level": finding["threat_level"],
            "confidence": round(float(finding["confidence"]), 3), "latitude": lat, "longitude": lon,
            "zone": zone, "battery": (drone or {}).get("battery"), "evidence_ref": ev_ref + ".jpg",
        })
        a = self._create_alert({
            "run_id": run["run_id"], "source_device": drone_id, "source_type": "DRONE_AI",
            "detection": finding["rule"], "threat_level": finding["threat_level"],
            "confidence": round(float(finding["confidence"]), 3), "latitude": lat, "longitude": lon,
            "geo_method": method, "zone": zone, "evidence_ref": ev_ref + ".jpg", "evidence_sha256": sha,
            "description": finding["description"] + (f" · ~{rng:.0f} m from drone" if rng else ""),
            "camera": cam.get("name"), "clip_ref": clip_ref,
        })
        self._refresh_run_status()
        return a

    # ================================================================ alerts
    def _create_alert(self, a):
        a = self.store.create_alert(a)
        self.log(f"[alert] {a['alert_id']} {a['threat_level']} {a['detection']} @ {a['latitude']},{a['longitude']}")
        self.bus.publish("alert", self._alert_view(a))
        if a["threat_level"] in config.AUTO_DISPATCH_LEVELS:
            a = self.dispatch(a["alert_id"], by="AUTO", note="auto-dispatch")
        return a

    def dispatch(self, alert_id, by="OPERATOR", note=None, target=None):
        """
        target None   -> DISPATCH_MODE policy (nearest unit with GPS, else ALL)
        target "ALL"  -> every handheld
        target "HAND_02" -> that unit only
        Works on NEW alerts, and re-directs DISPATCHED alerts nobody has taken yet.
        """
        a = self.store.get_alert(alert_id)
        if not a:
            raise ValidationError("unknown alert", 404)
        if a["status"] not in ("NEW", "DISPATCHED"):
            raise ValidationError(f"alert is already {a['status']} ({a['assigned_to']})", 409)
        near = self.nearest_handhelds(a)
        if target in (None, ""):
            if config.DISPATCH_MODE == "nearest" and near:
                target = near[0]["device_id"]
            else:
                target = "ALL"
        elif target != "ALL":
            with self.lock:
                if target not in self.handhelds:
                    raise ValidationError(f"unknown handheld {target}", 404)
        dist = next((n["distance_m"] for n in near if n["device_id"] == target), None)
        who = "ALL UNITS" if target == "ALL" else target + (f" ({dist:.0f} m)" if dist is not None else "")
        verb = "re-directed to" if a["status"] == "DISPATCHED" else "dispatched to"
        a = self.store.update_alert(alert_id, "DISPATCHED", by=by, note=f"{note + ': ' if note else ''}{verb} {who}",
                                    dispatched_to=target)
        view = self._alert_view(a)
        view["nearest"] = near[:3]
        self.bus.publish("alert", view)
        self.bus.publish("dispatch", view)
        self._refresh_run_status()
        return a

    def request_backup(self, alert_id, by="OPERATOR", note=None):
        a = self.store.get_alert(alert_id)
        if not a:
            raise ValidationError("unknown alert", 404)
        if a["status"] not in OPEN_STATUSES or a["status"] == "NEW":
            raise ValidationError(f"alert is {a['status']}; dispatch it first", 409)
        a = self.store.update_alert(alert_id, None, by=by, note=note or "BACKUP REQUESTED: all units", backup=1)
        view = self._alert_view(a)
        self.bus.publish("alert", view)
        self.bus.publish("dispatch", dict(view, backup_call=True))
        return a

    def dismiss(self, alert_id, by="OPERATOR", note=None):
        a = self.store.get_alert(alert_id)
        if not a:
            raise ValidationError("unknown alert", 404)
        if a["status"] not in OPEN_STATUSES:
            raise ValidationError(f"alert is {a['status']}", 409)
        a = self.store.update_alert(alert_id, "DISMISSED", by=by, note=note or "false positive")
        self.bus.publish("alert", self._alert_view(a))
        self._refresh_run_status()
        return a

    def operator_alert(self, body, snapshot_jpeg=None, cam=None):
        """An alert raised by the operator (e.g. spotted on CCTV) and sent straight to handhelds."""
        run = self.store.active_run()
        if not run:
            raise ValidationError("start an inspection run first", 409)
        level = str(body.get("threat_level", "HIGH")).upper()
        if level not in ("LOW", "MEDIUM", "HIGH"):
            raise ValidationError("threat_level must be LOW, MEDIUM or HIGH")
        det = (body.get("detection") or "OPERATOR_ALERT").upper().replace(" ", "_")[:40]
        lat, lon, method = body.get("latitude"), body.get("longitude"), "OPERATOR"
        if lat in (None, "") and body.get("use_drone_position", True):
            d = next(iter(self.drones.values()), None)
            if d and d.get("latitude") is not None:
                lat, lon, method = d["latitude"], d["longitude"], "DRONE_POSITION"
        if lat in (None, "") and cam and cam.get("lat") is not None:
            lat, lon, method = cam["lat"], cam["lon"], "CAMERA_POSITION"
        if lat in (None, ""):
            lat = lon = None
            method = "NONE"
        ev = None
        sha = None
        if snapshot_jpeg:
            ev = self.new_evidence_ref("operator") + ".jpg"
            with open(os.path.join(config.EVIDENCE_DIR, ev), "wb") as f:
                f.write(snapshot_jpeg)
            sha = hashlib.sha256(snapshot_jpeg).hexdigest()
            if self.ledger:
                self.ledger.add_file("EVIDENCE", ev, os.path.join(config.EVIDENCE_DIR, ev))
        a = self.store.create_alert({
            "run_id": run["run_id"], "source_device": "CONTROL_UNIT", "source_type": "OPERATOR",
            "detection": det, "threat_level": level, "confidence": 1.0,
            "latitude": float(lat) if lat is not None else None,
            "longitude": float(lon) if lon is not None else None, "geo_method": method,
            "zone": body.get("zone") or config.DEFAULT_ZONE, "evidence_ref": ev, "evidence_sha256": sha,
            "description": body.get("note") or "Raised by Control Unit operator", "camera": (cam or {}).get("name"),
        })
        self.bus.publish("alert", self._alert_view(a))
        a = self.dispatch(a["alert_id"], by="OPERATOR", target=body.get("target") or None)
        return a

    # ================================================================ operator messages
    def send_message(self, text, target="ALL", priority="INFO", by="OPERATOR"):
        text = (text or "").strip()
        if not text:
            raise ValidationError("message text is empty")
        priority = (priority or "INFO").upper()
        if priority not in MESSAGE_PRIORITIES:
            raise ValidationError(f"priority must be one of {sorted(MESSAGE_PRIORITIES)}")
        target = target or "ALL"
        m = self.store.add_message(by, target, priority, text[:280])
        self.bus.publish("message", m)
        return m

    def ack_message(self, msg_id, device_id):
        m = self.store.ack_message(msg_id, device_id)
        if not m:
            raise ValidationError("unknown message", 404)
        self.bus.publish("message_ack", {"msg_id": msg_id, "device_id": device_id, "acks": m["acks"]})
        return m

    def nearest_handhelds(self, a):
        if a.get("latitude") is None:
            return []
        out = []
        with self.lock:
            for h in self.handhelds.values():
                if h.get("online") and h.get("latitude") is not None:
                    out.append({"device_id": h["device_id"], "officer": h.get("officer"),
                                "distance_m": geo.distance_m(h["latitude"], h["longitude"],
                                                             a["latitude"], a["longitude"])})
        return sorted(out, key=lambda x: x["distance_m"])

    def _alert_view(self, a):
        v = dict(a)
        v["backup"] = bool(a.get("backup"))
        v["escalations"] = a.get("escalations") or 0
        if a.get("clip_ref"):
            v["clip_url"] = f"/api/clips/{a['clip_ref']}"
        if a.get("evidence_ref"):
            p = f"/evidence/{a['evidence_ref']}"
            v["evidence_url"] = self.url_signer(p) if self.url_signer else p
        if a.get("latitude") is not None:
            v["maps_url"] = f"https://www.google.com/maps/search/?api=1&query={a['latitude']:.6f},{a['longitude']:.6f}"
        return v

    def alerts(self, open_only=False):
        rows = self.store.list_alerts(OPEN_STATUSES if open_only else None, 100)
        return [self._alert_view(a) for a in rows]

    # ================================================================ health
    def snapshot(self):
        with self.lock:
            drones = [self._drone_view(d) for d in self.drones.values()]
            hh = [self._hh_view(h) for h in self.handhelds.values()]
        return {"run": self.store.active_run(), "drones": drones, "handhelds": hh,
                "errors": self.errors[:10], "server_time": now_iso()}

    def _health_loop(self):
        while True:
            time.sleep(1.0)
            now = time.time()
            with self.lock:
                for d in self.drones.values():
                    age = now - d.get("last_seen", 0)
                    link = "OK" if age < config.LINK_DEGRADED_S else (
                        "DEGRADED" if age < config.LINK_LOST_S else "LOST")
                    if link != d.get("link"):
                        d["link"] = link
                        self.bus.publish("telemetry", self._drone_view(d))
                        if link == "LOST":
                            self.bus.publish("warning", {"device_id": d["device_id"], "text": "Drone link lost"})
                for h in self.handhelds.values():
                    online = now - h.get("last_seen", 0) < config.HANDHELD_OFFLINE_S
                    if online != h.get("online"):
                        h["online"] = online
                        self.bus.publish("handheld", self._hh_view(h))
            try:
                self._escalate(now)
            except Exception as e:
                self.log(f"[escalation] {e}")

    def _escalate(self, now):
        """Dispatched but nobody acknowledged in time -> send to all units, raise the alarm again."""
        for a in self.store.list_alerts(["DISPATCHED"], 50):
            if (a.get("escalations") or 0) >= config.MAX_ESCALATIONS:
                continue
            if now - _ts(a["updated_at"]) < config.ESCALATE_AFTER_S:
                continue
            n = (a.get("escalations") or 0) + 1
            a = self.store.update_alert(
                a["alert_id"], "DISPATCHED", by="AUTO",
                note=f"ESCALATED #{n}: no unit responded in {config.ESCALATE_AFTER_S:.0f}s, sent to ALL UNITS",
                dispatched_to="ALL", escalations=n)
            view = self._alert_view(a)
            self.log(f"[escalation] {a['alert_id']} #{n}")
            self.bus.publish("alert", view)
            self.bus.publish("dispatch", dict(view, escalated=True))
