"""
REVELATION Control Unit — Flask server.

Run:   python -m control_unit.server --video 0
Then:  operator dashboard   http://<control-unit-ip>:5000/dashboard   (log in)
       RPF handheld page    http://<control-unit-ip>:5000/handheld    (pair with a code from the dashboard)

Cameras:
  --video SOURCE                         the drone camera (linked to drone telemetry for GPS)
  --cam "NAME|SOURCE"                    an extra fixed CCTV camera (repeatable)
  --cam "NAME|SOURCE|LAT,LON"            ... with its installed position

Security (see security.py, ledger.py, anchor.py):
  operators log in (roles VIEWER / OPERATOR / SUPERVISOR); field devices sign every message
  (HMAC-SHA256 + timestamp + nonce); every audit entry and evidence file is sealed into a
  signed blockchain ledger whose head is anchored to Bitcoin (OpenTimestamps) / Polygon.

Endpoints from the protocol document are kept:
  POST /api/run/start   POST /api/handheld/data   POST /api/run/end   GET /dashboard
"""
import argparse
import functools
import json
import os
import shutil
import sys as _sys
import time

from flask import (Flask, Response, abort, g, jsonify, redirect, render_template, request, send_from_directory,
                   session)

from . import config
from .bus import Bus
from .db import Store
from .hub import Hub, ValidationError, visible_to
from .telemetry import start_mavlink_bridge

if "--db" in _sys.argv:
    config.DB_PATH = os.path.abspath(_sys.argv[_sys.argv.index("--db") + 1])

DATA_DIR = os.path.dirname(os.path.abspath(config.DB_PATH))

from .anchor import Anchorer  # noqa: E402
from .ledger import Ledger  # noqa: E402
from .security import ROLES, Security  # noqa: E402

app = Flask(__name__)
store = Store(config.DB_PATH)
bus = Bus()
hub = Hub(store, bus, log=lambda s: print(s, flush=True))
sec = Security(DATA_DIR, log=lambda s: print(s, flush=True))
ledger = Ledger(store, os.path.join(DATA_DIR, "keys"), log=lambda s: print(s, flush=True))
anchorer = Anchorer(ledger, log=lambda s: print(s, flush=True))
hub.ledger = ledger
hub.url_signer = sec.signed_url
_n = hub.close_open_alerts(None, "left open by a finished run: closed at start-up")
if _n:
    print(f"  closed {_n} alert(s) left open by earlier runs", flush=True)
pipelines = {}          # cam_id -> VideoPipeline (ordered: first is the main/drone camera)

app.secret_key = sec.flask_secret
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=2 * 1024 * 1024)


def _sec_event(e):
    store.audit("SECURITY", e["kind"], e)
    bus.publish("security", e)


sec.on_event = _sec_event
ledger.on_block = lambda b: bus.publish("ledger", ledger.status())
anchorer.on_change = lambda: bus.publish("ledger", ledger.status())


# ------------------------------------------------------------------ helpers
@app.errorhandler(ValidationError)
def _verr(e):
    return jsonify({"status": "rejected", "error": str(e)}), e.code


@app.after_request
def _headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Permissions-Policy"] = "camera=(), microphone=()"
    if request.path.startswith("/api/") and "Cache-Control" not in r.headers:
        r.headers["Cache-Control"] = "no-store"
    return r


def _json():
    body = request.get_json(silent=True)
    if body is None:
        hub._reject("invalid JSON body", None)     # raises; malformed JSON is rejected + logged (COM-05)
    return body


def _ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


def user():
    if not config.REQUIRE_LOGIN:
        return {"username": "local", "name": "Operator", "role": "SUPERVISOR"}
    return session.get("user")


def need(role):
    """Operator endpoints: logged-in user with at least this role."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            u = user()
            if not u:
                return jsonify({"error": "login required"}), 401
            if ROLES[u["role"]] < ROLES[role]:
                sec.event("warn", "FORBIDDEN", f"{u['username']} ({u['role']}) tried {request.method} {request.path}",
                          ip=_ip())
                return jsonify({"error": f"{role.lower()} role required"}), 403
            g.user = u
            return fn(*a, **kw)
        return wrapper
    return deco


def device(fn):
    """Field-device endpoints: request must be signed by a provisioned device."""
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        ok, dev, why = sec.verify(request.method, request.path, request.get_data(), request.headers, _ip())
        if not ok:
            return jsonify({"status": "rejected", "error": f"security: {why}"}), 401
        body = request.get_json(silent=True) or {}
        claimed = body.get("device_id") or request.args.get("device_id")
        if sec.mode == "enforce" and claimed and dev and claimed != dev:
            sec.event("bad", "IMPERSONATION", f"{dev} signed a message claiming to be {claimed}", dev, _ip())
            return jsonify({"status": "rejected", "error": "security: device_id does not match signing device"}), 401
        g.device = dev
        return fn(*a, **kw)
    return wrapper


def by():
    u = getattr(g, "user", None) or user() or {}
    return u.get("name") or u.get("username") or "OPERATOR"


def _cam(cam_id=None):
    if not pipelines:
        return None
    if cam_id and cam_id in pipelines:
        return pipelines[cam_id]
    return next(iter(pipelines.values()))


# ------------------------------------------------------------------ pages + auth
@app.get("/")
def index():
    return redirect("/dashboard")


@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.get("/handheld")
def handheld_page():
    return render_template("handheld.html")


@app.post("/api/login")
def login():
    if not sec.allow("login", _ip(), 10):
        return jsonify({"error": "too many attempts, wait a minute"}), 429
    b = request.get_json(silent=True) or {}
    u, err = sec.login(b.get("username"), b.get("password"), _ip())
    if not u:
        time.sleep(0.5)
        return jsonify({"error": err}), 401
    session.clear()
    session["user"] = u
    return jsonify(u)


@app.post("/api/logout")
def logout():
    u = session.pop("user", None)
    if u:
        sec.event("info", "LOGOUT", f"{u['username']} signed out", ip=_ip())
    return jsonify({"status": "ok"})


@app.get("/api/me")
def me():
    return jsonify({"user": user(), "require_login": config.REQUIRE_LOGIN})


@app.get("/evidence/<path:name>")
def evidence(name):
    # dashboards (logged in) or a capability link handed to a handheld with its alert
    if not user() and not sec.check_url(request.path, request.args.get("exp"), request.args.get("tok")):
        abort(403)
    return send_from_directory(config.EVIDENCE_DIR, name)


@app.get("/video_feed")
@app.get("/video_feed/<cam_id>")
@need("VIEWER")
def video_feed(cam_id=None):
    p = _cam(cam_id)
    if p is None:
        abort(404)

    def gen():
        for jpg in p.frames():
            yield b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: " + str(len(jpg)).encode() + \
                  b"\r\n\r\n" + jpg + b"\r\n"
    return Response(gen(), mimetype="multipart/x-mixed-replace; boundary=frame")


@app.get("/snapshot.jpg")
@app.get("/snapshot/<cam_id>.jpg")
@need("VIEWER")
def snapshot(cam_id=None):
    p = _cam(cam_id)
    if p is None or p.jpeg is None:
        abort(404)
    return Response(p.jpeg, mimetype="image/jpeg")


@app.get("/api/clips/<ref>")
@need("VIEWER")
def clip(ref):
    """Evidence clip = numbered JPEG frames around the alert; the dashboard plays them."""
    d = os.path.join(config.EVIDENCE_DIR, "clips", os.path.basename(ref))
    if not os.path.isdir(d):
        abort(404)
    frames = sorted(f for f in os.listdir(d) if f.endswith(".jpg"))
    meta = {}
    if os.path.exists(os.path.join(d, "meta.txt")):
        for line in open(os.path.join(d, "meta.txt")):
            if "=" in line:
                k, v = line.strip().split("=", 1)
                meta[k] = v
    return jsonify({"ref": ref, "fps": int(meta.get("fps", config.CLIP_FPS)),
                    "alert_frame": int(meta.get("alert_frame", 0)), "camera": meta.get("camera"),
                    "frames": [f"/evidence/clips/{ref}/{f}" for f in frames]})


# ------------------------------------------------------------------ live events (SSE)
@app.get("/api/stream")
def stream():
    role = request.args.get("role", "dashboard")
    device_id = request.args.get("device_id")
    if role == "handheld":
        # EventSource cannot send headers, so the handheld signs the URL instead
        ok, dev, why = sec.verify("GET", "/api/stream", b"", {}, _ip(), query=request.args)
        if not ok:
            return jsonify({"error": f"security: {why}"}), 401
        device_id = dev or device_id

        def flt(m):
            t, d = m["type"], m["data"]
            if t == "run":
                return True
            if t == "dispatch":
                return visible_to(d, device_id)          # only units the alert was sent to
            if t == "alert":
                return d.get("status") != "NEW"          # status changes (taken, closed, cancelled)
            if t == "message":
                return d["target"] in ("ALL", device_id)
            return False
    else:
        if not user():
            return jsonify({"error": "login required"}), 401
        flt = None
    q = bus.subscribe(flt)

    def gen():
        try:
            yield "retry: 2000\n\n"
            yield bus.sse({"type": "hello", "data": {"role": role, "device_id": device_id}})
            last = time.time()
            while True:
                try:
                    msg = q.get(timeout=10)
                    yield bus.sse(msg)
                except Exception:
                    pass
                if time.time() - last > 10:
                    last = time.time()
                    yield ": keepalive\n\n"
        finally:
            bus.unsubscribe(q)
    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ------------------------------------------------------------------ runs (protocol §06)
@app.post("/api/run/start")
@need("OPERATOR")
def run_start():
    body = request.get_json(silent=True) or {}
    run = hub.start_run(by(), body.get("notes"))
    return jsonify({"status": "ACTIVE", "run_id": run["run_id"], "run": run})


@app.post("/api/run/end")
@need("OPERATOR")
def run_end():
    body = request.get_json(silent=True) or {}
    run = hub.end_run(body.get("run_id"))
    ledger.seal()
    try:
        anchorer.anchor_now()            # publish the run's final ledger state (queued if offline)
    except Exception as e:
        print(f"[anchor] {e}", flush=True)
    return jsonify({"status": "COMPLETED", "run_id": run["run_id"], "run": run})


@app.get("/api/time")
def api_time():
    """Clock for devices without NTP/internet (ESP32) so their signed timestamps are valid."""
    return jsonify({"epoch": int(time.time())})


@app.get("/api/run/current")
def run_current():
    # handhelds and devices poll this too; it reveals nothing sensitive
    return jsonify({"run": store.active_run()})


@app.get("/api/runs")
@need("VIEWER")
def runs():
    return jsonify(store.list_runs())


def _run_id(run_id):
    if run_id == "latest":
        r = store.list_runs(1)
        if not r:
            abort(404)
        return r[0]["run_id"]
    return run_id


@app.get("/api/runs/<run_id>/report")
@need("VIEWER")
def run_report(run_id):
    """Printable run log (open in the browser, Ctrl+P to save as PDF)."""
    from .report import build_html, collect
    d = collect(store, _run_id(run_id), ledger)
    if d is None:
        abort(404)
    return Response(build_html(d, evidence_prefix="/evidence/"), mimetype="text/html")


@app.get("/api/runs/<run_id>/export")
@need("VIEWER")
def run_export(run_id):
    """ZIP with the report, CSV logs, audit chain, ledger slice + proofs and evidence frames of one run."""
    from .report import build_zip
    rid = _run_id(run_id)
    ledger.seal()
    data = build_zip(store, rid, include_clips=request.args.get("clips") == "1", ledger=ledger)
    if data is None:
        abort(404)
    sec.event("info", "EXPORT", f"run {rid} exported by {by()}", ip=_ip())
    return Response(data, mimetype="application/zip",
                    headers={"Content-Disposition": f"attachment; filename={rid}_log.zip"})


# ------------------------------------------------------------------ field devices (signed)
@app.post("/api/pair")
def pair():
    """A handheld exchanges a one-time pairing code (shown on the dashboard) for its device secret."""
    if not sec.allow("pair", _ip(), 10):
        return jsonify({"error": "too many attempts, wait a minute"}), 429
    b = request.get_json(silent=True) or {}
    secret = sec.pair(b.get("device_id"), str(b.get("code", "")).strip(), _ip())
    if not secret:
        time.sleep(0.5)
        return jsonify({"error": "wrong or expired pairing code"}), 401
    return jsonify({"device_id": b["device_id"].strip().upper(), "secret": secret, "mode": sec.mode})


@app.post("/api/handheld/data")
@device
def handheld_data():
    return jsonify(hub.ingest_handheld(_json()))


@app.post("/api/handheld/heartbeat")
@device
def handheld_heartbeat():
    return jsonify(hub.handheld_heartbeat(_json()))


@app.get("/api/handheld/alerts")
@device
def handheld_alerts():
    """Polling fallback for devices without SSE (ESP32)."""
    hb = {"device_id": g.device or request.args.get("device_id", "")}
    for k in ("latitude", "longitude", "battery"):
        if request.args.get(k):
            hb[k] = float(request.args[k])
    return jsonify(hub.handheld_heartbeat(hb))


@app.post("/api/alerts/<alert_id>/officer")
@device
def officer_action(alert_id):
    b = _json()
    a = hub.officer_action(alert_id, b.get("device_id"), b.get("action"), b.get("note"))
    return jsonify(hub._alert_view(a))


@app.post("/api/messages/<msg_id>/ack")
@device
def message_ack(msg_id):
    b = _json()
    return jsonify(hub.ack_message(msg_id, b.get("device_id")))


@app.post("/api/drone/telemetry")
@device
def drone_telemetry():
    return jsonify(hub.ingest_telemetry(_json()))


# ------------------------------------------------------------------ operator
@app.get("/api/state")
@need("VIEWER")
def state():
    s = hub.snapshot()
    s["cameras"] = [p.status for p in pipelines.values()]
    s["video"] = s["cameras"][0] if s["cameras"] else {"video": "DISABLED"}
    s["zones"] = store.list_zones()
    s["messages"] = store.list_messages(20)
    s["user"] = user()
    s["ledger"] = ledger.status()
    s["security_mode"] = sec.mode
    s["config"] = {"auto_dispatch": sorted(config.AUTO_DISPATCH_LEVELS), "dispatch_mode": config.DISPATCH_MODE,
                   "escalate_after_s": config.ESCALATE_AFTER_S,
                   "abandon_s": config.ABANDON_SECONDS, "loiter_s": config.LOITER_SECONDS}
    return jsonify(s)


@app.get("/api/alerts")
@need("VIEWER")
def alerts():
    return jsonify(hub.alerts(open_only=request.args.get("open") == "1"))


@app.get("/api/alerts/<alert_id>")
@need("VIEWER")
def alert(alert_id):
    a = store.get_alert(alert_id)
    if not a:
        abort(404)
    return jsonify(hub._alert_view(a))


@app.post("/api/alerts/<alert_id>/dispatch")
@need("OPERATOR")
def alert_dispatch(alert_id):
    """body: {"target": null | "ALL" | "HAND_02", "note": "..."}"""
    b = request.get_json(silent=True) or {}
    return jsonify(hub._alert_view(hub.dispatch(alert_id, by(), b.get("note"), b.get("target"))))


@app.post("/api/alerts/<alert_id>/backup")
@need("OPERATOR")
def alert_backup(alert_id):
    b = request.get_json(silent=True) or {}
    return jsonify(hub._alert_view(hub.request_backup(alert_id, by(), b.get("note"))))


@app.post("/api/alerts/<alert_id>/dismiss")
@need("OPERATOR")
def alert_dismiss(alert_id):
    b = request.get_json(silent=True) or {}
    return jsonify(hub._alert_view(hub.dismiss(alert_id, by(), b.get("note"))))


@app.post("/api/operator/alert")
@need("OPERATOR")
def operator_alert():
    b = _json()
    p = _cam(b.get("cam_id"))
    snap = p.jpeg if (p is not None and b.get("attach_snapshot", True)) else None
    b["note"] = b.get("note") or ""
    a = hub.operator_alert(b, snap, p.cam if p else None)
    return jsonify(hub._alert_view(a))


@app.post("/api/operator/message")
@need("OPERATOR")
def operator_message():
    b = _json()
    return jsonify(hub.send_message(b.get("text"), b.get("target") or "ALL", b.get("priority") or "INFO", by=by()))


@app.get("/api/messages")
@need("VIEWER")
def messages():
    return jsonify(store.list_messages(50))


@app.get("/api/events")
@need("VIEWER")
def events():
    return jsonify(store.list_events(request.args.get("run_id"), int(request.args.get("limit", 100))))


@app.get("/api/cameras")
@need("VIEWER")
def cameras():
    return jsonify([p.status for p in pipelines.values()])


@app.get("/api/zones")
@need("VIEWER")
def zones():
    return jsonify(store.list_zones(request.args.get("cam_id")))


@app.post("/api/zones")
@need("OPERATOR")
def zone_add():
    b = _json()
    poly = b.get("polygon") or []
    if len(poly) < 3 or not all(0 <= x <= 1 and 0 <= y <= 1 for x, y in poly):
        raise ValidationError("polygon needs >= 3 points in normalised 0..1 image coordinates")
    p = _cam(b.get("cam_id"))
    cam_id = p.cam["id"] if p else b.get("cam_id")
    zid = store.save_zone(b.get("name") or "RESTRICTED", poly, cam_id=cam_id)
    if p:
        p.set_zones(store.list_zones(cam_id))
    return jsonify({"zone_id": zid, "cam_id": cam_id})


@app.delete("/api/zones")
@need("OPERATOR")
def zone_clear():
    cam_id = request.args.get("cam_id")
    store.delete_zones(cam_id)
    for p in pipelines.values():
        p.set_zones(store.list_zones(p.cam["id"]))
    return jsonify({"status": "cleared"})


@app.get("/api/audit/verify")
@need("VIEWER")
def audit_verify():
    return jsonify(store.verify_audit())


# ------------------------------------------------------------------ security centre + ledger
@app.get("/api/security")
@need("VIEWER")
def security_summary():
    s = sec.summary()
    s["ledger"] = ledger.status()
    s["anchors"] = ledger.anchors(20)
    s["anchor_backends"] = anchorer.backends
    s["internet"] = anchorer.state
    s["me"] = user()
    return jsonify(s)


@app.post("/api/security/mode")
@need("SUPERVISOR")
def security_mode():
    m = (request.get_json(silent=True) or {}).get("mode", "").lower()
    if m not in ("enforce", "monitor", "off"):
        raise ValidationError("mode must be enforce, monitor or off")
    sec.mode = m
    sec.event("warn" if m != "enforce" else "info", "SECURITY_MODE", f"device security set to {m.upper()} by {by()}")
    return jsonify({"mode": m})


@app.post("/api/security/pair-code")
@need("OPERATOR")
def security_pair_code():
    dev = ((request.get_json(silent=True) or {}).get("device_id") or "").strip().upper()
    if not dev:
        raise ValidationError("device_id required")
    return jsonify({"device_id": dev, "code": sec.new_pair_code(dev, by()), "valid_s": 300})


@app.post("/api/security/provision")
@need("SUPERVISOR")
def security_provision():
    """For ESP32 / drone companion computers: returns a device secret to flash into the firmware."""
    b = request.get_json(silent=True) or {}
    dev = (b.get("device_id") or "").strip().upper()
    if not dev:
        raise ValidationError("device_id required")
    return jsonify({"device_id": dev, "secret": sec.provision(dev, b.get("type", "HANDHELD"), by=by())})


@app.post("/api/security/revoke")
@need("SUPERVISOR")
def security_revoke():
    dev = ((request.get_json(silent=True) or {}).get("device_id") or "").strip().upper()
    if not sec.revoke(dev, by()):
        raise ValidationError("unknown device", 404)
    return jsonify({"status": "revoked", "device_id": dev})


@app.get("/api/ledger/verify")
@need("VIEWER")
def ledger_verify():
    ledger.seal()
    v = ledger.verify()
    v["audit"] = store.verify_audit()
    sec.event("info" if v["ok"] and v["audit"]["ok"] else "bad", "LEDGER_VERIFY",
              f"ledger {'INTACT' if v['ok'] else 'PROBLEMS: ' + '; '.join(v['problems'][:3])}; "
              f"{v['evidence_ok']}/{v['evidence_checked']} evidence files match; audit "
              f"{'intact' if v['audit']['ok'] else 'BROKEN'} (by {by()})")
    return jsonify(v)


@app.post("/api/ledger/anchor")
@need("OPERATOR")
def ledger_anchor():
    return jsonify({"results": anchorer.anchor_now(), "status": ledger.status(), "anchors": ledger.anchors(10)})


@app.get("/api/ledger/proof/<path:ref>")
@need("VIEWER")
def ledger_proof(ref):
    return jsonify({"public_key_ed25519": ledger.pub_hex, "entries": ledger.find(ref)})


@app.get("/api/ledger/blocks")
@need("VIEWER")
def ledger_blocks():
    n = int(request.args.get("n", 15))
    h = ledger.height() or 0
    out = []
    for i in range(h, max(-1, h - n), -1):
        b = ledger.block(i)
        if b:
            b["types"] = {}
            for r in b["records"]:
                b["types"][r["type"]] = b["types"].get(r["type"], 0) + 1
            del b["records"]
            out.append(b)
    return jsonify(out)


# ---- live demo for judges: tamper with evidence + records, then restore
TAMPER_DIR = os.path.join(DATA_DIR, "tamper_backup")


@app.post("/api/security/demo/tamper")
@need("SUPERVISOR")
def demo_tamper():
    if os.path.isdir(TAMPER_DIR):
        raise ValidationError("a tamper demo is already active; restore first", 409)
    ledger.seal()
    ev = next((r for b in store._q("SELECT records FROM ledger_blocks ORDER BY height DESC")
               for r in json.loads(b["records"]) if r["type"] == "EVIDENCE"), None)
    row = store._q("SELECT seq, payload FROM audit WHERE kind IN ('ALERT_CREATED','EVENT') ORDER BY seq DESC LIMIT 1",
                   one=True)
    if not ev and not row:
        raise ValidationError("nothing to tamper with yet: raise an alert first", 409)
    os.makedirs(TAMPER_DIR)
    done = []
    if ev:
        p = os.path.join(config.EVIDENCE_DIR, ev["meta"]["file"])
        shutil.copy2(p, os.path.join(TAMPER_DIR, "evidence.bin"))
        with open(os.path.join(TAMPER_DIR, "evidence.path"), "w") as f:
            f.write(p)
        import cv2
        img = cv2.imread(p)
        if img is not None:     # "photoshop" the evidence: black out the flagged object area
            h, w = img.shape[:2]
            cv2.rectangle(img, (w // 3, h // 3), (2 * w // 3, 2 * h // 3), (40, 40, 40), -1)
            cv2.imwrite(p, img)
        else:
            with open(p, "ab") as f:
                f.write(b"tampered")
        done.append(f"evidence photo {ev['ref']} edited (object blacked out)")
    if row:
        with open(os.path.join(TAMPER_DIR, "audit.json"), "w") as f:
            json.dump(row, f)
        pl = json.loads(row["payload"])
        for k in ("threat_level", "detection", "confidence"):
            if k in pl:
                pl[k] = "LOW" if k == "threat_level" else ("NOTHING_FOUND" if k == "detection" else 0.01)
        store._x("UPDATE audit SET payload=? WHERE seq=?", (json.dumps(pl, sort_keys=True, separators=(",", ":")),
                                                            row["seq"]))
        done.append(f"audit record #{row['seq']} rewritten (threat downgraded to LOW / NOTHING_FOUND)")
    sec.event("bad", "TAMPER_DEMO", "SIMULATED INSIDER ATTACK: " + "; ".join(done) + f" (by {by()})")
    v = ledger.verify()
    v["audit"] = store.verify_audit()
    return jsonify({"tampered": done, "verify": v})


@app.post("/api/security/demo/restore")
@need("SUPERVISOR")
def demo_restore():
    if not os.path.isdir(TAMPER_DIR):
        raise ValidationError("no tamper demo active", 409)
    if os.path.exists(os.path.join(TAMPER_DIR, "evidence.path")):
        p = open(os.path.join(TAMPER_DIR, "evidence.path")).read()
        shutil.copy2(os.path.join(TAMPER_DIR, "evidence.bin"), p)
    if os.path.exists(os.path.join(TAMPER_DIR, "audit.json")):
        row = json.load(open(os.path.join(TAMPER_DIR, "audit.json")))
        store._x("UPDATE audit SET payload=? WHERE seq=?", (row["payload"], row["seq"]))
    shutil.rmtree(TAMPER_DIR)
    v = ledger.verify()
    v["audit"] = store.verify_audit()
    sec.event("info", "TAMPER_RESTORED", f"tamper demo restored from backup by {by()}; ledger "
                                         f"{'INTACT' if v['ok'] else 'still has problems'}")
    return jsonify({"verify": v})


@app.post("/api/security/demo/attack")
@need("SUPERVISOR")
def demo_attack():
    """Fire forged / altered / replayed / impersonating packets at our own device API and report the outcome."""
    import secrets as _s
    from .security import sign as _sign
    client = app.test_client()
    results = []
    body = json.dumps({"device_id": "__VICTIM__", "device_type": "HANDHELD", "run_id": "RUN_X",
                       "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "detection": "CLEAR",
                       "threat_level": "LOW", "confidence": 0.9}).encode()

    def send(name, headers, data=None, path="/api/handheld/data"):
        data = data if data is not None else body.replace(b"__VICTIM__", victim.encode())
        r = client.post(path, data=data, headers={"Content-Type": "application/json", **headers})
        j = r.get_json(silent=True) or {}
        blocked = r.status_code == 401
        results.append({"attack": name, "http": r.status_code, "blocked": blocked,
                        "reason": j.get("error", "accepted")})

    dev = next((d for d, v in sec.devices.items() if not v.get("revoked") and v.get("type") == "HANDHELD"), None) \
        or next((d for d, v in sec.devices.items() if not v.get("revoked")), None)
    victim = dev or "HAND_02"
    send(f"1. Unsigned fake 'all clear' claiming to be {victim}", {})
    send(f"2. Forged signature for {victim} (attacker guesses the key)",
         {"X-Device-Id": victim, "X-Timestamp": str(int(time.time())), "X-Nonce": _s.token_hex(8),
          "X-Signature": _s.token_hex(32)})
    if dev:
        secret = sec.devices[dev]["secret"]
        hb = json.dumps({"device_id": dev}).encode()
        ts, nonce = str(int(time.time())), _s.token_hex(8)
        good = {"X-Device-Id": dev, "X-Timestamp": ts, "X-Nonce": nonce,
                "X-Signature": _sign(secret, ts, nonce, "POST", "/api/handheld/heartbeat", hb)}
        client.post("/api/handheld/heartbeat", data=hb, headers={"Content-Type": "application/json", **good})
        send(f"3. Replay of a captured genuine {dev} packet", good, hb, "/api/handheld/heartbeat")
        altered = json.dumps({"device_id": dev, "latitude": 0.0, "longitude": 0.0}).encode()
        ts2, n2 = str(int(time.time())), _s.token_hex(8)
        send(f"4. Genuine {dev} packet altered in transit (position changed)",
             {"X-Device-Id": dev, "X-Timestamp": ts2, "X-Nonce": n2,
              "X-Signature": _sign(secret, ts2, n2, "POST", "/api/handheld/heartbeat", hb)}, altered,
             "/api/handheld/heartbeat")
        old_ts, n3 = str(int(time.time()) - 600), _s.token_hex(8)
        send(f"5. Old {dev} packet re-sent 10 minutes later",
             {"X-Device-Id": dev, "X-Timestamp": old_ts, "X-Nonce": n3,
              "X-Signature": _sign(secret, old_ts, n3, "POST", "/api/handheld/heartbeat", hb)}, hb,
             "/api/handheld/heartbeat")
        imp = json.dumps({"device_id": "HAND_99"}).encode()
        ts4, n4 = str(int(time.time())), _s.token_hex(8)
        send(f"6. {dev} signs a message pretending to be HAND_99",
             {"X-Device-Id": dev, "X-Timestamp": ts4, "X-Nonce": n4,
              "X-Signature": _sign(secret, ts4, n4, "POST", "/api/handheld/heartbeat", imp)}, imp,
             "/api/handheld/heartbeat")
    blocked = sum(r["blocked"] for r in results)
    sec.event("info" if blocked == len(results) else "bad", "ATTACK_DEMO",
              f"simulated attacks: {blocked}/{len(results)} blocked (mode {sec.mode.upper()}, by {by()})")
    return jsonify({"mode": sec.mode, "results": results})


# ------------------------------------------------------------------ main
def _parse_cam(spec, n):
    parts = [x.strip() for x in spec.split("|")]
    if len(parts) < 2:
        raise SystemExit(f'--cam must be "NAME|SOURCE" or "NAME|SOURCE|LAT,LON", got: {spec}')
    cam = {"id": f"CAM_{n}", "name": parts[0], "drone_id": None, "lat": None, "lon": None}
    if len(parts) > 2 and parts[2]:
        lat, lon = parts[2].split(",")
        cam["lat"], cam["lon"] = float(lat), float(lon)
    return parts[1], cam


def main():
    ap = argparse.ArgumentParser(description="REVELATION Control Unit")
    ap.add_argument("--video", help="drone camera source (camera index, rtsp/udp URL or file)")
    ap.add_argument("--cam", action="append", default=[],
                    help='extra fixed camera: "NAME|SOURCE" or "NAME|SOURCE|LAT,LON" (repeatable)')
    ap.add_argument("--no-video", action="store_true", help="run without any video")
    ap.add_argument("--port", type=int, default=config.PORT)
    ap.add_argument("--db", help="SQLite file to use (e.g. data/test.db for test runs)")
    ap.add_argument("--https", action="store_true",
                    help="serve over HTTPS (certificate created automatically in certs/)")
    args = ap.parse_args()

    if not args.no_video:
        from .pipeline import VideoPipeline
        src = args.video if args.video is not None else config.VIDEO_SOURCE
        specs = []
        if src or not args.cam:
            specs.append((src, {"id": "CAM_1", "name": f"{config.VIDEO_DRONE_ID} camera",
                                "drone_id": config.VIDEO_DRONE_ID, "lat": None, "lon": None}))
        for spec in args.cam:
            specs.append(_parse_cam(spec, len(specs) + 1))
        for source, cam in specs:
            p = VideoPipeline(hub, source, cam)
            pipelines[cam["id"]] = p
            p.start()
            print(f"  camera {cam['id']}: {cam['name']}  <- {source or '(none)'}", flush=True)
    if config.MAVLINK_URL:
        start_mavlink_bridge(config.MAVLINK_URL, config.MAVLINK_DRONE_ID, hub.ingest_telemetry, hub.log)

    ssl = None
    if args.https:
        from .certs import ensure_cert
        ssl = ensure_cert(os.path.join(config.ROOT, "certs"))
    scheme = "https" if ssl else "http"
    st = ledger.status()
    print(f"\n  Database:         {config.DB_PATH}"
          f"\n  Device security:  {sec.mode.upper()}   (SECURITY_MODE=enforce|monitor|off)"
          f"\n  Ledger:           node {st['node_id']}, height {st['height']}, anchoring via {', '.join(anchorer.backends)}"
          f"\n  Control Unit up:  {scheme}://localhost:{args.port}/dashboard"
          f"\n  Handheld page:    {scheme}://<this-laptop-ip>:{args.port}/handheld\n", flush=True)
    app.run(host=config.HOST, port=args.port, threaded=True, ssl_context=ssl, use_reloader=False)


if __name__ == "__main__":
    main()
