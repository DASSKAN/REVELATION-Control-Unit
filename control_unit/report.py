"""
Run log export: everything recorded during one inspection run, as a ZIP.

  report.html          printable incident report (open in a browser, Ctrl+P to save as PDF)
  detections.csv       what the object detector tracked, one row per object per second
  ai_log.csv           detector observations (bag detected / unattended / attended again ...)
  alerts.csv           every alert with location, dispatch, assignment and result
  alert_timeline.csv   every status change of every alert (who did what, when)
  events.csv           field-device messages (drone AI events + handheld scans)
  messages.csv         operator messages to handhelds and who read them
  audit_chain.csv      hash-chained audit entries for the run + audit_verify.json
  ledger.json          blockchain ledger slice (signed blocks) + public key + anchors
  evidence_proofs.json Merkle proof of every evidence file -> block -> anchor
  anchors/             OpenTimestamps receipts (.ots) + block headers for independent verification
  verify_evidence.py   stand-alone checker: python verify_evidence.py
  evidence/            evidence frames for each alert (+ replay clip frames with ?clips=1)
"""
import csv
import html
import io
import json
import os
import zipfile
from collections import Counter
from datetime import datetime

from . import config


def _t(iso):
    try:
        return datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return None


def _secs(a, b):
    ta, tb = _t(a), _t(b)
    return (tb - ta).total_seconds() if ta and tb else None


def _csv(rows, cols):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in r.items()})
    return buf.getvalue()


def _response(a):
    """Response-time milestones for one alert, from its history."""
    first = {}
    for h in a["history"]:
        first.setdefault(h["status"], h["t"])
    out = {"dispatched": first.get("DISPATCHED"), "acknowledged": first.get("ACKNOWLEDGED"),
           "on_scene": first.get("ON_SCENE"),
           "closed": first.get("CLEARED") or first.get("CONFIRMED_THREAT") or first.get("DISMISSED")}
    out["to_ack_s"] = _secs(a["created_at"], out["acknowledged"])
    out["to_scene_s"] = _secs(a["created_at"], out["on_scene"])
    out["to_close_s"] = _secs(a["created_at"], out["closed"])
    return out


def collect(store, run_id, ledger=None):
    run = store.get_run(run_id)
    if not run:
        return None
    alerts = store.run_rows("alerts", run_id, "created_at")
    for a in alerts:
        a["history"] = json.loads(a["history"])
        a["response"] = _response(a)
    det_path = os.path.join(config.ROOT, "data", "logs", f"{run_id}_detections.csv")
    detections = []
    if os.path.exists(det_path):
        with open(det_path, newline="") as f:
            detections = list(csv.DictReader(f))
    return {
        "run": run,
        "alerts": alerts,
        "events": store.run_rows("events", run_id, "id"),
        "ai_log": store.list_ai_log(run_id),
        "messages": store.messages_between(run["start_time"], run["end_time"]),
        "audit": store.audit_between(run["start_time"], run["end_time"]),
        "audit_verify": store.verify_audit(),
        "detections": detections,
        "det_path": det_path,
        "ledger": _ledger_part(ledger, run, alerts) if ledger else None,
    }


def _ledger_part(ledger, run, alerts):
    v = ledger.verify()
    proofs = []
    for a in alerts:
        if a.get("evidence_ref"):
            base = a["evidence_ref"].rsplit(".", 1)[0]
            for e in ledger.find(base, ["EVIDENCE", "EVIDENCE_RAW", "CLIP"]):
                proofs.append({"alert_id": a["alert_id"], **e})
    exp = ledger.export(run["start_time"], None)
    heights = [b["height"] for b in exp["blocks"]]
    anchors = [x for x in ledger.anchors(500) if not heights or x["height"] >= min(heights)]
    return {"verify": v, "proofs": proofs, "export": exp, "anchors": anchors, "status": ledger.status()}


def build_zip(store, run_id, include_clips=False, ledger=None):
    d = collect(store, run_id, ledger)
    if d is None:
        return None
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        root = f"{run_id}_log/"
        z.writestr(root + "report.html", build_html(d, evidence_prefix="evidence/"))
        z.writestr(root + "run.json", json.dumps(d["run"], indent=2))
        if os.path.exists(d["det_path"]):
            z.write(d["det_path"], root + "detections.csv")
        z.writestr(root + "ai_log.csv", _csv(d["ai_log"], ["ts", "cam_id", "level", "text"]))
        z.writestr(root + "alerts.csv", _csv(
            [dict(a, to_ack_s=a["response"]["to_ack_s"], to_scene_s=a["response"]["to_scene_s"],
                  to_close_s=a["response"]["to_close_s"]) for a in d["alerts"]],
            ["alert_id", "created_at", "threat_level", "detection", "source_type", "source_device", "camera",
             "confidence", "latitude", "longitude", "geo_method", "zone", "status", "dispatched_to", "escalations",
             "backup", "assigned_to", "resolution", "to_ack_s", "to_scene_s", "to_close_s", "evidence_ref",
             "evidence_sha256", "description"]))
        z.writestr(root + "alert_timeline.csv", _csv(
            [{"alert_id": a["alert_id"], **h} for a in d["alerts"] for h in a["history"]],
            ["t", "alert_id", "status", "by", "note"]))
        z.writestr(root + "events.csv", _csv(d["events"], [
            "received_at", "message_id", "device_id", "device_type", "detection", "threat_level", "confidence",
            "latitude", "longitude", "zone", "battery", "alert_id", "evidence_ref"]))
        z.writestr(root + "messages.csv", _csv(d["messages"], ["created_at", "msg_id", "sender", "target",
                                                              "priority", "text", "acks"]))
        z.writestr(root + "audit_chain.csv", _csv(d["audit"], ["seq", "ts", "kind", "ref_id", "prev_hash", "hash",
                                                               "payload"]))
        z.writestr(root + "audit_verify.json", json.dumps(d["audit_verify"], indent=2))
        if d.get("ledger"):
            L = d["ledger"]
            z.writestr(root + "ledger.json", json.dumps(L["export"], indent=1, default=str))
            z.writestr(root + "ledger_verify.json", json.dumps(L["verify"], indent=2, default=str))
            z.writestr(root + "evidence_proofs.json", json.dumps(
                {"public_key_ed25519": L["export"]["public_key_ed25519"], "node_id": L["export"]["node_id"],
                 "proofs": L["proofs"]}, indent=1, default=str))
            adir = os.path.join(config.ROOT, "data", "anchors")
            wanted = {f"block_{a['height']}." for a in L["anchors"]}
            if os.path.isdir(adir):
                for f in os.listdir(adir):
                    if any(f.startswith(w) for w in wanted):
                        z.write(os.path.join(adir, f), root + "anchors/" + f)
            tool = os.path.join(config.ROOT, "tools", "verify_evidence.py")
            if os.path.exists(tool):
                z.write(tool, root + "verify_evidence.py")
        for a in d["alerts"]:
            ref = a.get("evidence_ref")
            if ref:
                for name in (ref, ref.replace(".jpg", "_raw.jpg")):
                    p = os.path.join(config.EVIDENCE_DIR, name)
                    if os.path.exists(p):
                        z.write(p, root + "evidence/" + name)
            if include_clips and a.get("clip_ref"):
                cdir = os.path.join(config.EVIDENCE_DIR, "clips", a["clip_ref"])
                if os.path.isdir(cdir):
                    for f in sorted(os.listdir(cdir)):
                        z.write(os.path.join(cdir, f), f"{root}evidence/clips/{a['clip_ref']}/{f}")
    return buf.getvalue()


# ---------------------------------------------------------------- HTML report
CSS = """
body{font:13px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#111;margin:0;background:#fff}
.wrap{max-width:1100px;margin:0 auto;padding:28px 24px}
h1{font-size:22px;margin:0}
h2{font-size:15px;margin:28px 0 8px;padding-bottom:4px;border-bottom:2px solid #111;text-transform:uppercase;letter-spacing:.06em}
.meta{color:#555;margin-top:4px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-top:14px}
.kpi{border:1px solid #ccc;padding:8px 10px}
.kpi b{display:block;font-size:20px;font-family:ui-monospace,Consolas,monospace}
.kpi span{font-size:11px;color:#555;text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{border-bottom:1px solid #ddd;padding:5px 6px;text-align:left;vertical-align:top}
th{background:#f3f3f3;font-weight:600}
.mono{font-family:ui-monospace,Consolas,monospace}
.alert{display:grid;grid-template-columns:320px 1fr;gap:14px;border:1px solid #ccc;padding:10px;margin-bottom:10px;page-break-inside:avoid}
.alert img{width:100%;border:1px solid #999}
.lvl{font-weight:700;padding:1px 6px;color:#fff;background:#b3140c;font-size:11px}
.lvl.MEDIUM{background:#c88400}.lvl.LOW{background:#555}
.st{font-weight:600}
.HIGH-row td:first-child{border-left:3px solid #b3140c}
.warn{color:#8a5a00}.bad{color:#b3140c}
.ok{color:#1d7a3a}
@media print{.wrap{padding:0}h2{page-break-after:avoid}}
"""


def _e(x):
    return html.escape("" if x is None else str(x))


def _fmt_s(s):
    return "–" if s is None else f"{s:.0f} s"


def _ledger_html(d):
    L = d.get("ledger")
    if not L:
        return ""
    v, st = L["verify"], L["status"]
    anchors = "".join(
        f"<tr><td>{_e(a['backend'])}</td><td class=mono>{a['height']}</td><td class=mono>{_e(a['block_hash'][:20])}…</td>"
        f"<td class='{'ok' if a['status'] in ('SUBMITTED', 'CONFIRMED') else 'warn'}'>{_e(a['status'])}</td>"
        f"<td class=mono style='word-break:break-all'>{_e(a.get('receipt') or '')}</td><td>{_e(a.get('detail') or '')}</td></tr>"
        for a in L["anchors"][:12])
    ev = {}
    for p in L["proofs"]:
        ev.setdefault(p["alert_id"], []).append(p)
    prow = "".join(
        f"<tr><td>{_e(aid)}</td><td>{_e(p['record']['type'])}</td><td class=mono>{_e(p['record']['sha256'][:16])}…</td>"
        f"<td class=mono>{p['block']['height']}</td><td class=mono>{len(p['proof'])} steps</td></tr>"
        for aid, ps in ev.items() for p in ps)
    probs = "".join(f"<li class=bad>{_e(x)}</li>" for x in v["problems"] + [f"evidence altered: {t['ref']}" for t in
                                                                             v["evidence_tampered"]])
    return f"""
<h2>Blockchain evidence ledger</h2>
<p>Node <b class=mono>{_e(st['node_id'])}</b> · Ed25519 public key <span class=mono style="word-break:break-all">{_e(st['public_key'])}</span></p>
<p>Chain height <b>{st['height']}</b> · head <span class=mono>{_e((st['head_hash'] or '')[:32])}…</span> ·
 verification <b class="{'ok' if v['ok'] else 'bad'}">{'INTACT' if v['ok'] else 'PROBLEMS FOUND'}</b>
 ({v['blocks']} blocks, {v['records']} records, {v['evidence_ok']}/{v['evidence_checked']} evidence files match their sealed hash)</p>
{f'<ul>{probs}</ul>' if probs else ''}
<table><tr><th>Anchor</th><th>Block</th><th>Block hash</th><th>Status</th><th>Receipt / tx</th><th>Detail</th></tr>
{anchors or '<tr><td colspan=6>Not anchored yet.</td></tr>'}</table>
<p class="meta">Evidence Merkle proofs (full proofs in evidence_proofs.json; check with verify_evidence.py):</p>
<table><tr><th>Alert</th><th>Type</th><th>SHA-256</th><th>Block</th><th>Merkle proof</th></tr>{prow or '<tr><td colspan=5>No evidence files.</td></tr>'}</table>"""


def build_html(d, evidence_prefix="/evidence/"):
    run, alerts = d["run"], d["alerts"]
    dur = _secs(run["start_time"], run["end_time"] or datetime.now().astimezone().isoformat())
    tracks = {(r["cam_id"], r["track_id"]): r["class"] for r in d["detections"]}
    by_class = Counter(tracks.values())
    ack_times = [a["response"]["to_ack_s"] for a in alerts if a["response"]["to_ack_s"] is not None]
    scene_times = [a["response"]["to_scene_s"] for a in alerts if a["response"]["to_scene_s"] is not None]
    status = Counter(a["status"] for a in alerts)
    av = d["audit_verify"]

    kpis = [
        ("Duration", f"{dur / 60:.1f} min" if dur else "–"),
        ("Objects tracked", sum(by_class.values())),
        ("Persons / bags", f"{by_class.get('person', 0)} / {sum(v for k, v in by_class.items() if k != 'person')}"),
        ("Alerts", len(alerts)),
        ("Confirmed threats", status.get("CONFIRMED_THREAT", 0)),
        ("Cleared", status.get("CLEARED", 0)),
        ("False alarms", status.get("DISMISSED", 0)),
        ("Avg time to ACK", _fmt_s(sum(ack_times) / len(ack_times)) if ack_times else "–"),
        ("Avg time on scene", _fmt_s(sum(scene_times) / len(scene_times)) if scene_times else "–"),
        ("Escalations", sum(a.get("escalations") or 0 for a in alerts)),
    ]

    # merged timeline
    tl = []
    for r in d["ai_log"]:
        tl.append((r["ts"], "AI", r["cam_id"], r["text"], "warn" if r["level"] == "warn" else ""))
    for a in alerts:
        for h in a["history"]:
            tl.append((h["t"], "ALERT", h.get("by") or "", f"{a['alert_id']} {a['detection']} → {h['status']}"
                       + (f" · {h['note']}" if h.get("note") else ""),
                       "bad" if h["status"] in ("NEW", "CONFIRMED_THREAT") or "ESCALATED" in (h.get("note") or "")
                       else "ok" if h["status"] == "CLEARED" else ""))
    for e in d["events"]:
        if e["device_type"] == "HANDHELD":
            tl.append((e["received_at"], "SCAN", e["device_id"],
                       f"{e['detection']} ({e['threat_level']}, {e['confidence']:.2f})"
                       + (f" for {e['alert_id']}" if e.get("alert_id") else ""),
                       "bad" if e["threat_level"] == "HIGH" else ""))
    for m in d["messages"]:
        tl.append((m["created_at"], "MESSAGE", m["sender"], f"[{m['priority']}] → {m['target']}: {m['text']}"
                   + (f" · read by {', '.join(m['acks'])}" if m["acks"] else ""), ""))
    tl.append((run["start_time"], "RUN", run.get("operator") or "", f"run {run['run_id']} started", "ok"))
    if run["end_time"]:
        tl.append((run["end_time"], "RUN", "", f"run {run['run_id']} completed", "ok"))
    tl.sort(key=lambda x: x[0])

    alert_html = []
    for a in alerts:
        r = a["response"]
        img = f'<img src="{evidence_prefix}{_e(a["evidence_ref"])}" alt="evidence">' if a.get("evidence_ref") else ""
        hist = "".join(f"<tr><td class=mono>{_e((h['t'] or '')[11:19])}</td><td>{_e(h['status'])}</td>"
                       f"<td>{_e(h.get('by'))}</td><td>{_e(h.get('note'))}</td></tr>" for h in a["history"])
        alert_html.append(f"""
<div class="alert"><div>{img}</div><div>
  <div><span class="lvl {a['threat_level']}">{a['threat_level']}</span> <b>{_e(a['alert_id'])} · {_e(a['detection'].replace('_', ' '))}</b>
   · <span class="st">{_e(a['status'])}</span></div>
  <div class="meta">{_e(a['created_at'])} · {_e(a.get('camera') or a['source_device'])} · {_e(a['source_type'])} · confidence {a['confidence']:.2f}</div>
  <p>{_e(a.get('description'))}</p>
  <table>
    <tr><th>Location</th><td class=mono>{'' if a['latitude'] is None else f"{a['latitude']:.6f}, {a['longitude']:.6f}"} ({_e(a['geo_method'])}) · {_e(a['zone'])}</td></tr>
    <tr><th>Dispatched to</th><td>{_e(a.get('dispatched_to'))}{f" · escalated ×{a['escalations']}" if a.get('escalations') else ''}{' · backup requested' if a.get('backup') else ''}</td></tr>
    <tr><th>Officer</th><td>{_e(a.get('assigned_to'))}</td></tr>
    <tr><th>Result</th><td>{_e(a.get('resolution'))}</td></tr>
    <tr><th>Response</th><td>ACK {_fmt_s(r['to_ack_s'])} · on scene {_fmt_s(r['to_scene_s'])} · closed {_fmt_s(r['to_close_s'])}</td></tr>
    <tr><th>Evidence SHA-256</th><td class=mono style="word-break:break-all">{_e(a.get('evidence_sha256'))}</td></tr>
  </table>
  <table style="margin-top:6px"><tr><th>Time</th><th>Status</th><th>By</th><th>Note</th></tr>{hist}</table>
</div></div>""")

    det_summary = "".join(f"<tr><td>{_e(k)}</td><td>{v}</td></tr>" for k, v in by_class.most_common())
    tl_html = "".join(f"<tr class='{c}'><td class=mono>{_e((t or '')[11:19])}</td><td>{_e(kind)}</td><td>{_e(who)}</td>"
                      f"<td class='{c}'>{_e(text)}</td></tr>" for t, kind, who, text, c in tl)

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Run log {_e(run['run_id'])}</title><style>{CSS}</style></head>
<body><div class="wrap">
<h1>REVELATION · RPF Control Unit · Inspection run log {_e(run['run_id'])}</h1>
<div class="meta">Started {_e(run['start_time'])} · ended {_e(run['end_time'] or 'still active')} · operator {_e(run.get('operator'))} · status {_e(run['status'])}</div>
<div class="meta">Generated {datetime.now().astimezone().isoformat(timespec='seconds')} · audit chain
 <b class="{'ok' if av['ok'] else 'bad'}">{'INTACT' if av['ok'] else 'BROKEN at entry ' + str(av.get('broken_at_seq'))}</b>
 ({av['entries']} entries{', latest hash ' + av['latest_hash'][:16] + '…' if av.get('latest_hash') else ''})</div>
<div class="kpis">{''.join(f'<div class="kpi"><b>{_e(v)}</b><span>{_e(k)}</span></div>' for k, v in kpis)}</div>

<h2>Alerts ({len(alerts)})</h2>
{''.join(alert_html) or '<p>No alerts during this run.</p>'}

{_ledger_html(d)}

<h2>Objects detected (unique tracks)</h2>
<table><tr><th>Class</th><th>Count</th></tr>{det_summary or '<tr><td colspan=2>No detection log for this run.</td></tr>'}</table>
<p class="meta">Full per-second detection log: detections.csv ({len(d['detections'])} rows).</p>

<h2>Timeline</h2>
<table><tr><th>Time</th><th>Type</th><th>Source</th><th>Event</th></tr>{tl_html}</table>
</div></body></html>"""
