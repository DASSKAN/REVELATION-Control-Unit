"""
Communication test plan from the protocol document (section 20), automated.

Run it against a separate test database so test alerts don't end up in your real log:
    python -m control_unit.server --no-video --db data/test.db
    python tools/test_protocol.py
"""
import argparse
import sys
import time

import requests

import devsign

results = []


def check(test_id, name, cond, detail=""):
    results.append(cond)
    print(f"{'PASS' if cond else 'FAIL'}  {test_id}  {name}  {detail}")


def pkt(run_id, **kw):
    p = {"message_id": f"TEST_{time.time_ns()}", "device_id": "HAND_TEST", "device_type": "HANDHELD",
         "run_id": run_id, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "detection": "CLEAR",
         "threat_level": "LOW", "confidence": 0.8, "latitude": 13.0826, "longitude": 80.2755,
         "zone": "PLATFORM_01", "battery": 80}
    p.update(kw)
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cu", default="http://127.0.0.1:5000")
    ap.add_argument("--user", default="operator")
    ap.add_argument("--password", default="Operator@123")
    args = ap.parse_args()
    cu = args.cu
    op = requests.Session()                        # control-room operator (logged in)
    r = op.post(cu + "/api/login", json={"username": args.user, "password": args.password})
    if not r.ok:
        sys.exit(f"login failed: {r.text}")
    s = devsign.session("HAND_TEST")               # signed handheld
    other = devsign.session("HAND_OTHER")
    drone = devsign.session("DRONE_TEST", "DRONE")

    # --- security checks
    anon = requests.Session()
    check("SEC-02", "operator API needs login", anon.post(cu + "/api/run/start", json={}).status_code == 401)
    r = anon.post(cu + "/api/handheld/heartbeat", json={"device_id": "HAND_TEST"})
    check("SEC-03", "unsigned device packet rejected", r.status_code == 401, r.json().get("error", ""))
    viewer = requests.Session()
    viewer.post(cu + "/api/login", json={"username": "viewer", "password": "Viewer@123"})
    check("SEC-04", "viewer cannot start a run", viewer.post(cu + "/api/run/start", json={}).status_code == 403)

    cur = op.get(cu + "/api/run/current").json()["run"]
    if cur:
        op.post(cu + "/api/run/end", json={})

    r = s.post(cu + "/api/handheld/data", json=pkt("RUN_XXX"))
    check("COM-04", "send without active run", r.status_code == 409, r.json().get("error", ""))

    r = op.post(cu + "/api/run/start", json={"operator": "test"})
    run_id = r.json().get("run_id")
    check("COM-01", "start inspection run", r.ok and r.json().get("status") == "ACTIVE", run_id)

    r = s.post(cu + "/api/handheld/data", json=pkt(run_id))
    check("COM-02", "send NORMAL packet", r.ok and r.json()["status"] == "accepted")

    r = s.post(cu + "/api/handheld/data",
               json=pkt(run_id, detection="EXPLOSIVE", threat_level="HIGH", confidence=0.94))
    alert_id = r.json().get("alert")
    a = op.get(f"{cu}/api/alerts/{alert_id}").json() if alert_id else {}
    check("COM-03", "send HIGH packet", r.ok and bool(alert_id), f"{alert_id} status={a.get('status')}")
    run = op.get(cu + "/api/run/current").json()["run"]
    check("COM-03b", "run enters ALERT state", run and run["status"] == "ALERT")

    r = s.post(cu + "/api/handheld/data", data="{not json", headers={"Content-Type": "application/json"})
    check("COM-05", "malformed JSON rejected", r.status_code == 400, r.json().get("error", ""))

    bad = pkt(run_id)
    del bad["confidence"]
    r = s.post(cu + "/api/handheld/data", json=bad)
    check("COM-05b", "missing required field rejected", r.status_code == 400, r.json().get("error", ""))

    p = pkt(run_id, message_id="MSG_DUP_TEST_%d" % time.time())
    s.post(cu + "/api/handheld/data", json=p)
    r = s.post(cu + "/api/handheld/data", json=p)
    check("COM-07", "duplicate message identified", r.ok and r.json()["status"] == "duplicate")

    # officer workflow on the HIGH alert
    if alert_id:
        ok = s.post(f"{cu}/api/alerts/{alert_id}/officer", json={"device_id": "HAND_TEST", "action": "ACK"}).ok
        r2 = other.post(f"{cu}/api/alerts/{alert_id}/officer", json={"device_id": "HAND_OTHER", "action": "ACK"})
        check("WF-01", "first officer takes alert, second is refused", ok and r2.status_code == 409)
        r = s.post(cu + "/api/handheld/data", json=pkt(run_id, alert_id=alert_id, detection="CLEAR"))
        a = op.get(f"{cu}/api/alerts/{alert_id}").json()
        check("WF-02", "verification closes alert", a["status"] == "CLEARED", a["status"])
        run = op.get(cu + "/api/run/current").json()["run"]
        check("WF-03", "run returns to ACTIVE", run and run["status"] == "ACTIVE")

    # telemetry + link loss
    drone.post(cu + "/api/drone/telemetry", json={"device_id": "DRONE_TEST", "seq": 1, "latitude": 13.08,
                                              "longitude": 80.27, "alt_agl": 30, "heading": 0})
    drone.post(cu + "/api/drone/telemetry", json={"device_id": "DRONE_TEST", "seq": 5, "latitude": 13.08,
                                              "longitude": 80.27, "alt_agl": 30, "heading": 0})
    st = {d["device_id"]: d for d in op.get(cu + "/api/state").json()["drones"]}
    check("COM-08a", "telemetry gaps counted", st["DRONE_TEST"]["lost_packets"] == 3)
    print("      waiting 6 s for link-loss detection…")
    time.sleep(6.5)
    st = {d["device_id"]: d for d in op.get(cu + "/api/state").json()["drones"]}
    check("COM-08b", "drone link marked LOST", st["DRONE_TEST"]["link"] == "LOST")

    r = op.get(cu + "/api/audit/verify").json()
    check("SEC-01", "audit hash chain intact", r["ok"], f"{r.get('entries')} entries")

    # replay: capture a genuinely signed request and send it again
    req = requests.Request("POST", cu + "/api/handheld/heartbeat", json={"device_id": "HAND_TEST"})
    prep = s.prepare_request(req)
    first = requests.Session().send(prep)
    again = requests.Session().send(prep)
    check("SEC-05", "replayed signed packet rejected", first.ok and again.status_code == 401,
          again.json().get("error", ""))
    r = op.get(cu + "/api/ledger/verify").json()
    check("SEC-06", "blockchain ledger verifies", r["ok"], f"{r['blocks']} blocks, {r['records']} records")

    r = op.post(cu + "/api/run/end", json={})
    check("COM-06", "end run", r.ok and r.json()["status"] == "COMPLETED")

    print(f"\n{sum(results)}/{len(results)} passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
