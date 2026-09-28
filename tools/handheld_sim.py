"""
Simulated RPF handheld (reference client for the ESP32 / phone app).

It heartbeats its GPS every 2 s, and when the Control Unit dispatches an
alert it acknowledges, "walks" to the coordinates, and submits a verification
scan using the protocol envelope.

  python tools/handheld_sim.py --id HAND_02 --officer "HC Arun" --result CLEAR
  python tools/handheld_sim.py --id HAND_03 --result EXPLOSIVE
"""
import argparse
import math
import time

import requests

import devsign   # signs every request with this handheld's device key

HOME = (13.08212, 80.27505)


def dist(a, b, c, d):
    R = 6371000
    p1, p2 = math.radians(a), math.radians(c)
    x = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(d - b) / 2) ** 2
    return 2 * R * math.asin(math.sqrt(x))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cu", default="http://127.0.0.1:5000")
    ap.add_argument("--id", default="HAND_02")
    ap.add_argument("--officer", default="HC Simulated")
    ap.add_argument("--lat", type=float, default=HOME[0])
    ap.add_argument("--lon", type=float, default=HOME[1])
    ap.add_argument("--speed", type=float, default=4.0, help="walking speed m/s (sped up for demos)")
    ap.add_argument("--result", choices=["CLEAR", "NARCOTICS", "EXPLOSIVE"], default="CLEAR")
    ap.add_argument("--once", action="store_true", help="exit after handling one alert")
    ap.add_argument("--ack-delay", type=float, default=3.0, help="seconds before the officer acknowledges")
    a = ap.parse_args()

    s = devsign.session(a.id, "HANDHELD")
    lat, lon, batt = a.lat, a.lon, 88
    task = None
    seen = {}
    print(f"{a.id} on duty at {lat:.6f},{lon:.6f}")
    while True:
        hb = {"device_id": a.id, "officer": a.officer, "latitude": lat, "longitude": lon, "battery": batt}
        try:
            r = s.post(a.cu + "/api/handheld/heartbeat", json=hb, timeout=2).json()
        except requests.RequestException as e:
            print("link error:", e)
            time.sleep(2)
            continue
        run_id = r.get("run_id")
        for m in r.get("messages", []):
            print(f"  MESSAGE [{m['priority']}] {m['text']}")
            s.post(f"{a.cu}/api/messages/{m['msg_id']}/ack", json={"device_id": a.id})
        if task is None:
            for al in r.get("alerts", []):
                if al["status"] == "DISPATCHED" and time.time() - seen.setdefault(al["alert_id"], time.time()) >= a.ack_delay:
                    ack = s.post(f"{a.cu}/api/alerts/{al['alert_id']}/officer",
                                 json={"device_id": a.id, "action": "ACK"})
                    if ack.ok:
                        task = ack.json()
                        print(f"ACK {task['alert_id']} {task['detection']} at {task['latitude']},{task['longitude']}")
                        s.post(f"{a.cu}/api/alerts/{task['alert_id']}/officer",
                               json={"device_id": a.id, "action": "EN_ROUTE"})
                    break
        else:
            tl, tn = task.get("latitude"), task.get("longitude")
            d = dist(lat, lon, tl, tn) if tl is not None else 0
            if d > 3:
                step = min(1.0, a.speed * 2 / d)
                lat += (tl - lat) * step
                lon += (tn - lon) * step
                print(f"  en route, {d:.0f} m to go")
            else:
                s.post(f"{a.cu}/api/alerts/{task['alert_id']}/officer",
                       json={"device_id": a.id, "action": "ON_SCENE"})
                level = "LOW" if a.result == "CLEAR" else "HIGH"
                msg = {
                    "message_id": f"{a.id}_{int(time.time() * 1000)}", "device_id": a.id,
                    "device_type": "HANDHELD", "run_id": run_id,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "detection": a.result,
                    "threat_level": level, "confidence": 0.91, "latitude": round(lat, 6),
                    "longitude": round(lon, 6), "zone": task.get("zone"), "battery": batt,
                    "alert_id": task["alert_id"],
                }
                res = s.post(a.cu + "/api/handheld/data", json=msg).json()
                print("  verification sent:", res)
                task = None
                if a.once:
                    return
        time.sleep(2)


if __name__ == "__main__":
    main()
