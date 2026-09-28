"""
Drone telemetry simulator / reference client.

Sends the drone heartbeat to the Control Unit at 2 Hz — the same thing the
companion computer (Raspberry Pi / ESP32) on the real drone should send.

  python tools/drone_sim.py --cu http://127.0.0.1:5000 --mode hover
  python tools/drone_sim.py --mode patrol          # flies a loop along the platform

Real drone: replace the simulated position with values read from the flight
controller (or skip this and set MAVLINK_URL on the Control Unit instead).
"""
import argparse
import math
import time

import requests

import devsign   # signs every request with this drone's device key

# Chennai Central, platform area (placeholder - set to your test site)
HOME = (13.08268, 80.27552)


def offset(lat, lon, n, e):
    return lat + n / 111320.0, lon + e / (111320.0 * math.cos(math.radians(lat)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cu", default="http://127.0.0.1:5000")
    ap.add_argument("--id", default="DRONE_01")
    ap.add_argument("--mode", choices=["hover", "patrol"], default="hover")
    ap.add_argument("--lat", type=float, default=HOME[0])
    ap.add_argument("--lon", type=float, default=HOME[1])
    ap.add_argument("--alt", type=float, default=30.0)
    ap.add_argument("--heading", type=float, default=20.0)
    ap.add_argument("--pitch", type=float, default=-45.0, help="camera pitch, -90 = straight down")
    ap.add_argument("--api-key", default="")
    ap.add_argument("--drop", type=float, default=0.0, help="fraction of packets to drop (link test)")
    a = ap.parse_args()

    import random
    s = devsign.session(a.id, "DRONE")
    if a.api_key:
        s.headers["X-API-Key"] = a.api_key
    seq, t0, batt = 0, time.time(), 96.0
    print(f"sending telemetry for {a.id} to {a.cu} at 2 Hz (Ctrl+C to stop)")
    while True:
        t = time.time() - t0
        seq += 1
        if a.mode == "patrol":
            # 120 m out-and-back along the platform axis
            along = 60 * math.sin(t / 25.0)
            lat, lon = offset(a.lat, a.lon, along * math.cos(math.radians(a.heading)),
                              along * math.sin(math.radians(a.heading)))
            speed = abs(60 / 25.0 * math.cos(t / 25.0))
            heading = a.heading if math.cos(t / 25.0) >= 0 else (a.heading + 180) % 360
        else:
            lat, lon = offset(a.lat, a.lon, 0.4 * math.sin(t / 3), 0.4 * math.cos(t / 4))  # GPS wander
            speed, heading = 0.2, a.heading
        batt = max(5.0, batt - 0.01)
        pkt = {
            "device_id": a.id, "device_type": "DRONE", "seq": seq,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "latitude": round(lat, 7), "longitude": round(lon, 7), "alt_agl": a.alt,
            "heading": round(heading, 1), "gimbal_pitch": a.pitch, "speed": round(speed, 2),
            "battery": round(batt), "mode": "POSHOLD" if a.mode == "hover" else "PATROL",
            "zone": "PLATFORM_01",
        }
        if random.random() >= a.drop:
            try:
                s.post(a.cu + "/api/drone/telemetry", json=pkt, timeout=1)
            except requests.RequestException as e:
                print("link error:", e)
        time.sleep(0.5)


if __name__ == "__main__":
    main()
