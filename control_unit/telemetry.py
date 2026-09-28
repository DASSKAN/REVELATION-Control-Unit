"""
Optional MAVLink bridge: reads position/attitude/battery straight from the
flight controller (INAV, ArduPilot, PX4) and feeds it to the hub as drone
telemetry, so no companion computer is needed for GPS.

Enable with   MAVLINK_URL=udpin:0.0.0.0:14550   (pip install pymavlink)

For a telemetry radio on USB use e.g. MAVLINK_URL=/dev/ttyUSB0 (57600 baud)
or COM5 on Windows.
"""
import threading
import time


def start_mavlink_bridge(url, drone_id, on_telemetry, log=print):
    try:
        from pymavlink import mavutil
    except ImportError:
        log("[mavlink] pymavlink not installed - run `pip install pymavlink` to enable")
        return None

    def run():
        while True:
            try:
                log(f"[mavlink] connecting to {url}")
                kw = {"baud": 57600} if not url.startswith(("udp", "tcp")) else {}
                m = mavutil.mavlink_connection(url, **kw)
                m.wait_heartbeat(timeout=10)
                log("[mavlink] heartbeat received")
                state = {"device_id": drone_id, "seq": 0}
                last_sent = 0.0
                while True:
                    msg = m.recv_match(blocking=True, timeout=5)
                    if msg is None:
                        continue
                    t = msg.get_type()
                    if t == "GLOBAL_POSITION_INT":
                        state["latitude"] = msg.lat / 1e7
                        state["longitude"] = msg.lon / 1e7
                        state["alt_agl"] = msg.relative_alt / 1000.0
                        state["speed"] = ((msg.vx ** 2 + msg.vy ** 2) ** 0.5) / 100.0
                        if msg.hdg != 65535:
                            state["heading"] = msg.hdg / 100.0
                    elif t == "ATTITUDE" and "heading" not in state:
                        import math
                        state["heading"] = (math.degrees(msg.yaw) + 360) % 360
                    elif t == "SYS_STATUS" and msg.battery_remaining >= 0:
                        state["battery"] = msg.battery_remaining
                    elif t == "HEARTBEAT":
                        state["mode"] = mavutil.mode_string_v10(msg)
                    elif t == "MOUNT_ORIENTATION":
                        state["gimbal_pitch"] = msg.pitch
                    # forward at 2 Hz, matching the drone heartbeat rate
                    now = time.time()
                    if now - last_sent >= 0.5 and "latitude" in state:
                        state["seq"] += 1
                        on_telemetry(dict(state))
                        last_sent = now
            except Exception as e:  # keep retrying; link drops are normal in the field
                log(f"[mavlink] link error: {e}; retrying in 3s")
                time.sleep(3)

    th = threading.Thread(target=run, daemon=True, name="mavlink")
    th.start()
    return th
