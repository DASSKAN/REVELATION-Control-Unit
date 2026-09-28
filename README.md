# REVELATION Control Unit (SIH26026)

This is the Control Unit for the drone and handheld railway security system. It:

1. Receives the drone's live video and its 2 Hz telemetry heartbeat (GPS, altitude, heading, battery)
2. Runs object detection and tracking on the video and applies threat rules (abandoned baggage, restricted-zone intrusion, loitering)
3. Converts each detection from a pixel position into a **ground GPS coordinate**, so it gives the object's position rather than the drone's
4. Raises an alarm on the operator dashboard (siren, red banner and alert card with an evidence frame)
5. Pushes the alert with its coordinates to RPF handhelds (phone page or ESP32). The officer acknowledges, navigates to the spot, scans with the handheld and sends back the result
6. Logs everything in SQLite, with a hash-chained audit log that shows if any record was later changed

The endpoints and JSON envelope follow the team's *Railway Security Communication Protocol* document. `/api/run/start`, `/api/handheld/data`, `/api/run/end` and `/dashboard` are unchanged.

```
 DRONE ──video (RTSP/UDP/capture card)──┐
   └──telemetry 2 Hz (HTTP JSON / MAVLink)─┤
                                           ▼
                          ┌──────── CONTROL UNIT (Flask) ────────┐
                          │ YOLOv8 → tracker → threat rules       │
                          │ pixel → GPS projection                │
                          │ alerts · run lifecycle · SQLite       │
                          │ hash-chained audit · evidence frames  │
                          └───┬──────────────────────────┬────────┘
                   SSE / REST │                          │ SSE / polling
                              ▼                          ▼
                 Operator dashboard            RPF handhelds (phone / ESP32)
                 alarm · confirm/dismiss       alert · coordinates · compass
                 tactical plot · zones         ACK → en route → on scene → scan result
```

## Quick start (laptop)

```bash
pip install -r requirements.txt
bash run_demo.sh path/to/any_platform_video.mp4      # Windows: run_demo.bat path\to\clip.mp4
```

Open `http://localhost:5000/dashboard`, click **Arm alarm sound**, then **Start run**. Alerts are only logged and dispatched while a run is active, which matches the protocol's run lifecycle.

To check the protocol behaviour (COM-01 to COM-08 from the protocol document, plus the officer workflow and the audit chain):

```bash
python -m control_unit.server --no-video      # terminal 1
python tools/test_protocol.py                 # terminal 2  -> 15/15 passed
```

## Connecting the real drone

**Video.** Set `VIDEO_SOURCE` (or pass `--video`) to whatever carries the camera feed to the laptop:

| Drone camera setup | VIDEO_SOURCE |
|---|---|
| Analog FPV → 5.8 GHz receiver → USB video capture card | `0` (or `1`) |
| Digital FPV / IP camera / companion computer with RTSP | `rtsp://192.168.x.x:8554/stream` |
| Raspberry Pi pushing H.264 over UDP | `udp://@:5600` |
| Recorded flight for testing | `path/to/flight.mp4` (plays in real time and loops) |

**Telemetry (needed for coordinates).** Use one of these:
- **Companion computer or ESP32 on the drone** POSTs to `/api/drone/telemetry` at 2 Hz. `tools/drone_sim.py` is the reference client and shows the exact packet.
- **Straight from the flight controller** (INAV, ArduPilot or PX4) over a telemetry radio: `pip install pymavlink`, then `MAVLINK_URL=udpin:0.0.0.0:14550` (or `/dev/ttyUSB0`, `COM5`).

The telemetry packet is:

```json
{"device_id":"DRONE_01","device_type":"DRONE","seq":412,"timestamp":"2026-09-27T19:20:10",
 "latitude":13.0826812,"longitude":80.2755190,"alt_agl":30.0,"heading":20.0,
 "gimbal_pitch":-45,"speed":0.2,"battery":82,"mode":"POSHOLD","zone":"PLATFORM_01"}
```

Link status is OK below 1.5 s since the last packet, DEGRADED below 5 s and LOST after that. Gaps in `seq` are counted as lost packets. The heartbeat rate and sequence numbers follow the RobotX 2026 handbook §3.4.

**Camera geometry.** Set `CAMERA_HFOV_DEG` to your camera's horizontal field of view. Send `gimbal_pitch` in telemetry, or set `DEFAULT_GIMBAL_PITCH_DEG` if the camera is fixed; a cinewhoop's camera tilt counts as the pitch. The projection assumes flat ground. At 30 m altitude and 45° pitch, an error of a few degrees in heading or pitch moves the point by a few metres. That is close enough to send an officer to the right spot, but it is not survey-grade.

## RPF handhelds

**Phone (fastest to demo).** Open `http://<control-unit-ip>:5000/handheld` and press **Start duty**. The phone then:
- vibrates and beeps when an alert is dispatched
- shows the evidence frame, the target coordinates, and the distance and bearing from the officer (with a compass arrow)
- opens the location in Maps
- walks through Acknowledge → En route → On scene → submit scan result

The first officer to acknowledge takes the alert, and other handhelds see that it has been taken. If the link drops, reports are held and resent.

> Phones only allow GPS on HTTPS pages. Run `bash tools/make_cert.sh <laptop-ip>`, then start the server with `--https`. Accept the certificate warning once on each phone.

**ESP32.** `esp32/handheld_alert/handheld_alert.ino` does the following:
- polls `/api/handheld/alerts`
- sounds a buzzer and lights an LED on a new alert
- shows the coordinates on Serial, or on an optional SSD1306 OLED
- sends ACK with the BOOT button
- sends a scan result with a button on GPIO 4, attaching the alert ID so the scan closes that alert

Replace `readSensor()` with the IMS or sensor reading when the hardware is ready.

## Control room: alarms, dispatch and escalation

**When a HIGH alert fires, the dashboard takes over the whole screen:**
- a red flashing screen, a two-tone siren and a spoken announcement (for example "Alert. Abandoned baggage. Platform one."), repeated every 12 s
- a desktop notification and a flashing browser tab
- a replay clip of the seconds before and after the alert, with the location, evidence hash, nearest units and a live dispatch status
- action buttons: **Dispatch nearest unit · Dispatch ALL units · Send to a chosen unit · Request backup · Message units · False alarm**

The siren keeps sounding until the operator presses **Acknowledge** (or Enter). **Start console** on the login screen arms the sound, voice and notifications, because browsers block audio until you click once.

**The response chain:**
```
detection ─> auto-dispatch to the NEAREST unit with GPS (else ALL units)
          ─> no ACK within 30 s  ─> ESCALATED: re-sent to ALL units, siren restarts   (up to 3 times)
          ─> officer ACK ─> EN ROUTE ─> ON SCENE ─> handheld scan
          ─> CLEARED, or CONFIRMED THREAT ─> console goes CRITICAL, siren + "evacuate, cordon off, call BDDS"
```

**Operator tools (right-hand panel):**
- **Send alert:** raise an incident by hand (suspicious person, unattended baggage, fight, medical…). You choose the priority, zone, coordinates, the units to send it to and a snapshot from the main camera.
- **Message units:** send a text instruction to all units or one unit, marked INFO or URGENT. There are quick buttons for common instructions ("Hold position", "Evacuate the platform", "Do not touch the object"…), and you can see which officers have read each message.
- **Per-unit buttons** in the units table to message or alert one officer.

**On the handheld:**
- An incoming alert fills the whole screen, flashes, vibrates and beeps until the officer taps ACKNOWLEDGE. Escalated alerts and backup calls are clearly flagged.
- Operator messages pop up full screen, and URGENT ones also sound the alarm. The officer taps GOT IT, which tells the control room the message was read.

Settings (set them with `$env:NAME=value` in PowerShell before starting the server):

| Setting | Default | Meaning |
|---|---|---|
| `DISPATCH_MODE` | `nearest` | `nearest` or `all` for auto-dispatch |
| `ESCALATE_AFTER_S` | `30` | seconds without an ACK before escalating |
| `AUTO_DISPATCH_LEVELS` | `HIGH` | levels sent to units automatically |
| `CLIP_PRE_S` / `CLIP_POST_S` | `6` / `6` | seconds of replay kept before and after each alert |

## Several cameras (video wall)

```
python -m control_unit.server --video 0 --cam "PF2 FOB CCTV|1" --cam "Yard gate|rtsp://192.168.1.50/stream|13.0829,80.2751"
```
`--video` is the drone camera, which is linked to drone GPS. Each `--cam "NAME|SOURCE|LAT,LON"` adds a fixed CCTV camera; its position is optional and is used as the alert location. Click a thumbnail to make it the main view. Each camera has its own restricted zones. Every camera runs its own detection, so 2 cameras roughly halve the frame rate on a laptop CPU.

## What the drone AI flags, and what it can't

The drone camera cannot see narcotics or explosives. It flags **behaviour** that needs a close check, and the handheld then verifies it (Detect → Verify, as on slide 2):

| Rule | Level | Setting |
|---|---|---|
| Bag stationary with no person within `OWNER_RADIUS_BAG_HEIGHTS` for `ABANDON_SECONDS` | HIGH | 20 s default (60 s is sensible for live use) |
| Person inside an operator-drawn zone (e.g. track bed) for `ZONE_DWELL_SECONDS` | HIGH | draw the zone on the dashboard video |
| Person roughly stationary for `LOITER_SECONDS` | MEDIUM | 90 s |

The "stationary" checks work on image position, so they assume the drone is **hovering**. While the drone is flying a patrol line, only the zone rule is dependable.

The model is stock YOLOv8n trained on COCO (person, backpack, handbag, suitcase). From 25–40 m people are small in the frame. Set `DETECT_TILES=2` to run the model on image tiles, which finds far more of them at about 5× the compute. For a better model, fine-tune on your own drone footage (`yolo train …`), export it with `yolo export model=best.pt format=onnx` and set `MODEL_PATH`.

## Files

```
control_unit/
  server.py      Flask routes (REST + SSE + MJPEG)          config.py   every setting, env-overridable
  hub.py         validation, alerts, dispatch, device health   db.py       SQLite + hash-chained audit
  pipeline.py    capture → detect → track → rules → alert       detector.py YOLOv8 ONNX
  tracker.py     IoU tracker                                    rules.py    threat rules
  geo.py         pixel → GPS, distance, bearing                 telemetry.py MAVLink bridge
  templates/     dashboard.html, handheld.html
tools/           drone_sim.py, handheld_sim.py, test_protocol.py, make_cert.sh
esp32/           handheld_alert.ino
models/          yolov8n.onnx
```

## Main API additions (beyond the protocol doc)

| Endpoint | Purpose |
|---|---|
| `POST /api/drone/telemetry` | drone heartbeat, 2 Hz |
| `POST /api/handheld/heartbeat` | officer GPS/battery; returns the open alerts for that device |
| `GET /api/handheld/alerts?device_id=` | polling version for ESP32 |
| `POST /api/alerts/<id>/officer` | `{"device_id","action":"ACK"/"EN_ROUTE"/"ON_SCENE"}` |
| `POST /api/alerts/<id>/dispatch`, `/dismiss` | operator decisions |
| `POST /api/handheld/data` with `alert_id` | verification scan that closes an alert |
| `GET /api/stream?role=dashboard\|handheld` | live Server-Sent Events |
| `GET /video_feed` | annotated MJPEG stream |
| `GET /api/audit/verify` | re-checks the whole hash chain |

## Blockchain + cybersecurity (theme: Blockchain & Cybersecurity)

**1. Blockchain evidence ledger** (`ledger.py`)
- Every 10 s the Control Unit seals a **block** containing every new audit entry and the **SHA-256 of every evidence photo and replay clip**. Audit entries cover runs, alerts, dispatches, officer actions, handheld scans, messages, logins and security events.
- Each block holds a Merkle root and the previous block's hash, and is **signed with the Control Unit's Ed25519 key** (proof of authority).
- **Verify** re-walks the chain and does four checks: re-hashes every evidence file, checks every signature, recomputes every Merkle root, and recomputes every audit entry from its contents. Anything edited, deleted or re-ordered shows up.

**2. Public anchoring: works online and offline** (`anchor.py`)
- **Online:** every minute, and at the end of each run, the newest block hash is published to **Bitcoin through OpenTimestamps**. No wallet or cost is needed, and a `.ots` receipt is saved.
- **Optionally Polygon Amoy:** `python -m pip install web3`, set `$env:POLYGON_PRIVATE_KEY="0x..."` for a test wallet, and get test POL from the Amoy faucet. The Polygon transaction link then appears in the Security centre.
- **Offline:** anchors are marked `QUEUED_OFFLINE` and sent automatically when internet returns. Each block contains the previous block's hash, so one anchor covers every earlier block.

**3. Signed device messages** (`security.py`)
- The drone, handhelds and ESP32 sign every message: `HMAC-SHA256(device key, timestamp + nonce + method + path + SHA-256(body))`.
- In `SECURITY_MODE=enforce` (the default), the Control Unit rejects **unsigned, forged, altered, replayed, stale and impersonating** packets, and logs each rejection as a security event.
- **Phones pair** with a one-time 6-digit code. In the dashboard: **Security → Devices → Get pairing code**; on the phone, enter it on the handheld page. That's needed once per phone.
- **ESP32 / drone computer:** in the dashboard, **Security → Devices → Create device key** (supervisor), then paste the key into the sketch as `DEVICE_SECRET`.
- The simulators on the laptop create their own keys automatically.

**4. Operator accounts:**

| User | Password | Role |
|---|---|---|
| `supervisor` | `Supervisor@123` | everything, plus security settings, device keys and demos |
| `operator` | `Operator@123` | runs, dispatch, alerts, messages, pairing |
| `viewer` | `Viewer@123` | watch only |

- **Change them:** `python tools/set_password.py supervisor`.
- Passwords are stored as PBKDF2 hashes. An account locks for 2 minutes after 5 failed logins, and logins and pairing are rate-limited.
- Every action is recorded under the signed-in user's name.
- Evidence images are served only to signed-in users, or through links that expire and are handed to the paired handheld.

**5. HTTPS:** `python -m control_unit.server --https --video 0` creates a certificate automatically (no OpenSSL needed). Open `https://<laptop-ip>:5000/handheld` on the phone and accept the warning once; the phone then gets GPS.

**6. Security centre** (the 🛡 button): ledger height, anchors, internet status, devices with signed and rejected counts, the security event log, a **Verify** button, and a **live attack demo** for judges:
- **Fire forged, replayed and altered packets:** 6 attacks, all blocked, with the reason for each.
- **Insider edits evidence + records:** it blacks out the object in an evidence photo and downgrades a stored threat. Verification immediately reports both. **Restore** puts everything back.

**7. Independent verification:** every run export contains `ledger.json`, `evidence_proofs.json`, the anchor receipts and `verify_evidence.py`. Anyone can run it without the Control Unit:
```
cd RUN_001_log
python verify_evidence.py
```
It checks each photo's hash, its Merkle proof, the block signature, and the chain up to the anchored block.

**Settings:** `SECURITY_MODE=enforce|monitor|off`, `REQUIRE_LOGIN=1|0`, `LEDGER_BLOCK_S=10`, `ANCHOR_INTERVAL_S=60`, `ANCHOR_BACKENDS=opentimestamps,polygon`.

**What these protections don't cover (be upfront with judges):**
- The drone video link itself isn't encrypted by this software; that's the radio's job (use a digital link with encryption, e.g. AES on the air unit).
- The ledger is **permissioned** (one signing authority, the Control Unit); public anchoring is what makes it tamper-evident to outsiders.
- The SQLite database isn't encrypted at rest; use full-disk encryption (BitLocker) on the Control Unit laptop.

## Before field use

- Change the default passwords, keep `SECURITY_MODE=enforce`, and run with `--https`
- Flask's built-in server is fine for a demo. For long runs, use `waitress` or `gunicorn` with threads
