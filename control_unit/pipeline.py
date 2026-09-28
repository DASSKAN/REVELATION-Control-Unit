"""
Video pipeline (one per camera):  capture -> detect -> track -> rules -> geolocate -> alert,
an annotated MJPEG stream for the dashboard, and a short evidence clip around every alert.

A camera is either the drone camera (linked to drone telemetry, so detections get
projected GPS coordinates) or a fixed CCTV camera (optionally with its own lat/lon).
"""
import collections
import csv
import os
import threading
import time
from datetime import datetime

import cv2
import numpy as np

from . import config, geo
from .detector import Detector
from .rules import RuleEngine
from .tracker import Tracker

_LOG_LOCK = threading.Lock()
GREEN = (80, 220, 120)
CYAN = (230, 200, 60)
RED = (60, 60, 255)
AMBER = (0, 190, 255)
WHITE = (240, 240, 240)


def _open(source):
    src = int(source) if str(source).isdigit() else source
    cap = cv2.VideoCapture(src, cv2.CAP_FFMPEG) if isinstance(src, str) and "://" in src else cv2.VideoCapture(src)
    return cap


class VideoPipeline:
    def __init__(self, hub, source=None, cam=None):
        """
        cam = {"id": "CAM_1", "name": "Drone camera", "drone_id": "DRONE_01" or None,
               "lat": None, "lon": None}
        """
        self.hub = hub
        self.source = config.VIDEO_SOURCE if source is None else source
        self.cam = cam or {"id": "CAM_1", "name": "Drone camera", "drone_id": config.VIDEO_DRONE_ID,
                           "lat": None, "lon": None}
        self.clip_buf = collections.deque(maxlen=max(1, int(config.CLIP_PRE_S * config.CLIP_FPS)))
        self.clips = []            # active post-alert recordings: {"dir","until","n"}
        self.clip_lock = threading.Lock()
        self.tracks = []           # latest tracker output (written by the detect loop, drawn by the video loop)
        self.last_clip_t = 0.0
        self.is_file = bool(self.source) and os.path.isfile(str(self.source))
        self.detector = None
        groups = {c: "person" for c in config.PERSON_CLASSES}
        groups.update({c: "bag" for c in config.BAG_CLASSES})
        self.tracker = Tracker(groups, conf_new=config.CONF_THRESHOLD, conf_keep=config.TRACK_KEEP_CONF,
                               max_age={"person": config.PERSON_MAX_AGE_S, "bag": config.BAG_MAX_AGE_S})
        self.rules = RuleEngine()
        self.rules.set_zones(hub.store.list_zones(self.cam["id"]))
        self.latest_raw = None
        self.raw_lock = threading.Lock()
        self.jpeg = None
        self.jpeg_cond = threading.Condition()
        self.status = {"video": "NO SOURCE" if not self.source else "CONNECTING", "fps": 0.0,
                       "infer_ms": 0.0, "backend": None, "source": str(self.source), "tracks": 0,
                       "cam_id": self.cam["id"], "name": self.cam["name"],
                       "drone_id": self.cam.get("drone_id")}
        self.running = True

    # ------------------------------------------------------------ public
    def start(self):
        try:
            classes = list(config.PERSON_CLASSES) + list(config.BAG_CLASSES)
            self.detector = Detector(config.MODEL_PATH, config.MODEL_INPUT,
                                     min(config.CONF_THRESHOLD, config.TRACK_KEEP_CONF),
                                     config.NMS_THRESHOLD, keep_classes=classes)
            self.status["backend"] = self.detector.backend
        except Exception as e:
            self.hub.log(f"[video] detector failed to load: {e}")
            self.status["backend"] = f"ERROR: {e}"
        threading.Thread(target=self._reader, daemon=True, name=f"video-reader-{self.cam['id']}").start()
        threading.Thread(target=self._processor, daemon=True, name=f"video-proc-{self.cam['id']}").start()

    def set_zones(self, zones):
        self.rules.set_zones(zones)

    def frames(self):
        """Generator of JPEG bytes for the MJPEG endpoint."""
        last = None
        while self.running:
            with self.jpeg_cond:
                self.jpeg_cond.wait(timeout=1.0)
                buf = self.jpeg
            if buf is not None and buf is not last:
                last = buf
                yield buf

    # ------------------------------------------------------------ capture
    def _reader(self):
        if not self.source:
            while self.running:
                with self.raw_lock:
                    self.latest_raw = None
                time.sleep(0.5)
            return
        while self.running:
            cap = _open(self.source)
            if not cap.isOpened():
                self.status["video"] = "NO SIGNAL"
                self.hub.log(f"[video] cannot open {self.source}; retrying")
                time.sleep(2)
                continue
            self.status["video"] = "LIVE"
            fps = cap.get(cv2.CAP_PROP_FPS) or 30
            period = 1.0 / fps if self.is_file and fps > 0 else 0
            t_next = time.time()
            while self.running:
                ok, frame = cap.read()
                if not ok:
                    if self.is_file and config.VIDEO_LOOP_FILES:
                        cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
                        continue
                    self.status["video"] = "NO SIGNAL"
                    break
                with self.raw_lock:
                    self.latest_raw = (time.time(), frame)
                if period:   # play files in real time
                    t_next += period
                    d = t_next - time.time()
                    if d > 0:
                        time.sleep(d)
                    else:
                        t_next = time.time()
            cap.release()
            time.sleep(1)

    # ------------------------------------------------------------ processing
    # Two loops so a slow model never slows the video:
    #   _processor  : every camera frame -> draw the latest boxes -> stream + replay buffer   (camera fps)
    #   _detect_loop: newest frame -> model -> tracker -> rules -> alerts                    (model fps)
    def _processor(self):
        last_t = None
        frames_win = 0
        last_pub = 0
        threading.Thread(target=self._detect_loop, daemon=True, name=f"detect-{self.cam['id']}").start()
        while self.running:
            with self.raw_lock:
                item = self.latest_raw
            if item is None or item[0] == last_t:
                if item is None and self.status["video"] != "LIVE":
                    self._publish(self._placeholder(self.status["video"]))
                    time.sleep(0.5)
                else:
                    time.sleep(0.004)
                continue
            last_t, frame = item
            drone = self.hub.drone_state(self.cam["drone_id"]) if self.cam.get("drone_id") else None
            tracks = list(self.tracks)
            annot = self._annotate(frame, tracks, drone, set())
            self._record(annot, last_t)
            self._publish(annot)
            frames_win += 1
            if time.time() - last_pub > 1.0:
                self.status["fps"] = round(frames_win / (time.time() - last_pub), 1) if last_pub else 0.0
                frames_win = 0
                last_pub = time.time()
                self.status["recording"] = len(self.clips)
                self.hub.bus.publish("video_status", {
                    **self.status,
                    "persons": sum(1 for t in tracks if t.cls in config.PERSON_CLASSES),
                    "bags": sum(1 for t in tracks if t.cls in config.BAG_CLASSES),
                })
                try:
                    self._log_tracks(tracks, frame.shape[1], frame.shape[0], drone)
                except Exception as e:
                    self.hub.log(f"[video] detection log failed: {e}")

    def _detect_loop(self):
        last_t = None
        det_n, det_t0 = 0, time.time()
        while self.running:
            with self.raw_lock:
                item = self.latest_raw
            if not self.detector or item is None or item[0] == last_t:
                time.sleep(0.005)
                continue
            last_t, frame = item
            H, W = frame.shape[:2]
            try:
                ti = time.time()
                dets = self.detector(frame, config.DETECT_TILES)
                self.status["infer_ms"] = round((time.time() - ti) * 1000, 1)
                tracks = self.tracker.update(dets, last_t)
                self.tracks = tracks
                det_n += 1
                if time.time() - det_t0 > 2:
                    self.status["det_fps"] = round(det_n / (time.time() - det_t0), 1)
                    det_n, det_t0 = 0, time.time()
                armed = self.hub.store.active_run() is not None
                if armed and not getattr(self, "_was_armed", False):
                    # new run = clean slate: forget cooldowns / alerted flags from the previous run
                    self.rules.cooldown.clear()
                    for t in tracks:
                        t.state.pop("alerted", None)
                    # run just started: record what the camera is already watching
                    np_ = sum(1 for t in tracks if t.cls in config.PERSON_CLASSES)
                    bags = [t for t in tracks if t.cls in config.BAG_CLASSES]
                    un = [t for t in bags if t.state.get("unattended_since")]
                    self.rules.notes.append(("info", f"run armed: tracking {np_} persons, {len(bags)} bags"
                                             + (f" ({len(un)} already unattended: " + ", ".join(
                                                 f"{t.name} #{t.id} {t.state.get('unattended_for', 0):.0f}s" for t in un) + ")"
                                                if un else "")))
                self._was_armed = armed
                findings = self.rules.evaluate(tracks, W, H, last_t, armed=armed)
                for f in findings:
                    self.rules.notes.append(("warn", f"RULE {f['rule']} fired: {f['description']}"))
                self.status["tracks"] = len(tracks)
                run = self.hub.store.active_run() if self.rules.notes else None
                for level, text in self.rules.notes:
                    text = f"{self.cam['id']}: {text}"
                    self.hub.bus.publish("ai_note", {"level": level, "text": text})
                    if run:
                        self.hub.store.add_ai_log(run["run_id"], self.cam["id"], level, text)
                self.rules.notes.clear()
                if findings:
                    drone = self.hub.drone_state(self.cam["drone_id"]) if self.cam.get("drone_id") else None
                    annot = self._annotate(frame, tracks, drone, {f["track"].id for f in findings})
                    for f in findings:
                        g = self._geolocate(f["track"], W, H, drone) if drone else None
                        ev = self._evidence(frame, annot, f)
                        try:
                            ref = self.hub.new_evidence_ref(f["rule"])
                            clip = self._start_clip(ref, last_t)
                            self.hub.raise_ai_alert(f, ev, frame, g, drone, cam=self.cam, ev_ref=ref, clip_ref=clip)
                        except Exception as e:
                            self.hub.log(f"[video] alert failed: {e}")
            except Exception as e:
                self.hub.log(f"[video] detection error: {e}")
                time.sleep(0.5)

    # ------------------------------------------------------------ detection log (1 row per object per second)
    LOG_COLS = ["timestamp", "run_id", "cam_id", "camera", "track_id", "class", "confidence",
                "x1", "y1", "x2", "y2", "state", "object_lat", "object_lon", "drone_lat", "drone_lon", "drone_alt_m"]

    def _log_tracks(self, tracks, W, H, drone):
        run = self.hub.store.active_run()
        if not run or not tracks:
            return
        path = os.path.join(config.ROOT, "data", "logs", f"{run['run_id']}_detections.csv")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        ts = datetime.now().astimezone().isoformat(timespec="seconds")
        rows = []
        for t in tracks:
            if time.time() - t.last_seen > 1.5:
                continue
            if t.state.get("alerted"):
                state = "ALERTED"
            elif t.state.get("in_zone"):
                state = f"IN_ZONE:{t.state['in_zone']}"
            elif t.state.get("unattended_for", 0) > 1:
                state = f"UNATTENDED_{t.state['unattended_for']:.0f}s"
            elif t.state.get("owner"):
                state = f"ATTENDED_BY_{t.state['owner']}"
            else:
                state = "TRACKED"
            g = self._geolocate(t, W, H, drone) if drone else None
            rows.append([ts, run["run_id"], self.cam["id"], self.cam["name"], t.id, t.name, f"{t.conf:.3f}",
                         *[int(v) for v in t.box], state,
                         f"{g[0]:.7f}" if g else "", f"{g[1]:.7f}" if g else "",
                         drone.get("latitude", "") if drone else "", drone.get("longitude", "") if drone else "",
                         drone.get("alt_agl", "") if drone else ""])
        with _LOG_LOCK:
            new = not os.path.exists(path)
            with open(path, "a", newline="") as f:
                w = csv.writer(f)
                if new:
                    w.writerow(self.LOG_COLS)
                w.writerows(rows)

    # ------------------------------------------------------------ evidence clips
    def _record(self, img, t):
        if t - self.last_clip_t < 1.0 / config.CLIP_FPS:
            return
        self.last_clip_t = t
        h = int(img.shape[0] * config.CLIP_WIDTH / img.shape[1])
        small = cv2.resize(img, (config.CLIP_WIDTH, h), interpolation=cv2.INTER_AREA)
        ok, buf = cv2.imencode(".jpg", small, [cv2.IMWRITE_JPEG_QUALITY, 70])
        if not ok:
            return
        b = buf.tobytes()
        with self.clip_lock:
            self._record_locked(b, t)

    def _record_locked(self, b, t):
        self.clip_buf.append(b)
        for c in list(self.clips):
            self._write_clip_frame(c, b)
            if t >= c["until"]:
                self.clips.remove(c)
                if getattr(self.hub, "ledger", None):
                    self.hub.ledger.add_clip(c["ref"], c["dir"])     # hash of every replay frame -> blockchain

    def _start_clip(self, ref, t):
        d = os.path.join(config.EVIDENCE_DIR, "clips", ref)
        os.makedirs(d, exist_ok=True)
        c = {"dir": d, "until": t + config.CLIP_POST_S, "n": 0, "ref": ref}
        with self.clip_lock:
            pre = list(self.clip_buf)
        for b in pre:                           # the seconds BEFORE the alert
            self._write_clip_frame(c, b)
        c["alert_index"] = c["n"]
        with open(os.path.join(d, "meta.txt"), "w") as f:
            f.write(f"fps={config.CLIP_FPS}\nalert_frame={c['n']}\ncamera={self.cam['name']}\n")
        with self.clip_lock:
            self.clips.append(c)
        return ref

    @staticmethod
    def _write_clip_frame(c, b):
        with open(os.path.join(c["dir"], f"f_{c['n']:04d}.jpg"), "wb") as f:
            f.write(b)
        c["n"] += 1

    def _geolocate(self, tr, W, H, drone):
        if not drone or drone.get("latitude") is None:
            return None
        u, v = tr.foot
        return geo.pixel_to_ground(
            u, v, W, H, drone["latitude"], drone["longitude"], drone.get("alt_agl"),
            drone.get("heading", 0.0), drone.get("gimbal_pitch", config.DEFAULT_GIMBAL_PITCH_DEG),
            config.CAMERA_HFOV_DEG, config.MAX_GEO_RANGE_M)

    # ------------------------------------------------------------ drawing
    def _annotate(self, frame, tracks, drone, flagged):
        img = frame.copy()
        H, W = img.shape[:2]
        s = max(1.0, W / 1280)
        # zones
        if self.rules.zones:
            over = img.copy()
            for z in self.rules.zones:
                pts = np.array([[x * W, y * H] for x, y in z["polygon"]], np.int32)
                cv2.fillPoly(over, [pts], (40, 40, 200))
                cv2.polylines(img, [pts], True, RED, max(1, int(2 * s)))
                cv2.putText(img, z["name"], tuple(pts[0]), cv2.FONT_HERSHEY_SIMPLEX, 0.5 * s, RED, max(1, int(s)))
            img = cv2.addWeighted(over, 0.18, img, 0.82, 0)
        # tracks
        for t in tracks:
            if t.cls in config.PERSON_CLASSES and time.time() - t.last_seen > 1.0:
                continue
            if t.cls in config.BAG_CLASSES and t.max_conf < config.BAG_MIN_CONF:
                continue            # never seen clearly: not shown (likely a bucket / can / cloth)
            x1, y1, x2, y2 = map(int, t.box)
            is_bag = t.cls in config.BAG_CLASSES
            col = CYAN if is_bag else GREEN
            label = f"{t.name} #{t.id} {t.conf:.2f}"
            ua = t.state.get("unattended_for", 0)
            if is_bag and ua > 1:
                col = AMBER
                label += f" unattended {ua:.0f}/{config.ABANDON_SECONDS:.0f}s"
            elif is_bag and t.state.get("owner"):
                label += f" near #{t.state['owner']}"
            if t.state.get("in_zone"):
                col = RED
                label += " IN ZONE"
            if t.id in flagged or t.state.get("alerted"):
                col = RED
                if t.state.get("alerted"):
                    label = f"THREAT: {t.name} #{t.id} abandoned {ua:.0f}s"
            th = max(1, int((4 if t.state.get("alerted") else 2) * s))
            cv2.rectangle(img, (x1, y1), (x2, y2), col, th)
            (tw, tht), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, 0.45 * s, 1)
            cv2.rectangle(img, (x1, y1 - tht - 6), (x1 + tw + 6, y1), col, -1)
            cv2.putText(img, label, (x1 + 3, y1 - 4), cv2.FONT_HERSHEY_SIMPLEX, 0.45 * s, (20, 20, 20), 1,
                        cv2.LINE_AA)
        # HUD
        run = self.hub.store.active_run()
        lines = [f"{self.cam['id']}  {self.cam['name'].upper()}   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                 f"RUN {run['run_id']} {run['status']}" if run else "NO ACTIVE RUN - not logging"]
        if drone:
            lines.append(f"{drone['device_id']}  ALT {drone.get('alt_agl', 0):.0f}m  "
                         f"HDG {drone.get('heading', 0):03.0f}  SPD {drone.get('speed', 0):.1f}m/s  "
                         f"BAT {drone.get('battery', '-')}%  LINK {drone.get('link', '-')}")
            if drone.get("latitude") is not None:
                lines.append(f"GPS {drone['latitude']:.6f}, {drone['longitude']:.6f}")
        elif self.cam.get("drone_id"):
            lines.append(f"{self.cam['drone_id']}: no telemetry")
        y = int(24 * s)
        for ln in lines:
            cv2.putText(img, ln, (int(12 * s), y), cv2.FONT_HERSHEY_SIMPLEX, 0.5 * s, (0, 0, 0), 3, cv2.LINE_AA)
            cv2.putText(img, ln, (int(12 * s), y), cv2.FONT_HERSHEY_SIMPLEX, 0.5 * s, WHITE, 1, cv2.LINE_AA)
            y += int(20 * s)
        if run and int(time.time() * 2) % 2 == 0:
            cv2.circle(img, (W - int(70 * s), int(22 * s)), int(7 * s), (40, 40, 235), -1)
        if run:
            cv2.putText(img, "REC", (W - int(58 * s), int(28 * s)), cv2.FONT_HERSHEY_SIMPLEX, 0.55 * s, WHITE,
                        max(1, int(1.5 * s)), cv2.LINE_AA)
        return img

    def _evidence(self, frame, annot, f):
        img = annot.copy()
        x1, y1, x2, y2 = map(int, f["track"].box)
        cv2.rectangle(img, (x1 - 4, y1 - 4), (x2 + 4, y2 + 4), RED, 3)
        banner = f"{f['rule']}  {f['threat_level']}  {f['description']}"
        cv2.rectangle(img, (0, img.shape[0] - 34), (img.shape[1], img.shape[0]), (20, 20, 160), -1)
        cv2.putText(img, banner[:120], (10, img.shape[0] - 11), cv2.FONT_HERSHEY_SIMPLEX, 0.6, WHITE, 1,
                    cv2.LINE_AA)
        return img

    def _placeholder(self, text):
        img = np.full((720, 1280, 3), 18, np.uint8)
        cv2.putText(img, text, (60, 360), cv2.FONT_HERSHEY_SIMPLEX, 1.4, (90, 90, 90), 2, cv2.LINE_AA)
        cv2.putText(img, f"source: {self.source or 'not configured (set VIDEO_SOURCE)'}", (60, 410),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (90, 90, 90), 1, cv2.LINE_AA)
        return img

    def _publish(self, img):
        if img.shape[1] > config.STREAM_WIDTH:
            h = int(img.shape[0] * config.STREAM_WIDTH / img.shape[1])
            img = cv2.resize(img, (config.STREAM_WIDTH, h), interpolation=cv2.INTER_AREA)
        ok, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, config.JPEG_QUALITY])
        if ok:
            with self.jpeg_cond:
                self.jpeg = buf.tobytes()
                self.jpeg_cond.notify_all()
