"""
Control Unit configuration.

Every value can be overridden with an environment variable of the same name,
e.g.  VIDEO_SOURCE=rtsp://192.168.144.25:8554/main.264 python -m control_unit.server
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env(name, default, cast=str):
    val = os.environ.get(name)
    if val is None:
        return default
    if cast is bool:
        return val.strip().lower() in ("1", "true", "yes", "on")
    return cast(val)


# ---------------------------------------------------------------- server
HOST = _env("HOST", "0.0.0.0")          # 0.0.0.0 so handhelds on the Wi-Fi can reach it
PORT = _env("PORT", 5000, int)
DB_PATH = _env("DB_PATH", os.path.join(ROOT, "data", "control_unit.db"))
EVIDENCE_DIR = _env("EVIDENCE_DIR", os.path.join(ROOT, "evidence"))
API_KEY = _env("API_KEY", "")           # legacy shared key (optional); per-device signatures replace it

# ---------------------------------------------------------------- cybersecurity
# enforce = unsigned / forged / replayed device messages are rejected
# monitor = accepted but flagged on the dashboard (use while setting devices up)
# off     = no checks (lab testing only)
SECURITY_MODE = _env("SECURITY_MODE", "enforce").lower()
REQUIRE_LOGIN = _env("REQUIRE_LOGIN", True, bool)

# ---------------------------------------------------------------- blockchain ledger + public anchoring
LEDGER_BLOCK_S = _env("LEDGER_BLOCK_S", 10.0, float)          # seal a block every N s (if anything happened)
ANCHOR_INTERVAL_S = _env("ANCHOR_INTERVAL_S", 60.0, float)    # publish the newest block hash every N s
ANCHOR_BACKENDS = _env("ANCHOR_BACKENDS", "opentimestamps")   # opentimestamps,polygon
OTS_CALENDARS = [c.strip() for c in _env("OTS_CALENDARS",
                 "https://a.pool.opentimestamps.org,https://b.pool.opentimestamps.org,"
                 "https://a.pool.eternitywall.com").split(",") if c.strip()]
POLYGON_PRIVATE_KEY = _env("POLYGON_PRIVATE_KEY", "")         # test wallet key; enables Polygon anchoring
POLYGON_RPC = _env("POLYGON_RPC", "https://rpc-amoy.polygon.technology")
POLYGON_CHAIN_ID = _env("POLYGON_CHAIN_ID", 80002, int)       # 80002 = Amoy testnet
POLYGON_EXPLORER = _env("POLYGON_EXPLORER", "https://amoy.polygonscan.com")

# ---------------------------------------------------------------- drone video
# What the Control Unit reads the drone camera from:
#   "0" / "1"                      USB capture card / FPV receiver (device index)
#   "rtsp://ip:port/path"          IP camera / digital FPV / companion computer RTSP
#   "udp://@:5600"                 raw H.264 over UDP (needs OpenCV built with FFmpeg)
#   "/path/to/clip.mp4"            recorded flight, looped (demo / testing)
#   ""                             no video (telemetry + handheld only)
VIDEO_SOURCE = _env("VIDEO_SOURCE", "")
VIDEO_LOOP_FILES = _env("VIDEO_LOOP_FILES", True, bool)
VIDEO_DRONE_ID = _env("VIDEO_DRONE_ID", "DRONE_01")   # whose telemetry geolocates this video
STREAM_WIDTH = _env("STREAM_WIDTH", 1280, int)   # width of the annotated stream sent to the dashboard
JPEG_QUALITY = _env("JPEG_QUALITY", 75, int)

# ---------------------------------------------------------------- detector
MODEL_PATH = _env("MODEL_PATH", os.path.join(ROOT, "models", "yolov8n.onnx"))
MODEL_INPUT = _env("MODEL_INPUT", 640, int)
DETECT_EVERY_N_FRAMES = _env("DETECT_EVERY_N_FRAMES", 2, int)
DETECT_TILES = _env("DETECT_TILES", 1, int)   # 2 = 2x2 tiling for small targets at altitude (~5x compute)
CONF_THRESHOLD = _env("CONF_THRESHOLD", 0.35, float)
NMS_THRESHOLD = _env("NMS_THRESHOLD", 0.45, float)
# Hysteresis: a NEW object needs CONF_THRESHOLD, but an object already being tracked
# stays alive on weaker detections down to TRACK_KEEP_CONF. Stops boxes flickering out.
TRACK_KEEP_CONF = _env("TRACK_KEEP_CONF", 0.2, float)
# A bag must be seen clearly at least once (confidence >= BAG_MIN_CONF) before it is shown or can
# raise an alarm. Stops weak guesses (buckets, cans, cloth) from turning into abandoned-bag alerts.
# With the small yolov8n model use ~0.35; with yolov8s/m keep 0.5.
BAG_MIN_CONF = _env("BAG_MIN_CONF", 0.5, float)
# How long a track survives without being detected. Bags don't move, so they get longer.
PERSON_MAX_AGE_S = _env("PERSON_MAX_AGE_S", 2.0, float)
BAG_MAX_AGE_S = _env("BAG_MAX_AGE_S", 15.0, float)

# COCO class ids the rules care about
PERSON_CLASSES = {0: "person"}
BAG_CLASSES = {24: "backpack", 26: "handbag", 28: "suitcase"}

# ---------------------------------------------------------------- threat rules
# Seconds a bag must sit still with no person near it before it is "abandoned".
# 60 s is a sensible field value; lower it for demos.
ABANDON_SECONDS = _env("ABANDON_SECONDS", 20.0, float)
# "Near" = a person's box centre within this many bag-heights of the bag
OWNER_RADIUS_BAG_HEIGHTS = _env("OWNER_RADIUS_BAG_HEIGHTS", 4.0, float)
# A "person" box covering more than this fraction of the frame is someone/something right in front of
# the lens (an arm, a hand), not a person standing in the scene, so it never counts as the bag's owner.
OCCLUDER_FRACTION = _env("OCCLUDER_FRACTION", 0.35, float)
# Seconds a person must stay inside a restricted zone before alerting
ZONE_DWELL_SECONDS = _env("ZONE_DWELL_SECONDS", 2.0, float)
# Seconds a person must stay roughly in one place to count as loitering
LOITER_SECONDS = _env("LOITER_SECONDS", 90.0, float)
# Max movement (fraction of frame diagonal) still counted as "stationary"
STATIONARY_FRACTION = _env("STATIONARY_FRACTION", 0.04, float)
# Do not raise the same rule for the same track again within this window
ALERT_COOLDOWN_SECONDS = _env("ALERT_COOLDOWN_SECONDS", 120.0, float)

# Alert levels that are pushed to handhelds without waiting for the operator.
# Everything else waits for "Confirm & dispatch" on the dashboard.
AUTO_DISPATCH_LEVELS = set(
    x.strip().upper() for x in _env("AUTO_DISPATCH_LEVELS", "HIGH").split(",") if x.strip()
)

# Who gets an auto-dispatched alert first:
#   "nearest" = the closest online handheld with GPS (falls back to ALL if nobody has GPS)
#   "all"     = every online handheld
DISPATCH_MODE = _env("DISPATCH_MODE", "nearest")
# If nobody acknowledges a dispatched alert within this many seconds, it escalates:
# re-sent to ALL units, the Control Unit siren restarts and the alert is marked ESCALATED.
ESCALATE_AFTER_S = _env("ESCALATE_AFTER_S", 30.0, float)
MAX_ESCALATIONS = _env("MAX_ESCALATIONS", 3, int)

# ---------------------------------------------------------------- evidence clips
# Every AI alert saves a short clip: CLIP_PRE_S before the alert and CLIP_POST_S after it.
CLIP_PRE_S = _env("CLIP_PRE_S", 6.0, float)
CLIP_POST_S = _env("CLIP_POST_S", 6.0, float)
CLIP_FPS = _env("CLIP_FPS", 6, int)
CLIP_WIDTH = _env("CLIP_WIDTH", 640, int)

# ---------------------------------------------------------------- drone camera geometry
# Used to turn a pixel into a ground coordinate. Override per drone.
CAMERA_HFOV_DEG = _env("CAMERA_HFOV_DEG", 110.0, float)     # typical cinewhoop FPV/action cam
DEFAULT_GIMBAL_PITCH_DEG = _env("DEFAULT_GIMBAL_PITCH_DEG", -45.0, float)  # -90 = straight down
MAX_GEO_RANGE_M = _env("MAX_GEO_RANGE_M", 400.0, float)      # beyond this the projection is not trusted

# ---------------------------------------------------------------- telemetry / link health
# Drone is expected to heartbeat at 2 Hz (same rate RobotX uses for vehicle heartbeats)
LINK_DEGRADED_S = _env("LINK_DEGRADED_S", 1.5, float)
LINK_LOST_S = _env("LINK_LOST_S", 5.0, float)
HANDHELD_OFFLINE_S = _env("HANDHELD_OFFLINE_S", 20.0, float)
LOW_BATTERY_PCT = _env("LOW_BATTERY_PCT", 20, int)

# Optional: read telemetry straight from the flight controller over MAVLink
# (INAV / ArduPilot / PX4). Example: "udpin:0.0.0.0:14550". Requires `pip install pymavlink`.
MAVLINK_URL = _env("MAVLINK_URL", "")
MAVLINK_DRONE_ID = _env("MAVLINK_DRONE_ID", "DRONE_01")

# Station context shown to operators
DEFAULT_ZONE = _env("DEFAULT_ZONE", "PLATFORM_01")
