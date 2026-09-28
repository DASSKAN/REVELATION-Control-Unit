"""
Wipe runs, events, alerts and the audit log (e.g. after testing) and archive
the old database + evidence frames instead of deleting them.

Stop the Control Unit first, then:   python tools/reset_db.py
"""
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from control_unit import config  # noqa: E402

stamp = time.strftime("%Y%m%d_%H%M%S")
archive = os.path.join(config.ROOT, "data", f"archive_{stamp}")
os.makedirs(archive, exist_ok=True)
moved = 0
for f in (config.DB_PATH, config.DB_PATH + "-wal", config.DB_PATH + "-shm"):
    if os.path.exists(f):
        shutil.move(f, os.path.join(archive, os.path.basename(f)))
        moved += 1
if os.path.isdir(config.EVIDENCE_DIR):
    ev = [x for x in os.listdir(config.EVIDENCE_DIR) if x.endswith(".jpg")]
    if ev:
        os.makedirs(os.path.join(archive, "evidence"), exist_ok=True)
        for x in ev:
            shutil.move(os.path.join(config.EVIDENCE_DIR, x), os.path.join(archive, "evidence", x))
print(f"Archived old database and {len(ev) if os.path.isdir(config.EVIDENCE_DIR) else 0} evidence frames to {archive}")
print("Next start of the Control Unit begins with a clean log (RUN_001, ALT_0001).")
