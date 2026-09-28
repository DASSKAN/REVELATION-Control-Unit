"""
Offline check of tracker + abandoned-baggage rule under bad detections.
python tools/test_rules.py
"""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("ABANDON_SECONDS", "8")
from control_unit import config
from control_unit.rules import RuleEngine
from control_unit.tracker import Tracker

groups = {0: "person", 24: "bag", 26: "bag", 28: "bag"}
BAG = [700, 500, 820, 660]
fails = 0

def run(name, frames, expect_alert_between, armed_from=0):
    global fails
    random.seed(1)
    tr = Tracker(groups, config.CONF_THRESHOLD, config.TRACK_KEEP_CONF,
                 {"person": config.PERSON_MAX_AGE_S, "bag": config.BAG_MAX_AGE_S})
    re = RuleEngine()
    fired = None
    for i in range(frames):
        t = i * 0.1                                   # 10 detections per second
        dets = frames_fn(i, t)
        tracks = tr.update(dets, t)
        for f in re.evaluate(tracks, 1280, 720, t, armed=t >= armed_from):
            if f["rule"] == "ABANDONED_BAGGAGE" and fired is None:
                fired = t
    lo, hi = expect_alert_between
    ok = (fired is None and lo is None) or (fired is not None and lo is not None and lo <= fired <= hi)
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'}  {name}: alert at {fired}")

def bag_det(i):
    # detected ~55% of frames, confidence 0.18-0.5, label flips backpack/handbag
    if random.random() > 0.55:
        return []
    cls = 24 if random.random() < 0.7 else 26
    j = random.uniform(-6, 6)
    return [{"cls": cls, "name": "backpack" if cls == 24 else "handbag",
             "conf": 0.65 if random.random() < 0.15 else random.uniform(0.2, 0.5),   # a real bag is seen clearly now and then
             "box": [BAG[0]+j, BAG[1]+j, BAG[2]+j, BAG[3]+j]}]

# 1. owner stands next to bag for 5 s, walks off; flickering bag
def frames_fn(i, t):
    d = bag_det(i)
    if t < 5:
        d.append({"cls": 0, "name": "person", "conf": 0.8, "box": [850, 300, 980, 700]})
    return d
run("flickering bag, owner leaves at 5s", 250, (12.5, 15))

# 2. bag sometimes misread as a person at the same spot (your first webcam screenshot)
def frames_fn(i, t):
    d = bag_det(i)
    if random.random() < 0.3:
        d.append({"cls": 0, "name": "person", "conf": 0.42, "box": [BAG[0]-10, BAG[1]-20, BAG[2]+10, BAG[3]+5]})
    return d
run("bag partly misread as person", 200, (8, 11))

# 3. owner stays next to the bag the whole time -> no alert
def frames_fn(i, t):
    return bag_det(i) + [{"cls": 0, "name": "person", "conf": 0.8, "box": [850, 300, 980, 700]}]
run("owner stays", 300, (None, None))

# 4. your recording: bag left BEFORE "Start run"; run started 20 s later -> alert right away
def frames_fn(i, t):
    return bag_det(i)
run("bag left before Start run (run starts at 20s)", 300, (20, 21.5), armed_from=20)

# 5. an arm right in front of the lens (person box ~ whole frame) must not count as the owner
def frames_fn(i, t):
    return bag_det(i) + [{"cls": 0, "name": "person", "conf": 0.46, "box": [60, 0, 1220, 720]}]
run("arm in front of the lens is not an owner", 150, (8, 10))

# 6. a bucket the model calls "suitcase" at 0.2-0.34 (your screenshot) must never alarm
def frames_fn(i, t):
    return [{"cls": 28, "name": "suitcase", "conf": random.uniform(0.2, 0.34), "box": [300, 300, 420, 460]}]
run("weak false 'suitcase' (bucket) never alarms", 300, (None, None))

sys.exit(1 if fails else 0)
