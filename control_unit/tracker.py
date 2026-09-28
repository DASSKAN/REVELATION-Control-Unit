"""
Lightweight multi-object tracker (IoU + centre-distance matching).
Gives every person/bag a stable ID so the rules can reason over time.

Robustness features (these matter on low-quality webcam / drone video):
  - hysteresis: a new track needs conf >= conf_new, an existing track is kept
    alive by detections down to conf_keep
  - per-group memory: bags are static, so a bag track survives many missed
    frames (bag_max_age); people expire quickly (person_max_age)
  - class groups: the model often flips a bag between backpack / handbag /
    suitcase; those labels are treated as the same object
"""
import itertools
import time
from collections import Counter

import numpy as np


def iou(a, b):
    x1, y1 = max(a[0], b[0]), max(a[1], b[1])
    x2, y2 = min(a[2], b[2]), min(a[3], b[3])
    inter = max(0.0, x2 - x1) * max(0.0, y2 - y1)
    ua = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / ua if ua > 0 else 0.0


class Track:
    def __init__(self, tid, det, t, group):
        self.id = tid
        self.group = group
        self.cls = det["cls"]
        self.name = det["name"]
        self.labels = Counter({(det["cls"], det["name"]): 1})
        self.box = list(det["box"])
        self.conf = det["conf"]
        self.max_conf = det["conf"]
        self.first_seen = t
        self.last_seen = t
        self.hits = 1
        self.history = [(t, *self.center)]      # (t, cx, cy)
        self.state = {}                         # scratch space for rules

    @property
    def center(self):
        b = self.box
        return ((b[0] + b[2]) / 2, (b[1] + b[3]) / 2)

    @property
    def foot(self):
        b = self.box
        return ((b[0] + b[2]) / 2, b[3])

    @property
    def height(self):
        return self.box[3] - self.box[1]

    def update(self, det, t):
        a = 0.6   # light smoothing to stop boxes jittering
        self.box = [a * n + (1 - a) * o for n, o in zip(det["box"], self.box)]
        # confidence: smoothed, so one weak frame doesn't drop the displayed score
        self.conf = 0.7 * self.conf + 0.3 * det["conf"]
        self.max_conf = max(self.max_conf, det["conf"])
        self.labels[(det["cls"], det["name"])] += 1
        (self.cls, self.name), _ = self.labels.most_common(1)[0]
        self.last_seen = t
        self.hits += 1
        self.history.append((t, *self.center))
        if len(self.history) > 600:
            self.history = self.history[-600:]

    def displacement_since(self, t0):
        pts = [(x, y) for (t, x, y) in self.history if t >= t0]
        if len(pts) < 2:
            return 0.0
        pts = np.array(pts)
        med = np.median(pts, 0)
        # 90th percentile, so a few wild boxes from a bad frame don't count as movement
        return float(np.percentile(np.linalg.norm(pts - med, axis=1), 90) * 2)


class Tracker:
    def __init__(self, groups, conf_new=0.35, conf_keep=0.15, max_age=None, iou_thr=0.2, min_hits=3):
        """
        groups     {cls_id: group_name}, e.g. {0:"person", 24:"bag", 26:"bag", 28:"bag"}
        max_age    {group_name: seconds}
        """
        self.groups = groups
        self.conf_new = conf_new
        self.conf_keep = conf_keep
        self.max_age = max_age or {}
        self.tracks = {}
        self.ids = itertools.count(1)
        self.iou_thr = iou_thr
        self.min_hits = min_hits

    def update(self, dets, t=None):
        t = time.time() if t is None else t
        dets = [d for d in dets if d["conf"] >= self.conf_keep and d["cls"] in self.groups]
        pairs = []
        for tid, tr in self.tracks.items():
            for j, d in enumerate(dets):
                if self.groups[d["cls"]] != tr.group:
                    continue
                s = iou(tr.box, d["box"])
                if s < self.iou_thr:
                    # allow centre-distance match for small / fast objects
                    cx, cy = tr.center
                    b = d["box"]
                    dist = np.hypot((b[0] + b[2]) / 2 - cx, (b[1] + b[3]) / 2 - cy)
                    if dist < 0.5 * max(tr.height, 1):
                        s = self.iou_thr * 0.99
                    else:
                        continue
                pairs.append((s, tid, j))
        pairs.sort(reverse=True)
        used_t, used_d = set(), set()
        for s, tid, j in pairs:
            if tid in used_t or j in used_d:
                continue
            self.tracks[tid].update(dets[j], t)
            used_t.add(tid)
            used_d.add(j)
        for j, d in enumerate(dets):
            if j not in used_d and d["conf"] >= self.conf_new:
                tid = next(self.ids)
                self.tracks[tid] = Track(tid, d, t, self.groups[d["cls"]])
        for tid in [k for k, tr in self.tracks.items()
                    if t - tr.last_seen > self.max_age.get(tr.group, 3.0)]:
            del self.tracks[tid]
        return [tr for tr in self.tracks.values() if tr.hits >= self.min_hits]
