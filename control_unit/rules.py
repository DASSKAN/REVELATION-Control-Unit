"""
Threat rules that turn tracked objects into suspicious-activity findings.

The drone camera cannot see narcotics or explosives. What it can flag is
behaviour that warrants a close-range check with the handheld:

  ABANDONED_BAGGAGE   bag stationary with nobody near it for ABANDON_SECONDS   -> HIGH
  RESTRICTED_ZONE     person inside an operator-drawn zone (e.g. track bed)    -> HIGH
  LOITERING           person stays in one spot for LOITER_SECONDS              -> MEDIUM

The image-space stationarity checks assume the drone is hovering or the
camera view is roughly fixed. While the drone is translating, only the zone
rule is reliable, and zones are drawn relative to the current view.
"""
import math
import time

import cv2
import numpy as np

from . import config


def _same_object(pbox, bbox):
    """True if a person box is really the bag itself (same place, similar size)."""
    x1, y1 = max(pbox[0], bbox[0]), max(pbox[1], bbox[1])
    x2, y2 = min(pbox[2], bbox[2]), min(pbox[3], bbox[3])
    inter = max(0.0, x2 - x1) * max(0.0, y2 - y1)
    pa = (pbox[2] - pbox[0]) * (pbox[3] - pbox[1])
    ba = (bbox[2] - bbox[0]) * (bbox[3] - bbox[1])
    if pa <= 0 or ba <= 0:
        return False
    # the person box is mostly covered by the bag and is not much bigger than it
    return inter / pa > 0.5 and pa < 2.5 * ba


def point_in_poly(pt, poly_px):
    return cv2.pointPolygonTest(np.array(poly_px, dtype=np.float32), pt, False) >= 0


class RuleEngine:
    def __init__(self):
        self.zones = []          # list of {"zone_id","name","polygon":[[x,y] normalised]}
        self.cooldown = {}       # (rule, track_id) -> last fire time
        self.notes = []          # (level, text) for the operator log; drained by the pipeline
        self.armed = False       # True while an inspection run is active

    def set_zones(self, zones):
        self.zones = zones

    def _ready(self, key, now):
        # Only fire (and only start the cooldown) while an inspection run is active.
        # Otherwise a bag left before "Start run" would burn its cooldown and never alert.
        if not self.armed:
            return False
        last = self.cooldown.get(key)
        if last is not None and now - last < config.ALERT_COOLDOWN_SECONDS:
            return False
        self.cooldown[key] = now
        return True

    def evaluate(self, tracks, frame_w, frame_h, now=None, armed=True):
        now = time.time() if now is None else now
        self.armed = armed
        diag = math.hypot(frame_w, frame_h)
        still = config.STATIONARY_FRACTION * diag
        people = [t for t in tracks if t.cls in config.PERSON_CLASSES]
        bags = [t for t in tracks if t.cls in config.BAG_CLASSES and t.max_conf >= config.BAG_MIN_CONF]
        findings = []

        # ---- abandoned baggage
        for b in bags:
            if not b.state.get("announced"):
                b.state["announced"] = True
                self.notes.append(("info", f"{b.name} #{b.id} detected"))
            bx, by = b.center
            radius = config.OWNER_RADIUS_BAG_HEIGHTS * max(b.height, 20)
            owner = None
            for p in people:
                if now - p.last_seen > 1.0:
                    continue            # person not actually seen in the last second
                if _same_object(p.box, b.box):
                    continue            # a "person" box on top of the bag is the bag misread
                pw, ph = p.box[2] - p.box[0], p.box[3] - p.box[1]
                if pw * ph > config.OCCLUDER_FRACTION * frame_w * frame_h:
                    if not p.state.get("occluder_noted"):
                        p.state["occluder_noted"] = True
                        self.notes.append(("info", f"person #{p.id} fills the frame (too close to the camera): "
                                                   f"not counted as a bag owner"))
                    continue
                if math.hypot(p.center[0] - bx, p.center[1] - by) < radius:
                    owner = p
                    break
            if owner:
                if b.state.get("unattended_since"):
                    self.notes.append(("info", f"{b.name} #{b.id} attended again (person #{owner.id} near)"))
                b.state.pop("unattended_since", None)
                b.state.pop("alerted", None)
                b.state["owner"] = owner.id
            else:
                if not b.state.get("unattended_since"):
                    b.state["unattended_since"] = now
                    self.notes.append(("warn", f"{b.name} #{b.id} unattended: alert in {config.ABANDON_SECONDS:.0f}s if nobody returns"))
                b.state.pop("owner", None)
            since = b.state.get("unattended_since")
            b.state["unattended_for"] = (now - since) if since else 0.0
            if since and now - since >= config.ABANDON_SECONDS:
                # a weak detection box jitters; judge "not moved" relative to the bag's own size
                still_b = max(still, 0.75 * b.height)
                if b.displacement_since(since) < still_b and self._ready(("ABANDONED_BAGGAGE", b.id), now):
                    b.state["alerted"] = True
                    findings.append({
                        "rule": "ABANDONED_BAGGAGE", "threat_level": "HIGH", "track": b,
                        "confidence": b.conf,
                        "description": f"{b.name} #{b.id} unattended for {now - since:.0f}s, no person within reach",
                    })

        # ---- restricted zones
        for z in self.zones:
            poly_px = [(x * frame_w, y * frame_h) for x, y in z["polygon"]]
            if len(poly_px) < 3:
                continue
            for p in people:
                key = f"zone_{z['zone_id']}_since"
                if point_in_poly(p.foot, poly_px):
                    p.state.setdefault(key, now)
                    p.state["in_zone"] = z["name"]
                    if now - p.state[key] >= config.ZONE_DWELL_SECONDS and \
                            self._ready(("RESTRICTED_ZONE", z["zone_id"], p.id), now):
                        findings.append({
                            "rule": "RESTRICTED_ZONE", "threat_level": "HIGH", "track": p,
                            "confidence": p.conf,
                            "description": f"person #{p.id} inside restricted zone '{z['name']}'",
                        })
                else:
                    p.state.pop(key, None)
                    if p.state.get("in_zone") == z["name"]:
                        p.state.pop("in_zone", None)

        # ---- loitering
        for p in people:
            age = now - p.first_seen
            if age >= config.LOITER_SECONDS and p.displacement_since(now - config.LOITER_SECONDS) < still * 1.5:
                if self._ready(("LOITERING", p.id), now):
                    findings.append({
                        "rule": "LOITERING", "threat_level": "MEDIUM", "track": p,
                        "confidence": p.conf,
                        "description": f"person #{p.id} stationary for {age:.0f}s",
                    })

        # drop cooldown entries for tracks that no longer exist
        live = {t.id for t in tracks}
        for k in [k for k in self.cooldown if k[-1] not in live and now - self.cooldown[k] > 600]:
            del self.cooldown[k]
        return findings
