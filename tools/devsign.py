"""
Request signing for field devices (used by the simulators; reference for the drone
companion computer). Every request gets X-Device-Id / X-Timestamp / X-Nonce /
X-Signature headers: HMAC-SHA256(secret, "ts\\nnonce\\nMETHOD\\npath\\nsha256(body)").

The simulators run on the Control Unit laptop, so they read (or create) their
secret in data/devices.json directly. A real device gets its secret by pairing
(phone) or from  Security centre -> Provision device  (ESP32 / drone computer).
"""
import hashlib
import hmac
import json
import os
import secrets
import time
from urllib.parse import urlparse

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEVICES = os.path.join(ROOT, "data", "devices.json")


def local_secret(device_id, dtype):
    """Secret for a simulator on this laptop; provisions it on first use."""
    os.makedirs(os.path.dirname(DEVICES), exist_ok=True)
    d = json.load(open(DEVICES)) if os.path.exists(DEVICES) else {}
    if device_id not in d or d[device_id].get("revoked"):
        d[device_id] = {"secret": secrets.token_hex(32), "type": dtype,
                        "created": time.strftime("%Y-%m-%dT%H:%M:%S"), "by": "local simulator", "revoked": False}
        tmp = DEVICES + ".tmp"
        json.dump(d, open(tmp, "w"), indent=2)
        os.replace(tmp, DEVICES)
    return d[device_id]["secret"]


class DeviceAuth(requests.auth.AuthBase):
    def __init__(self, device_id, secret_hex):
        self.dev, self.key = device_id, bytes.fromhex(secret_hex)

    def __call__(self, r):
        body = r.body or b""
        if isinstance(body, str):
            body = body.encode()
        ts, nonce = str(int(time.time())), secrets.token_hex(12)
        path = urlparse(r.url).path
        msg = f"{ts}\n{nonce}\n{r.method.upper()}\n{path}\n{hashlib.sha256(body).hexdigest()}"
        r.headers.update({"X-Device-Id": self.dev, "X-Timestamp": ts, "X-Nonce": nonce,
                          "X-Signature": hmac.new(self.key, msg.encode(), hashlib.sha256).hexdigest()})
        return r


def session(device_id, dtype="HANDHELD", secret=None):
    s = requests.Session()
    s.auth = DeviceAuth(device_id, secret or local_secret(device_id, dtype))
    return s
