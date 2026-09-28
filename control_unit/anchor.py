"""
Public anchoring of the ledger head.

Why: the Control Unit's own chain proves nothing was changed *after* sealing
only if nobody could quietly rebuild the whole chain. Publishing the latest
block hash to a public blockchain fixes that: a rebuilt chain would have a
different hash from the one already on Bitcoin / Polygon.

Backends (set ANCHOR_BACKENDS, comma separated):
  opentimestamps  Free, no wallet. The block hash is submitted to public
                  OpenTimestamps calendars, which aggregate it into a Bitcoin
                  transaction (confirmed in a few hours). A .ots receipt is
                  saved; verify it at https://opentimestamps.org with the
                  matching block_<n>.header.json file.
  polygon         Optional. Sends a 0-value transaction to itself on Polygon
                  (Amoy testnet by default) with the block hash in the data
                  field. Needs:  pip install web3,  POLYGON_PRIVATE_KEY=0x...
                  and a little test POL from the Amoy faucet.

No internet: anchoring is queued (QUEUED_OFFLINE) and retried automatically.
Because every block includes the previous block's hash, anchoring the newest
block also covers everything before it.
"""
import os
import socket
import threading
import time
from urllib.parse import urlparse

import requests

from . import config
from .ledger import canon, header_of, now_iso

OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_SHA256 = b"\x08"


def online(host, port=443, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class Anchorer:
    def __init__(self, ledger, log=print):
        self.ledger = ledger
        self.store = ledger.store
        self.log = log
        self.dir = os.path.join(config.ROOT, "data", "anchors")
        os.makedirs(self.dir, exist_ok=True)
        self.backends = [b.strip().lower() for b in config.ANCHOR_BACKENDS.split(",") if b.strip()]
        if config.POLYGON_PRIVATE_KEY and "polygon" not in self.backends:
            self.backends.append("polygon")
        self.lock = threading.Lock()
        self.on_change = None
        self.state = {"internet": None, "last_check": None}
        threading.Thread(target=self._loop, daemon=True, name="anchor").start()

    # ------------------------------------------------------------ bookkeeping
    def _row(self, height, bh, backend, status, receipt=None, url=None, detail=None):
        t = now_iso()
        self.store._x("INSERT INTO ledger_anchors(height,block_hash,backend,status,receipt,url,detail,created_at,"
                      "updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (height, bh, backend, status, receipt, url, detail, t, t))
        if self.on_change:
            self.on_change()

    def _last_done(self, backend):
        r = self.store._q("SELECT MAX(height) AS h FROM ledger_anchors WHERE backend=? AND status IN "
                          "('SUBMITTED','CONFIRMED')", (backend,), one=True)
        return r["h"] if r and r["h"] is not None else -1

    # ------------------------------------------------------------ main loop
    def _loop(self):
        time.sleep(15)
        while True:
            try:
                self.anchor_now()
            except Exception as e:
                self.log(f"[anchor] {e}")
            time.sleep(config.ANCHOR_INTERVAL_S)

    def anchor_now(self, force=False):
        with self.lock:
            self.ledger.seal()
            head = self.ledger.head()
            if not head:
                return []
            results = []
            for be in self.backends:
                if not force and self._last_done(be) >= head["height"]:
                    continue
                try:
                    if be == "opentimestamps":
                        results.append(self._ots(head))
                    elif be == "polygon":
                        results.append(self._polygon(head))
                except Exception as e:
                    self._row(head["height"], head["block_hash"], be, "FAILED", detail=str(e)[:300])
                    results.append({"backend": be, "status": "FAILED", "detail": str(e)})
            return results

    def _queue(self, head, be, why):
        # keep one queued row per backend, pointing at the newest head
        q = self.store._q("SELECT id FROM ledger_anchors WHERE backend=? AND status='QUEUED_OFFLINE'", (be,), one=True)
        if q:
            self.store._x("UPDATE ledger_anchors SET height=?, block_hash=?, detail=?, updated_at=? WHERE id=?",
                          (head["height"], head["block_hash"], why, now_iso(), q["id"]))
            if self.on_change:
                self.on_change()
        else:
            self._row(head["height"], head["block_hash"], be, "QUEUED_OFFLINE", detail=why)
        return {"backend": be, "status": "QUEUED_OFFLINE", "detail": why}

    def _covered(self, be, height):
        self.store._x("UPDATE ledger_anchors SET status='COVERED', detail=?, updated_at=? WHERE backend=? AND "
                      "status='QUEUED_OFFLINE'", (f"covered by anchor of block {height}", now_iso(), be))

    # ------------------------------------------------------------ OpenTimestamps (Bitcoin)
    def _ots(self, head):
        u = urlparse(config.OTS_CALENDARS[0])
        ok_net = any(online(urlparse(c).hostname, urlparse(c).port or (443 if urlparse(c).scheme == "https" else 80))
                     for c in config.OTS_CALENDARS)
        if not ok_net:
            self.state.update(internet=False, last_check=now_iso())
            return self._queue(head, "opentimestamps", "no internet: will anchor automatically when online")
        digest = bytes.fromhex(head["block_hash"])
        hdr_bytes = canon(header_of(head))
        base = os.path.join(self.dir, f"block_{head['height']}.header.json")
        with open(base, "wb") as f:
            f.write(hdr_bytes)            # sha256(this file) == block_hash
        accepted, errors = [], []
        for cal in config.OTS_CALENDARS:
            try:
                r = requests.post(cal.rstrip("/") + "/digest", data=digest, timeout=10,
                                  headers={"Accept": "application/vnd.opentimestamps.v1",
                                           "User-Agent": "revelation-control-unit"})
                if r.status_code == 200 and r.content:
                    with open(f"{base}.{urlparse(cal).hostname}.ots", "wb") as f:
                        f.write(OTS_MAGIC + b"\x01" + OTS_SHA256 + digest + r.content)
                    accepted.append(urlparse(cal).hostname)
                else:
                    errors.append(f"{cal}: HTTP {r.status_code}")
            except requests.RequestException as e:
                errors.append(f"{cal}: {e.__class__.__name__}")
        self.state.update(internet=bool(accepted), last_check=now_iso())
        if not accepted:
            return self._queue(head, "opentimestamps", "calendars unreachable (will retry): " + "; ".join(errors)[:200])
        receipt = os.path.basename(base) + ".<calendar>.ots"
        self._row(head["height"], head["block_hash"], "opentimestamps", "SUBMITTED", receipt=receipt,
                  url="https://opentimestamps.org",
                  detail=f"accepted by {', '.join(accepted)}; Bitcoin confirmation follows in a few hours")
        self._covered("opentimestamps", head["height"])
        self.log(f"[anchor] block {head['height']} submitted to OpenTimestamps ({', '.join(accepted)})")
        return {"backend": "opentimestamps", "status": "SUBMITTED", "calendars": accepted}

    # ------------------------------------------------------------ Polygon (optional)
    def _polygon(self, head):
        pu = urlparse(config.POLYGON_RPC)
        if not online(pu.hostname, pu.port or (443 if pu.scheme == "https" else 80)):
            return self._queue(head, "polygon", "no internet: will anchor automatically when online")
        try:
            from web3 import Web3
        except ImportError:
            raise RuntimeError("web3 not installed: python -m pip install web3")
        w3 = Web3(Web3.HTTPProvider(config.POLYGON_RPC, request_kwargs={"timeout": 15}))
        acct = w3.eth.account.from_key(config.POLYGON_PRIVATE_KEY)
        data = b"REVELATION-CU|" + head["block_hash"].encode()
        tx = {"to": acct.address, "value": 0, "data": data, "nonce": w3.eth.get_transaction_count(acct.address),
              "chainId": config.POLYGON_CHAIN_ID, "gasPrice": int(w3.eth.gas_price * 1.2)}
        tx["gas"] = int(w3.eth.estimate_gas({k: tx[k] for k in ("to", "value", "data")} | {"from": acct.address}) * 1.2)
        signed = acct.sign_transaction(tx)
        raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
        txh = w3.eth.send_raw_transaction(raw).hex()
        if not txh.startswith("0x"):
            txh = "0x" + txh
        url = config.POLYGON_EXPLORER.rstrip("/") + "/tx/" + txh
        self._row(head["height"], head["block_hash"], "polygon", "SUBMITTED", receipt=txh, url=url,
                  detail=f"tx from {acct.address}")
        self._covered("polygon", head["height"])
        self.log(f"[anchor] block {head['height']} anchored on Polygon: {url}")
        return {"backend": "polygon", "status": "SUBMITTED", "tx": txh, "url": url}
