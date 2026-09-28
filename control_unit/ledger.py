"""
Evidence ledger: a permissioned blockchain kept by the Control Unit.

  record   {type, ref, sha256, ts, meta}      one fact: an audit entry, an evidence file, a clip ...
  block    header {height, ts, prev_hash, merkle_root, n_records, signer}
           block_hash = sha256(canonical header)
           signature  = Ed25519(Control Unit key, block_hash)      (proof of authority)

Every audit-log entry (runs, alerts, dispatches, officer actions, scans,
messages, security events) and the SHA-256 of every evidence file goes into
the next block. Blocks are sealed every LEDGER_BLOCK_S seconds.

What this gives you:
  * change any past record or evidence file  -> Merkle root / file hash no longer matches
  * delete or re-order blocks                -> prev_hash link breaks
  * rebuild the chain with a different key   -> signatures fail against the published public key
  * rebuild the whole chain with our own key -> the block hashes already anchored on Bitcoin /
                                               Polygon (anchor.py) no longer match
Merkle proofs let anyone verify a single evidence photo without the rest of the database
(tools/verify_evidence.py).
"""
import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger_blocks (
    height      INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    merkle_root TEXT NOT NULL,
    n_records   INTEGER NOT NULL,
    signer      TEXT NOT NULL,
    signature   TEXT NOT NULL,
    block_hash  TEXT NOT NULL,
    records     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger_anchors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    height      INTEGER NOT NULL,
    block_hash  TEXT NOT NULL,
    backend     TEXT NOT NULL,
    status      TEXT NOT NULL,       -- QUEUED_OFFLINE | SUBMITTED | CONFIRMED | FAILED | COVERED
    receipt     TEXT,                -- tx hash / .ots file
    url         TEXT,
    detail      TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
"""
GENESIS_PREV = "0" * 64


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def leaf_hash(rec):
    return sha256_hex(canon(rec))


def merkle_root(leaves):
    if not leaves:
        return sha256_hex(b"")
    level = [bytes.fromhex(x) for x in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def merkle_proof(leaves, index):
    """[[side, sibling_hex], ...] from leaf to root; side = 'L' if sibling is on the left."""
    proof = []
    level = [bytes.fromhex(x) for x in leaves]
    i = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = i ^ 1
        proof.append(["L" if sib < i else "R", level[sib].hex()])
        level = [hashlib.sha256(level[j] + level[j + 1]).digest() for j in range(0, len(level), 2)]
        i //= 2
    return proof


def apply_proof(leaf_hex, proof):
    h = bytes.fromhex(leaf_hex)
    for side, sib in proof:
        s = bytes.fromhex(sib)
        h = hashlib.sha256(s + h).digest() if side == "L" else hashlib.sha256(h + s).digest()
    return h.hex()


def header_of(b):
    return {"height": b["height"], "ts": b["ts"], "prev_hash": b["prev_hash"], "merkle_root": b["merkle_root"],
            "n_records": b["n_records"], "signer": b["signer"]}


class Ledger:
    def __init__(self, store, key_dir, log=print):
        self.store = store
        self.log = log
        self.lock = threading.RLock()
        self.pending = []
        self.on_block = None           # callback(block) for the dashboard
        with store.lock:
            store.conn.executescript(SCHEMA)
            store.conn.commit()
        self.key = self._load_key(os.path.join(key_dir, "ledger_ed25519.pem"))
        self.pub_hex = self.key.public_key().public_bytes(serialization.Encoding.Raw,
                                                          serialization.PublicFormat.Raw).hex()
        self.node_id = "CU-" + sha256_hex(bytes.fromhex(self.pub_hex))[:10].upper()
        if self.height() is None:
            self._seal([{"type": "GENESIS", "ref": self.node_id, "sha256": sha256_hex(b"REVELATION"),
                         "ts": now_iso(), "meta": {"public_key": self.pub_hex}}])
        store.on_audit = self._on_audit
        threading.Thread(target=self._loop, daemon=True, name="ledger").start()

    # ------------------------------------------------------------ keys
    @staticmethod
    def _load_key(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            k = Ed25519PrivateKey.generate()
            with open(path, "wb") as f:
                f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    # ------------------------------------------------------------ adding records
    def add(self, rtype, ref, sha, meta=None):
        with self.lock:
            self.pending.append({"type": rtype, "ref": ref, "sha256": sha, "ts": now_iso(), "meta": meta or {}})

    def add_file(self, rtype, ref, path):
        if not os.path.exists(path):
            return None
        h = file_sha256(path)
        rel = os.path.relpath(path, config.EVIDENCE_DIR).replace("\\", "/")
        self.add(rtype, ref, h, {"file": rel, "bytes": os.path.getsize(path)})
        return h

    def add_clip(self, ref, clip_dir):
        """A replay clip is recorded as one manifest hash over all its frames."""
        frames = sorted(f for f in os.listdir(clip_dir) if f.endswith(".jpg"))
        manifest = {f: file_sha256(os.path.join(clip_dir, f)) for f in frames}
        rel = os.path.relpath(clip_dir, config.EVIDENCE_DIR).replace("\\", "/")
        self.add("CLIP", ref, sha256_hex(canon(manifest)), {"dir": rel, "frames": len(frames), "manifest": manifest})

    def _on_audit(self, kind, ref_id, h):
        self.add("AUDIT", f"{kind}:{ref_id}", h)

    # ------------------------------------------------------------ blocks
    def height(self):
        r = self.store._q("SELECT MAX(height) AS h FROM ledger_blocks", one=True)
        return r["h"] if r else None

    def head(self):
        return self.store._q("SELECT * FROM ledger_blocks ORDER BY height DESC LIMIT 1", one=True)

    def block(self, height):
        b = self.store._q("SELECT * FROM ledger_blocks WHERE height=?", (height,), one=True)
        if b:
            b["records"] = json.loads(b["records"])
        return b

    def seal(self):
        with self.lock:
            if not self.pending:
                return None
            recs, self.pending = self.pending, []
        return self._seal(recs)

    def _seal(self, recs):
        with self.lock:
            prev = self.head()
            height = 0 if prev is None else prev["height"] + 1
            leaves = [leaf_hash(r) for r in recs]
            hdr = {"height": height, "ts": now_iso(), "prev_hash": prev["block_hash"] if prev else GENESIS_PREV,
                   "merkle_root": merkle_root(leaves), "n_records": len(recs), "signer": self.pub_hex}
            bh = sha256_hex(canon(hdr))
            sig = self.key.sign(bytes.fromhex(bh)).hex()
            self.store._x("INSERT INTO ledger_blocks(height,ts,prev_hash,merkle_root,n_records,signer,signature,"
                          "block_hash,records) VALUES(?,?,?,?,?,?,?,?,?)",
                          (height, hdr["ts"], hdr["prev_hash"], hdr["merkle_root"], len(recs), self.pub_hex, sig, bh,
                           json.dumps(recs, sort_keys=True)))
        b = dict(hdr, block_hash=bh, signature=sig)
        if self.on_block:
            try:
                self.on_block(b)
            except Exception:
                pass
        return b

    def _loop(self):
        while True:
            time.sleep(config.LEDGER_BLOCK_S)
            try:
                self.seal()
            except Exception as e:
                self.log(f"[ledger] seal failed: {e}")

    # ------------------------------------------------------------ verification
    def verify(self, check_files=True):
        """Walk the whole chain: links, Merkle roots, hashes, signatures, and re-hash evidence files."""
        rows = self.store._q("SELECT * FROM ledger_blocks ORDER BY height")
        res = {"ok": True, "blocks": len(rows), "records": 0, "problems": [], "evidence_checked": 0,
               "evidence_ok": 0, "evidence_tampered": [], "evidence_missing": [], "signer": self.pub_hex,
               "node_id": self.node_id}
        prev = GENESIS_PREV
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.pub_hex))
        for b in rows:
            recs = json.loads(b["records"])
            res["records"] += len(recs)
            h = b["height"]
            if b["prev_hash"] != prev:
                res["problems"].append(f"block {h}: link to previous block broken")
            if merkle_root([leaf_hash(r) for r in recs]) != b["merkle_root"] or len(recs) != b["n_records"]:
                res["problems"].append(f"block {h}: records were altered (Merkle root mismatch)")
            bh = sha256_hex(canon(header_of(b)))
            if bh != b["block_hash"]:
                res["problems"].append(f"block {h}: header altered (hash mismatch)")
            try:
                if b["signer"] != self.pub_hex:
                    raise ValueError("unknown signer")
                pub.verify(bytes.fromhex(b["signature"]), bytes.fromhex(b["block_hash"]))
            except Exception:
                res["problems"].append(f"block {h}: signature invalid")
            prev = b["block_hash"]
            if check_files:
                for r in recs:
                    if r["type"] in ("EVIDENCE", "EVIDENCE_RAW") and r.get("meta", {}).get("file"):
                        res["evidence_checked"] += 1
                        p = os.path.join(config.EVIDENCE_DIR, r["meta"]["file"])
                        if not os.path.exists(p):
                            res["evidence_missing"].append({"ref": r["ref"], "block": h})
                        elif file_sha256(p) != r["sha256"]:
                            res["evidence_tampered"].append({"ref": r["ref"], "block": h, "file": r["meta"]["file"]})
                        else:
                            res["evidence_ok"] += 1
        # cross-check: every audit entry sealed into the ledger must still exist unchanged in the audit log.
        # Catches an insider who edits a record AND recomputes the whole audit hash chain.
        sealed = {}
        for b in rows:
            for r in json.loads(b["records"]):
                if r["type"] == "AUDIT":
                    sealed[r["sha256"]] = (r["ref"], b["height"])
        # recompute each audit row from its contents, so an edited row cannot keep its old hash
        have = set()
        for x in self.store._q("SELECT ts, kind, ref_id, payload, prev_hash FROM audit"):
            try:
                body = canon({"ts": x["ts"], "kind": x["kind"], "ref_id": x["ref_id"],
                              "payload": json.loads(x["payload"])})
                have.add(hashlib.sha256(x["prev_hash"].encode() + body).hexdigest())
            except ValueError:
                pass
        gone = [(ref, h) for hh, (ref, h) in sealed.items() if hh not in have]
        for ref, h in gone[:5]:
            res["problems"].append(f"audit entry {ref} (sealed in block {h}) was altered or deleted")
        if len(gone) > 5:
            res["problems"].append(f"... and {len(gone) - 5} more audit entries altered or deleted")
        res["audit_sealed"] = len(sealed)
        res["ok"] = not (res["problems"] or res["evidence_tampered"] or res["evidence_missing"])
        head = rows[-1] if rows else None
        res["head"] = {"height": head["height"], "block_hash": head["block_hash"], "ts": head["ts"]} if head else None
        return res

    # ------------------------------------------------------------ proofs + export
    def find(self, ref_prefix, rtypes=None):
        """All ledger entries whose ref starts with ref_prefix, with Merkle proofs."""
        out = []
        for b in self.store._q("SELECT * FROM ledger_blocks ORDER BY height"):
            recs = json.loads(b["records"])
            leaves = [leaf_hash(r) for r in recs]
            for i, r in enumerate(recs):
                if r["ref"].startswith(ref_prefix) and (not rtypes or r["type"] in rtypes):
                    out.append({"record": r, "leaf": leaves[i], "proof": merkle_proof(leaves, i),
                                "block": header_of(b) | {"block_hash": b["block_hash"], "signature": b["signature"]}})
        return out

    def export(self, since=None, until=None):
        """Portable ledger slice for a run: blocks, anchors, public key. Enough to verify offline."""
        q = "SELECT * FROM ledger_blocks"
        args = []
        if since:
            q += " WHERE ts>=?"
            args.append(since)
            if until:
                q += " AND ts<=?"
                args.append(until)
        blocks = self.store._q(q + " ORDER BY height", tuple(args))
        # always include the head so the slice can be tied to the latest anchor
        head = self.head()
        if head and (not blocks or blocks[-1]["height"] != head["height"]):
            blocks.append(head)
        for b in blocks:
            b["records"] = json.loads(b["records"])
        return {"format": "revelation-ledger-v1", "node_id": self.node_id, "public_key_ed25519": self.pub_hex,
                "exported_at": now_iso(), "blocks": blocks, "anchors": self.anchors(200)}

    def anchors(self, limit=50):
        return self.store._q("SELECT * FROM ledger_anchors ORDER BY id DESC LIMIT ?", (limit,))

    def status(self):
        head = self.head()
        with self.lock:
            pend = len(self.pending)
        last = self.store._q("SELECT * FROM ledger_anchors WHERE status IN ('SUBMITTED','CONFIRMED') "
                             "ORDER BY id DESC LIMIT 1", one=True)
        queued = self.store._q("SELECT COUNT(*) AS n FROM ledger_anchors WHERE status='QUEUED_OFFLINE'", one=True)
        return {"node_id": self.node_id, "public_key": self.pub_hex, "height": head["height"] if head else None,
                "head_hash": head["block_hash"] if head else None, "head_ts": head["ts"] if head else None,
                "pending": pend, "last_anchor": last, "queued_offline": queued["n"] if queued else 0,
                "block_interval_s": config.LEDGER_BLOCK_S}
