"""
Independent evidence verification (does not need the Control Unit or its database).

Run inside an exported run log folder (RUN_xxx_log/):
    python verify_evidence.py
or  python verify_evidence.py path/to/RUN_xxx_log

For every evidence file it checks:
  1. the file's SHA-256 matches the hash sealed in the ledger     (photo not edited)
  2. the Merkle proof leads from that record to the block's root  (record is really in the block)
  3. the block hash matches its header, and the Ed25519 signature
     verifies with the Control Unit's public key                 (block issued by this Control Unit)
  4. the block chain links forward to an anchored block, and the anchored
     block header file hashes to the anchored hash                (chain existed at anchor time)
Needs:  pip install cryptography
"""
import hashlib
import json
import os
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    Ed25519PublicKey = None


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def apply_proof(leaf, proof):
    h = bytes.fromhex(leaf)
    for side, sib in proof:
        s = bytes.fromhex(sib)
        h = hashlib.sha256(s + h).digest() if side == "L" else hashlib.sha256(h + s).digest()
    return h.hex()


def header(b):
    return {k: b[k] for k in ("height", "ts", "prev_hash", "merkle_root", "n_records", "signer")}


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
    P = json.load(open(os.path.join(root, "evidence_proofs.json")))
    L = json.load(open(os.path.join(root, "ledger.json")))
    pub_hex = P["public_key_ed25519"]
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)) if Ed25519PublicKey else None
    blocks = {b["height"]: b for b in L["blocks"]}
    anchors = [a for a in L.get("anchors", []) if a["status"] in ("SUBMITTED", "CONFIRMED")]
    print(f"Control Unit {P['node_id']}  public key {pub_hex[:16]}…\n")
    bad = 0
    for p in P["proofs"]:
        r, blk = p["record"], p["block"]
        lines = []
        ok = True
        f = r.get("meta", {}).get("file")
        if f:
            path = os.path.join(root, "evidence", os.path.basename(f))
            if os.path.exists(path):
                same = sha(open(path, "rb").read()) == r["sha256"]
                lines.append(("file hash matches ledger" if same else "FILE WAS ALTERED (hash differs)", same))
                ok &= same
            else:
                lines.append(("file not included in this export (hash only)", True))
        leaf = sha(canon(r))
        inb = leaf == p["leaf"] and apply_proof(leaf, p["proof"]) == blk["merkle_root"]
        lines.append((f"Merkle proof into block {blk['height']}", inb))
        hdr_ok = sha(canon(header(blk))) == blk["block_hash"]
        lines.append(("block header hash", hdr_ok))
        if pub:
            try:
                pub.verify(bytes.fromhex(blk["signature"]), bytes.fromhex(blk["block_hash"]))
                sig_ok = blk["signer"] == pub_hex
            except Exception:
                sig_ok = False
            lines.append(("Ed25519 signature by the Control Unit", sig_ok))
        else:
            sig_ok = True
            lines.append(("signature not checked (pip install cryptography)", True))
        # walk forward to an anchored block
        anc_txt, h, cur = "not anchored in this export", blk["height"], blk["block_hash"]
        chain_ok = True
        for a in sorted(anchors, key=lambda a: a["height"]):
            if a["height"] < h:
                continue
            x = h
            while x < a["height"] and chain_ok:
                nxt = blocks.get(x + 1)
                if not nxt or nxt["prev_hash"] != (blocks[x]["block_hash"] if x in blocks else cur):
                    chain_ok = False
                    break
                if sha(canon(header(nxt))) != nxt["block_hash"]:
                    chain_ok = False
                x += 1
            if chain_ok and (blocks.get(a["height"], {}).get("block_hash", cur) == a["block_hash"]):
                hf = os.path.join(root, "anchors", f"block_{a['height']}.header.json")
                extra = ""
                if os.path.exists(hf):
                    extra = " (header file hash matches)" if sha(open(hf, "rb").read()) == a["block_hash"] \
                        else " (HEADER FILE MISMATCH)"
                anc_txt = f"anchored via {a['backend']} at block {a['height']}: {a.get('receipt') or ''}{extra}"
                break
        lines.append((anc_txt, chain_ok))
        ok &= inb and hdr_ok and sig_ok and chain_ok
        bad += not ok
        print(f"{'VALID  ' if ok else 'INVALID'}  {p['alert_id']}  {r['type']}  {r['ref']}")
        for t, good in lines:
            print(f"         {'✓' if good else '✗'} {t}")
    print(f"\n{len(P['proofs']) - bad}/{len(P['proofs'])} evidence items verified")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
