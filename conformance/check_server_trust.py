#!/usr/bin/env python3
"""The server-trust vectors are the bytes the format says, rebuilt here from the prose.

`knst_server_trust.json` fixes what the offline root signs (a delegation), what a delegated
server key signs (label ‖ kid ‖ body) and the bodies of a sender certificate and a tree head.
construct-core and construct-server check the signatures; this rebuilds every byte string from
the stated fields with nothing but the standard library, so the file cannot drift from the
format description in construct-docs/decisions/server-keys-rooted-offline-and-hybrid.md without
something reddening. Signatures (hybrid Ed25519 ‖ ML-DSA-65) are not checked here — that needs
an ML-DSA implementation; their lengths are.

Exit 1 on any disagreement. Run it from anywhere.
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

VECTORS = Path(__file__).resolve().parent / "knst_server_trust.json"
PUBLIC_KEY_LEN = 32 + 1952
SIGNATURE_LEN = 64 + 3309
PURPOSE = {"sender-cert": 1, "kt-head": 2, "sticker-manifest": 3}
LABEL = {p: f"konstruct/v1/{p}".encode() for p in PURPOSE}


def lp(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


def kid(key: bytes) -> bytes:
    return hashlib.sha256(b"konstruct/v1/kid" + key).digest()[:16]


def body(purpose: str, f: dict) -> bytes:
    if purpose == "sender-cert":
        return (lp(f["user_id"].encode()) + lp(f["domain"].encode())
                + lp(bytes.fromhex(f["identity_key"])) + lp(f["device_id"].encode())
                + struct.pack(">qq", f["issued_at"], f["expires_at"]))
    if purpose == "kt-head":
        return struct.pack(">Q", f["tree_size"]) + bytes.fromhex(f["root_hash"])
    raise ValueError(purpose)


def main() -> int:
    v = json.loads(VECTORS.read_text())
    errors = []

    def check(cond, what):
        if not cond:
            errors.append(what)

    key = bytes.fromhex(v["server_key"]["public_key"])
    check(len(key) == PUBLIC_KEY_LEN, "server key length")
    check(len(bytes.fromhex(v["root"]["public_key"])) == PUBLIC_KEY_LEN, "root key length")
    check(bytes.fromhex(v["server_key"]["kid"]) == kid(key), "kid")

    for d in v["delegations"]:
        p = d["purpose"]
        signable = (b"konstruct/v1/delegation" + bytes([1, PURPOSE[p]])
                    + struct.pack(">qq", d["not_before"], d["not_after"]) + key)
        check(bytes.fromhex(d["signable"]) == signable, f"delegation {p}: signable")
        enc = bytes.fromhex(d["encoded"])
        check(len(enc) == 18 + PUBLIC_KEY_LEN + SIGNATURE_LEN, f"delegation {p}: length")
        check(enc[:18 + PUBLIC_KEY_LEN] == bytes([1, PURPOSE[p]])
              + struct.pack(">qq", d["not_before"], d["not_after"]) + key,
              f"delegation {p}: encoding")

    for s in v["signatures"]:
        p = s["purpose"]
        b = body(p, s["fields"])
        check(bytes.fromhex(s["body"]) == b, f"signature {p}: body")
        check(bytes.fromhex(s["signable"]) == LABEL[p] + kid(key) + b, f"signature {p}: signable")
        check(len(bytes.fromhex(s["signature"])) == SIGNATURE_LEN, f"signature {p}: length")

    check(len(v["delegations"]) == 2 and len(v["signatures"]) == 2, "vectors look truncated")
    for e in errors:
        print(f"knst_server_trust.json: {e}", file=sys.stderr)
    if not errors:
        print("knst_server_trust.json: ok")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
