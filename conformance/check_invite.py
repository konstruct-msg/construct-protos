#!/usr/bin/env python3
"""The invite vectors are what the v5 rules say they are.

`knst_invite.json` fixes, for one signing key, the three things every implementation of the
invite must produce identically: the signed canonical string, the Ed25519 signature over it, and
the compact binary ("CIv1") the QR code and the link carry. iOS, Android and the server each
build these independently, and a disagreement fails only at redeem time as "invalid signature".

This re-derives every field from the stated inputs and refuses the file if any stored value
differs. `--write` regenerates the file instead. Needs `cryptography`.
"""

import json
import struct
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

VECTORS = Path(__file__).resolve().parent / "knst_invite.json"
MAGIC = b"CIv1"
FLAG_HAS_USERNAME = 0x01


def canonical(f: dict) -> str:
    return "|".join([
        str(f["v"]), f["jti"].lower(), f["uuid"].lower(), f["device_id"], f["server"],
        str(f["ts"]), f.get("un") or "", str(f["ttl"]), f["addr"],
    ])


def binary(f: dict, sig: bytes) -> bytes:
    un = (f.get("un") or "").encode()
    server = f["server"].encode()
    out = MAGIC + bytes([FLAG_HAS_USERNAME if un else 0, f["v"]])
    out += uuid.UUID(f["jti"]).bytes + uuid.UUID(f["uuid"]).bytes + bytes.fromhex(f["device_id"])
    out += struct.pack(">Q", f["ts"]) + sig
    out += bytes([len(server)]) + server
    if un:
        out += bytes([len(un)]) + un
    out += struct.pack(">I", f["ttl"]) + bytes.fromhex(f["addr"])
    return out


def derive(seed_hex: str, fields: dict) -> dict:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    vk = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    text = canonical(fields)
    sig = key.sign(text.encode())
    return {
        "verifying_key": vk.hex(),
        "canonical": text,
        "signature": sig.hex(),
        "binary": binary(fields, sig).hex(),
    }


SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
BASE = {
    "v": 5,
    "jti": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
    "uuid": "14f28d31-5b2a-4c1e-9a3d-6f0e2b7c8d90",
    "device_id": "6f5e37ac1b2c3d4e5f60718293a4b5c6",
    "server": "konstruct.cc",
    "ts": 1790000000,
    "ttl": 300,
    "addr": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
}


def build() -> dict:
    valid = []
    for name, extra in [("with_username", {"un": "alice"}), ("without_username", {})]:
        fields = {**BASE, **extra}
        valid.append({"name": name, "fields": fields, **derive(SEED, fields)})

    good = bytes.fromhex(valid[0]["binary"])
    refused = [
        {
            "name": "version_4",
            "why": "v5 is the only version accepted",
            "binary": (good[:5] + bytes([4]) + good[6:]).hex(),
        },
        {
            "name": "addr_truncated",
            "why": "addr is exactly 32 bytes; a short one reads as truncated",
            "binary": good[:-1].hex(),
        },
        {
            "name": "trailing_byte",
            "why": "nothing follows addr",
            "binary": (good + b"\x00").hex(),
        },
    ]
    return {
        "_doc": "v5 invite vectors. canonical = v|jti|uuid|device_id|server|ts|un|ttl|hex(addr); "
                "signature = Ed25519(signing_seed, canonical); binary = CIv1 compact layout. "
                "Checked by check_invite.py. Decision: construct-docs "
                "decisions/invite-carries-the-account-address.md.",
        "signing_seed": SEED,
        "valid": valid,
        "refused": refused,
    }


def main() -> int:
    fresh = build()
    if "--write" in sys.argv:
        VECTORS.write_text(json.dumps(fresh, indent=2) + "\n")
        print(f"wrote {VECTORS.name}")
        return 0
    stored = json.loads(VECTORS.read_text())
    if stored != fresh:
        print("knst_invite.json disagrees with the rules — regenerate with --write and review the diff")
        return 1
    print(f"{VECTORS.name}: {len(fresh['valid'])} valid, {len(fresh['refused'])} refused — consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
