#!/usr/bin/env python3
"""The contact-card vectors decode to what they claim.

`knst_contact_card.json` fixes how a CONTENT_TYPE_CONTACT_CARD (27) payload is read: a
`ContactCard` proto, or — at exactly 32 bytes — a bare intake key from a build before the card.
iOS and Android each parse it, and a disagreement would file an address one client pins and the
other raises a security event about. This re-decodes every `card` case with `protoc` against the
proto as it is now and checks the stated fields. `--write` regenerates the file.

Needs `protoc` on PATH.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "core" / "envelope.proto"
VECTORS = Path(__file__).resolve().parent / "knst_contact_card.json"
MESSAGE = "shared.proto.core.v1.ContactCard"

KEY = bytes(range(0x10, 0x30))            # an intake key
ADDR = bytes(range(0xA0, 0xC0))           # an account address


def field(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


def varint_field(tag: int, value: int) -> bytes:
    out = bytearray([tag])
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def build() -> dict:
    cases = [
        {"name": "key_and_address", "payload": (field(0x0A, KEY) + field(0x12, ADDR)).hex(),
         "reads_as": "card", "intake_key": KEY.hex(), "account_address": ADDR.hex(),
         "intake_generation": 0},
        # Since 2026-10-29: the key's generation. 300 needs two varint bytes, so a reader that
        # takes one byte reads it wrong.
        {"name": "key_address_generation",
         "payload": (field(0x0A, KEY) + field(0x12, ADDR) + varint_field(0x18, 300)).hex(),
         "reads_as": "card", "intake_key": KEY.hex(), "account_address": ADDR.hex(),
         "intake_generation": 300},
        {"name": "address_only", "payload": field(0x12, ADDR).hex(),
         "reads_as": "card", "intake_key": None, "account_address": ADDR.hex(),
         "intake_generation": 0},
        {"name": "key_only", "payload": field(0x0A, KEY).hex(),
         "reads_as": "card", "intake_key": KEY.hex(), "account_address": None,
         "intake_generation": 0},
        {"name": "legacy_bare_key", "payload": KEY.hex(),
         "reads_as": "legacy_intake_key", "intake_key": KEY.hex(), "account_address": None,
         "intake_generation": 0},
    ]
    return {
        "_doc": "CONTENT_TYPE_CONTACT_CARD (27) payloads. 32 bytes exactly = a bare intake key from "
                "a build before the card; anything else is a ContactCard proto. A field of the "
                "wrong length is ignored, not an error. intake_generation absent = 0, a key from "
                "before generations; a holder replaces its key only with a higher generation "
                "(construct-core intake_offer). Checked by check_contact_card.py. Decisions: "
                "construct-docs decisions/contact-card-carries-the-address-back.md, "
                "decisions/intake-key-is-the-accounts-not-the-devices.md.",
        "cases": cases,
    }


def decode(hex_bytes: str) -> str:
    r = subprocess.run(["protoc", "-I", str(ROOT), f"--decode={MESSAGE}", str(PROTO)],
                       input=bytes.fromhex(hex_bytes), capture_output=True, check=True)
    return r.stdout.decode()


def main() -> int:
    fresh = build()
    if "--write" in sys.argv:
        VECTORS.write_text(json.dumps(fresh, indent=2) + "\n")
        print(f"wrote {VECTORS.name}")
        return 0
    if json.loads(VECTORS.read_text()) != fresh:
        print("knst_contact_card.json disagrees with the rules — regenerate with --write")
        return 1
    for case in fresh["cases"]:
        if case["reads_as"] != "card":
            continue
        text = decode(case["payload"])
        for name in ("intake_key", "account_address"):
            present = re.search(rf"^{name}: ", text, re.M) is not None
            if present != (case[name] is not None):
                print(f"{case['name']}: {name} presence disagrees with protoc")
                return 1
        match = re.search(r"^intake_generation: (\d+)$", text, re.M)
        if (int(match.group(1)) if match else 0) != case["intake_generation"]:
            print(f"{case['name']}: intake_generation disagrees with protoc")
            return 1
    print(f"{VECTORS.name}: {len(fresh['cases'])} cases — consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
