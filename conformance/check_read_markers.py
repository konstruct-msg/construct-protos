#!/usr/bin/env python3
"""The read-marker vectors encode and apply as they claim.

`knst_read_markers.json` fixes what every client must agree on for CONTENT_TYPE_READ_SYNC (30):
how a `ReadMarkers` payload reads (`decode` — bytes produced here by `protoc` from the proto as it
is now), when a marker moves the boundary it is about (`apply`), and which incoming messages the
boundary covers (`covers`). A disagreement is silent: one device shows a chat as read and the
other does not, or a contact's forged marker clears a count. `--write` regenerates the file.

Decision: construct-docs decisions/read-state-syncs-between-own-devices.md. Needs `protoc`.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "core" / "envelope.proto"
VECTORS = Path(__file__).resolve().parent / "knst_read_markers.json"
MESSAGE = "shared.proto.core.v1.ReadMarkers"

ALICE = "14f28d31-0c4e-4b7a-9f3e-2a5d6c7b8e90"
BOB = "7d0a9b1c-3e2f-4a5b-8c6d-9e0f1a2b3c4d"
M1 = "a3f1c2d4-5b6e-4f70-8a91-b2c3d4e5f607"
M2 = "b4e2d3c5-6c7f-4081-9ba2-c3d4e5f60718"


def encode(text: str) -> str:
    r = subprocess.run(["protoc", "-I", str(ROOT), f"--encode={MESSAGE}", str(PROTO)],
                       input=text.encode(), capture_output=True, check=True)
    return r.stdout.hex()


def marker_text(partner: str, message_id: str, sent_at: int) -> str:
    return (f'markers {{ partner_user_id: "{partner}" last_read_message_id: "{message_id}" '
            f'last_read_sent_at_ms: {sent_at} }}')


def later(a: tuple, b: tuple) -> bool:
    """(sent_at_ms, message_id) strictly after — the one ordering every client uses."""
    return (a[0], a[1].encode()) > (b[0], b[1].encode())


def build() -> dict:
    decode = [
        {"name": "two_chats",
         "text": marker_text(ALICE, M1, 1_760_500_000_000) + " " + marker_text(BOB, M2, 1_760_500_001_000),
         "markers": [
             {"partner_user_id": ALICE, "last_read_message_id": M1, "last_read_sent_at_ms": 1_760_500_000_000},
             {"partner_user_id": BOB, "last_read_message_id": M2, "last_read_sent_at_ms": 1_760_500_001_000},
         ]},
        {"name": "empty", "text": "", "markers": []},
    ]
    for case in decode:
        case["payload"] = encode(case.pop("text"))

    # held: the boundary this device keeps for the partner (null = none yet);
    # from_own_account: whether the envelope came from one of this account's devices.
    apply = [
        {"name": "first_marker", "held": None, "marker": [100, M1], "from_own_account": True, "result": "apply"},
        {"name": "later_time", "held": [100, M2], "marker": [101, M1], "from_own_account": True, "result": "apply"},
        {"name": "earlier_time", "held": [101, M1], "marker": [100, M2], "from_own_account": True, "result": "ignore"},
        {"name": "same_time_greater_id", "held": [100, M1], "marker": [100, M2], "from_own_account": True, "result": "apply"},
        {"name": "same_time_smaller_id", "held": [100, M2], "marker": [100, M1], "from_own_account": True, "result": "ignore"},
        {"name": "same_marker_again", "held": [100, M1], "marker": [100, M1], "from_own_account": True, "result": "ignore"},
        {"name": "from_a_contact", "held": None, "marker": [100, M1], "from_own_account": False, "result": "drop"},
    ]
    # boundary: [sent_at_ms, message_id]; message: an incoming message's [sent_at_ms, id].
    covers = [
        {"name": "the_message_itself", "boundary": [100, M1], "message": [100, M1], "read": True},
        {"name": "earlier", "boundary": [100, M1], "message": [99, M2], "read": True},
        {"name": "later", "boundary": [100, M1], "message": [101, M1], "read": False},
        {"name": "same_time_smaller_id", "boundary": [100, M2], "message": [100, M1], "read": True},
        {"name": "same_time_greater_id", "boundary": [100, M1], "message": [100, M2], "read": False},
    ]
    return {
        "_doc": ("CONTENT_TYPE_READ_SYNC (30). decode: a ReadMarkers payload and how it reads. "
                 "Order on (sent_at_ms, message_id): by time, then by id as bytes. apply: a marker "
                 "from the own account moves the partner's boundary only if strictly later "
                 "(result 'apply'), else 'ignore'; one not from the own account is 'drop', whatever "
                 "it says. covers: an incoming message is read iff it is at or before the boundary. "
                 "Checked by check_read_markers.py. Decision: construct-docs "
                 "decisions/read-state-syncs-between-own-devices.md."),
        "decode": decode,
        "apply": apply,
        "covers": covers,
    }


def check(vectors: dict) -> list[str]:
    errors = []
    built = build()
    for a, b in zip(vectors["decode"], built["decode"]):
        if a != b:
            errors.append(f"decode {a['name']}: the proto no longer encodes it as recorded")
    if len(vectors["decode"]) != len(built["decode"]):
        errors.append("decode: case count changed")
    for case in vectors["apply"]:
        if not case["from_own_account"]:
            want = "drop"
        elif case["held"] is None or later(tuple(case["marker"]), tuple(case["held"])):
            want = "apply"
        else:
            want = "ignore"
        if case["result"] != want:
            errors.append(f"apply {case['name']}: says {case['result']}, the rule says {want}")
    for case in vectors["covers"]:
        want = not later(tuple(case["message"]), tuple(case["boundary"]))
        if case["read"] != want:
            errors.append(f"covers {case['name']}: says {case['read']}, the rule says {want}")
    return errors


def main() -> int:
    if "--write" in sys.argv:
        VECTORS.write_text(json.dumps(build(), ensure_ascii=False, indent=2) + "\n")
        print(f"wrote {VECTORS.name}")
    errors = check(json.loads(VECTORS.read_text()))
    if errors:
        for e in errors:
            print(f"  ✗ {e}", file=sys.stderr)
        return 1
    print("read markers: vectors encode and apply as recorded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
