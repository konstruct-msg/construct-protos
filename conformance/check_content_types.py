#!/usr/bin/env python3
"""Every ContentType in envelope.proto has exactly one row here, and vice versa.

`knst_content_types.json` says what clients must do with a content type. It does not get to
invent one. This checks the two halves agree on which values exist and what they are called —
without it, a type added to the proto would simply have no row, and the clients' conformance
tests would pass by never being asked about it.

Exit 1 on any disagreement. No dependencies; run it from anywhere.
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "core" / "envelope.proto"
VECTORS = Path(__file__).resolve().parent / "knst_content_types.json"

DISPOSITIONS = {
    "transcript_incoming",
    "transcript_own_device",
    "silent_control",
    "not_carried",
}
ROUTING_KINDS = {
    "DIRECT_MESSAGE",
    "CONTROL_MESSAGE",
    "SENDER_SYNC",
    "SESSION_RESET_INIT",
}
SESSION_OPS = {"PING", "READY", "RESET_INIT", "END", None}
SIDE_CHANNELS = {"call_signal", "delivery_receipt", None}


def proto_content_types(text: str) -> dict[int, str]:
    """The `enum ContentType { … }` body, as {value: name}."""
    match = re.search(r"^enum ContentType \{(.*?)^\}", text, re.S | re.M)
    if not match:
        sys.exit("could not find `enum ContentType` in envelope.proto")
    body = match.group(1)
    return {
        int(value): name
        for name, value in re.findall(r"^\s*(CONTENT_TYPE_\w+)\s*=\s*(\d+)\s*;", body, re.M)
    }


def main() -> int:
    proto = proto_content_types(PROTO.read_text())
    vectors = json.loads(VECTORS.read_text())
    rows = {row["value"]: row for row in vectors["types"]}

    errors: list[str] = []

    for value, name in sorted(proto.items()):
        row = rows.get(value)
        if row is None:
            errors.append(
                f"{name} = {value} is in envelope.proto and has no row — "
                f"add one, or the clients are never asked about it"
            )
        elif row["name"] != name:
            errors.append(f"{value}: proto says {name}, vectors say {row['name']}")

    for value, row in sorted(rows.items()):
        if value not in proto:
            errors.append(f"{row['name']} = {value} has a row but is not in envelope.proto")

    for value, row in sorted(rows.items()):
        where = f"{row.get('name', value)} = {value}"
        if row["disposition"] not in DISPOSITIONS:
            errors.append(f"{where}: disposition {row['disposition']!r} is not one of {sorted(DISPOSITIONS)}")
        if row["routing_kind"] not in ROUTING_KINDS:
            errors.append(f"{where}: routing_kind {row['routing_kind']!r} is not one of {sorted(ROUTING_KINDS)}")
        if row["session_control_op"] not in SESSION_OPS:
            errors.append(f"{where}: session_control_op {row['session_control_op']!r} is unknown")
        if row["framed_side_channel"] not in SIDE_CHANNELS:
            errors.append(f"{where}: framed_side_channel {row['framed_side_channel']!r} is unknown")
        # A side channel is a handler for a *framed* payload — it cannot exist off byte 5.
        if row["framed_side_channel"] and not row["knst_byte5"]:
            errors.append(f"{where}: has a framed_side_channel but is not carried in KNST byte 5")
        # "Not carried" and "has a disposition in the transcript" cannot both be true.
        if row["disposition"] == "not_carried" and row["knst_byte5"]:
            errors.append(f"{where}: marked not_carried but knst_byte5 is true")

    if errors:
        for e in errors:
            print(f"  ✗ {e}", file=sys.stderr)
        print(
            "\nenvelope.proto and knst_content_types.json disagree.\n"
            "The proto owns which values exist; the vectors own what clients do with them.",
            file=sys.stderr,
        )
        return 1

    print(f"conformance: {len(rows)} content types, envelope.proto and vectors agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
