#!/usr/bin/env python3
"""Structural check of knst_history_snapshot.json against the frozen layout.

Does not verify hybrid signatures (that is a client test against construct-core).
Does check: the 24 named vectors exist, CTH1 record order and phase legality,
frame lengths 6575 / 5421 / 6582, payload_len cap, and that the proto has a
`oneof body` and no HistoryBodyKind.

Exit 1 on any disagreement. No dependencies; run it from anywhere.
"""

from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = Path(__file__).resolve().parent / "knst_history_snapshot.json"
PROTO = ROOT / "client" / "history_snapshot.proto"

OPENING_LEN = 6575
REPLY_LEN = 5421
CTHF_HEADER_LEN = 6582
MAX_RECORD_BYTES = 512 * 1024 * 1024
REQUIRED_IDS = [f"V{i}" for i in range(1, 25)]

RT = {
    0x00: "end",
    0x01: "manifest",
    0x02: "contact",
    0x03: "chat",
    0x04: "message",
    0x05: "reaction",
    0x06: "peer",
    0x07: "call",
    0x08: "media",
}

TRANSCRIPT_TYPES = {0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
MEDIA_TYPES = {0x08}


def parse_cth1(data: bytes) -> tuple[list[int], list[int]]:
    """Return (record_types including End, payload_lens excluding End)."""
    if data[:4] != b"CTH1":
        raise ValueError("missing CTH1 magic")
    if len(data) < 6:
        raise ValueError("truncated after magic")
    if data[4] != 0x01:
        raise ValueError(f"version {data[4]:#x} is not 0x01")
    types: list[int] = []
    lens: list[int] = []
    i = 5
    while i < len(data):
        rtype = data[i]
        i += 1
        if rtype == 0x00:
            types.append(0x00)
            break
        if i + 8 > len(data):
            raise ValueError("truncated payload_len")
        (plen,) = struct.unpack_from("<Q", data, i)
        i += 8
        if plen > MAX_RECORD_BYTES:
            raise ValueError(f"payload_len {plen} exceeds cap (checker does not allocate)")
        if i + plen > len(data):
            raise ValueError("truncated payload")
        i += plen
        types.append(rtype)
        lens.append(plen)
    else:
        raise ValueError("stream has no End")
    if i != len(data):
        raise ValueError("trailing bytes after End")
    return types, lens


def names_of(types: list[int]) -> list[str]:
    return [RT.get(t, "unknown") for t in types]


def phase_ok(phase: int, types: list[int]) -> str | None:
    body = [t for t in types if t != 0x00]
    if not body or body[0] != 0x01:
        return "manifest not first"
    rest = body[1:]
    if phase == 1:
        if any(t in MEDIA_TYPES for t in rest):
            return "media in phase 1"
    elif phase == 2:
        if any(t in TRANSCRIPT_TYPES for t in rest):
            return "transcript in phase 2"
        if any(t not in MEDIA_TYPES for t in rest):
            return "non-media in phase 2"
    elif phase == 3:
        pass
    elif phase == 0:
        return "phase 0"
    else:
        return f"unknown phase {phase}"
    # Reaction before any Message
    seen_message = False
    for t in rest:
        if t == 0x04:
            seen_message = True
        if t == 0x05 and not seen_message:
            return "reaction before message"
    return None


def main() -> int:
    errors: list[str] = []

    proto = PROTO.read_text()
    if "oneof body" not in proto:
        errors.append("history_snapshot.proto has no `oneof body`")
    if re.search(r"enum\s+HistoryBodyKind", proto):
        errors.append("history_snapshot.proto still has HistoryBodyKind")
    if "message_content" not in proto or "media_album" not in proto or "profile_share" not in proto:
        errors.append("history_snapshot.proto oneof is missing a v1 case")

    doc = json.loads(VECTORS.read_text())
    rows = {row["id"]: row for row in doc["vectors"]}
    for vid in REQUIRED_IDS:
        if vid not in rows:
            errors.append(f"{vid} is missing")
    for vid in sorted(rows):
        if vid not in REQUIRED_IDS:
            errors.append(f"{vid} is extra — the frozen list is V1–V24")

    consts = doc.get("$constants", {})
    if consts.get("ctt1_v2_opening_len") != OPENING_LEN:
        errors.append(f"$constants.ctt1_v2_opening_len is {consts.get('ctt1_v2_opening_len')}, want {OPENING_LEN}")
    if consts.get("ctt1_v2_reply_len") != REPLY_LEN:
        errors.append(f"$constants.ctt1_v2_reply_len is {consts.get('ctt1_v2_reply_len')}, want {REPLY_LEN}")
    if consts.get("cthf_header_len") != CTHF_HEADER_LEN:
        errors.append(f"$constants.cthf_header_len is {consts.get('cthf_header_len')}, want {CTHF_HEADER_LEN}")

    for vid, row in rows.items():
        where = f"{vid} {row.get('name', '')}".strip()
        hx = row.get("hex")
        if hx:
            try:
                data = bytes.fromhex(hx)
            except ValueError:
                errors.append(f"{where}: hex is not valid")
                continue
            if b"CTM1" in data:
                errors.append(f"{where}: contains CTM1 magic — wire form only")
            if row.get("byte_len") != len(data):
                errors.append(f"{where}: byte_len {row.get('byte_len')} != {len(data)}")

        kind = row.get("kind")
        expect = row.get("expect")

        if kind == "cth1_stream":
            if not hx:
                errors.append(f"{where}: cth1_stream has no hex")
                continue
            data = bytes.fromhex(hx)
            try:
                types, _ = parse_cth1(data)
            except ValueError as e:
                errors.append(f"{where}: {e}")
                continue
            got = names_of(types)
            want = row.get("records")
            if want is not None and got != want:
                errors.append(f"{where}: records {got} != {want}")
            phase = row.get("phase")
            if phase is None:
                errors.append(f"{where}: missing phase")
            else:
                reason = phase_ok(phase, types)
                if expect in {"record_order", "malformed"}:
                    if reason is None and expect == "record_order":
                        errors.append(f"{where}: expected a record_order violation, parser saw none")
                    if expect == "malformed" and phase != 0 and reason is None:
                        errors.append(f"{where}: expected malformed, parser accepted the stream")
                elif expect in {"decode_ok", "applied", "skipped", "hint_dropped_bad_id", "envelope_manifest_mismatch"}:
                    if reason is not None:
                        errors.append(f"{where}: phase/order illegal ({reason}) but expect={expect}")

        elif kind == "cth1_header_only":
            if vid != "V15":
                errors.append(f"{where}: only V15 is cth1_header_only")
                continue
            data = bytes.fromhex(hx)
            if data[:5] != b"CTH1\x01":
                errors.append(f"{where}: prefix is not CTH1 v1")
            (plen,) = struct.unpack_from("<Q", data, 6)
            if plen <= MAX_RECORD_BYTES:
                errors.append(f"{where}: payload_len {plen} is not over the cap")
            if expect != "malformed":
                errors.append(f"{where}: expect should be malformed")

        elif kind == "ctt1_v2_opening":
            data = bytes.fromhex(hx)
            if len(data) != OPENING_LEN:
                errors.append(f"{where}: opening is {len(data)} bytes, want {OPENING_LEN}")
            if data[:5] != b"CTT1\x02":
                errors.append(f"{where}: prefix is not CTT1 v2")
            if vid == "V22":
                kem = data[2114:3202]
                if any(kem):
                    errors.append(f"{where}: kemCt is not all zeros")
                if expect != "malformed":
                    errors.append(f"{where}: expect should be malformed")
            if vid == "V21" and expect != "verify_fail":
                errors.append(f"{where}: expect should be verify_fail")
            if vid == "V19" and expect != "verify_ok_with_tag":
                errors.append(f"{where}: expect should be verify_ok_with_tag")

        elif kind == "ctt1_v2_reply":
            data = bytes.fromhex(hx)
            if len(data) != REPLY_LEN:
                errors.append(f"{where}: reply is {len(data)} bytes, want {REPLY_LEN}")

        elif kind == "cthf_header":
            data = bytes.fromhex(hx)
            if len(data) != CTHF_HEADER_LEN:
                errors.append(f"{where}: CTHF header is {len(data)} bytes, want {CTHF_HEADER_LEN}")
            if data[:5] != b"CTHF\x01":
                errors.append(f"{where}: prefix is not CTHF v1")
            if vid == "V24" and expect != "kem_key_id_mismatch":
                errors.append(f"{where}: expect should be kem_key_id_mismatch")
            if vid == "V23":
                if "chunk0_combined" not in row or "file_channel_key" not in row:
                    errors.append(f"{where}: missing chunk 0 / key fields")

        elif kind == "preimage":
            if expect != "exact_hex":
                errors.append(f"{where}: expect should be exact_hex")
            if vid == "V17":
                for field in ("preimage_utf8", "tag", "instance_name"):
                    if field not in row:
                        errors.append(f"{where}: missing {field}")
                tag = row.get("tag", "")
                inst = row.get("instance_name", "")
                if len(tag) != 32 or len(inst) != 32:
                    errors.append(f"{where}: tag/instance_name must be 32 hex chars (16 bytes)")
            if vid == "V18":
                fp = row.get("fp", "")
                if len(fp) != 64:
                    errors.append(f"{where}: fp must be 64 hex chars (32 bytes)")

        else:
            errors.append(f"{where}: unknown kind {kind!r}")

    if errors:
        for e in errors:
            print(f"  ✗ {e}", file=sys.stderr)
        print(
            "\nknst_history_snapshot.json failed structural checks.\n"
            "The proto owns the schema; the vectors pin the bytes.",
            file=sys.stderr,
        )
        return 1

    print(f"conformance: {len(rows)} history-snapshot vectors, layout agrees")
    return 0


if __name__ == "__main__":
    sys.exit(main())
