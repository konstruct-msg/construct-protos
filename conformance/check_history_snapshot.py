#!/usr/bin/env python3
"""Structural check of knst_history_snapshot.json against the frozen layout.

Does not verify hybrid signatures (that is a client test against construct-core).
Does check: the 28 named vectors exist, CTH1 record order and phase legality,
the MediaBlob field order, frame lengths 7055 / 5421 / 7062, payload_len cap,
the channel key derivation (HKDF, stdlib), the CTHF chunk framing, and that the
proto has a `oneof body` and no HistoryBodyKind.

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

OPENING_LEN = 7055
REPLY_LEN = 5421
CTHF_HEADER_LEN = 7062
MAX_RECORD_BYTES = 512 * 1024 * 1024
REQUIRED_IDS = [f"V{i}" for i in range(1, 29)]
KEM_CT_LEN = 1568
MAX_SEALED_CHUNK = 65_536 + 12 + 16

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


def media_payloads(data: bytes) -> list[bytes]:
    """The payloads of the MediaBlob records in a CTH1 stream."""
    out, i = [], 5
    while i < len(data) and data[i] != 0x00:
        rtype = data[i]
        (plen,) = struct.unpack_from("<Q", data, i + 1)
        if rtype == 0x08:
            out.append(data[i + 9 : i + 9 + plen])
        i += 9 + plen
    return out


def media_fields_in_order(payload: bytes) -> bool:
    """HistoryMediaBlob fields must be 1, 2, 3 in that order (each optional but blob last)."""
    numbers, i = [], 0
    while i < len(payload):
        key = payload[i]
        i += 1
        length, shift = 0, 0
        while True:
            b = payload[i]
            i += 1
            length |= (b & 0x7F) << shift
            shift += 7
            if b < 0x80:
                break
        numbers.append(key >> 3)
        i += length
    return numbers == sorted(numbers) and len(set(numbers)) == len(numbers)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    import hashlib
    import hmac

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def chunk_frames(data: bytes) -> list[tuple[int, int]] | str:
    """(offset, sealed_len) of each chunk after a CTHF header, or why the framing is wrong."""
    frames, i = [], CTHF_HEADER_LEN
    while True:
        if i + 4 > len(data):
            return "no EOF frame"
        (n,) = struct.unpack_from("<I", data, i)
        if n == 0:
            return frames if i + 4 == len(data) else "bytes after EOF"
        if n > MAX_SEALED_CHUNK or n < 12 + 16 + 1:
            return f"chunk length {n} no writer produces"
        frames.append((i, n))
        i += 4 + n


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
            errors.append(f"{vid} is extra — the frozen list is V1–V28")

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
                if reason is None and not all(media_fields_in_order(m) for m in media_payloads(data)):
                    reason = "MediaBlob fields out of order"
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
                kem = data[2114 : 2114 + KEM_CT_LEN]
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

        elif kind == "channel_key":
            ikm = bytes.fromhex(row["ecdh"]) + bytes.fromhex(row["kem_shared_secret"])
            snap = bytes.fromhex(row["snapshot_id"])
            if hkdf_sha256(ikm, b"construct_transfer_v2", snap).hex() != row.get("nearby_key"):
                errors.append(f"{where}: nearby_key is not HKDF(ecdh || kem_ss, construct_transfer_v2, snapshot_id)")
            if hkdf_sha256(ikm, b"construct_history_file_v1", snap).hex() != row.get("file_key"):
                errors.append(f"{where}: file_key is not HKDF(ecdh || kem_ss, construct_history_file_v1, snapshot_id)")

        elif kind == "cthf_file":
            if "from" in row:
                if row.get("from") not in rows or row.get("mutation") != "swap_chunks_0_1":
                    errors.append(f"{where}: a derived file names V27 and swap_chunks_0_1")
                if expect != "chunk_open_failed":
                    errors.append(f"{where}: expect should be chunk_open_failed")
                continue
            data = bytes.fromhex(hx)
            if data[:CTHF_HEADER_LEN] != bytes.fromhex(rows["V23"]["hex"]):
                errors.append(f"{where}: header is not V23's")
            frames = chunk_frames(data)
            if isinstance(frames, str):
                errors.append(f"{where}: {frames}")
            elif len(frames) != row.get("chunk_count") or len(frames) < 2:
                errors.append(f"{where}: {len(frames)} chunks, want {row.get('chunk_count')} (at least 2)")

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
