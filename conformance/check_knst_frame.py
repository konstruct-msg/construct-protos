#!/usr/bin/env python3
"""The KNST frame vectors say how the plaintext frame reads.

Every message body is framed before encryption: a 30-byte header, then the payload.

    [0..4]   magic b"KNST"
    [4]      version 0x01
    [5]      content_type — inside the ciphertext, which is why the server cannot read it
    [6..22]  message id, the UUID's 16 raw bytes
    [22..24] chunk_index    (u16, big-endian)
    [24..26] total_chunks   (u16, big-endian)
    [26..30] plaintext_length (u32, big-endian)
    [30..]   payload

iOS, Android, the TUI and (from 0.29) construct-core each read it, and until 2026-10-02 nothing
fixed it but their agreement. A frame is a *control frame* — a call signal, a receipt, a card, a
profile: one message, never split — when the header is valid, total_chunks is 1 and
plaintext_length does not exceed the payload; its body is the first plaintext_length bytes.
Anything else is not one: a client must not guess. `--write` regenerates the file.
"""

import json
import struct
import sys
import uuid
from pathlib import Path

VECTORS = Path(__file__).resolve().parent / "knst_frame.json"
MAGIC = b"KNST"
VERSION = 1
HEADER = 30
MESSAGE_ID = uuid.UUID("0b8e2f5c-6a1d-4e7b-9c3f-1a2b3c4d5e6f")


def frame(payload: bytes, content_type: int, *, index=0, total=1, length=None,
          magic=MAGIC, version=VERSION) -> bytes:
    length = len(payload) if length is None else length
    return (magic + bytes([version, content_type]) + MESSAGE_ID.bytes
            + struct.pack(">HHI", index, total, length) + payload)


def read(data: bytes):
    """The rule, as every reader must apply it."""
    if len(data) < HEADER or data[:4] != MAGIC or data[4] != VERSION:
        return None
    index, total, length = struct.unpack(">HHI", data[22:30])
    payload = data[30:]
    return {"content_type": data[5], "message_id": str(uuid.UUID(bytes=data[6:22])),
            "chunk_index": index, "total_chunks": total, "plaintext_length": length,
            "control": total == 1 and length <= len(payload),
            "body": payload[:length].hex() if total == 1 and length <= len(payload) else None}


SIGNAL = bytes.fromhex("0a0663616c6c2d31")   # some call-signal proto bytes

# Splitting a body into frames: every frame carries at most CHUNK_PAYLOAD bytes, all of them the
# same message id, content type and plaintext_length (the whole body's), chunk_index 0..total-1.
# An empty body is one frame. More than MAX_CHUNKS frames is refused, not truncated.
CHUNK_PAYLOAD = 3770
MAX_CHUNKS = 256


def body(n: int) -> bytes:
    return bytes(i % 251 for i in range(n))


def chunks(payload: bytes, content_type: int):
    total = max(1, -(-len(payload) // CHUNK_PAYLOAD))
    if total > MAX_CHUNKS:
        return None
    return [frame(payload[i * CHUNK_PAYLOAD:(i + 1) * CHUNK_PAYLOAD], content_type,
                  index=i, total=total, length=len(payload)) for i in range(total)]


def build() -> dict:
    raw = [
        ("call_signal", frame(SIGNAL, 12)),
        ("profile", frame(b"\x0a\x05Alice", 29)),
        ("empty_body", frame(b"", 14)),
        ("padded_body_is_cut_to_length", frame(SIGNAL + b"\x00\x00\x00", 12, length=len(SIGNAL))),
        ("chunk_of_two_is_not_control", frame(b"part one", 1, index=0, total=2, length=8)),
        ("length_past_payload_is_not_control", frame(SIGNAL, 12, length=len(SIGNAL) + 1)),
        ("wrong_magic", frame(SIGNAL, 12, magic=b"KNSU")),
        ("wrong_version", frame(SIGNAL, 12, version=2)),
        ("truncated_header", frame(SIGNAL, 12)[:29]),
    ]
    cases = []
    for name, data in raw:
        parsed = read(data)
        case = {"name": name, "frame": data.hex(), "is_frame": parsed is not None}
        if parsed:
            case.update(parsed)
        cases.append(case)
    encode = []
    for name, size in [("empty", 0), ("small", 5), ("exactly_one_chunk", CHUNK_PAYLOAD),
                       ("one_byte_over", CHUNK_PAYLOAD + 1), ("three_chunks", 2 * CHUNK_PAYLOAD + 1)]:
        frames = chunks(body(size), 1)
        encode.append({"name": name, "payload_len": size, "content_type": 1,
                       "frames": [f.hex() for f in frames]})
    encode.append({"name": "over_max_chunks", "payload_len": MAX_CHUNKS * CHUNK_PAYLOAD + 1,
                   "content_type": 1, "frames": None})
    return {
        "_doc": "KNST plaintext frame (30-byte header, big-endian). is_frame: magic KNST, version 1, "
                "at least 30 bytes. control: total_chunks == 1 and plaintext_length <= payload "
                "length; body = the first plaintext_length bytes of the payload. encode: a body "
                "split into frames of at most chunk_payload_size bytes, message id as in cases, "
                "payload byte i = i mod 251; frames null = refused (over max_chunks). Checked by "
                "check_knst_frame.py.",
        "message_id": str(MESSAGE_ID),
        "chunk_payload_size": CHUNK_PAYLOAD,
        "max_chunks": MAX_CHUNKS,
        "cases": cases,
        "encode": encode,
    }


def main() -> int:
    fresh = build()
    if "--write" in sys.argv:
        VECTORS.write_text(json.dumps(fresh, indent=2) + "\n")
        print(f"wrote {VECTORS.name}")
        return 0
    if json.loads(VECTORS.read_text()) != fresh:
        print("knst_frame.json disagrees with the rule — regenerate with --write")
        return 1
    print(f"{VECTORS.name}: {len(fresh['cases'])} cases — consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
