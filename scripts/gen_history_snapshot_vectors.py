#!/usr/bin/env python3
"""Generate construct-protos/conformance/knst_history_snapshot.json.

Fixed seeds live here and in scripts/gen_history_crypto/. Re-run:

    python3 scripts/gen_history_snapshot_vectors.py

The crypto helper (same crate versions as construct-core) must be built first:

    cargo build --release --manifest-path scripts/gen_history_crypto/Cargo.toml
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "scripts" / "gen_history_crypto" / "target" / "release" / "gen_history_crypto"
OUT = ROOT / "conformance" / "knst_history_snapshot.json"

MAGIC = b"CTH1"
VERSION = 0x01
MAX_RECORD_BYTES = 512 * 1024 * 1024
OPENING_LEN = 7055
REPLY_LEN = 5421
CTHF_HEADER_LEN = 7062

RT_END = 0x00
RT_MANIFEST = 0x01
RT_CONTACT = 0x02
RT_CHAT = 0x03
RT_MESSAGE = 0x04
RT_REACTION = 0x05
RT_PEER = 0x06
RT_CALL = 0x07
RT_MEDIA = 0x08
RT_RESERVED = 0x09

SNAPSHOT_ID = bytes([0xAA] * 16)
USER_ID = bytes.fromhex("00000000000040008000000000000001")
SOURCE_DEVICE_HEX_PLACEHOLDER = "0" * 32  # replaced from helper
MSG_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
PEER_USER = bytes.fromhex("00000000000040008000000000000002")
CREATED_AT = 1_800_000_000
TS_MS = 1_800_000_000_000


# --- protobuf (proto3, no deps) ------------------------------------------------

def _varint(n: int) -> bytes:
    out = bytearray()
    n &= (1 << 64) - 1
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _key(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def p_bytes(field: int, value: bytes) -> bytes:
    return _key(field, 2) + _varint(len(value)) + value


def p_string(field: int, value: str) -> bytes:
    return p_bytes(field, value.encode("utf-8"))


def p_varint(field: int, value: int) -> bytes:
    return _key(field, 0) + _varint(value)


def p_bool(field: int, value: bool) -> bytes:
    return p_varint(field, 1 if value else 0)


def p_msg(field: int, value: bytes) -> bytes:
    return p_bytes(field, value)


def encode_manifest(*, phase: int, source_device_id: str, **counts: int) -> bytes:
    body = b"".join(
        [
            p_varint(1, 1),
            p_bytes(2, SNAPSHOT_ID),
            p_bytes(3, USER_ID),
            p_string(4, source_device_id),
            p_varint(5, CREATED_AT),
            p_string(6, "test-1.0"),
            p_varint(7, counts.get("contact_count", 0)),
            p_varint(8, counts.get("chat_count", 0)),
            p_varint(9, counts.get("message_count", 0)),
            p_varint(10, counts.get("reaction_count", 0)),
            p_varint(11, counts.get("media_blob_count", 0)),
            p_varint(12, counts.get("media_byte_count", 0)),
            p_varint(13, phase),
        ]
    )
    return body


def encode_contact() -> bytes:
    return b"".join(
        [
            p_bytes(1, PEER_USER),
            p_string(2, "alice"),
            p_string(3, "Alice"),
            p_string(4, ""),
            p_bytes(5, b""),
            p_bool(6, True),
            p_bool(7, False),
            p_bool(8, True),
            p_bool(9, True),
            p_varint(10, CREATED_AT),
            p_varint(11, CREATED_AT),
        ]
    )


def encode_chat() -> bytes:
    return p_bytes(1, PEER_USER) + p_bool(2, True) + p_bool(3, False)


def encode_text_message() -> bytes:
    text_msg = p_string(1, "hello")
    content = p_msg(1, text_msg)  # MessageContent.text
    return b"".join(
        [
            p_string(1, MSG_ID),
            p_bytes(2, PEER_USER),
            p_bytes(3, USER_ID),
            p_varint(4, TS_MS),
            p_bool(5, False),
            p_msg(6, content),  # body.message_content
            p_varint(14, 2),
        ]
    )


def encode_album_message() -> bytes:
    item = b"".join(
        [
            p_varint(1, 1),  # MEDIA_TYPE_IMAGE
            p_string(2, "https://example.invalid/a"),
            p_bytes(3, bytes(32)),
            p_bytes(4, bytes(32)),
            p_varint(5, 4),
            p_string(6, "image/jpeg"),
            p_string(13, "media-1"),
        ]
    )
    album = p_msg(1, item)
    return b"".join(
        [
            p_string(1, "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
            p_bytes(2, PEER_USER),
            p_bytes(3, USER_ID),
            p_varint(4, TS_MS + 1),
            p_bool(5, False),
            p_msg(15, album),
        ]
    )


def encode_profile_share() -> bytes:
    # ProfileShareData binary v1: version, len-prefixed displayName, four optionals, i64 timestamp.
    inner = bytearray([0x01])

    def lp(b: bytes) -> None:
        inner.extend(struct.pack("<H", len(b)))
        inner.extend(b)

    name = "Bob".encode()
    lp(name)
    for _ in range(4):
        inner.append(0)  # optional absent
    inner.extend(struct.pack("<q", CREATED_AT))
    return b"".join(
        [
            p_string(1, "cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
            p_bytes(2, PEER_USER),
            p_bytes(3, USER_ID),
            p_varint(4, TS_MS + 2),
            p_bool(5, False),
            p_bytes(16, bytes(inner)),
        ]
    )


def encode_reaction() -> bytes:
    return b"".join(
        [
            p_string(1, MSG_ID),
            p_bytes(2, USER_ID),
            p_string(3, "👍"),
            p_varint(4, TS_MS + 10),
        ]
    )


def encode_peer(device_id_hex: str, identity_key: bytes) -> bytes:
    return b"".join(
        [
            p_bytes(1, PEER_USER),
            p_string(2, device_id_hex),
            p_bytes(3, identity_key),
            p_varint(4, CREATED_AT),
        ]
    )


def encode_call() -> bytes:
    return b"".join(
        [
            p_string(1, "call-1"),
            p_bytes(2, PEER_USER),
            p_bool(3, True),
            p_varint(4, 0),
            p_varint(5, CREATED_AT),
            p_varint(6, 12),
        ]
    )


def encode_media() -> bytes:
    return p_string(1, "media-1") + p_string(2, "image/jpeg") + p_bytes(3, b"\xff\xd8jpeg")


# --- CTH1 stream ---------------------------------------------------------------

def record(rtype: int, payload: bytes) -> bytes:
    return bytes([rtype]) + struct.pack("<Q", len(payload)) + payload


def stream(records: list[tuple[int, bytes]]) -> bytes:
    out = bytearray(MAGIC + bytes([VERSION]))
    for rtype, payload in records:
        out.extend(record(rtype, payload))
    out.append(RT_END)
    return bytes(out)


def parse_record_types(data: bytes) -> list[int]:
    """Used by the checker; duplicated here so the generator can self-describe."""
    assert data[:4] == MAGIC
    types = []
    i = 5
    while i < len(data):
        rtype = data[i]
        i += 1
        if rtype == RT_END:
            types.append(RT_END)
            break
        (plen,) = struct.unpack_from("<Q", data, i)
        i += 8 + plen
        types.append(rtype)
    return types


# --- crypto helper -------------------------------------------------------------

def load_keys() -> dict:
    if not HELPER.exists():
        sys.exit(
            f"{HELPER} missing. Build with:\n"
            "  cargo build --release --manifest-path scripts/gen_history_crypto/Cargo.toml"
        )
    raw = subprocess.check_output([str(HELPER)], cwd=ROOT)
    return json.loads(raw.decode())


def helper_sign(msg: bytes, ed_only: bool = False) -> bytes:
    cmd = "sign-ed" if ed_only else "sign"
    out = subprocess.check_output([str(HELPER), cmd, msg.hex()], cwd=ROOT)
    return bytes.fromhex(out.decode().strip())


def dashed_user_id() -> str:
    b = USER_ID
    hexed = b.hex()
    return f"{hexed[0:8]}-{hexed[8:12]}-{hexed[12:16]}-{hexed[16:20]}-{hexed[20:32]}"


def discovery(user_dashed: str, device_hex: str) -> tuple[str, str]:
    preimage = ("cth1:" + user_dashed + device_hex).encode("utf-8")
    tag = hashlib.sha256(preimage).digest()[:16].hex()
    instance = hashlib.sha256(("ctt1_instance:" + tag).encode("utf-8")).digest()[:16].hex()
    return tag, instance


# --- CTT1 v2 / CTHF frames -----------------------------------------------------

def opening_prefix(sender_eph: bytes, typ: int, payload_len: int) -> bytes:
    return b"CTT1" + bytes([0x02]) + sender_eph + bytes([typ]) + struct.pack("<Q", payload_len)


def opening_transcript(
    *,
    sender_eph: bytes,
    sender_identity: bytes,
    sender_hybrid: bytes,
    snapshot_id: bytes,
    sender_id: bytes,
    receiver_id: bytes,
    kyber_key_id: int,
    kem_ct: bytes,
    typ: int,
    payload_len: int,
) -> bytes:
    return (
        sender_eph
        + sender_identity
        + sender_hybrid
        + snapshot_id
        + sender_id
        + receiver_id
        + struct.pack("<I", kyber_key_id)
        + kem_ct
        + bytes([typ])
        + struct.pack("<Q", payload_len)
    )


def build_opening(keys: dict, *, typ: int = 0x02, kem_ct: bytes | None = None, ed_only: bool = False) -> bytes:
    sender_eph = bytes.fromhex(keys["sender_eph_public"])
    sender_identity = bytes.fromhex(keys["offering_identity_public"])
    sender_hybrid = bytes.fromhex(keys["hybrid_public"])
    sender_id = bytes.fromhex(keys["offering_device_id_raw"])
    receiver_id = bytes.fromhex(keys["receiver_device_id_raw"])
    kyber_key_id = keys["kyber_key_id"]
    if kem_ct is None:
        kem_ct = bytes.fromhex(keys["kem_ct"])
    payload_len = 0
    snapshot = bytes(16) if typ == 0x03 else SNAPSHOT_ID
    body = (
        sender_identity
        + sender_hybrid
        + snapshot
        + sender_id
        + receiver_id
        + struct.pack("<I", kyber_key_id)
        + kem_ct
    )
    tagged = b"ctt1v2-s" + opening_transcript(
        sender_eph=sender_eph,
        sender_identity=sender_identity,
        sender_hybrid=sender_hybrid,
        snapshot_id=snapshot,
        sender_id=sender_id,
        receiver_id=receiver_id,
        kyber_key_id=kyber_key_id,
        kem_ct=kem_ct,
        typ=typ,
        payload_len=payload_len,
    )
    sig = helper_sign(tagged, ed_only=ed_only)
    frame = opening_prefix(sender_eph, typ, payload_len) + body + sig
    assert len(frame) == OPENING_LEN, len(frame)
    return frame


def build_reply(keys: dict) -> bytes:
    receiver_eph = bytes.fromhex(keys["receiver_eph_public"])
    sender_eph = bytes.fromhex(keys["sender_eph_public"])
    receiver_identity = bytes.fromhex(keys["receiver_identity_public"])
    # Reply advertises the receiver's hybrid key. The fixture reuses the offering
    # hybrid keypair (one test key); production uses the receiver's own.
    receiver_hybrid = bytes.fromhex(keys["hybrid_public"])
    sender_id = bytes.fromhex(keys["offering_device_id_raw"])
    receiver_id = bytes.fromhex(keys["receiver_device_id_raw"])
    kem_ct = bytes.fromhex(keys["kem_ct"])
    tagged = (
        b"ctt1v2-r"
        + receiver_eph
        + sender_eph
        + receiver_identity
        + receiver_hybrid
        + SNAPSHOT_ID
        + sender_id
        + receiver_id
        + kem_ct
    )
    sig = helper_sign(tagged)
    frame = receiver_eph + receiver_identity + receiver_hybrid + sig
    assert len(frame) == REPLY_LEN, len(frame)
    return frame


def build_cthf(keys: dict, *, kyber_key_id: int | None = None) -> bytes:
    if kyber_key_id is None:
        kyber_key_id = keys["kyber_key_id"]
    user_id = USER_ID
    recipient = bytes.fromhex(keys["receiver_device_id_raw"])
    source = bytes.fromhex(keys["offering_device_id_raw"])
    sender_eph = bytes.fromhex(keys["sender_eph_public"])
    sender_identity = bytes.fromhex(keys["offering_identity_public"])
    sender_hybrid = bytes.fromhex(keys["hybrid_public"])
    kem_ct = bytes.fromhex(keys["kem_ct"])
    tagged = (
        b"cthf1"
        + user_id
        + recipient
        + source
        + SNAPSHOT_ID
        + sender_eph
        + sender_identity
        + sender_hybrid
        + struct.pack("<I", kyber_key_id)
        + kem_ct
    )
    sig = helper_sign(tagged)
    header = (
        b"CTHF"
        + bytes([0x01])
        + user_id
        + recipient
        + source
        + SNAPSHOT_ID
        + sender_eph
        + sender_identity
        + sender_hybrid
        + struct.pack("<I", kyber_key_id)
        + kem_ct
        + sig
    )
    assert len(header) == CTHF_HEADER_LEN, len(header)
    return header


def vec(
    vid: str,
    name: str,
    kind: str,
    expect: str,
    *,
    hex_payload: str | None = None,
    records: list[str] | None = None,
    phase: int | None = None,
    note: str = "",
    extra: dict | None = None,
) -> dict:
    row = {
        "id": vid,
        "name": name,
        "kind": kind,
        "expect": expect,
    }
    if hex_payload is not None:
        row["hex"] = hex_payload
        row["byte_len"] = len(bytes.fromhex(hex_payload))
    if records is not None:
        row["records"] = records
    if phase is not None:
        row["phase"] = phase
    if note:
        row["note"] = note
    if extra:
        row.update(extra)
    return row


def main() -> int:
    keys = load_keys()
    source_hex = bytes.fromhex(keys["offering_device_id_raw"]).hex()
    identity_pub = bytes.fromhex(keys["offering_identity_public"])
    good_device_hex = source_hex
    bad_device_hex = "00" * 16

    man1 = encode_manifest(phase=1, source_device_id=source_hex, contact_count=1, chat_count=1, message_count=1)
    man2 = encode_manifest(phase=2, source_device_id=source_hex, media_blob_count=1)
    man3 = encode_manifest(phase=3, source_device_id=source_hex, contact_count=1, message_count=1, media_blob_count=1)
    man0 = encode_manifest(phase=0, source_device_id=source_hex)

    contact = encode_contact()
    chat = encode_chat()
    peer_ok = encode_peer(good_device_hex, identity_pub)
    peer_bad = encode_peer(bad_device_hex, identity_pub)
    call = encode_call()
    msg_text = encode_text_message()
    msg_album = encode_album_message()
    msg_profile = encode_profile_share()
    reaction = encode_reaction()
    media = encode_media()

    v1 = stream([(RT_MANIFEST, man1)])
    v2 = stream([(RT_MANIFEST, man2)])
    v3 = stream([(RT_MANIFEST, man3)])
    v4 = stream([(RT_MANIFEST, man0)])
    v5 = stream(
        [
            (RT_MANIFEST, man1),
            (RT_CONTACT, contact),
            (RT_CHAT, chat),
            (RT_PEER, peer_ok),
            (RT_CALL, call),
        ]
    )
    v6 = stream([(RT_MANIFEST, man1), (RT_PEER, peer_bad)])
    v7 = stream([(RT_MANIFEST, man1), (RT_MESSAGE, msg_text)])
    v8 = stream([(RT_MANIFEST, man1), (RT_MESSAGE, msg_album)])
    v9 = stream([(RT_MANIFEST, man1), (RT_MESSAGE, msg_profile)])
    v10 = stream([(RT_MANIFEST, man1), (RT_MESSAGE, msg_text), (RT_REACTION, reaction)])
    v11 = stream([(RT_MANIFEST, man1), (RT_REACTION, reaction), (RT_MESSAGE, msg_text)])
    v12 = stream([(RT_MANIFEST, man1), (RT_MEDIA, media)])
    v13 = stream([(RT_MANIFEST, man2), (RT_MESSAGE, msg_text)])
    # V14: envelope snapshot_id (all 0xBB) ≠ manifest (all 0xAA)
    v14 = stream([(RT_MANIFEST, man1)])
    # V15: payload_len > maxRecordBytes, no payload bytes follow
    v15 = MAGIC + bytes([VERSION]) + bytes([RT_MESSAGE]) + struct.pack("<Q", MAX_RECORD_BYTES + 1)
    v16 = stream([(RT_MANIFEST, man1), (RT_RESERVED, b"future-group")])

    tag, instance = discovery(dashed_user_id(), keys["receiver_device_id_raw"])
    # receiver_device_id_raw is 16 bytes → 32 hex; matches CryptoDeviceId encoding.

    v19 = build_opening(keys)
    v20 = build_reply(keys)
    v21 = build_opening(keys, ed_only=True)
    v22 = build_opening(keys, kem_ct=bytes(1568))
    v23 = build_cthf(keys)
    v24 = build_cthf(keys, kyber_key_id=keys["wrong_kyber_key_id"])

    vectors = [
        vec("V1", "manifest_phase_1", "cth1_stream", "decode_ok", hex_payload=v1.hex(), records=["manifest", "end"], phase=1),
        vec("V2", "manifest_phase_2", "cth1_stream", "decode_ok", hex_payload=v2.hex(), records=["manifest", "end"], phase=2),
        vec("V3", "manifest_phase_3", "cth1_stream", "decode_ok", hex_payload=v3.hex(), records=["manifest", "end"], phase=3),
        vec("V4", "manifest_phase_0", "cth1_stream", "malformed", hex_payload=v4.hex(), records=["manifest", "end"], phase=0, note="phase 0 is unknown_version / malformed"),
        vec(
            "V5",
            "contact_chat_peer_call",
            "cth1_stream",
            "decode_ok",
            hex_payload=v5.hex(),
            records=["manifest", "contact", "chat", "peer", "call", "end"],
            phase=1,
        ),
        vec(
            "V6",
            "peer_hint_bad_id",
            "cth1_stream",
            "hint_dropped_bad_id",
            hex_payload=v6.hex(),
            records=["manifest", "peer", "end"],
            phase=1,
            note="device_id is not SHA256(identity_key)[0..16]",
        ),
        vec("V7", "message_content_text", "cth1_stream", "decode_ok", hex_payload=v7.hex(), records=["manifest", "message", "end"], phase=1),
        vec("V8", "message_media_album", "cth1_stream", "decode_ok", hex_payload=v8.hex(), records=["manifest", "message", "end"], phase=1),
        vec("V9", "message_profile_share", "cth1_stream", "decode_ok", hex_payload=v9.hex(), records=["manifest", "message", "end"], phase=1),
        vec("V10", "reaction_after_message", "cth1_stream", "applied", hex_payload=v10.hex(), records=["manifest", "message", "reaction", "end"], phase=1),
        vec("V11", "reaction_before_message", "cth1_stream", "record_order", hex_payload=v11.hex(), records=["manifest", "reaction", "message", "end"], phase=1),
        vec("V12", "media_in_phase_1", "cth1_stream", "record_order", hex_payload=v12.hex(), records=["manifest", "media", "end"], phase=1),
        vec("V13", "transcript_in_phase_2", "cth1_stream", "record_order", hex_payload=v13.hex(), records=["manifest", "message", "end"], phase=2),
        vec(
            "V14",
            "envelope_manifest_mismatch",
            "cth1_stream",
            "envelope_manifest_mismatch",
            hex_payload=v14.hex(),
            records=["manifest", "end"],
            phase=1,
            extra={"envelope_snapshot_id": bytes([0xBB] * 16).hex(), "manifest_snapshot_id": SNAPSHOT_ID.hex()},
        ),
        vec(
            "V15",
            "payload_len_over_cap",
            "cth1_header_only",
            "malformed",
            hex_payload=v15.hex(),
            extra={"payload_len": MAX_RECORD_BYTES + 1, "max_record_bytes": MAX_RECORD_BYTES},
            note="payload_len > 512 MiB; decoder must not allocate",
        ),
        vec("V16", "unknown_record_0x09", "cth1_stream", "skipped", hex_payload=v16.hex(), records=["manifest", "unknown", "end"], phase=1),
        vec(
            "V17",
            "discovery_tag",
            "preimage",
            "exact_hex",
            extra={
                "preimage_utf8": "cth1:" + dashed_user_id() + keys["receiver_device_id_raw"],
                "tag": tag,
                "instance_name": instance,
            },
        ),
        vec(
            "V18",
            "qr_fp",
            "preimage",
            "exact_hex",
            extra={
                "preimage": keys["offering_identity_public"] + keys["hybrid_public"],
                "fp": keys["qr_fp"],
            },
            note="fp = SHA256(identity_pub || hybrid_identity_pub), 32 bytes",
        ),
        vec(
            "V19",
            "ctt1_v2_opening",
            "ctt1_v2_opening",
            "verify_ok_with_tag",
            hex_payload=v19.hex(),
            extra={"tag": "ctt1v2-s"},
            note="signature verifies with tag ctt1v2-s, fails without",
        ),
        vec(
            "V20",
            "ctt1_v2_reply",
            "ctt1_v2_reply",
            "verify_ok_with_tag",
            hex_payload=v20.hex(),
            extra={"tag": "ctt1v2-r"},
        ),
        vec(
            "V21",
            "ctt1_v2_opening_ed25519_only",
            "ctt1_v2_opening",
            "verify_fail",
            hex_payload=v21.hex(),
            note="ML-DSA half is zeros; hybrid_verify must fail",
        ),
        vec(
            "V22",
            "ctt1_v2_opening_zero_kem_ct",
            "ctt1_v2_opening",
            "malformed",
            hex_payload=v22.hex(),
            note="type 0x02 with 1568 zero kemCt is malformed",
        ),
        vec(
            "V23",
            "cthf_header",
            "cthf_header",
            "verify_ok",
            hex_payload=v23.hex(),
            extra={
                "chunk0_combined": keys["chunk0_combined"],
                "chunk0_plaintext": keys["chunk0_plaintext"],
                "file_channel_key": keys["file_channel_key"],
                "aad": SNAPSHOT_ID.hex() + USER_ID.hex() + struct.pack("<I", 0).hex(),
            },
            note="header verifies; chunk 0 opens with the derived key",
        ),
        vec(
            "V24",
            "cthf_wrong_kyber_key_id",
            "cthf_header",
            "kem_key_id_mismatch",
            hex_payload=v24.hex(),
            extra={"recipient_kyber_key_id": keys["wrong_kyber_key_id"], "current_kyber_key_id": keys["kyber_key_id"]},
        ),
    ]

    doc = {
        "$schema_version": 1,
        "$authority": "construct-protos/client/history_snapshot.proto",
        "$spec": "construct-docs/client/shared/construct-history-snapshot.md",
        "$design": "construct-docs/client/specs/DEVICE_LINK_HISTORY_TRANSFER.md",
        "$purpose": [
            "Golden bytes for CTH1 streams, CTT1 v2 frames, CTHF headers, discovery tags and",
            "Flow A QR fp. Every client that implements history transfer reads this file.",
            "A byte change is a PR 1 amendment first, vectors second, code third.",
        ],
        "$constants": {
            "max_record_bytes": MAX_RECORD_BYTES,
            "ctt1_v2_opening_len": OPENING_LEN,
            "ctt1_v2_reply_len": REPLY_LEN,
            "cthf_header_len": CTHF_HEADER_LEN,
            "hybrid_signature_len": 3373,
            "mlkem1024_ct_len": 1568,
            "snapshot_id": SNAPSHOT_ID.hex(),
            "user_id": USER_ID.hex(),
        },
        "$keys": {
            "comment": "The only place these test keys exist. Seeds are in scripts/gen_history_crypto/src/main.rs.",
            "hybrid_public": keys["hybrid_public"],
            "offering_identity_public": keys["offering_identity_public"],
            "receiver_identity_public": keys["receiver_identity_public"],
            "offering_device_id_raw": keys["offering_device_id_raw"],
            "receiver_device_id_raw": keys["receiver_device_id_raw"],
            "kyber_public": keys["kyber_public"],
            "kyber_key_id": keys["kyber_key_id"],
            "hybrid_ed25519_seed": keys["hybrid_ed25519_seed"],
            "hybrid_mldsa_seed": keys["hybrid_mldsa_seed"],
            "offering_identity_secret": keys["offering_identity_secret"],
            "receiver_identity_secret": keys["receiver_identity_secret"],
            "sender_eph_secret": keys["sender_eph_secret"],
            "kyber_secret": keys["kyber_secret"],
        },
        "vectors": vectors,
    }
    OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {OUT} ({len(vectors)} vectors)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
