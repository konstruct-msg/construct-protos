#!/usr/bin/env python3
"""The fixture manifest's canonical bytes hash to its pack_id, and its fields are what it says.

`knst_sticker_pack.json` fixes how a pack's identity is computed: SHA-256 over the manifest with
pack_id and signature cleared. This re-derives everything from the stated fields with `protoc`
against the proto as it stands — a renumbered field, a changed type or a differently-ordered
encoder changes the canonical bytes and fails here rather than as "every pack is rejected".

Exit 1 on any disagreement. Needs `protoc` on PATH; run it from anywhere.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "messaging" / "sticker_pack.proto"
VECTORS = Path(__file__).resolve().parent / "knst_sticker_pack.json"
MESSAGE = "shared.proto.messaging.v1.StickerPackManifest"


def esc(b: bytes) -> str:
    return "".join(f"\\x{x:02x}" for x in b)


def encode(textproto: str) -> bytes:
    return subprocess.run(
        ["protoc", "-I", str(ROOT), f"--encode={MESSAGE}", str(PROTO)],
        input=textproto.encode(), capture_output=True, check=True,
    ).stdout


def main() -> int:
    doc = json.loads(VECTORS.read_text())
    m = doc["manifest"]
    errors: list[str] = []

    entries = " ".join(
        f'stickers {{ sha256: "{esc(bytes.fromhex(e["sha256"]))}" emoji: "{e["emoji"]}" '
        f'width: {e["width"]} height: {e["height"]} byte_len: {e["byte_len"]} }}'
        for e in m["stickers"]
    )
    canon_tp = f'title: "{m["title"]}" publisher: "{m["publisher"]}" {entries}'
    canonical = encode(canon_tp)
    if canonical.hex() != doc["canonical_hex"]:
        errors.append("canonical bytes differ from the stated fields")
    pack_id = hashlib.sha256(canonical).hexdigest()
    if pack_id != doc["pack_id_hex"]:
        errors.append(f"pack_id: sha256(canonical) is {pack_id}, file says {doc['pack_id_hex']}")

    sig = bytes.fromhex(doc["signature_hex"])
    full_tp = f'pack_id: "{esc(bytes.fromhex(doc["pack_id_hex"]))}" {canon_tp}'
    if sig:
        full_tp += f' signature: "{esc(sig)}"'
    if encode(full_tp).hex() != doc["manifest_hex"]:
        errors.append("manifest_hex is not canonical + pack_id (+ signature)")

    for e in m["stickers"]:
        if len(bytes.fromhex(e["sha256"])) != 32:
            errors.append(f'entry {e["emoji"]}: sha256 is not 32 bytes')
        if e["width"] != 512 or e["height"] != 512:
            errors.append(f'entry {e["emoji"]}: not 512×512')
        if not (0 < e["byte_len"] <= 100 * 1024):
            errors.append(f'entry {e["emoji"]}: byte_len out of range')
        if not (1 <= len(e["emoji"].encode()) <= 32):
            errors.append(f'entry {e["emoji"]!r}: emoji out of the StickerRef range')

    for err in errors:
        print(f"✗ {err}")
    if not errors:
        print(f'✓ pack {doc["pack_id_hex"][:16]}…: {len(m["stickers"])} entries, canonical bytes and pack_id re-derive')
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
