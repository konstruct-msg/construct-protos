#!/usr/bin/env python3
"""The sticker vectors decode to what they claim, and the cases agree with the rules.

`knst_sticker_ref.json` is the authority for two things every client must compute identically:
the bytes of a `MessageContent.sticker` and the answer of the validator. This re-decodes each
vector with `protoc` against the proto as it is now — so a renumbered field or a changed type
fails here, not on a device — and re-runs the stated rules over every case, so a case whose
`valid` disagrees with `rules` cannot sit in the file telling clients two things.

Exit 1 on any disagreement. Needs `protoc` on PATH; run it from anywhere.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "messaging" / "content.proto"
VECTORS = Path(__file__).resolve().parent / "knst_sticker_ref.json"
MESSAGE = "shared.proto.messaging.v1.MessageContent"


def decode(hex_bytes: str) -> str:
    r = subprocess.run(
        ["protoc", "-I", str(ROOT), f"--decode={MESSAGE}", str(PROTO)],
        input=bytes.fromhex(hex_bytes), capture_output=True, check=True,
    )
    return r.stdout.decode()


def field(text: str, name: str) -> str | None:
    m = re.search(rf'^\s*{name}: (.+)$', text, re.M)
    return m.group(1) if m else None


def unescape(protoc_string: str) -> bytes:
    """protoc --decode prints bytes as a C-escaped, double-quoted string."""
    body = protoc_string[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out += c.encode()
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in "01234567":
            j = i + 1
            while j < len(body) and j < i + 4 and body[j] in "01234567":
                j += 1
            out.append(int(body[i + 1:j], 8))
            i = j
        elif nxt == "x":
            out.append(int(body[i + 2:i + 4], 16))
            i += 4
        else:
            out += {"n": b"\n", "r": b"\r", "t": b"\t", "\\": b"\\", '"': b'"', "'": b"'"}[nxt]
            i += 2
    return bytes(out)


def main() -> int:
    doc = json.loads(VECTORS.read_text())
    errors: list[str] = []

    for v in doc["vectors"]:
        text = decode(v["message_content_hex"])
        if not text.lstrip().startswith("sticker {"):
            errors.append(f'{v["id"]}: oneof is not `sticker`')
            continue
        got_pack = unescape(field(text, "pack_id") or '""').hex()
        got_index = int(field(text, "index") or 0)
        got_emoji = unescape(field(text, "emoji") or '""').decode()
        if got_pack != v["pack_id_hex"]:
            errors.append(f'{v["id"]}: pack_id decoded {got_pack}, vector says {v["pack_id_hex"]}')
        if got_index != v["index"]:
            errors.append(f'{v["id"]}: index decoded {got_index}, vector says {v["index"]}')
        if got_emoji != v["emoji"]:
            errors.append(f'{v["id"]}: emoji decoded {got_emoji!r}, vector says {v["emoji"]!r}')

    rules = doc["rules"]
    for c in doc["cases"]:
        pack_ok = len(bytes.fromhex(c["pack_id_hex"])) == rules["pack_id_bytes"]
        n = len(c["emoji"].encode("utf-8"))
        emoji_ok = rules["emoji_min_bytes"] <= n <= rules["emoji_max_bytes"]
        computed = pack_ok and emoji_ok
        if computed != c["valid"]:
            errors.append(f'case {c.get("why") or c["emoji"]!r}: rules say {computed}, file says {c["valid"]}')

    for e in errors:
        print(f"✗ {e}")
    if not errors:
        print(f'✓ {len(doc["vectors"])} vectors decode as stated, {len(doc["cases"])} cases agree with rules')
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
