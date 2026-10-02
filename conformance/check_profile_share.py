#!/usr/bin/env python3
"""The profile-share vectors encode and apply as they claim.

`knst_profile_share.json` fixes two things both clients must agree on for CONTENT_TYPE_PROFILE
(29): how a `ProfileShare` payload reads (`decode` cases — bytes produced here by `protoc` from the
proto as it is now), and what a receiver does with one given what it already holds (`apply`
cases). A disagreement is silent: one client shows the new name and the other the old one, or
one clears an avatar the other keeps. `--write` regenerates the file.

Needs `protoc` on PATH.
"""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROTO = ROOT / "core" / "envelope.proto"
VECTORS = Path(__file__).resolve().parent / "knst_profile_share.json"
MESSAGE = "shared.proto.core.v1.ProfileShare"

KEY = bytes(range(0x20, 0x40))   # a 32-byte media key
SHORT_KEY = bytes(range(0x20, 0x30))


def avatar_text(key: bytes) -> str:
    octal = "".join(f"\\{b:03o}" for b in key)
    return (f'avatar_set {{ media_id: "m-1" media_url: "https://media.example/m-1" '
            f'media_key: "{octal}" mime_type: "image/jpeg" }}')


def encode(text: str) -> str:
    r = subprocess.run(["protoc", "-I", str(ROOT), f"--encode={MESSAGE}", str(PROTO)],
                       input=text.encode(), capture_output=True, check=True)
    return r.stdout.hex()


SET = {"media_id": "m-1", "media_url": "https://media.example/m-1", "media_key": KEY.hex(),
       "mime_type": "image/jpeg"}


def build() -> dict:
    decode = [
        {"name": "name_and_avatar",
         "text": f'display_name: "Alice" edited_at_ms: 1759400000000 {avatar_text(KEY)}',
         "display_name": "Alice", "edited_at_ms": 1759400000000, "avatar": {"set": SET}},
        {"name": "avatar_removed",
         "text": 'display_name: "Alice" edited_at_ms: 1759400000001 avatar_removed: true',
         "display_name": "Alice", "edited_at_ms": 1759400000001, "avatar": "removed"},
        {"name": "avatar_unchanged",
         "text": 'display_name: "Алиса" edited_at_ms: 1759400000002',
         "display_name": "Алиса", "edited_at_ms": 1759400000002, "avatar": "unchanged"},
        {"name": "short_key_is_unchanged",
         "text": f'display_name: "Alice" edited_at_ms: 1759400000003 {avatar_text(SHORT_KEY)}',
         "display_name": "Alice", "edited_at_ms": 1759400000003, "avatar": "unchanged"},
    ]
    for case in decode:
        case["payload"] = encode(case.pop("text"))

    # held_edited_at_ms: null = nothing applied yet for this sender.
    # result: "ignore", or "apply" with what happens to the avatar held.
    apply = [
        {"name": "first_profile", "held_edited_at_ms": None, "edited_at_ms": 10,
         "avatar": "unchanged", "result": "apply", "avatar_action": "keep"},
        {"name": "newer", "held_edited_at_ms": 10, "edited_at_ms": 11,
         "avatar": "set", "result": "apply", "avatar_action": "download"},
        {"name": "same_is_not_newer", "held_edited_at_ms": 11, "edited_at_ms": 11,
         "avatar": "set", "result": "ignore", "avatar_action": None},
        {"name": "older_is_ignored", "held_edited_at_ms": 11, "edited_at_ms": 9,
         "avatar": "removed", "result": "ignore", "avatar_action": None},
        {"name": "removed_clears", "held_edited_at_ms": 11, "edited_at_ms": 12,
         "avatar": "removed", "result": "apply", "avatar_action": "clear"},
        {"name": "unchanged_keeps", "held_edited_at_ms": 12, "edited_at_ms": 13,
         "avatar": "unchanged", "result": "apply", "avatar_action": "keep"},
    ]
    return {
        "_doc": "CONTENT_TYPE_PROFILE (29). decode: a ProfileShare payload and how it reads; avatar "
                "is {set: ...}, \"removed\" or \"unchanged\" (absent, or a key that is not 32 bytes). "
                "apply: a profile is applied only if edited_at_ms is strictly greater than the one "
                "held for that sender (none held = apply); then set → download and replace, "
                "removed → clear, unchanged → keep. Checked by check_profile_share.py. Decision: "
                "construct-docs decisions/profile-share-is-a-typed-versioned-state.md.",
        "decode": decode,
        "apply": apply,
    }


def check_apply(case: dict) -> bool:
    held = case["held_edited_at_ms"]
    newer = held is None or case["edited_at_ms"] > held
    if not newer:
        return case["result"] == "ignore" and case["avatar_action"] is None
    action = {"set": "download", "removed": "clear", "unchanged": "keep"}[case["avatar"]]
    return case["result"] == "apply" and case["avatar_action"] == action


def main() -> int:
    fresh = build()
    if "--write" in sys.argv:
        VECTORS.write_text(json.dumps(fresh, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote {VECTORS.name}")
        return 0
    if json.loads(VECTORS.read_text()) != fresh:
        print("knst_profile_share.json disagrees with the proto or the rules — regenerate with --write")
        return 1
    for case in fresh["apply"]:
        if not check_apply(case):
            print(f"apply/{case['name']}: result disagrees with the rule")
            return 1
    print(f"{VECTORS.name}: {len(fresh['decode'])} decode + {len(fresh['apply'])} apply cases — consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
