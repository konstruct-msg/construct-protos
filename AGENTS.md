# AGENTS.md — construct-protos

Context for AI agents working in this repository.

---

## What is construct-protos?

Shared protobuf definitions for the entire Construct ecosystem.
Used by: `construct-server`, `construct-tui`, `construct-android`, `construct-messenger`.
(`construct-engine` was retired 2026-07-28 and is not a consumer.)

## Adding a value to `ContentType` — read this first

`core/envelope.proto` owns which content types exist. It does **not** say what a client must do
with one, and until 2026-08-23 nothing did: iOS and the TUI each carried their own classification
and had already drifted on 13 and 23 without anything reporting it, because the symptom is a
payload that renders as a bubble on one client and vanishes on the other.

`conformance/knst_content_types.json` is now that authority, and every client has a test reading
it. **A new content type gets its row in the same change as the enum value.** Run
`conformance/check_content_types.py` — it fails if the proto and the vectors disagree about which
values exist, which is the case where a client's conformance test would pass by never being asked.

Contact-card vectors: `conformance/knst_contact_card.json`, checked by
`conformance/check_contact_card.py` (needs `protoc`). How a type-27 payload is read — a
`ContactCard`, or at exactly 32 bytes a bare intake key from before the card — by both clients.

KNST frame vectors: `conformance/knst_frame.json`, checked by `conformance/check_knst_frame.py`
(`--write` regenerates). The 30-byte plaintext header every body is framed with, and when a frame
is a control frame (one message, total_chunks 1) and what its body is. iOS, Android, the TUI and
construct-core read it; until 2026-10-02 only their agreement fixed it.

Profile vectors: `conformance/knst_profile_share.json`, checked by
`conformance/check_profile_share.py` (needs `protoc`, `--write` regenerates). How a
CONTENT_TYPE_PROFILE (29) payload reads — the avatar is set, removed or unchanged — and when a
receiver applies one: only if `edited_at_ms` is newer than the one it holds. Both clients read it.

Invite vectors: `conformance/knst_invite.json`, checked by `conformance/check_invite.py`
(`--write` regenerates). iOS, Android and the server each build the v5 canonical string and the
compact binary independently, and a disagreement surfaces only at redeem as "invalid signature" —
so a change to `InviteToken` or the CIv1 layout is a change to that file in the same commit.

History-snapshot vectors: `conformance/knst_history_snapshot.json`, checked by
`conformance/check_history_snapshot.py`.

Sticker vectors: `conformance/knst_sticker_ref.json`, checked by `conformance/check_sticker_ref.py`
(needs `protoc`). A sticker is `MessageContent.sticker` *inside* the E2EE plaintext, so it is
**not** a `ContentType` and gets no row in `knst_content_types.json`; what the clients must agree
on instead is the bytes of the oneof and the validator (32-byte pack hash, 1..32-byte emoji), and
that file is where they agree.

Sticker packs: `messaging/sticker_pack.proto` (`StickerPackManifest`, `StickerEntry`). A pack's
identity is the SHA-256 of its canonical bytes — proto3 binary, ascending field order, `pack_id`
and `signature` cleared — and `conformance/knst_sticker_pack.json` fixes those bytes on one
fixture pack; `check_sticker_pack.py` re-derives them. A client that hashes differently rejects
every real pack, so a change to that message is a change to that file in the same commit. Schema is `client/history_snapshot.proto` (never
mirrored). Regenerate with `scripts/gen_history_snapshot_vectors.py`.

Full reasoning: `construct-docs/decisions/wire-format-one-authority.md`.

---

## Structure

```
construct-protos/
├── buf.yaml            — buf.build config
├── core/               — Shared types (crypto, identity, envelope, pagination)
├── messaging/          — Message content types (e2ee, mls, p2p, content)
├── services/           — gRPC service definitions (one .proto per service)
│   ├── auth_service.proto
│   ├── user_service.proto
│   ├── messaging_service.proto
│   ├── notification_service.proto
│   ├── invite_service.proto
│   ├── media_service.proto
│   ├── key_service.proto
│   ├── sentinel_service.proto
│   ├── mls_service.proto (stub — not in production)
│   └── sticker_service.proto
├── signaling/          — WebRTC signaling service
│   └── signaling_service.proto
└── client/             — Client-only schemas. Never mirrored, never enters construct-server.
```

`client/` is client-only: never mirrored from `construct-server`, never copied into
`construct-server/shared/proto`. `scripts/sync-from-server.sh` lists `core messaging
services signaling` and does not touch this directory. iOS `generate_grpc_swift.sh`
finds any `*.proto` in the repo; TUI `build.rs` lists files and adds a path here when
that client implements the schema. Do not invent a second generator to keep these
out of the server — the mirror's directory list is the mechanism.

---

## Services & Ports

| Service | Port | Description |
|---------|------|-------------|
| AuthService | 50051 | Registration, login, device management, PoW |
| UserService | 50052 | Profile, contacts, blocking, search |
| MessagingService | 50053 | Send/receive E2EE messages, stream |
| NotificationService | 50054 | APNs/FCM push notifications |
| InviteService | 50055 | Invite link creation and redemption |
| MediaService | 50056 | S3 upload, presigned URLs |
| KeyService | 50057 | X3DH pre-key management |
| SentinelService | 50059 | Anti-spam, rate limiting, trust scoring |
| SignalingService | 50060 | WebRTC SDP/ICE signaling |
| StickerService | 50056 (with MediaService, media-service) | Public content-addressed sticker packs; every RPC unauthenticated, integrity by signed manifest + hashes |

---

## Editing protos

```bash
# Validate
buf lint

# Generate (Swift — for construct-messenger)
buf generate --template buf.gen.swift.yaml

# Generate (Kotlin — for construct-android)
buf generate --template buf.gen.kotlin.yaml

# Generate (Rust — for construct-server / construct-engine)
# Done in the consuming crate's build.rs via tonic-build
```

**Rules:**
- Never edit files in `generated/` — they are auto-generated
- All `bytes` fields that carry crypto material must be `bytes`, not `string`
- Proto field numbers are immutable once in production — never reuse a field number
- Add new fields at the end of a message; never insert in the middle
- When adding a new service, add it to this AGENTS.md service table
- `client/` is not a server mirror. Do not add it to `sync-from-server.sh`. Do not copy it into `construct-server`.

---
---

## Documentation & session notes

All docs live in `~/Code/construct-docs` (Obsidian vault, flat domain folders:
`architecture/ backend/ client/ cryptocore/ security/ decisions/ sessions/ …`).
**The vault's `AGENTS.md` is authoritative** for structure and writing rules — read it before
contributing docs. If a path is missing, search the domain folder rather than trusting old links.

After any session with architectural changes, design decisions, root-cause analysis, or
non-obvious choices:

1. Write a session note `sessions/YYYY-MM-DD-<topic>.md` (sections: Context / What Changed /
   **Why** / Decisions / Open Questions) — `## Why` with rejected alternatives is mandatory.
2. If it constrains future work, add/update `decisions/<slug>.md`.
3. Patch the affected spec in its domain folder in the **same** session.
4. Append one line to `~/Code/construct-docs/log.md`: `[YYYY-MM-DD HH:MM] note | <topic>`.

Session notes are plain markdown, no YAML frontmatter; `[[wikilinks]]` to other notes are welcome.
Before creating a note, search for an existing one and extend it rather than duplicating.

## Git workflow (branch + PR only)

**Never commit on `main`.** Every change goes on a topic branch cut from an up-to-date `main`
(`feat|fix|docs|chore|test/<topic>`) and lands through a GitHub pull request. Agents push and
open the PR only when asked.

`main` is what a release is built from, so it moves only by a reviewed merge. From 2026-09-11 to
2026-10-01 changes went straight to `main` across the construct-* repos — two people on the
project made a branch per change look like ceremony. That was reversed on purpose: the habit has
to be in place before there is a release for it to break.

A commit that landed on `main` by mistake and is not pushed moves off it with
`git branch <topic> && git reset --keep origin/main && git switch <topic>`. Pushed history is
never rewritten.
