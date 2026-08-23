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
│   └── mls_service.proto (stub — not in production)
└── signaling/          — WebRTC signaling service
    └── signaling_service.proto
```

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
