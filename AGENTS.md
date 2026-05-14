# AGENTS.md — construct-protos

Context for AI agents working in this repository.

---

## What is construct-protos?

Shared protobuf definitions for the entire Construct ecosystem.
Used by: `construct-server`, `construct-engine`, `construct-tui`, `construct-android`, `construct-messenger`.

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

## Shared Construct Docs Workflow

These instructions apply to GitHub Copilot, Codex, OpenCode, and similar coding agents.

### Division of labour — read this first

| Role | Tool | Responsibility |
|------|------|----------------|
| **Coding agent** (you) | Copilot / Codex | Write code + drop raw session notes into `wiki/sessions/` and `wiki/decisions/`. That is all. |
| **Wiki pipeline** | `obsidian-llm-wiki-local` (olw) | Reads `raw/`, synthesizes concepts, creates/updates wiki articles, generates cross-links. |
| **Developer** | Human + Obsidian | Reviews wiki draft articles, approves/rejects. Curates `raw/`. |

**Your job is code.** olw handles article synthesis. Write plain-markdown session notes; let the pipeline do the rest.

### Shared knowledge base

- Vault: `/Users/maximeliseyev/Code/constrcut-docs`
- `raw/` — source corpus. Do **not** rewrite or reorganize.
- `wiki/` — canonical curated knowledge base. **Read** from here before architectural work.
- `wiki/.drafts/` — **reserved for olw**. Never write here manually.
- `wiki/sessions/` — where coding agents write session notes.
- `wiki/decisions/` — where coding agents write long-lived decision records.

### Where to save durable reasoning

After any session involving architectural changes, design decisions, API changes, or non-obvious implementation choices:

1. **Always** create or update `wiki/sessions/YYYY-MM-DD-<topic>.md`.
2. **Always** fill in `# Why` — reasoning, alternatives considered, why rejected. Most important section.
3. If the decision constrains future work, also create `wiki/decisions/<topic>.md`.
4. Session notes: plain markdown, **no YAML frontmatter, no `[[wikilinks]]`** — olw adds those.

Required note sections: `# Context`, `# What Changed`, `# Why`, `# Intended Outcome`, `# Decisions`, `# Open Questions`

### Operational logging

Append a one-line entry to `wiki/log.md` after writing a note.
Format: `[YYYY-MM-DD HH:MM] note | <topic>`

