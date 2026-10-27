# AGENTS.md — construct-protos

Shared protobuf definitions and cross-client conformance vectors for the whole Construct
ecosystem. Consumers: `construct-server`, `construct-core`, `construct-tui`, `construct-android`,
`construct-messenger`. This repo is where "what a message means" has one authority; a client or
server that decides it separately drops messages silently.

| Area | Read first |
|---|---|
| Why these rules exist; checklist before any new protocol feature | `~/Code/construct-docs/decisions/rules-from-the-first-year.md` |
| Wire format, one authority | `~/Code/construct-docs/decisions/wire-format-one-authority.md` |
| One meaning, two carriers | `~/Code/construct-docs/decisions/one-meaning-two-carriers.md` |
| Read-state sync (type 30) | `decisions/read-state-syncs-between-own-devices.md` |
| Device certificates | `decisions/devices-of-an-account-sign-each-other.md` |
| Server-trust vectors | `decisions/server-keys-rooted-offline-and-hybrid.md` |
| Everything else | `~/Code/construct-docs` (vault; its own `AGENTS.md` is authoritative) — `decisions/` paths are relative to it |

## The Zen of Konstruct

```
Someone has solved it before. Read them first.
The core decides; the app executes.
A message names the state it means. Time is not an address.
Reproduce, then fix.
One meaning, one carrier.
Bytes stay bytes.
Measure, then build.
The effect is the proof, not the exit code.
A test that cannot fail is worse than no test.
Boring before new.
Temporary is permanent, unless something checks it.
What nothing reads is not sent.
Silence is the worst failure: a message that never appears raises no error.
```

Canonical source: `~/Code/construct-docs/decisions/rules-from-the-first-year.md`. Change it there first.

## Rules

1. **Prior art first.** A new message type or schema starts with a note: how Signal / MLS (RFC 9420) / Matrix carry it, and why we deviate. Group messages follow MLS framing.
2. **The core decides.** A proto states shape, not behaviour. What two clients must compute identically lives in `construct-core`; the vectors here are the executable agreement, not a second implementation.
3. **A control message names the state it refers to.** A new control message carries an epoch, key or number the receiver can compare. A field that exists to be compared with a clock means the message has no address.
4. **Reproduce before fixing.** A vector that reproduces a disagreement lands red first; the fix turns it green.
5. **One meaning, one carrier.** A new `content_type` gets its row in `conformance/knst_content_types.json` in the same change as the enum value. Different identifiers get different types, never a bare `string`.
6. **Bytes stay bytes.** Crypto material, keys, ciphertexts and payloads are `bytes`, never `string`; no base64 or JSON inside a proto field.
7. **Measure, then build.** A field added for a limit or an optimisation cites the measurement; a field no measurement needs is not added.
8. **The effect is the proof.** Run the `conformance/check_*.py` for what you touched and read the output — a client test that is never asked a case passes by silence.
9. **A test must be able to fail.** A new vector is mutation-checked: change one byte of the input and see the check go red. A script that cannot fail is worse than none.
10. **Depth before breadth.** No schema for a surface (groups, rooms, Studio) until its predecessor is boring on the stand.
11. **A temporary exception has an end date and a check.** A deprecated field is marked with what replaces it and what check notices when it can go; a stub (`mls_service.proto`) says it is a stub.
12. **Branch and PR, always;** see Git.

**Three questions for a change to a delivery or crypto message**, answered in the commit message: (1) what does the server or any relay learn that it did not before — every new field outside the E2EE plaintext is something the server reads; (2) what can a party withhold or substitute that it could not before; (3) which trust boundary moves, and which way.

**A producer with no consumer is a defect.** A new message or field lands with a reader in at least one client or the server, or is not added.

## Invariants of this repo

### Schema

- Never edit `generated/`. Field numbers are immutable once in production — never reuse one; add new fields at the end of a message, never in the middle.
- `buf lint` before pushing. Generate: `buf generate --template buf.gen.swift.yaml` (Swift), `buf.gen.kotlin.yaml` (Kotlin); Rust is `tonic-build` in the consuming crate's `build.rs`.
- A new service goes into the ports list below.
- `client/` is client-only: never mirrored from `construct-server`, never copied into `construct-server/shared/proto`. `scripts/sync-from-server.sh` lists `core messaging services signaling` and must not gain `client/`. Do not invent a second generator to keep it out — the mirror's directory list is the mechanism.
- Layout: `core/` shared types · `messaging/` content types · `services/` one `.proto` per gRPC service (`mls_service.proto` is a stub, not in production) · `signaling/` · `client/`.

Ports: Auth 50051 · User 50052 · Messaging 50053 · Notification 50054 · Invite 50055 · Media 50056 · Key 50057 · Sentinel 50059 · Signaling 50060. StickerService shares 50056 with Media: public content-addressed packs, every RPC unauthenticated, integrity by signed manifest + hashes.

### Conformance vectors

`core/envelope.proto` owns which content types exist; `conformance/knst_content_types.json` owns what a client must do with one (transcript or control, handler, whether a sealed envelope may name it). Every client has a test reading it. `check_content_types.py` fails when the proto and the vectors disagree on which values exist.

Each file below is changed in the same commit as the message it fixes; its `check_*.py` is the gate (`--write` regenerates where the script offers it; "protoc" means it needs `protoc`).

| Vector | Fixes | Notes |
|---|---|---|
| `knst_contact_card.json` | type-27 payload: a `ContactCard`, or exactly 32 bytes = bare intake key from before the card | protoc |
| `knst_frame.json` | the 30-byte plaintext KNST header; when a frame is a control frame (total_chunks 1); how a body splits (3770 bytes each, ≤256 frames) | iOS, Android, TUI, core read it |
| `knst_profile_share.json` | type-29 payload: avatar set / removed / unchanged; applied only if `edited_at_ms` is newer | protoc |
| `knst_read_markers.json` | type-30: a marker moves the boundary only if strictly later on `(sent_at_ms, message_id)`, never from anyone but the own account; type 30 is `own_devices_only` | protoc |
| `knst_invite.json` | v5 canonical string and compact CIv1 binary, built independently by iOS, Android and server; a mismatch shows only at redeem as "invalid signature" | |
| `knst_history_snapshot.json` | history snapshot; schema is `client/history_snapshot.proto` (never mirrored) | regenerate with `scripts/gen_history_snapshot_vectors.py` |
| `knst_device_certificate.json` | what a device signs when vouching for a linked one: the 5382-byte `DevicePreKeyBundle.device_certificate` and `ConfirmDeviceLinkRequest.link_key_proof` | core signs and judges; script rebuilds every byte string but the signatures |
| `knst_sticker_ref.json` | a sticker is `MessageContent.sticker` inside the E2EE plaintext — **not** a `ContentType`, no row in `knst_content_types.json`; oneof bytes and validator (32-byte pack hash, 1..32-byte emoji) | protoc |
| `knst_sticker_pack.json` | `messaging/sticker_pack.proto`: pack identity = SHA-256 of canonical bytes (proto3 binary, ascending field order, `pack_id` and `signature` cleared); a different hash rejects every real pack | |
| `knst_server_trust.json` | what the offline root signs, what a delegated key signs (`label ‖ kid ‖ body`), bodies of `SenderCertificate.server_signature_hybrid` and `SignedTreeHead.signature` | authority is the `construct-server-trust` crate in construct-core (`write_server_trust_vectors`); stdlib only |

Other vectors without a note here (`knst_safety_number`, `knst_device_copy_tag`, `knst_token_seal`, `transport_route`) follow the same rule: `check_*.py` or the owning crate is the gate, and a change to the message is a change to the file.

## Git

- **Never commit on `main`.** Topic branch (`feat|fix|docs|chore|test/<topic>`) from up-to-date `main`, PR into `main`; `main` is what a release is built from. The owner merges.
- Check `git branch --show-current` and `git status` before every commit; other sessions share the tree. Never `checkout -- .`, `restore .`, `reset --hard` or `stash`; name files. Never rewrite pushed history. A commit made on `main` by mistake and not pushed moves with `git branch <topic> && git reset --keep origin/main && git switch <topic>`.
- Docs: the vault's `AGENTS.md` is authoritative; a decision that constrains future work goes to `decisions/`, one line to `log.md`.
