# construct-protos

Protobuf definitions for the [Construct](https://github.com/maximeliseyev/construct-server) messaging platform.

## Directory Structure

```
construct-protos/
├── core/           # Shared types (crypto, identity, envelope, pagination)
├── messaging/      # Message content types
├── services/       # gRPC service definitions
│   ├── auth_service.proto
│   ├── user_service.proto
│   ├── messaging_service.proto
│   ├── notification_service.proto
│   ├── invite_service.proto
│   ├── media_service.proto
│   ├── key_service.proto
│   ├── mls_service.proto
│   └── sentinel_service.proto
└── signaling/      # WebRTC signaling (future)
```

## Services & Ports

| Service            | Port  | Description                        |
|--------------------|-------|------------------------------------|
| AuthService        | 50051 | Registration, login, recovery      |
| UserService        | 50052 | Profile, contacts, blocking        |
| MessagingService   | 50053 | Send/receive E2E encrypted messages |
| NotificationService| 50054 | Push notifications (APNs/FCM)      |
| InviteService      | 50055 | User invites                       |
| MediaService       | 50056 | File upload/download               |
| KeyService         | 50057 | X3DH key bundles, OTPKs            |
| MlsService         | 50058 | Group chats (OpenMLS, post-MVP)    |
| SentinelService    | 50059 | Anti-spam, rate limiting           |

## Generating Swift Code (iOS)

### Prerequisites

```bash
brew install protobuf swift-protobuf grpc-swift
```

### Generate

```bash
./scripts/generate-swift.sh
# Output: generated/swift/
```

### Swift Package Manager

Add generated files to your Xcode project or reference the generated directory in your Swift package.

## Generating Rust Code (Server)

The server uses `tonic-build` via `build.rs` — no manual generation needed.  
See `construct-server/shared/build.rs`.

## Versioning

- This repository is pinned to construct-server via the `PROTOS_VERSION` tag.
- Tag format: `v{major}.{minor}.{patch}` — mirrors the server release.
- Breaking changes (field removal, type changes) increment the major version.

## Updating from Server

```bash
./scripts/sync-from-server.sh /path/to/construct-server
```

## Trademark

**Konstruct™** / **Конструкт™** and the logo are trademarks of Maxim Eliseyev. The open-source
license on this code does **not** grant trademark rights — see [TRADEMARK.md](TRADEMARK.md).
Forks that distribute a modified version must rebrand.
