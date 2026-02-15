# Cyfra Auth Server - Architecture

Push notification relay server for the Cyfra encrypted messaging app. Sits between mobile clients and Expo Push Notification Service.

## Project Structure

```
cyfra-auth-server/
  Cargo.toml              # Workspace root (members: server, shared)
  server/
    Cargo.toml
    src/main.rs            # HTTP server (warp) - the only binary
  shared/
    Cargo.toml
    src/
      lib.rs               # Public module exports + constants (ports, buffer sizes)
      encryption.rs        # All cryptography: Ed25519, X25519, AES-256-GCM, SHA-256
      storage.rs           # sled embedded DB wrapper (sync + async get/set)
      users.rs             # User struct and CRUD (used by broader Cyfra system, not this server directly)
      messages.rs          # Message/Chat/Envelope structs (used by broader Cyfra system)
      utils.rs             # Hex encoding, time formatting helpers
      shellio.rs           # Terminal I/O helpers (used by CLI clients)
    tests/
      crypto_test_vectors.rs  # Cross-platform crypto compatibility tests
```

## Server (`server/src/main.rs`)

### Overview

An HTTP server using **warp** on `0.0.0.0:3000`. Two POST endpoints, an embedded **sled** database at `./auth_db`, and outbound HTTPS to Expo.

### Endpoints

#### `POST /register_device`

Mobile clients call this to register their push token.

Request body (JSON, max 16KB):
```json
{
  "username": "string",
  "client_type": "apple" or "android",
  "push_token": "ExponentPushToken[xxxxx]",
  "public_key": "hex-encoded Ed25519 public key (32 bytes)",
  "signature": "hex-encoded Ed25519 signature (64 bytes)",
  "timestamp": 1707955200000
}
```

Processing:
1. **Input sanitization**: Rejects `username`, `client_type`, `push_token` containing `|` (pipe is the signed-data delimiter)
2. **Timestamp freshness**: Rejects timestamps older than 5 minutes (replay protection). Auto-detects seconds vs milliseconds.
3. **Signature verification**: Verifies Ed25519 signature over the string `register_device|{username}|{client_type}|{push_token}|{timestamp_as_decimal_string}`. The timestamp is the raw u64 converted to its decimal string representation (not binary).
4. **Storage**: Stores a `PushTokenRecord` JSON blob in sled, keyed by `{public_key_bytes}push_token`.

Responses:
- `200 "Registered"` - success
- `400 "Fields must not contain '|'"` - pipe in input fields
- `400 "Timestamp too old or too far in the future"` - stale timestamp
- `400 "Invalid hex for public key"` / `"Invalid hex for signature"` - bad hex encoding
- `401 "Invalid signature"` - Ed25519 verification failed

#### `POST /push_trigger`

Message servers (e.g., Pluto) call this to trigger a push notification to a user.

Request body (JSON, max 16KB):
```json
{
  "recipient_pub_key": "hex-encoded Ed25519 public key",
  "sender_pub_key": "hex-encoded Ed25519 public key",
  "timestamp": 1707955200000,
  "signed_timestamp": "hex-encoded Ed25519 signature"
}
```

Processing:
1. **Timestamp freshness**: Same 5-minute window check as register_device.
2. **Hex decoding**: All three hex fields are decoded with explicit error messages on failure.
3. **Signature verification**: Verifies Ed25519 signature over `{timestamp_as_8_little_endian_bytes}{recipient_public_key_bytes}`. Note: this is raw binary concatenation, NOT a string - different format from register_device.
4. **Token lookup**: Looks up `{recipient_pub_key_bytes}push_token` in sled.
5. **Push delivery**: If found and enabled, spawns an async task to POST to Expo. Errors are logged to stderr.

Responses:
- `200 "Triggered"` - push notification dispatched (async, may still fail)
- `400 "Timestamp too old or too far in the future"` - stale timestamp
- `400 "Invalid hex for ..."` - bad hex encoding
- `401 "Invalid signed_timestamp"` - Ed25519 verification failed
- `404 "Recipient not found or disabled"` - no push token registered

### Database Schema (sled)

Key-value store at `./auth_db`. Single key pattern:

| Key | Value |
|-----|-------|
| `{ed25519_public_key_bytes (32)}push_token` | JSON: `PushTokenRecord { expo_push_token, platform, enabled, updated_at }` |

### Push Delivery

The server does NOT contact Apple/Google directly. It sends to **Expo Push Notification Service**:

```
This Server  --->  https://exp.host/--/api/v2/push/send  --->  APNs / FCM
```

Payload sent to Expo:
```json
{
  "to": "ExponentPushToken[xxxxx]",
  "title": "New Message",
  "body": "You have a new encrypted message",
  "sound": "default"
}
```

A single `reqwest::Client` is created at startup and reused for connection pooling. Push is fire-and-forget (response returns before push completes) but errors are logged.

## Shared Library (`shared/`)

Reusable crate shared across the Cyfra ecosystem (this server, message server, CLI clients).

### `encryption.rs` - Cryptography

| Function | Algorithm | Purpose |
|----------|-----------|---------|
| `sign` / `verify` | **Ed25519** (ring) | Identity signing. Used by this server to authenticate requests. |
| `generate_enc_keypair` / `get_shared_secret` | **X25519** (x25519-dalek) | Diffie-Hellman key exchange for end-to-end encryption. Not used by this server directly. |
| `encrypt_data` / `decrypt_data` | **AES-256-GCM** (ring) | Symmetric encryption with authenticated associated data. Not used by this server directly. |
| `hash` | **SHA-256** (ring) | Hashing. Used for user credential storage (in users.rs). |

The nonce for AES-256-GCM uses a counter starting at 1, encoded as big-endian in the last 4 bytes of a 12-byte nonce.

### `storage.rs` - Database

Thin wrapper around **sled** (embedded key-value store). Provides sync and async (`Arc<RwLock<DB>>`) variants of get/set. Async versions acquire a read lock for gets and a write lock for sets. Writes call `db.flush()` after every insert.

### Other Modules

- **`users.rs`**: User account CRUD with encrypted-at-rest storage. Key = SHA256(username + password), encryption key = SHA256(password). Used by the broader Cyfra client system, not by this server's endpoints.
- **`messages.rs`**: Message, Chat, Envelope, Satchel structs for the messaging protocol. Not used by this server.
- **`utils.rs`**: Hex encoding/decoding, time formatting.
- **`shellio.rs`**: Terminal I/O (clear screen, input prompts). Used by CLI clients.
- **`lib.rs`**: Exports all modules. Contains constants like port numbers and protocol messages (`"verified"` for both verification and key update confirmations).

## Security Model

- **No passwords on the server**: Authentication is purely Ed25519 signature-based. Clients prove ownership of their private key.
- **Replay protection**: Signed timestamps must be within 5 minutes of server time.
- **Input sanitization**: Pipe characters rejected in fields that become part of pipe-delimited signed data.
- **Signature format difference**: `register_device` signs pipe-delimited ASCII strings; `push_trigger` signs binary-concatenated bytes. Both use Ed25519 but the payload construction differs - any client implementation must match these formats exactly.
- **Push tokens are not encrypted at rest**: The sled database stores Expo push tokens in plaintext JSON.

## Building and Running

```bash
cargo build --release
# Binary is at target/release/server
./target/release/server
# Listens on 0.0.0.0:3000, creates ./auth_db on first run
```

## Dependencies (Key)

| Crate | Version | Purpose |
|-------|---------|---------|
| warp | 0.3 | HTTP server framework |
| reqwest | 0.11 (rustls-tls) | Outbound HTTPS to Expo |
| sled | 0.34 | Embedded key-value database |
| ring | 0.17 | Ed25519, AES-256-GCM, SHA-256 |
| x25519-dalek | 2.0 | X25519 Diffie-Hellman |
| tokio | 1.x (full) | Async runtime |
| serde / serde_json | 1.x | JSON serialization |
| hex | 0.4 | Hex encoding/decoding |
