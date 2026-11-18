# Security & Cryptographic Design

## Threat Model & Mitigations

| Threat | Control Implemented |
|---|---|
| Unsigned or forged AAMARVA authorization grant | Canonical JSON verification via Ed25519 / ECDSA P-256 against `AAMARVA_TRUSTED_SIGNING_KEYS_JSON` (`keyId` rotation supported). |
| Tampered Gateway issuance responses / unauthenticated Gateway origin | Every encrypted token response returns `gatewayPublicKey` (separate from agent keys) + `gatewaySignature` signed by `GatewayIdentityKeyManager` (private keys never exposed). |
| AAMARVA backend inspecting or intercepting plaintext token | Token encrypted with agent public key (`X25519`/`P-256` ECDH+HKDF-SHA256+AES-256-GCM or `RSA-OAEP-256`); plaintext never returned to AAMARVA or persisted. |
| Token replay or concurrent race on redemption | `SHA-256(token)` lookup inside atomic SQLite `BEGIN IMMEDIATE` transaction or Redis Lua `EVAL` script; second attempt rejected with `409`. |
| Token or session outliving underlying authorization grant | Token TTL and session TTL are strictly clamped to `authorizationExpiresAtMs`; grants `<15s` are rejected; execution enforces both `expiresAtMs` and `authorizationExpiresAtMs`. |
| Cross-agent, cross-account, or cross-server session reuse | Every redemption and relayed MCP execution strictly checks `agentId`, `accountId`, `mcpServerId`, and `gatewayId` against the persisted session record. |
| Spoofed `X-Forwarded-Proto: https` bypass over HTTP | TLS middleware checks `req.socket.encrypted` directly and only trusts `X-Forwarded-Proto: https` when peer `req.socket.remoteAddress` matches configured `TRUSTED_PROXY_IPS`. |
| Unauthenticated access to Operator Console | Console is disabled by default in `production`; enabling it in production requires `OPERATOR_CONSOLE_AUTH_TOKEN` (≥32 chars) verified in constant time with full audit logging. |
| Stale revocation or duplicate revocation webhook replay | Production defaults `AAMARVA_ONLINE_REVOCATION_CHECK=true` (fail-closed on unreachable backend); webhooks deduplicate `revocationId` atomically and support `sessionId`, `authorizationId`, `agentId+accountId`, and `accountId` revocation. |
| Tool discovery treated as execution permission | `ToolExecutionService` re-validates `session.scope.allowedTools` on every `tools/call` invocation; unauthorized tools fail closed (`403`) before touching MCP. |
| Direct agent bypass of AAMARVA mediation | No agent-facing MCP routes exist. `/api/v1/aamarva/*` requires `x-aamarva-hmac-sha256` over `(method, path, timestamp, requestId, sha256(body))` + header replay claim. |
| Secret leakage in logs or health checks | `redactSensitiveData` recursively masks `token`, `privateKey`, `secret`, `authorization`, `mcpCredentials`, etc.; `/healthz` and `/readyz` emit zero secrets. |
| In-memory replay state lost across restarts/instances | `validateGatewayConfig` blocks `STATE_STORE_DRIVER=memory` and `ALLOW_IN_MEMORY_STORE=true` when `NODE_ENV=production`. |

## Cryptographic Constructions

- **Grant Signatures**: Ed25519 (`crypto.verify(null, ...)`) and ECDSA P-256 (`crypto.verify('sha256', ...)`).
- **Gateway Identity Signing**: Dedicated Ed25519 / ECDSA P-256 keypair(s) managed by `GatewayIdentityKeyManager` with SHA-256 SPKI fingerprints (`sha256:<hex>`), separate from agent encryption keys.
- **Short-Lived Tokens**: 256-bit `crypto.randomBytes(32)` base64url secret prefixed with `agw1.tok_<16-byte-hex>.`.
- **Envelope Encryption (`AAMARVA-GW-ENV-V1`)**:
  - Ephemeral ECDH (`x25519` or `prime256v1`) → HKDF-SHA256 (`salt` 32B, `info = aamarva-mcp-gateway:token-envelope:v1:<agentId>:<tokenId>`) → AES-256-GCM (12B random IV, AAD over canonicalized envelope metadata).
  - Or RSA-OAEP-SHA256 (≥2048-bit key) wrapping a 256-bit CEK + AES-256-GCM.
- **Backend Relay & Outbox Sync Auth**: HMAC-SHA256 using `AAMARVA_BACKEND_AUTH_SECRET` with timestamp skew enforcement (`AAMARVA_MAX_CLOCK_SKEW_SECONDS`) and atomic `requestId` / `idempotencyKey` deduplication.
