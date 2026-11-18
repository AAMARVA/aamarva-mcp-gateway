# Authorization Flow

The Gateway implements the complete 7-phase authorization workflow faithfully.

## Phase 1 — Authorization Originates from AAMARVA

1. AAMARVA Core authenticates the agent, evaluates policy (including FLOOR human approval if required), and constructs an authorization grant containing `authorizationId`, `agentId`, `agentName`, `accountId`, `agentPublicKeyPem`, `mcpServerId`, `gatewayId`, `allowedTools`, `issuedAt`, and `expiresAt`.
2. AAMARVA signs the canonicalized claims object using its private signing key (`ed25519` or `ecdsa-p256-sha256`) and sends `{ claims, keyId, signature }` to `POST /api/v1/aamarva/authorizations/issue-token`.
3. `AamarvaAuthorizationAdapter` verifies the HMAC backend headers, checks clock skew, verifies the asymmetric signature against `AAMARVA_TRUSTED_SIGNING_KEYS_JSON[keyId]`, and verifies `gatewayId` and `mcpServerId` match this installation.

## Phase 2 — Short-Lived Token Generation

`generateShortLivedToken` creates an unpredictable 256-bit CSPRNG token (`agw1.tok_<32-hex>.<43-base64url>`) containing no PII or account identifiers. Token expiration is strictly clamped to `Math.min(now + tokenTtlSeconds, authorizationGrant.expiresAt)`; grants with less than `15` seconds remaining validity are rejected (`400 INSUFFICIENT_GRANT_VALIDITY`). Only the token's SHA-256 digest (`tokenHash`) is persisted in the state store along with strict bindings (`agentId`, `accountId`, `mcpServerId`, `gatewayId`, `scope`, `expiresAtMs`, `authorizationExpiresAtMs`).

## Phase 3 — Public-Key Envelope Encryption

`encryptTokenForAgent` inspects the agent's verified public key (`crypto.createPublicKey`) and builds an authenticated `AAMARVA-GW-ENV-V1` envelope:
- **X25519 / P-256**: Ephemeral ECDH + HKDF-SHA256 + AES-256-GCM with AAD binding `(version, algorithm, tokenId, agentId, accountId, mcpServerId, gatewayId, expiresAt)`.
- **RSA (≥2048-bit)**: RSA-OAEP-SHA256 key wrap + AES-256-GCM with identical AAD.

Plaintext tokens are never returned to AAMARVA or stored in logs or databases.

## Phase 4 — Encrypted Token & Gateway Public Key Returned to AAMARVA

Gateway returns HTTP `201` with `{ tokenId, expiresAt, gatewayId, mcpServerId, redemptionEndpoint: "/api/v1/redeem", encryptedToken, gatewayPublicKey, gatewaySignature, correlationId }`.
- `gatewayPublicKey` carries the Gateway's own asymmetric identity (`keyId`, `algorithm`, `purpose: "gateway-response-signing"`, `encoding: "PEM-SPKI"`, `publicKey`, `fingerprint`), kept strictly separate from the agent's encryption key.
- `gatewaySignature` signs the canonicalized response envelope using the active Gateway private key.

AAMARVA relays `encryptedToken` (and associated public-key metadata) to the agent without being able to decrypt the token.

## Phase 5 — Agent-Side Decryption

The autonomous agent's external ADK/runtime decrypts `encryptedToken` using its own private key. The Gateway never performs agent-side decryption in production.

## Phase 6 — One-Time Atomic Token Redemption & Session Synchronization

The agent sends `POST /api/v1/redeem` over TLS with `{ token, agentId, accountId, mcpServerId }`.
`RedemptionService` validates token format, computes `SHA-256(token)`, and calls `store.redeemTokenAtomically`:
1. Verifies token exists, is unredeemed, unrevoked, and neither the token nor its underlying `authorizationExpiresAtMs` has expired.
2. Verifies `agentId`, `accountId`, `mcpServerId`, and `gatewayId` bindings.
3. Atomically marks `redeemedAtMs`, creates a short-lived `GatewaySession` (`sess_<32-hex>`) with `expiresAtMs = Math.min(now + sessionTtlSeconds, authorizationExpiresAtMs)`, and inserts a durable `SessionSyncOutboxItem` in the same SQLite `BEGIN IMMEDIATE` transaction or Redis Lua script.
4. Immediately attempts idempotent delivery (`POST /v1/gateway/sessions/established` with HMAC + `x-aamarva-idempotency-key`) via `SessionSyncOutboxProcessor` (falling back to exponential-backoff retries + startup recovery if AAMARVA is temporarily unreachable).
5. Returns a redemption acknowledgement including `sessionSyncStatus` (`delivered` | `pending_retry` | `failed`). Any duplicate or concurrent second attempt fails with HTTP `409 TOKEN_ALREADY_REDEEMED`.

## Phase 7 — Subsequent MCP Execution via AAMARVA

1. Agent sends MCP requests to AAMARVA using its normal ADK channel.
2. AAMARVA forwards the request to `POST /api/v1/aamarva/mcp/tools/list` or `POST /api/v1/aamarva/mcp/tools/call` authenticated with AAMARVA backend HMAC headers and a unique `requestId`.
3. `ExecutionProxy` validates:
   - Request binding (`gatewayId`, `mcpServerId`)
   - Request replay (`ReplayProtection.verifyAndClaimRequest`)
   - Active session (`GatewaySessionManager.validateActiveSession`: exists, neither `expiresAtMs` nor `authorizationExpiresAtMs` expired, not revoked, matches `agentId` + `accountId`, and `toolName` is in `session.scope.allowedTools`)
   - Online revocation check (`AamarvaBackendClient.checkAuthorizationStatus`, enabled by default in production and fail-closed on errors)
4. Only after all checks pass is the request forwarded to the upstream MCP server; the original MCP response or error is returned to AAMARVA.
