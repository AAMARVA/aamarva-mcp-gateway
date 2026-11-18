# API Reference

This document lists **only** the actual HTTP endpoints implemented in `src/gateway/core/gateway.ts`, `src/gateway/aamarva/backend-relay.ts`, and `src/gateway/routes/execution-routes.ts`.

When `ENABLE_AAMARVA_ADAPTER=true` (default), strict ingress allowlisting permits **only** `POST /handshake`, `POST /issuetoken`, and `POST /execute`. All other paths and methods are rejected (`404` / `405`).

---

## 1. AAMARVA Backend-Authenticated Endpoints

Every request to `POST /handshake` and `POST /issuetoken` MUST include valid backend HMAC headers:
- `x-aamarva-gateway-id`: Gateway installation ID
- `x-aamarva-timestamp`: Unix epoch milliseconds
- `x-aamarva-request-id`: Unique per-request ID (replay-protected)
- `x-aamarva-hmac-sha256`: Hex HMAC-SHA256 over `${METHOD}\n${PATH}\n${TIMESTAMP}\n${REQUEST_ID}\n${SHA256_HEX(RAW_BODY)}`

### `POST /handshake` (G1)
Executes the mandatory initial MCP verification handshake on behalf of authenticated AAMARVA Core:
1. Validates the Ed25519 / P-256 signature over `claims`, challenge freshness, single-use challenge uniqueness (`409 HANDSHAKE_CHALLENGE_REPLAYED`), and endpoint binding (`403 ENDPOINT_MISMATCH`).
2. Decrypts external MCP credentials (`AAMARVA-GW-CRED-V1`) if present.
3. Establishes a real outbound MCP connection (`streamable-http` or pre-configured `stdio`), performs MCP `initialize` + `tools/list`, hashes the normalized tool catalog (`toolsListHash`), and stores encrypted connection state at rest (`AAMARVA-GW-STORED-CRED-V1`).
4. Returns (`200 OK`): `{ verified: true, protocolVersion, serverInfo, capabilities, serverCapabilities, mcpInitialize, attestation, gatewayPublicKey, gatewaySignature, tools, correlationId }` where `attestation` conforms to `AAMARVA-GW-ATTEST-V1`. On failure, returns `verified: false` without any attestation or signature.

### `POST /issuetoken` (G2)
Verifies AAMARVA's Ed25519 / P-256 signature over `claims` (and verifies active `connectionId` / `integrationId` / `endpoint` ownership if referenced), validates the required `expires_in_minutes` lifetime, encrypts the short-lived token with `claims.agentPublicKeyPem` (EC P-256 SPKI), and returns a Gateway-signed response.

**Request Body:**
```json
{
  "keyId": "aamarva-core-key-1",
  "claims": {
    "authorizationId": "auth_...",
    "invocationId": "inv_...",
    "gatewayId": "gw_...",
    "accountId": "acct_...",
    "integrationId": "int_...",
    "agentId": "agent_...",
    "agentName": "Procurement Agent",
    "agentPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "agentPublicKeyFingerprint": "sha256:...",
    "allowedTools": ["inventory_lookup"],
    "issuedAt": "2026-11-18T00:00:00.000Z",
    "expiresAt": "2026-11-18T01:00:00.000Z"
  },
  "signature": "<base64 signature over canonical claims>",
  "expires_in_minutes": 15
}
```

**`expires_in_minutes` Validation & Expiration Behavior:**
- **Mandatory top-level field**: `expires_in_minutes` MUST be provided at the top level of the JSON request body. Requests omitting top-level `expires_in_minutes` are rejected even if `claims.expires_in_minutes` is present. If `claims.expires_in_minutes` is also supplied, it must match the top-level value.
- **Type & range**: Must be a valid positive safe integer (`number`, integer `>= 1`, no strings, decimals, `0`, negative numbers, `null`, booleans, or overflow values).
- **No default/fallback**: Missing, zero, negative, or invalid values are rejected immediately with `400`:
  - `MISSING_EXPIRES_IN_MINUTES` — when top-level `expires_in_minutes` is omitted
  - `INVALID_EXPIRES_IN_MINUTES` — when `expires_in_minutes` is not a valid positive safe integer or conflicts with `claims.expires_in_minutes`
- **Issued token expiration**: Only the top-level `expires_in_minutes` value configures token lifetime (`expires_in_minutes * 60` seconds, clamped only so the token never outlives the signed grant's `claims.expiresAt`; grants with `<15s` remaining are rejected with `400 INSUFFICIENT_GRANT_VALIDITY`).

**Success (`201 Created`):**
`{ tokenId, expiresAt, gatewayId, mcpServerId, agentId, accountId, authorizationId, invocationId, redemptionEndpoint: "/execute", encryptionAlgorithm, envelopeVersion, encryptedToken, gatewayKeyId, gatewayPublicKeyFingerprint, gatewayPublicKey, gatewaySignature, correlationId }`.

**Error Codes:** `400 MISSING_EXPIRES_IN_MINUTES / INVALID_EXPIRES_IN_MINUTES / MISSING_AGENT_ID / MISSING_AGENT_NAME / MISSING_AGENT_PUBLIC_KEY / INVALID_AGENT_PUBLIC_KEY / AGENT_KEY_FINGERPRINT_MISMATCH / INVALID_AUTHORIZATION_PAYLOAD / INSUFFICIENT_GRANT_VALIDITY`, `401 INVALID_AAMARVA_SIGNATURE / INVOCATION_EXPIRED`, `403 GATEWAY_MISMATCH / CONNECTION_NOT_VERIFIED / ACCOUNT_MISMATCH / ENDPOINT_MISMATCH / TOOL_NOT_AUTHORIZED`.

---

## 2. Agent-Facing Execution & Redemption Endpoint

### `POST /execute` (G3)
Implemented in `src/gateway/routes/execution-routes.ts` and `src/gateway/redemption/redemption-controller.ts`.
Requires TLS (`REQUIRE_TLS=true`) and `Content-Type: application/json`.

Supports two modes:
1. **Authenticated MCP JSON-RPC / Streamable HTTP Execution** (`Authorization: Bearer <token>` with optional `mcp-session-id` header): atomically redeems the one-time token on first request (binding session + `mcp-session-id`), verifies session/agent/tool scope/revocation on every call, and proxies `initialize`, `notifications/initialized`, `tools/list`, and `tools/call` directly to the bound upstream MCP server.
2. **One-Time Redemption Handshake** (`{ token, agentId, accountId, mcpServerId }`): atomically consumes the one-time token (`agw1.tok_...`), establishes `sess_...`, triggers durable session sync (`POST /v1/gateway/sessions/established`), and returns `{ redeemed: true, sessionId, gatewayId, mcpServerId, agentId, accountId, expiresAt, allowedTools, sessionSyncStatus, correlationId }`.

**Error Codes:** `400 INVALID_REQUEST / INVALID_TOKEN_FORMAT`, `401 MISSING_EXECUTION_TOKEN / TOKEN_EXPIRED / AUTHORIZATION_EXPIRED / TOKEN_REVOKED / SESSION_REVOKED`, `403 TOKEN_NOT_FOUND / AGENT_MISMATCH / ACCOUNT_MISMATCH / SERVER_MISMATCH / SESSION_TOKEN_MISMATCH / TLS_REQUIRED`, `409 TOKEN_ALREADY_REDEEMED`, `429 RATE_LIMIT_EXCEEDED`.

---

## 3. Operational Health Endpoints (Only when `ENABLE_AAMARVA_ADAPTER=false`)

- `GET /healthz` — Liveness probe (`200 OK`).
- `GET /readyz` — Readiness probe verifying state store connectivity and upstream MCP connection (`200 OK` or `503 Service Unavailable`).

