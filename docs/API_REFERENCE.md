# API Reference

This document lists **only** the actual HTTP endpoints implemented in `src/gateway/routes/`.

---

## 1. Agent-Facing Endpoint (ONE TIME ONLY)

### `POST /api/v1/redeem`

Implemented in `src/gateway/routes/redemption-routes.ts` and `src/gateway/redemption/redemption-controller.ts`.
Requires TLS (`REQUIRE_TLS=true`) and `Content-Type: application/json`.

**Request Body:**
```json
{
  "token": "agw1.tok_...<secret>",
  "agentId": "agent_procure_77",
  "accountId": "acct_acme_01",
  "mcpServerId": "mcp_arch_01"
}
```

**Success (`200 OK`):**
```json
{
  "redeemed": true,
  "sessionId": "sess_...",
  "gatewayId": "gw_arch_01",
  "mcpServerId": "mcp_arch_01",
  "agentId": "agent_procure_77",
  "accountId": "acct_acme_01",
  "expiresAt": "2026-11-17T08:00:00.000Z",
  "allowedTools": ["inventory_lookup", "calculate_quote"],
  "sessionSyncStatus": "delivered",
  "correlationId": "corr_...",
  "nextStep": "Session established. Close direct connection to Gateway; send all subsequent MCP requests through AAMARVA backend mediation."
}
```

**Error Codes:** `400 INVALID_REQUEST / INVALID_TOKEN_FORMAT`, `401 TOKEN_EXPIRED / AUTHORIZATION_EXPIRED / TOKEN_REVOKED`, `403 AGENT_MISMATCH / ACCOUNT_MISMATCH / SERVER_MISMATCH / TLS_REQUIRED`, `409 TOKEN_ALREADY_REDEEMED`, `429 RATE_LIMIT_EXCEEDED`.

---

## 2. AAMARVA Backend-Authenticated Endpoints

Mounted at `/api/v1/aamarva/*` (`src/gateway/routes/aamarva-routes.ts`).
Every request MUST include valid backend HMAC headers:
- `x-aamarva-gateway-id`: Gateway installation ID
- `x-aamarva-timestamp`: Unix epoch milliseconds
- `x-aamarva-request-id`: Unique per-request ID (replay-protected)
- `x-aamarva-hmac-sha256`: Hex HMAC-SHA256 over `${METHOD}\n${PATH}\n${TIMESTAMP}\n${REQUEST_ID}\n${SHA256_HEX(RAW_BODY)}`

### `POST /api/v1/aamarva/mcp/handshake`
Executes the mandatory initial MCP verification handshake on behalf of authenticated AAMARVA Core:
1. Validates the Ed25519 / P-256 signature over `claims`, challenge freshness, single-use challenge uniqueness (`409 HANDSHAKE_CHALLENGE_REPLAYED`), and endpoint binding (`403 ENDPOINT_MISMATCH`).
2. Decrypts external MCP credentials (`AAMARVA-GW-CRED-V1`) if present.
3. Establishes a real outbound MCP connection (`streamable-http` or pre-configured `stdio`), performs MCP `initialize` + `tools/list`, hashes the normalized tool catalog (`toolsListHash`), and stores the encrypted connection credentials at rest (`AAMARVA-GW-STORED-CRED-V1`).
4. Returns (`200 OK`): `{ verified: true, attestation, gatewayPublicKey, gatewaySignature, tools, correlationId }` where `attestation` conforms to `AAMARVA-GW-ATTEST-V1`. On failure, returns `verified: false` without any attestation or signature.

### `POST /api/v1/aamarva/authorizations/issue-token`
Verifies AAMARVA's Ed25519 / P-256 signature over `claims` (and verifies active `connectionId` / `integrationId` / `endpoint` ownership if referenced), clamps token TTL to the grant's `expiresAt` (rejecting grants with `<15s` remaining as `400 INSUFFICIENT_GRANT_VALIDITY`), encrypts the short-lived token with `claims.agentPublicKeyPem`, and returns (`201 Created`):
`{ tokenId, expiresAt, gatewayId, mcpServerId, redemptionEndpoint, encryptedToken, gatewayPublicKey, gatewaySignature, correlationId }`.

### `POST /api/v1/aamarva/authorizations/revoke`
Verifies AAMARVA's signature over revocation claims, deduplicates `revocationId` idempotently, and immediately revokes matching unredeemed tokens, active sessions, and (on account revocation) verified external MCP connections.

### `POST /api/v1/aamarva/mcp/tools/list`
Validates active session (including authorization grant expiry and connection/endpoint bindings) + `requestId` replay check and returns upstream MCP tools filtered strictly to `session.scope.allowedTools`.

### `POST /api/v1/aamarva/mcp/tools/call`
Validates active session + `requestId` replay check + call-time tool authorization + connection/endpoint binding + online revocation check, then forwards `tools/call` to the bound upstream MCP server and returns `{ requestId, sessionId, mcpServerId, toolName, result, correlationId }`.

---

## 3. Operational Health Endpoints

- `GET /healthz` — Liveness probe (`200 OK`).
- `GET /readyz` — Readiness probe verifying state store connectivity and upstream MCP connection (`200 OK` or `503 Service Unavailable`).
