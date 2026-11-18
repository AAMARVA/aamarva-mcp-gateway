# AAMARVA Backend Integration & Contract Audit

## Stage 1 Contract Audit Matrix

No AAMARVA Core source repository or canonical ADK OpenAPI specification was supplied in this greenfield workspace. Per architectural rules, the Gateway isolates all AAMARVA integration inside `src/gateway/aamarva/` behind explicit Zod-validated contracts and documents the exact integration status below.

| Integration | Actual Contract | Source | Status |
|---|---|---|---|
| AAMARVA → Gateway initial MCP verification handshake | `POST /api/v1/aamarva/mcp/handshake` (Ed25519 / P-256 signed challenge + HMAC headers → outbound MCP `initialize` + `tools/list` → `AAMARVA-GW-ATTEST-V1` signed attestation) | Gateway specification (AAMARVA Core spec not provided) | **Unavailable externally** — Contract defined & tested with Contract Harness |
| AAMARVA → Gateway authorization | `POST /api/v1/aamarva/authorizations/issue-token` (Ed25519 / P-256 signed claims + HMAC headers) | Gateway specification (AAMARVA Core spec not provided) | **Unavailable externally** — Contract defined & tested with Contract Harness |
| Gateway → AAMARVA encrypted token | HTTP `201` JSON response containing `encryptedToken` (`AAMARVA-GW-ENV-V1`), `gatewayPublicKey`, and `gatewaySignature` | Gateway specification (AAMARVA Core relay spec not provided) | **Unavailable externally** — Contract defined & tested with Contract Harness |
| AAMARVA → Agent token delivery | Existing AAMARVA Core / ADK encrypted relay channel (relays encrypted token & public-key metadata) | AAMARVA Core / ADK (external) | **External AAMARVA-owned** |
| Agent → Gateway token redemption | `POST /api/v1/redeem` (TLS, atomic single-use) | Gateway specification | **Implemented & verified in Gateway** |
| Gateway → AAMARVA session sync | `POST /v1/gateway/sessions/established` (HMAC-SHA256 + `x-aamarva-idempotency-key` via durable outbox) | Gateway specification (AAMARVA Core receiver spec not provided) | **Unavailable externally** — Outbox & HMAC client implemented; tested with local mock backend |
| Agent → AAMARVA subsequent MCP request | Existing AAMARVA ADK → AAMARVA Backend pathway | AAMARVA ADK / Core (external) | **External AAMARVA-owned** |
| AAMARVA → Gateway MCP execution | `POST /api/v1/aamarva/mcp/tools/list` & `POST /api/v1/aamarva/mcp/tools/call` | Gateway specification (AAMARVA Core caller spec not provided) | **Unavailable externally** — Contract defined & tested with Contract Harness |
| Gateway → Upstream MCP server | MCP JSON-RPC over STDIO / Streamable HTTP (`@modelcontextprotocol/sdk`) | Model Context Protocol spec | **Implemented & verified against real MCP servers** |

## Missing AAMARVA Backend Capabilities Required for Production End-to-End Operation

To connect this Gateway to a live AAMARVA Core deployment, AAMARVA Core must provide:
1. **Initial MCP Verification Initiator & Attestation Verifier**: Generates a single-use cryptographic `challenge`, signs `AamarvaHandshakeClaims` (optionally encrypting upstream MCP credentials using `AAMARVA-GW-CRED-V1`), calls `POST /api/v1/aamarva/mcp/handshake`, and independently verifies `gatewaySignature` over `attestation` (`AAMARVA-GW-ATTEST-V1`) against its trusted Gateway public key, asserting `verified === true`, `mcpInitialized === true`, `toolsDiscoverySuccess === true`, and matching `challenge`, `accountId`, `integrationId`, and `canonicalEndpoint` before marking the integration verified.
2. **Gateway Authorization Grant Signer**: Issues Ed25519 or P-256 signed grants matching `AamarvaAuthorizationGrantClaimsSchema` (`src/gateway/aamarva/contracts.ts`, binding `connectionId`/`integrationId`/`endpoint`) and calls `POST /api/v1/aamarva/authorizations/issue-token`.
3. **Encrypted Envelope Relay**: Verifies `gatewaySignature` using `gatewayPublicKey` (optional/recommended) and delivers `encryptedToken` (`AAMARVA-GW-ENV-V1`) intact to the target agent without attempting decryption.
4. **Session Synchronization Receiver**: Accepts `POST /v1/gateway/sessions/established` idempotently (deduplicated via `x-aamarva-idempotency-key` / `idempotencyKey`) to record the active Gateway `sessionId` and TTLs.
5. **Gateway Execution Relay**: Routes subsequent agent MCP requests to `POST /api/v1/aamarva/mcp/tools/list` and `POST /api/v1/aamarva/mcp/tools/call` signed with `x-aamarva-hmac-sha256` and associates requests with the `sessionId` (and `connectionId`/`expectedEndpoint`) established during Phase 6.
6. **Revocation Webhook / Status Endpoint**: Calls `POST /api/v1/aamarva/authorizations/revoke` (with unique `revocationId`) upon revocation, and exposes `POST /v1/gateway/authorizations/status` for `AAMARVA_ONLINE_REVOCATION_CHECK=true`.

## Adapter Boundary & Key Rotation

- **AAMARVA Key Rotation**: Configure multiple public keys in `AAMARVA_TRUSTED_SIGNING_KEYS_JSON` keyed by `keyId`. AAMARVA specifies `keyId` on each signed grant so overlapping key rollovers work with zero downtime.
- **Gateway Key Rotation**: Configure multiple Gateway signing keypairs in `GATEWAY_SIGNING_KEYS_JSON` and set `GATEWAY_ACTIVE_SIGNING_KEY_ID` to the active `keyId`.
- **No Direct DB Access**: Gateway never connects to AAMARVA's database.
