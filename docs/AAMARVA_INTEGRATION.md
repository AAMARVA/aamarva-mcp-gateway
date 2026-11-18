# AAMARVA Backend Integration & Contract Audit

## Stage 1 Contract Audit Matrix

No AAMARVA Core source repository or canonical ADK OpenAPI specification was supplied in this greenfield workspace. Per architectural rules, the Gateway isolates all AAMARVA integration inside `src/gateway/aamarva/` behind explicit Zod-validated contracts and documents the exact integration status below.

| Integration | Actual Contract | Source | Status |
|---|---|---|---|
| AAMARVA → Gateway initial MCP verification handshake | `POST /handshake` (Ed25519/P-256 signed challenge + HMAC headers → outbound MCP `initialize` + `tools/list` → `AAMARVA-GW-ATTEST-V1` signed attestation) | Gateway specification (AAMARVA Core spec not provided) | **Unavailable externally** — Contract defined & tested with Contract Harness |
| AAMARVA → Gateway authorization | `POST /issuetoken` (Ed25519/P-256 signed claims + mandatory top-level positive-integer `expires_in_minutes` + HMAC headers) | Gateway specification (AAMARVA Core spec not provided) | **Unavailable externally** — Contract defined & tested with Contract Harness |
| Gateway → AAMARVA encrypted token | HTTP `201` JSON response containing `encryptedToken` (`AAMARVA-GW-ENV-V1`), `gatewayPublicKey`, and `gatewaySignature` | Gateway specification (AAMARVA Core relay spec not provided) | **Unavailable externally** — Contract defined & tested with Contract Harness |
| AAMARVA → Agent token delivery | Existing AAMARVA Core / ADK encrypted relay channel (relays encrypted token & public-key metadata) | AAMARVA Core / ADK (external) | **External AAMARVA-owned** |
| Agent → Gateway token redemption & MCP execution | `POST /execute` (TLS, atomic single-use token redemption + authenticated MCP Streamable HTTP / JSON-RPC execution) | Gateway specification | **Implemented & verified in Gateway** |
| Gateway → AAMARVA session sync | `POST /v1/gateway/sessions/established` (HMAC-SHA256 + `x-aamarva-idempotency-key` via durable outbox) | Gateway specification (AAMARVA Core receiver spec not provided) | **Unavailable externally** — Outbox & HMAC client implemented; tested with local mock backend |
| Gateway → Upstream MCP server | MCP JSON-RPC over STDIO / Streamable HTTP (`@modelcontextprotocol/sdk`) | Model Context Protocol spec | **Implemented & verified against real MCP servers** |

## Missing AAMARVA Backend Capabilities Required for Production End-to-End Operation

To connect this Gateway to a live AAMARVA Core deployment, AAMARVA Core must provide:
1. **Initial MCP Verification Initiator & Attestation Verifier**: Generates a single-use cryptographic `challenge`, signs `AamarvaHandshakeClaims` (optionally encrypting upstream MCP credentials using `AAMARVA-GW-CRED-V1`), calls `POST /handshake`, and independently verifies `gatewaySignature` over `attestation` (`AAMARVA-GW-ATTEST-V1`) against its trusted Gateway public key, asserting `verified === true`, `mcpInitialized === true`, `toolsDiscoverySuccess === true`, and matching `challenge`, `accountId`, `integrationId`, and `canonicalEndpoint` before marking the integration verified.
2. **Gateway Authorization Grant Signer**: Issues Ed25519 or P-256 signed grants matching `AamarvaIssueTokenEndpointClaimsSchema` (`src/gateway/aamarva/contracts.ts`, binding `connectionId`/`integrationId`/`endpoint`) and calls `POST /issuetoken` with mandatory top-level positive-integer `expires_in_minutes`.
3. **Encrypted Envelope Relay**: Verifies `gatewaySignature` using `gatewayPublicKey` (optional/recommended) and delivers `encryptedToken` (`AAMARVA-GW-ENV-V1`) intact to the target agent without attempting decryption.
4. **Session Synchronization Receiver**: Accepts `POST /v1/gateway/sessions/established` idempotently (deduplicated via `x-aamarva-idempotency-key` / `idempotencyKey`) to record the active Gateway `sessionId` and TTLs.
5. **Online Authorization Status Endpoint**: Exposes `POST /v1/gateway/authorizations/status` for `AAMARVA_ONLINE_REVOCATION_CHECK=true`.

## Adapter Boundary & Key Rotation

- **AAMARVA Key Rotation**: Configure multiple public keys in `AAMARVA_TRUSTED_SIGNING_KEYS_JSON` keyed by `keyId`. AAMARVA specifies `keyId` on each signed grant so overlapping key rollovers work with zero downtime.
- **Gateway Key Rotation**: Configure multiple Gateway signing keypairs in `GATEWAY_SIGNING_KEYS_JSON` and set `GATEWAY_ACTIVE_SIGNING_KEY_ID` to the active `keyId`.
- **No Direct DB Access**: Gateway never connects to AAMARVA's database.
