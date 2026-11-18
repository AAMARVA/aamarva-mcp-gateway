# Architecture

## 1. Strict Three-Component Separation

| Component | Ownership | Explicitly Excluded |
|---|---|---|
| **AAMARVA Core Platform** | Agent IDs, public keys, authentication, FLOOR approvals, tool permissions, revocation | Does not own MCP owner credentials or tool implementations |
| **AAMARVA ADK** | Agent-side auth, key management, agent-side decryption, AAMARVA communication | Never installed inside Gateway or upstream MCP server |
| **AAMARVA MCP Gateway** | AAMARVA signature verification, short-lived token issuance/encryption, one-time atomic redemption, session enforcement, MCP transport proxying | Does not register agents, approve permissions, or implement MCP tool logic |

## 2. Two Communication Paths

The Gateway maintains exactly two operational communication relationships:

1. **Gateway ↔ AAMARVA Backend** (`/api/v1/aamarva/*`, authenticated via HMAC-SHA256 + timestamp + requestId replay protection)
2. **Gateway ↔ Existing MCP Server** (STDIO or Streamable HTTP via `@modelcontextprotocol/sdk`)

### Single Direct Agent-to-Gateway Interaction

An autonomous agent interacts directly with the Gateway **exactly once**:

- `POST /api/v1/redeem` — submits its decrypted short-lived token over TLS to establish a Gateway authorization session.

There are **no** direct agent-to-Gateway MCP execution endpoints (`/mcp`, `/tools/call`, etc.). All subsequent `tools/list` and `tools/call` operations flow:

`Agent (ADK) → AAMARVA Backend → Gateway (/api/v1/aamarva/mcp/*) → Upstream MCP Server`

## 3. Module Map

- `src/gateway/config/` — Environment parsing, Zod schema validation, fail-closed production guards, and secret redaction.
- `src/gateway/crypto/` — Ed25519 / ECDSA P-256 signature verification, CSPRNG token generation, X25519 / P-256 ECDH+HKDF+AES-256-GCM and RSA-OAEP-256 envelope encryption, and constant-time token validation.
- `src/gateway/storage/` — `GatewayStateStore` interface with atomic `SqliteGatewayStateStore` (`BEGIN IMMEDIATE` WAL), `RedisGatewayStateStore` (atomic Lua script), and test-only `InMemoryGatewayStateStore`.
- `src/gateway/redemption/` — Token issuance, atomic single-use redemption, and replay protection.
- `src/gateway/aamarva/` — AAMARVA contracts, signature/HMAC verifier, authorization/revocation adapter, backend relay controller, and outbound client.
- `src/gateway/mcp/` — `@modelcontextprotocol/sdk` transport abstraction (`StdioMcpTransportAdapter`, `StreamableHttpMcpTransportAdapter`), scope-filtered tool discovery, tool execution, and response forwarding.
- `src/gateway/proxy/` — Request binding validator, session & online revocation validator, execution proxy, and error normalizer.
- `src/gateway/middleware/` — Backend HMAC auth, sliding-window rate limiter, TLS enforcement, JSON size/type validation, and fail-closed error handling.
- `src/gateway/observability/` — Redacted structured JSON logger, typed audit event recorder, and operational metrics.
