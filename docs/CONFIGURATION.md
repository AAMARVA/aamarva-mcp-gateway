# Configuration Reference

All configuration is loaded via `loadGatewayConfig()` (`src/gateway/config/environment.ts`) and validated fail-closed with Zod (`src/gateway/config/validation.ts`).

| Variable | Required | Default | Description |
|---|---|---|---|
| `NODE_ENV` | No | `development` | `development`, `test`, or `production`. Production enforces TLS, persistent store, and `ENABLE_SANDBOX=false`. |
| `PORT` | No | `3000` | HTTP listener port. |
| `GATEWAY_ID` | Yes | `gw_aamarva_local_01` | Unique identifier for this Gateway installation. |
| `MCP_SERVER_ID` | Yes | `mcp_srv_local_01` | Bound upstream MCP server identifier verified in grants and tokens. |
| `GATEWAY_PUBLIC_URL` | Yes | `http://localhost:3000` | External HTTPS base URL of this Gateway. |
| `GATEWAY_ACTIVE_SIGNING_KEY_ID` | Prod Yes | Ephemeral dev key | Active `keyId` inside `GATEWAY_SIGNING_KEYS_JSON` used to sign token issuance responses. |
| `GATEWAY_SIGNING_KEYS_JSON` | Prod Yes | Ephemeral dev keypair | JSON map `{ [keyId]: { privateKeyPem, publicKeyPem? } }` for the Gateway's own Ed25519 or P-256 signing identity. |
| `AAMARVA_BASE_URL` | Yes | `https://api.aamarva.example.com` | Base URL for outbound AAMARVA backend calls. |
| `AAMARVA_BACKEND_AUTH_SECRET` | Prod Yes | Ephemeral dev secret | Minimum 16-char shared secret for HMAC-SHA256 authentication on `/api/v1/aamarva/*`. |
| `AAMARVA_TRUSTED_SIGNING_KEYS_JSON` | Prod Yes | Ephemeral dev key | JSON object mapping `keyId` → PEM SPKI public key (Ed25519 or P-256). Supports rotation. |
| `AAMARVA_MAX_CLOCK_SKEW_SECONDS` | No | `60` | Max clock drift allowed on signed grants and backend HMAC timestamps (5–300). |
| `AAMARVA_ONLINE_REVOCATION_CHECK` | Prod Yes | `true` in prod | Verifies authorization status with AAMARVA before each MCP execution (fail-closed). |
| `ALLOW_OFFLINE_REVOCATION_IN_PROD` | No | `false` | Explicit override required if disabling online revocation check in `production`. |
| `TOKEN_TTL_SECONDS` | No | `120` | Short-lived token lifetime (15–600), strictly clamped to grant expiration. |
| `SESSION_TTL_SECONDS` | No | `900` | Gateway authorization session lifetime (60–86400), strictly clamped to grant expiration. |
| `REQUIRE_TLS` | Prod Yes | `true` in prod | Rejects non-HTTPS requests (`403 TLS_REQUIRED`) unless socket is encrypted or peer matches `TRUSTED_PROXY_IPS`. |
| `TRUSTED_PROXY_IPS` | No | `""` | Comma-separated peer proxy IPs trusted to terminate TLS and supply `X-Forwarded-Proto: https`. |
| `ALLOW_IN_MEMORY_STORE` | No | `false` | Must remain `false` in production. |
| `STATE_STORE_DRIVER` | No | `sqlite` | `sqlite` (WAL `BEGIN IMMEDIATE`), `redis` (distributed Lua), or `memory` (test only). |
| `SQLITE_DB_PATH` | If sqlite | `./data/gateway-state.db` | Path to SQLite state database. |
| `REDIS_URL` | If redis | — | `redis://` or `rediss://` URI for multi-instance Gateway clusters. |
| `MCP_TRANSPORT` | No | `stdio` | `stdio` or `streamable-http`. |
| `MCP_STDIO_COMMAND` | If stdio | `node` | Executable for STDIO MCP server. |
| `MCP_STDIO_ARGS_JSON` | If stdio | `["examples/sample-mcp-stdio.ts"]` | JSON array of arguments passed to STDIO command. |
| `MCP_STDIO_CWD` | No | — | Working directory for STDIO server. |
| `MCP_HTTP_URL` | If http | — | Upstream Streamable HTTP MCP endpoint URL. |
| `MCP_UPSTREAM_AUTH_HEADER` | No | — | Owner-local `Authorization` header sent only to upstream MCP server. |
| `MCP_REQUEST_TIMEOUT_MS` | No | `15000` | Upstream MCP call timeout in ms (500–300000). |
| `MAX_REQUEST_BODY_BYTES` | No | `1048576` | Max JSON payload size in bytes. |
| `REDEEM_RATE_LIMIT_MAX` | No | `30` | Max redemption requests per IP per window. |
| `REDEEM_RATE_LIMIT_WINDOW_MS` | No | `60000` | Redemption rate-limit window in ms. |
| `RELAY_RATE_LIMIT_MAX` | No | `300` | Max backend relay requests per IP per window. |
| `RELAY_RATE_LIMIT_WINDOW_MS` | No | `60000` | Relay rate-limit window in ms. |
| `ENABLE_OPERATOR_CONSOLE` | No | `false` in prod | Disabled by default in production. Enables `/api/console/*`. |
| `OPERATOR_CONSOLE_AUTH_TOKEN` | If console in prod | — | Mandatory Bearer token (≥32 chars) whenever `ENABLE_OPERATOR_CONSOLE=true` in production. |
| `ENABLE_SANDBOX` | No | `false` in prod | Must be `false` in production; enables local mock harness in dev only. |
