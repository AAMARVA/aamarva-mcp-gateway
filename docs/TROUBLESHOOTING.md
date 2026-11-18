# Troubleshooting Guide

## `403 TLS_REQUIRED` on `/api/v1/redeem` or `/api/v1/aamarva/*`
- **Cause**: `REQUIRE_TLS=true` is enabled, and the incoming request arrived over plain HTTP without `X-Forwarded-Proto: https`.
- **Resolution**: Terminate TLS at your load balancer/reverse proxy and forward `X-Forwarded-Proto: https` (and configure Express `trust proxy` accordingly). For local non-production testing only, set `REQUIRE_TLS=false`.

## `401 INVALID_AAMARVA_SIGNATURE` on `/issue-token`
- **Cause**: Either `keyId` is not present in `AAMARVA_TRUSTED_SIGNING_KEYS_JSON`, the payload claims were modified after signing, or `issuedAt`/`expiresAt` failed timestamp validation.
- **Resolution**: Verify `keyId` matches an active PEM key in `AAMARVA_TRUSTED_SIGNING_KEYS_JSON`, ensure canonical JSON serialization matches `canonicalizeJson()`, and check NTP clock synchronization (`AAMARVA_MAX_CLOCK_SKEW_SECONDS`).

## `409 TOKEN_ALREADY_REDEEMED`
- **Cause**: The agent (or an attacker) submitted the same single-use token more than once.
- **Resolution**: Tokens are strictly one-time use. If a session was lost before acknowledgement, AAMARVA Core must issue a fresh authorization grant.

## `403 TOOL_NOT_AUTHORIZED`
- **Cause**: The requested `toolName` is not in the session's `scope.allowedTools` list granted by AAMARVA.
- **Resolution**: Update tool assignment permissions in AAMARVA Core and issue a new grant if the agent requires that tool.

## `503` on `/readyz` (`mcpUpstream: "disconnected"`)
- **Cause**: Upstream STDIO process exited or Streamable HTTP MCP endpoint is unreachable.
- **Resolution**: Check `MCP_STDIO_COMMAND` / `MCP_HTTP_URL`, verify upstream MCP credentials (`MCP_UPSTREAM_AUTH_HEADER`), and inspect Gateway structured logs for `MCP_TRANSPORT_ERROR`.

## Startup failure in production (`ZodError`)
- **Cause**: Production guard rejected `STATE_STORE_DRIVER=memory`, `ALLOW_IN_MEMORY_STORE=true`, `REQUIRE_TLS=false`, `ENABLE_SANDBOX=true`, or missing signing keys/backend secret.
- **Resolution**: Use `sqlite` or `redis`, enable TLS, disable sandbox, and provide production credentials.
