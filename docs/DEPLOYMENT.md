# Production Deployment Guide

## 1. Prerequisites

- Node.js 22+
- TLS termination reverse proxy (e.g., Envoy, Nginx, ALB, Cloud Run) forwarding `X-Forwarded-Proto: https`
- Persistent volume (for `STATE_STORE_DRIVER=sqlite`) or shared Redis (`STATE_STORE_DRIVER=redis` for multi-replica deployments)
- Trusted AAMARVA Core Ed25519 / P-256 public key(s) and backend HMAC secret

## 2. Production Environment Checklist

Set these mandatory production settings:

```env
NODE_ENV=production
REQUIRE_TLS=true
TRUSTED_PROXY_IPS=10.0.0.10
ALLOW_IN_MEMORY_STORE=false
ENABLE_SANDBOX=false
ENABLE_OPERATOR_CONSOLE=false
AAMARVA_ONLINE_REVOCATION_CHECK=true
STATE_STORE_DRIVER=redis
REDIS_URL=rediss://:password@redis.internal:6379
GATEWAY_ID=gw_prod_erp_01
MCP_SERVER_ID=mcp_erp_01
GATEWAY_ACTIVE_SIGNING_KEY_ID=gw-2026-01
GATEWAY_SIGNING_KEYS_JSON='{"gw-2026-01":{"privateKeyPem":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"}}'
AAMARVA_BACKEND_AUTH_SECRET=<32+ byte secret>
AAMARVA_TRUSTED_SIGNING_KEYS_JSON='{"aamarva-2026-01":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"}'
```

## 3. Standalone Headless Deployment (Recommended for Production)

```bash
npm ci
npm run build
npm run gateway
```

`npm run build` compiles the Gateway into `dist-server/gateway.mjs` (zero Vite or Operator Console dependencies). `npm run gateway` runs `node dist-server/gateway.mjs` cleanly on Node.js 22 without any TypeScript runtime loader.

For development without compiling first, use `npm run dev:gateway` or `npm run dev`.

## 4. Docker Deployment

```bash
docker build -t aamarva-mcp-gateway:latest .
docker run -d \
  --name aamarva-gateway \
  -p 3000:3000 \
  --env-file .env.production \
  -v gateway-data:/app/data \
  aamarva-mcp-gateway:latest
```

## 5. Health Probes

- **Liveness**: `GET /healthz` → HTTP `200` (`{ "status": "ok", "gatewayId": "...", "mcpServerId": "..." }`)
- **Readiness**: `GET /readyz` → HTTP `200` when both state store (`sqlite`/`redis`) and upstream MCP connection are healthy; HTTP `503` otherwise.

Both endpoints expose zero secret material.

## 6. Secret Rotation

1. Add the new AAMARVA public key alongside the existing key in `AAMARVA_TRUSTED_SIGNING_KEYS_JSON` (e.g., `{"k1": "...", "k2": "..."}`).
2. Restart/roll Gateway replicas.
3. Once AAMARVA switches signing to `k2` and old grants expire, remove `k1`.
