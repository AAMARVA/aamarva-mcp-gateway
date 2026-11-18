# AAMARVA MCP Gateway

**AAMARVA MCP Gateway** is an independently installable, authorization-aware Model Context Protocol (MCP) pass-through proxy. It connects independently operated MCP servers to AAMARVA's existing agent identity, cryptographic signature verification, and authorization infrastructure without requiring MCP server owners to rewrite tools or install the agent-facing AAMARVA ADK.

## Architectural Role

Three independent components exist:

1. **AAMARVA Core Platform** (external): Owns agent identities, public keys, FLOOR human approvals, tool assignment policies, and permission revocation.
2. **AAMARVA ADK** (external): Installed by autonomous agent developers; handles agent-side keys and AAMARVA communication.
3. **AAMARVA MCP Gateway** (this product): Operated by MCP server owners. Verifies AAMARVA-signed authorization grants, issues and public-key encrypts short-lived tokens, atomically redeems a token **once** directly from the agent, and enforces session/scope authorization on all subsequent MCP requests relayed through the AAMARVA backend.

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Run automated test suite (crypto, atomic concurrency, MCP STDIO/HTTP, architectural boundaries)
npm test

# 3. Start Gateway + Operator Console in development mode
npm run dev

# 4. Or build and run compiled standalone headless Gateway server
npm run build
npm run gateway
```

See `docs/DEPLOYMENT.md` for production TLS, SQLite/Redis state store configuration, and Docker instructions.

## Documentation Index

- `docs/ARCHITECTURE.md` — Component boundaries and two-path communication separation
- `docs/AUTHORIZATION_FLOW.md` — 7-phase token issuance, encryption, redemption, and relay lifecycle
- `docs/SECURITY.md` — Threat model, cryptographic design, and fail-closed controls
- `docs/MCP_INTEGRATION.md` — Connecting existing STDIO and Streamable HTTP MCP servers
- `docs/AAMARVA_INTEGRATION.md` — Stage 1 Contract Audit Matrix and backend integration contract
- `docs/CONFIGURATION.md` — Complete environment variable reference
- `docs/DEPLOYMENT.md` — Production deployment and Docker guide
- `docs/API_REFERENCE.md` — Actual HTTP endpoints implemented in code
- `docs/TROUBLESHOOTING.md` — Operational failure diagnostics
