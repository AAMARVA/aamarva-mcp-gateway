# MCP Server Integration Guide

The Gateway acts as an authorization-aware MCP proxy over `@modelcontextprotocol/sdk`. Existing MCP servers require **zero code changes** and **zero AAMARVA dependencies**.

## Supported Transports

### 1. STDIO Transport (`MCP_TRANSPORT="stdio"`)

Used when the Gateway spawns and supervises a local MCP server process over standard input/output (`StdioMcpTransportAdapter` wrapping `StdioClientTransport`).

```env
MCP_TRANSPORT="stdio"
MCP_STDIO_COMMAND="node"
MCP_STDIO_ARGS_JSON='["/path/to/your-mcp-server.js"]'
MCP_STDIO_CWD="/path/to/server"
MCP_REQUEST_TIMEOUT_MS=15000
```

### 2. Streamable HTTP Transport (`MCP_TRANSPORT="streamable-http"`)

Used when connecting to an independently hosted MCP HTTP server (`StreamableHttpMcpTransportAdapter` wrapping `StreamableHTTPClientTransport`).

```env
MCP_TRANSPORT="streamable-http"
MCP_HTTP_URL="http://127.0.0.1:4100/mcp"
MCP_UPSTREAM_AUTH_HEADER="Bearer owner-local-mcp-secret"
MCP_REQUEST_TIMEOUT_MS=15000
```

`MCP_UPSTREAM_AUTH_HEADER` stays strictly inside the MCP owner's Gateway process and is never sent to AAMARVA or autonomous agents.

## Protocol Lifecycle Handled

- `initialize` & capability negotiation on `connect()`
- `tools/list` filtered to `session.scope.allowedTools`
- `tools/call` verified at execution time against `session.scope.allowedTools`
- Original MCP `content`, `structuredContent`, and `isError` preservation
- Per-request timeout & `AbortSignal` cancellation propagation
- Graceful `disconnect()` on `SIGTERM`/`SIGINT`
