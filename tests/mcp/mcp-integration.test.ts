import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startSampleStreamableHttpMcpServer } from '../../examples/sample-mcp-http.ts';
import type { GatewaySession } from '../../src/gateway/core/authorization-context.ts';
import { GatewaySessionManager } from '../../src/gateway/core/gateway-session.ts';
import { ResponseForwarder } from '../../src/gateway/mcp/response-forwarder.ts';
import { StdioMcpTransportAdapter } from '../../src/gateway/mcp/stdio-adapter.ts';
import { StreamableHttpMcpTransportAdapter } from '../../src/gateway/mcp/streamable-http-adapter.ts';
import { ToolDiscoveryService } from '../../src/gateway/mcp/tool-discovery.ts';
import { ToolExecutionService } from '../../src/gateway/mcp/tool-execution.ts';
import { AuditRecorder } from '../../src/gateway/observability/audit.ts';
import { GatewayLogger } from '../../src/gateway/observability/logger.ts';
import { GatewayMetrics } from '../../src/gateway/observability/metrics.ts';
import { ExecutionProxy } from '../../src/gateway/proxy/execution-proxy.ts';
import { ProxyResponseHandler } from '../../src/gateway/proxy/response-handler.ts';
import { SessionValidator } from '../../src/gateway/proxy/session-validator.ts';
import { InMemoryGatewayStateStore } from '../../src/gateway/storage/adapters/memory-store.ts';

describe('MCP Upstream Integration (STDIO & Streamable HTTP)', () => {
  let store: InMemoryGatewayStateStore;
  let stdioAdapter: StdioMcpTransportAdapter;
  let proxy: ExecutionProxy;
  let activeSession: GatewaySession;

  beforeAll(async () => {
    store = new InMemoryGatewayStateStore();
    await store.init();

    const logger = new GatewayLogger({ gatewayId: 'gw_mcp_test', silent: true });
    const audit = new AuditRecorder(logger);
    const metrics = new GatewayMetrics();

    stdioAdapter = new StdioMcpTransportAdapter({
      command: 'node',
      args: [path.resolve(process.cwd(), 'examples/sample-mcp-stdio.ts')],
      defaultTimeoutMs: 10_000,
      audit,
    });
    await stdioAdapter.connect();

    const now = Date.now();
    await store.saveIssuedToken({
      tokenId: 'tok_mcp_1',
      tokenHash: 'hash_mcp_1',
      authorizationId: 'auth_mcp_1',
      agentId: 'agent_mcp',
      agentName: 'MCP Agent',
      accountId: 'acct_mcp',
      mcpServerId: 'mcp_srv_1',
      gatewayId: 'gw_mcp_test',
      scope: { allowedTools: ['inventory_lookup', 'calculate_quote', 'simulate_upstream_error'] },
      aamarvaKeyId: 'k1',
      issuedAtMs: now,
      expiresAtMs: now + 60_000,
      authorizationExpiresAtMs: now + 600_000,
      redeemedAtMs: null,
      redeemedBySessionId: null,
      revokedAtMs: null,
    });

    const redeemed = await store.redeemTokenAtomically({
      tokenHash: 'hash_mcp_1',
      agentId: 'agent_mcp',
      accountId: 'acct_mcp',
      mcpServerId: 'mcp_srv_1',
      gatewayId: 'gw_mcp_test',
      sessionId: 'sess_mcp_1',
      sessionExpiresAtMs: now + 300_000,
      correlationId: 'corr_mcp_setup',
      nowMs: now,
    });
    if (!redeemed.ok) throw new Error('Setup failed');
    activeSession = redeemed.session;

    const sessionManager = new GatewaySessionManager({
      store,
      gatewayId: 'gw_mcp_test',
      mcpServerId: 'mcp_srv_1',
    });

    proxy = new ExecutionProxy({
      gatewayId: 'gw_mcp_test',
      mcpServerId: 'mcp_srv_1',
      sessionValidator: new SessionValidator({ sessionManager, onlineRevocationCheck: false }),
      toolDiscovery: new ToolDiscoveryService(stdioAdapter),
      toolExecution: new ToolExecutionService(stdioAdapter),
      forwarder: new ResponseForwarder(),
      responseHandler: new ProxyResponseHandler(),
      audit,
      metrics,
    });
  }, 20_000);

  afterAll(async () => {
    await stdioAdapter.disconnect();
    await store.close();
  });

  it('initializes upstream STDIO server and filters tool discovery by session scope', async () => {
    const status = stdioAdapter.getStatus();
    expect(status.connected).toBe(true);
    expect(status.serverInfo?.name).toBe('acme-erp-mcp-server');

    const res = await proxy.listAuthorizedTools({
      requestId: 'req_list_1',
      sessionId: activeSession.sessionId,
      agentId: 'agent_mcp',
      accountId: 'acct_mcp',
      mcpServerId: 'mcp_srv_1',
      gatewayId: 'gw_mcp_test',
    });

    expect(res.statusCode).toBe(200);
    const tools = res.body.tools as Array<{ name: string }>;
    const names = tools.map((t) => t.name);
    expect(names).toContain('inventory_lookup');
    expect(names).toContain('calculate_quote');
    // Sensitive tool outside scope must NOT be exposed
    expect(names).not.toContain('ledger_export');
  });

  it('forwards authorized tool execution and blocks unauthorized tools before reaching MCP', async () => {
    const allowedRes = await proxy.executeAuthorizedTool({
      requestId: 'req_call_1',
      sessionId: activeSession.sessionId,
      agentId: 'agent_mcp',
      accountId: 'acct_mcp',
      mcpServerId: 'mcp_srv_1',
      gatewayId: 'gw_mcp_test',
      toolName: 'inventory_lookup',
      arguments: { sku: 'SKU-VALVE-400' },
    });

    expect(allowedRes.statusCode).toBe(200);
    const result = allowedRes.body.result as { content: Array<{ text: string }> };
    expect(JSON.parse(result.content[0].text)).toMatchObject({
      found: true,
      sku: 'SKU-VALVE-400',
      stock: 42,
    });

    // Unauthorized tool call MUST be rejected 403
    const deniedRes = await proxy.executeAuthorizedTool({
      requestId: 'req_call_denied',
      sessionId: activeSession.sessionId,
      agentId: 'agent_mcp',
      accountId: 'acct_mcp',
      mcpServerId: 'mcp_srv_1',
      gatewayId: 'gw_mcp_test',
      toolName: 'ledger_export',
      arguments: { fiscalQuarter: '2026-Q4' },
    });
    expect(deniedRes.statusCode).toBe(403);
    expect(deniedRes.body.error).toBe('TOOL_NOT_AUTHORIZED');
  });

  it('preserves original MCP tool errors and supports concurrent executions', async () => {
    const errRes = await proxy.executeAuthorizedTool({
      requestId: 'req_call_err',
      sessionId: activeSession.sessionId,
      agentId: 'agent_mcp',
      accountId: 'acct_mcp',
      mcpServerId: 'mcp_srv_1',
      gatewayId: 'gw_mcp_test',
      toolName: 'simulate_upstream_error',
      arguments: { reason: 'Stock locked for audit' },
    });

    expect(errRes.statusCode).toBe(200);
    const mcpResult = errRes.body.result as { isError: boolean; content: Array<{ text: string }> };
    expect(mcpResult.isError).toBe(true);
    expect(mcpResult.content[0].text).toContain('ERP_ERROR: Stock locked for audit');

    const concurrent = await Promise.all(
      [10, 20, 50, 100].map((qty, idx) =>
        proxy.executeAuthorizedTool({
          requestId: `req_conc_${idx}`,
          sessionId: activeSession.sessionId,
          agentId: 'agent_mcp',
          accountId: 'acct_mcp',
          mcpServerId: 'mcp_srv_1',
          gatewayId: 'gw_mcp_test',
          toolName: 'calculate_quote',
          arguments: { quantity: qty, unitPriceUsd: 100 },
        }),
      ),
    );
    for (const r of concurrent) {
      expect(r.statusCode).toBe(200);
    }
  });

  it('connects to an independent Streamable HTTP MCP server with explicit loopback dev opt-in and rejects loopback by default', async () => {
    const ownerSecret = 'Bearer mcp-owner-local-secret-99';
    const httpServer = await startSampleStreamableHttpMcpServer({
      requiredAuthHeader: ownerSecret,
    });

    const logger = new GatewayLogger({ gatewayId: 'gw_http_test', silent: true });

    // Strict SSRF default rejects http://127.0.0.1 unless explicitly opted in for dev/test
    const strictAdapter = new StreamableHttpMcpTransportAdapter({
      endpointUrl: httpServer.url,
      upstreamAuthHeader: ownerSecret,
      defaultTimeoutMs: 10_000,
      audit: new AuditRecorder(logger),
    });
    await expect(strictAdapter.connect()).rejects.toThrow();

    const httpAdapter = new StreamableHttpMcpTransportAdapter({
      endpointUrl: httpServer.url,
      upstreamAuthHeader: ownerSecret,
      defaultTimeoutMs: 10_000,
      allowInsecureHttp: true,
      allowLoopbackHttp: true,
      audit: new AuditRecorder(logger),
    });

    try {
      await httpAdapter.connect();
      const tools = await httpAdapter.listTools();
      expect(tools.map((t) => t.name)).toContain('inventory_lookup');

      const res = await httpAdapter.callTool({
        name: 'calculate_quote',
        arguments: { quantity: 50, unitPriceUsd: 200 },
      });
      const parsed = JSON.parse((res.content[0] as { text: string }).text) as { totalUsd: number };
      expect(parsed.totalUsd).toBe(8800);
    } finally {
      await httpAdapter.disconnect();
      await httpServer.close();
    }
  });

  it('fails closed when upstream MCP server is unavailable or request times out', async () => {
    const logger = new GatewayLogger({ gatewayId: 'gw_unavail', silent: true });
    const badHttpAdapter = new StreamableHttpMcpTransportAdapter({
      endpointUrl: 'http://127.0.0.1:59999/mcp',
      defaultTimeoutMs: 500,
      allowInsecureHttp: true,
      allowLoopbackHttp: true,
      audit: new AuditRecorder(logger),
    });

    await expect(badHttpAdapter.connect()).rejects.toThrow();
    expect(badHttpAdapter.isConnected()).toBe(false);

    // Pre-aborted signal on active STDIO proxy cancels cleanly
    const abortController = new AbortController();
    abortController.abort();
    const cancelledRes = await proxy.executeAuthorizedTool({
      requestId: 'req_cancelled_1',
      sessionId: activeSession.sessionId,
      agentId: 'agent_mcp',
      accountId: 'acct_mcp',
      mcpServerId: 'mcp_srv_1',
      gatewayId: 'gw_mcp_test',
      toolName: 'inventory_lookup',
      arguments: { sku: 'SKU-VALVE-400' },
      signal: abortController.signal,
    });
    expect([502, 504]).toContain(cancelledRes.statusCode);
  });
});
