import { Router } from 'express';
import type { McpUpstreamAdapter } from '../mcp/mcp-transport.ts';
import type { GatewayStateStore } from '../storage/interfaces.ts';

export function createHealthRouter(options: {
  gatewayId: string;
  mcpServerId: string;
  store: GatewayStateStore;
  mcpAdapter: McpUpstreamAdapter;
}): Router {
  const router = Router();

  router.get('/healthz', (_req, res) => {
    res.status(200).json({
      status: 'ok',
      service: 'aamarva-mcp-gateway',
      gatewayId: options.gatewayId,
      mcpServerId: options.mcpServerId,
    });
  });

  router.get('/readyz', async (_req, res) => {
    const storeOk = await options.store.ping();
    const mcpConnected = options.mcpAdapter.isConnected();

    const ready = storeOk && mcpConnected;
    res.status(ready ? 200 : 503).json({
      ready,
      gatewayId: options.gatewayId,
      mcpServerId: options.mcpServerId,
      checks: {
        stateStore: storeOk ? 'ok' : 'unavailable',
        stateStoreDriver: options.store.driverName,
        mcpUpstream: mcpConnected ? 'connected' : 'disconnected',
      },
    });
  });

  return router;
}
