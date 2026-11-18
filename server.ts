import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import { loadGatewayConfig } from './src/gateway/config/environment.ts';
import { AamarvaMcpGateway } from './src/gateway/core/gateway.ts';
import { createErrorHandlerMiddleware } from './src/gateway/middleware/error-handler.ts';
import { createOperatorConsoleRouter } from './src/gateway/routes/console-routes.ts';

async function startServer(): Promise<void> {
  const config = loadGatewayConfig(process.env);
  const gateway = new AamarvaMcpGateway(config);
  await gateway.start();

  const app = express();
  app.set(
    'trust proxy',
    config.security.trustedProxies.length > 0 ? config.security.trustedProxies : false,
  );
  app.disable('x-powered-by');

  // Attach strict Gateway security routes:
  // /healthz, /readyz, POST /api/v1/redeem, POST /api/v1/aamarva/*
  gateway.attachGatewayRoutes(app);

  // Operator Console & non-production Protocol Sandbox Harness (disabled by default in production)
  if (config.features.enableOperatorConsole) {
    app.use('/api/console', createOperatorConsoleRouter(gateway));
  }

  app.use(createErrorHandlerMiddleware(gateway.logger));

  const distDir = path.resolve(process.cwd(), 'dist');
  const isProdBuild = process.env.NODE_ENV === 'production' && fs.existsSync(distDir);

  if (config.features.enableOperatorConsole) {
    if (isProdBuild) {
      app.use(express.static(distDir));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    } else if (process.env.NODE_ENV !== 'production') {
      const { createServer: createViteServer } = await import('vite');
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa',
      });
      app.use(vite.middlewares);
    }
  }

  const server = app.listen(config.port, '0.0.0.0', () => {
    gateway.logger.info({
      event: 'SERVER_LISTENING',
      outcome: 'success',
      message: `AAMARVA MCP Gateway & Operator Console listening on http://0.0.0.0:${config.port}`,
    });
  });

  const shutdown = async () => {
    server.close(async () => {
      await gateway.stop();
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => {
    void shutdown();
  });
  process.on('SIGINT', () => {
    void shutdown();
  });
}

startServer().catch((err) => {
  console.error('Failed to start AAMARVA MCP Gateway server:', err);
  process.exit(1);
});
