import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import type { Express } from 'express';
import { loadGatewayConfig } from './src/gateway/config/environment.ts';
import type { GatewayConfig } from './src/gateway/config/validation.ts';
import { AamarvaMcpGateway } from './src/gateway/core/gateway.ts';
import { createErrorHandlerMiddleware } from './src/gateway/middleware/error-handler.ts';
import { attachStrictAamarvaIngressGuard } from './src/gateway/middleware/request-validation.ts';
import { createOperatorConsoleRouter } from './src/gateway/routes/console-routes.ts';

export interface CreateServerAppOptions {
  config?: GatewayConfig;
  gateway?: AamarvaMcpGateway;
  env?: NodeJS.ProcessEnv;
  distDir?: string;
  forceProdStatic?: boolean;
  mountViteInDev?: boolean;
}

export async function createServerApp(options: CreateServerAppOptions = {}): Promise<{
  app: Express;
  config: GatewayConfig;
  gateway: AamarvaMcpGateway;
}> {
  const config = options.config ?? loadGatewayConfig(options.env ?? process.env);
  const gateway = options.gateway ?? new AamarvaMcpGateway(config);
  if (!options.gateway) {
    await gateway.start();
  }

  const app = express();
  app.set(
    'trust proxy',
    config.security.trustedProxies.length > 0 ? config.security.trustedProxies : false,
  );
  app.set('strict routing', true);
  app.set('case sensitive routing', true);
  app.disable('x-powered-by');

  // Central ingress allowlist BEFORE any router, console, static-file, Vite, or SPA handler
  if (config.aamarva.adapterEnabled) {
    attachStrictAamarvaIngressGuard(app);
  }

  // Gateway security routes:
  // When adapterEnabled=true: strictly POST /handshake, POST /issuetoken, POST /execute ONLY.
  // When adapterEnabled=false: also mounts GET /healthz and GET /readyz.
  gateway.attachGatewayRoutes(app);

  // Operator Console API (blocked at ingress when adapterEnabled=true)
  if (config.features.enableOperatorConsole) {
    app.use('/api/console', createOperatorConsoleRouter(gateway));
  }

  const distDir = options.distDir ?? path.resolve(process.cwd(), 'dist');
  const isProdBuild =
    (options.forceProdStatic ?? process.env.NODE_ENV === 'production') && fs.existsSync(distDir);

  if (config.features.enableOperatorConsole) {
    if (isProdBuild) {
      app.use(express.static(distDir));
      app.get('*', (_req, res) => {
        res.sendFile(path.join(distDir, 'index.html'));
      });
    } else if (
      options.mountViteInDev ??
      (!config.aamarva.adapterEnabled && process.env.NODE_ENV !== 'production')
    ) {
      const { createServer: createViteServer } = await import('vite');
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa',
      });
      app.use(vite.middlewares);
    }
  }

  app.use((_req, res) => {
    res.status(404).json({
      error: 'NOT_FOUND',
      message: 'Endpoint not found',
    });
  });

  app.use(createErrorHandlerMiddleware(gateway.logger));

  return { app, config, gateway };
}

export async function startServer(): Promise<void> {
  const { app, config, gateway } = await createServerApp();

  const server = app.listen(config.port, '0.0.0.0', () => {
    gateway.logger.info({
      event: 'SERVER_LISTENING',
      outcome: 'success',
      message: config.aamarva.adapterEnabled
        ? `AAMARVA MCP Gateway (strict three-endpoint mode) listening on http://0.0.0.0:${config.port}`
        : `AAMARVA MCP Gateway & Operator Console listening on http://0.0.0.0:${config.port}`,
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

function isDirectEntrypoint(): boolean {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  try {
    return fs.realpathSync(argv1) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isDirectEntrypoint()) {
  startServer().catch((err) => {
    console.error('Failed to start AAMARVA MCP Gateway server:', err);
    process.exit(1);
  });
}
