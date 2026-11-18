import 'dotenv/config';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Express } from 'express';
import { loadGatewayConfig } from './config/environment.ts';
import type { GatewayConfig } from './config/validation.ts';
import { AamarvaMcpGateway, type GatewayOverrides } from './core/gateway.ts';

export async function createGatewayApp(options?: {
  config?: GatewayConfig;
  gateway?: AamarvaMcpGateway;
  env?: NodeJS.ProcessEnv;
  overrides?: GatewayOverrides;
  connectMcpOnBoot?: boolean;
}): Promise<{
  app: Express;
  config: GatewayConfig;
  gateway: AamarvaMcpGateway;
}> {
  const config = options?.config ?? loadGatewayConfig(options?.env ?? process.env);
  const gateway = options?.gateway ?? new AamarvaMcpGateway(config, options?.overrides);
  if (!options?.gateway) {
    await gateway.start({ connectMcpOnBoot: options?.connectMcpOnBoot });
  }
  const app = gateway.createStandaloneApp();
  return { app, config, gateway };
}

export async function main(): Promise<void> {
  const { app, config, gateway } = await createGatewayApp();
  const server = app.listen(config.port, '0.0.0.0', () => {
    gateway.logger.info({
      event: 'HTTP_SERVER_LISTENING',
      outcome: 'success',
      message: `AAMARVA MCP Gateway listening on port ${config.port}`,
    });
  });

  const shutdown = async (signal: string) => {
    gateway.logger.info({
      event: 'SIGNAL_RECEIVED',
      outcome: 'success',
      message: `Received ${signal}; shutting down gracefully`,
    });
    server.close(async () => {
      await gateway.stop();
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => {
    void shutdown('SIGTERM');
  });
  process.on('SIGINT', () => {
    void shutdown('SIGINT');
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
  main().catch((err) => {
    console.error(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'error',
        event: 'GATEWAY_BOOT_FAILED',
        message: err instanceof Error ? err.message : 'Fatal startup error',
      }),
    );
    process.exit(1);
  });
}
