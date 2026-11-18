import 'dotenv/config';
import { loadGatewayConfig } from './config/environment.ts';
import { AamarvaMcpGateway } from './core/gateway.ts';

async function main(): Promise<void> {
  const config = loadGatewayConfig(process.env);
  const gateway = new AamarvaMcpGateway(config);
  await gateway.start();

  const app = gateway.createStandaloneApp();
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
