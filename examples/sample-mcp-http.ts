import http from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express from 'express';
import { createSampleMcpServer } from './sample-mcp-stdio.ts';

export async function startSampleStreamableHttpMcpServer(options: {
  port?: number;
  requiredAuthHeader?: string;
} = {}): Promise<{ url: string; close: () => Promise<void> }> {
  const app = express();
  app.use(express.json());

  app.post('/mcp', async (req, res) => {
    if (options.requiredAuthHeader) {
      const auth = req.header('authorization');
      if (auth !== options.requiredAuthHeader) {
        res.status(401).json({ error: 'Unauthorized upstream MCP access' });
        return;
      }
    }

    const server = createSampleMcpServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    res.on('close', () => {
      void transport.close();
      void server.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  const server = http.createServer(app);
  await new Promise<void>((resolve) => {
    server.listen(options.port ?? 0, '127.0.0.1', () => resolve());
  });
  const addr = server.address();
  const actualPort = typeof addr === 'object' && addr ? addr.port : (options.port ?? 4100);

  return {
    url: `http://127.0.0.1:${actualPort}/mcp`,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}
