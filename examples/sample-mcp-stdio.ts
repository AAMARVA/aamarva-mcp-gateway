import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

export function createSampleMcpServer(): McpServer {
  const server = new McpServer({
    name: 'acme-erp-mcp-server',
    version: '1.4.0',
  });

  server.registerTool(
    'inventory_lookup',
    {
      title: 'Inventory Lookup',
      description: 'Look up current warehouse stock and unit pricing by SKU.',
      inputSchema: {
        sku: z.string().min(1),
      },
    },
    async ({ sku }) => {
      const catalog: Record<string, { name: string; stock: number; unitPriceUsd: number }> = {
        'SKU-VALVE-400': { name: 'Titanium Control Valve 400mm', stock: 42, unitPriceUsd: 315.0 },
        'SKU-SENSOR-X2': { name: 'Differential Pressure Sensor X2', stock: 128, unitPriceUsd: 89.5 },
        'SKU-PUMP-90': { name: 'Cryogenic Transfer Pump 90L', stock: 7, unitPriceUsd: 1840.0 },
      };
      const item = catalog[sku.toUpperCase()];
      if (!item) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ found: false, sku }) }],
        };
      }
      return {
        content: [{ type: 'text', text: JSON.stringify({ found: true, sku: sku.toUpperCase(), ...item }) }],
      };
    },
  );

  server.registerTool(
    'calculate_quote',
    {
      title: 'Calculate Order Quote',
      description: 'Calculate volume-discounted order total for a quantity and unit price.',
      inputSchema: {
        quantity: z.number().int().positive(),
        unitPriceUsd: z.number().positive(),
      },
    },
    async ({ quantity, unitPriceUsd }) => {
      const discountRate = quantity >= 50 ? 0.12 : quantity >= 10 ? 0.05 : 0;
      const subtotal = quantity * unitPriceUsd;
      const total = Number((subtotal * (1 - discountRate)).toFixed(2));
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ quantity, unitPriceUsd, discountRate, totalUsd: total }),
          },
        ],
      };
    },
  );

  server.registerTool(
    'ledger_export',
    {
      title: 'Export Financial Ledger',
      description: 'Privileged tool exporting sensitive accounting ledger entries.',
      inputSchema: {
        fiscalQuarter: z.string().min(2),
      },
    },
    async ({ fiscalQuarter }) => {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              fiscalQuarter,
              exportedRows: 1240,
              classification: 'RESTRICTED_FINANCE',
            }),
          },
        ],
      };
    },
  );

  server.registerTool(
    'simulate_upstream_error',
    {
      title: 'Simulate Upstream Tool Error',
      description: 'Returns a native MCP tool error result to verify error preservation.',
      inputSchema: {
        reason: z.string().default('Upstream ERP constraint violation'),
      },
    },
    async ({ reason }) => {
      return {
        isError: true,
        content: [{ type: 'text', text: `ERP_ERROR: ${reason}` }],
      };
    },
  );

  return server;
}

const isDirectExecution =
  typeof process !== 'undefined' &&
  Array.isArray(process.argv) &&
  process.argv[1]?.endsWith('sample-mcp-stdio.ts');

if (isDirectExecution) {
  const server = createSampleMcpServer();
  const transport = new StdioServerTransport();
  server.connect(transport).catch((err) => {
    console.error('Failed to start sample STDIO MCP server:', err);
    process.exit(1);
  });
}
