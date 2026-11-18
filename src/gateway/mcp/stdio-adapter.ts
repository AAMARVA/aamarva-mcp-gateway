import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { AuditRecorder } from '../observability/audit.ts';
import { BaseMcpUpstreamAdapter } from './mcp-transport.ts';

export class StdioMcpTransportAdapter extends BaseMcpUpstreamAdapter {
  private readonly command: string;
  private readonly args: string[];
  private readonly cwd?: string;
  private readonly env?: Record<string, string>;

  constructor(options: {
    command: string;
    args: string[];
    cwd?: string;
    env?: Record<string, string>;
    defaultTimeoutMs: number;
    audit: AuditRecorder;
  }) {
    super({
      transportType: 'stdio',
      defaultTimeoutMs: options.defaultTimeoutMs,
      audit: options.audit,
    });
    this.command = options.command;
    this.args = options.args;
    this.cwd = options.cwd;
    this.env = options.env;
  }

  protected createTransport(): Transport {
    return new StdioClientTransport({
      command: this.command,
      args: this.args,
      cwd: this.cwd,
      env: this.env,
      stderr: 'pipe',
    });
  }
}
