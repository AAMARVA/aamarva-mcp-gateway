import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { AuditRecorder } from '../observability/audit.ts';

export interface McpToolDefinition {
  name: string;
  title?: string;
  description?: string;
  inputSchema: Record<string, unknown>;
}

export interface McpToolCallResult {
  content: Array<Record<string, unknown>>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
  _meta?: Record<string, unknown>;
}

export interface McpUpstreamStatus {
  connected: boolean;
  transport: 'stdio' | 'streamable-http';
  serverInfo?: { name: string; version: string };
  negotiatedProtocolVersion?: string;
  serverCapabilities?: Record<string, unknown>;
  lastError?: string;
  activeRequests: number;
}

export interface McpUpstreamAdapter {
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  isConnected(): boolean;
  getStatus(): McpUpstreamStatus;
  listTools(options?: { timeoutMs?: number; signal?: AbortSignal }): Promise<McpToolDefinition[]>;
  callTool(
    params: { name: string; arguments: Record<string, unknown> },
    options?: { timeoutMs?: number; signal?: AbortSignal },
  ): Promise<McpToolCallResult>;
}

export abstract class BaseMcpUpstreamAdapter implements McpUpstreamAdapter {
  protected readonly transportType: 'stdio' | 'streamable-http';
  protected readonly defaultTimeoutMs: number;
  protected readonly audit: AuditRecorder;
  protected client: Client | null = null;
  protected transport: Transport | null = null;
  protected connected = false;
  protected connectPromise: Promise<void> | null = null;
  protected negotiatedProtocolVersion: string | undefined;
  protected lastError: string | undefined;
  protected activeRequests = 0;

  constructor(options: {
    transportType: 'stdio' | 'streamable-http';
    defaultTimeoutMs: number;
    audit: AuditRecorder;
  }) {
    this.transportType = options.transportType;
    this.defaultTimeoutMs = options.defaultTimeoutMs;
    this.audit = options.audit;
  }

  protected abstract createTransport(): Transport;

  async connect(): Promise<void> {
    if (this.connected && this.client) return;
    if (this.connectPromise) return this.connectPromise;

    this.connectPromise = (async () => {
      try {
        const client = new Client(
          {
            name: 'aamarva-mcp-gateway',
            version: '1.0.0',
          },
          {
            capabilities: {},
          },
        );

        const transport = this.createTransport();
        const origSetProtocolVersion = transport.setProtocolVersion?.bind(transport);
        transport.setProtocolVersion = (version: string) => {
          this.negotiatedProtocolVersion = version;
          origSetProtocolVersion?.(version);
        };
        transport.onclose = () => {
          this.connected = false;
        };
        transport.onerror = (err: Error) => {
          this.lastError = err.message;
          this.audit.record({
            event: 'MCP_TRANSPORT_ERROR',
            outcome: 'failure',
            message: `MCP transport error: ${err.message}`,
          });
        };

        await client.connect(transport, { timeout: this.defaultTimeoutMs });
        this.client = client;
        this.transport = transport;
        this.connected = true;
        this.lastError = undefined;
      } catch (err) {
        this.connected = false;
        this.lastError = err instanceof Error ? err.message : 'MCP initialization failed';
        this.audit.record({
          event: 'MCP_TRANSPORT_ERROR',
          outcome: 'failure',
          message: `Failed to initialize upstream MCP server: ${this.lastError}`,
        });
        throw err;
      } finally {
        this.connectPromise = null;
      }
    })();

    return this.connectPromise;
  }

  async disconnect(): Promise<void> {
    this.connected = false;
    const currentClient = this.client;
    const currentTransport = this.transport;
    this.client = null;
    this.transport = null;
    try {
      await currentClient?.close();
    } catch {
      // ignore close errors during shutdown
    }
    try {
      await currentTransport?.close();
    } catch {
      // ignore close errors during shutdown
    }
  }

  isConnected(): boolean {
    return this.connected && this.client !== null;
  }

  getStatus(): McpUpstreamStatus {
    const serverVersion = this.client?.getServerVersion();
    const serverCapabilities = this.client?.getServerCapabilities();
    return {
      connected: this.isConnected(),
      transport: this.transportType,
      serverInfo: serverVersion
        ? { name: serverVersion.name, version: serverVersion.version }
        : undefined,
      negotiatedProtocolVersion: this.negotiatedProtocolVersion,
      serverCapabilities: serverCapabilities as Record<string, unknown> | undefined,
      lastError: this.lastError,
      activeRequests: this.activeRequests,
    };
  }

  private async ensureClient(): Promise<Client> {
    if (!this.isConnected()) {
      await this.connect();
    }
    if (!this.client) {
      throw new Error('Upstream MCP client not connected');
    }
    return this.client;
  }

  async listTools(options?: {
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<McpToolDefinition[]> {
    const client = await this.ensureClient();
    const timeout = options?.timeoutMs ?? this.defaultTimeoutMs;
    this.activeRequests += 1;
    try {
      const res = await client.listTools(undefined, {
        timeout,
        signal: options?.signal,
      });
      return res.tools.map((tool) => ({
        name: tool.name,
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema as Record<string, unknown>,
      }));
    } catch (err) {
      this.lastError = err instanceof Error ? err.message : 'MCP listTools failed';
      throw err;
    } finally {
      this.activeRequests -= 1;
    }
  }

  async callTool(
    params: { name: string; arguments: Record<string, unknown> },
    options?: { timeoutMs?: number; signal?: AbortSignal },
  ): Promise<McpToolCallResult> {
    const client = await this.ensureClient();
    const timeout = options?.timeoutMs ?? this.defaultTimeoutMs;
    this.activeRequests += 1;
    try {
      const result = await client.callTool(
        {
          name: params.name,
          arguments: params.arguments,
        },
        undefined,
        {
          timeout,
          signal: options?.signal,
        },
      );
      return {
        content: (result.content ?? []) as Array<Record<string, unknown>>,
        structuredContent: result.structuredContent as Record<string, unknown> | undefined,
        isError: Boolean(result.isError),
        _meta: result._meta as Record<string, unknown> | undefined,
      };
    } catch (err) {
      this.lastError = err instanceof Error ? err.message : 'MCP callTool failed';
      throw err;
    } finally {
      this.activeRequests -= 1;
    }
  }
}
