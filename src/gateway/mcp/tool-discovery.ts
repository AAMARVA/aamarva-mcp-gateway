import type { GatewaySession } from '../core/authorization-context.ts';
import type { McpToolDefinition, McpUpstreamAdapter } from './mcp-transport.ts';

/**
 * Discovers tools from the upstream MCP server and filters them strictly
 * to the tools permitted in the Gateway authorization session scope.
 * Tool discovery never grants execution permission.
 */
export class ToolDiscoveryService {
  private readonly upstream: McpUpstreamAdapter;

  constructor(upstream: McpUpstreamAdapter) {
    this.upstream = upstream;
  }

  async listAuthorizedTools(
    session: GatewaySession,
    options?: { timeoutMs?: number; signal?: AbortSignal; adapterOverride?: McpUpstreamAdapter },
  ): Promise<McpToolDefinition[]> {
    const targetAdapter = options?.adapterOverride ?? this.upstream;
    const allTools = await targetAdapter.listTools({
      timeoutMs: options?.timeoutMs,
      signal: options?.signal,
    });
    const allowedSet = new Set(session.scope.allowedTools);
    return allTools.filter((tool) => allowedSet.has(tool.name));
  }

  async listAllUpstreamTools(options?: {
    timeoutMs?: number;
    signal?: AbortSignal;
    adapterOverride?: McpUpstreamAdapter;
  }): Promise<McpToolDefinition[]> {
    const targetAdapter = options?.adapterOverride ?? this.upstream;
    return targetAdapter.listTools({
      timeoutMs: options?.timeoutMs,
      signal: options?.signal,
    });
  }
}
