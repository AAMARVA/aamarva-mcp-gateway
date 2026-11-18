import type { GatewaySession } from '../core/authorization-context.ts';
import type { McpToolCallResult, McpUpstreamAdapter } from './mcp-transport.ts';

export class ToolExecutionService {
  private readonly upstream: McpUpstreamAdapter;

  constructor(upstream: McpUpstreamAdapter) {
    this.upstream = upstream;
  }

  /**
   * Executes an MCP tool call only after verifying at call-time that the tool
   * is explicitly permitted by the active session's scope.
   */
  async executeTool(params: {
    session: GatewaySession;
    toolName: string;
    arguments: Record<string, unknown>;
    timeoutMs?: number;
    signal?: AbortSignal;
    adapterOverride?: McpUpstreamAdapter;
  }): Promise<McpToolCallResult> {
    if (!params.session.scope.allowedTools.includes(params.toolName)) {
      throw new Error(`Unauthorized tool execution blocked: ${params.toolName}`);
    }

    const targetAdapter = params.adapterOverride ?? this.upstream;
    return targetAdapter.callTool(
      {
        name: params.toolName,
        arguments: params.arguments,
      },
      {
        timeoutMs: params.timeoutMs,
        signal: params.signal,
      },
    );
  }
}
