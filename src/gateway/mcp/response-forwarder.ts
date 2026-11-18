import type { McpToolCallResult, McpToolDefinition } from './mcp-transport.ts';

export interface RelayToolsListResponse {
  requestId: string;
  sessionId: string;
  mcpServerId: string;
  tools: McpToolDefinition[];
}

export interface RelayToolCallResponse {
  requestId: string;
  sessionId: string;
  mcpServerId: string;
  toolName: string;
  result: McpToolCallResult;
}

export class ResponseForwarder {
  formatToolsList(params: {
    requestId: string;
    sessionId: string;
    mcpServerId: string;
    tools: McpToolDefinition[];
  }): RelayToolsListResponse {
    return {
      requestId: params.requestId,
      sessionId: params.sessionId,
      mcpServerId: params.mcpServerId,
      tools: params.tools,
    };
  }

  formatToolCallResult(params: {
    requestId: string;
    sessionId: string;
    mcpServerId: string;
    toolName: string;
    result: McpToolCallResult;
  }): RelayToolCallResponse {
    return {
      requestId: params.requestId,
      sessionId: params.sessionId,
      mcpServerId: params.mcpServerId,
      toolName: params.toolName,
      result: params.result,
    };
  }
}
