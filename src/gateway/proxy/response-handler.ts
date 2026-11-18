export interface ProxyHttpResult {
  statusCode: number;
  body: Record<string, unknown>;
}

export class ProxyResponseHandler {
  denied(code: string, message: string, correlationId: string, statusCode = 403): ProxyHttpResult {
    return {
      statusCode,
      body: {
        error: code,
        message,
        correlationId,
      },
    };
  }

  upstreamError(err: unknown, correlationId: string): ProxyHttpResult {
    const rawMessage = err instanceof Error ? err.message : 'Upstream MCP execution failed';
    const isTimeout =
      rawMessage.toLowerCase().includes('timeout') || rawMessage.toLowerCase().includes('abort');
    return {
      statusCode: isTimeout ? 504 : 502,
      body: {
        error: isTimeout ? 'MCP_EXECUTION_TIMEOUT' : 'MCP_UPSTREAM_ERROR',
        message: isTimeout ? 'Upstream MCP request timed out' : 'Upstream MCP execution failed',
        correlationId,
      },
    };
  }

  success(payload: Record<string, unknown>): ProxyHttpResult {
    return {
      statusCode: 200,
      body: payload,
    };
  }
}
