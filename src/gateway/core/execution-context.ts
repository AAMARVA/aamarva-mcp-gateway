import crypto from 'node:crypto';

export interface ExecutionContext {
  correlationId: string;
  requestId: string;
  gatewayId: string;
  mcpServerId: string;
  sessionId?: string;
  agentId?: string;
  accountId?: string;
  toolName?: string;
  receivedAtMs: number;
}

export function createExecutionContext(params: {
  gatewayId: string;
  mcpServerId: string;
  requestId?: string;
  correlationId?: string;
  sessionId?: string;
  agentId?: string;
  accountId?: string;
  toolName?: string;
}): ExecutionContext {
  return {
    correlationId: params.correlationId ?? `corr_${crypto.randomBytes(8).toString('hex')}`,
    requestId: params.requestId ?? `req_${crypto.randomBytes(8).toString('hex')}`,
    gatewayId: params.gatewayId,
    mcpServerId: params.mcpServerId,
    sessionId: params.sessionId,
    agentId: params.agentId,
    accountId: params.accountId,
    toolName: params.toolName,
    receivedAtMs: Date.now(),
  };
}
