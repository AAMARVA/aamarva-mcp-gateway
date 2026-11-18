import type { GatewayLogger } from './logger.ts';

export type AuditEventType =
  | 'GATEWAY_STARTUP'
  | 'GATEWAY_SHUTDOWN'
  | 'BACKEND_AUTH_SUCCESS'
  | 'BACKEND_AUTH_FAILED'
  | 'AUTHORIZATION_RECEIVED'
  | 'SIGNATURE_VERIFICATION_SUCCEEDED'
  | 'SIGNATURE_VERIFICATION_FAILED'
  | 'TOKEN_ISSUED'
  | 'TOKEN_ENCRYPTED'
  | 'TOKEN_ENCRYPTION_FAILED'
  | 'TOKEN_REDEEM_SUCCEEDED'
  | 'TOKEN_REDEEM_FAILED'
  | 'TOKEN_REPLAY_BLOCKED'
  | 'SESSION_CREATED'
  | 'SESSION_EXPIRED'
  | 'SESSION_REVOKED'
  | 'SESSION_SYNC_DELIVERED'
  | 'SESSION_SYNC_RETRY_SCHEDULED'
  | 'SESSION_SYNC_FAILED'
  | 'OPERATOR_AUTH_SUCCEEDED'
  | 'OPERATOR_AUTH_FAILED'
  | 'MCP_HANDSHAKE_SUCCEEDED'
  | 'MCP_HANDSHAKE_FAILED'
  | 'HANDSHAKE_CHALLENGE_REPLAYED'
  | 'CONNECTION_SUBSTITUTION_BLOCKED'
  | 'SSRF_BLOCKED'
  | 'PLAINTEXT_CREDENTIALS_REJECTED'
  | 'MCP_TOOLS_LISTED'
  | 'MCP_TOOL_EXECUTED'
  | 'MCP_TOOL_DENIED'
  | 'MCP_TOOL_FAILED'
  | 'MCP_TRANSPORT_ERROR'
  | 'BACKEND_RELAY_ERROR';

export interface AuditEventInput {
  event: AuditEventType;
  message: string;
  outcome: 'success' | 'failure' | 'denied';
  correlationId?: string;
  requestId?: string;
  agentId?: string;
  accountId?: string;
  mcpServerId?: string;
  sessionId?: string;
  toolName?: string;
  details?: Record<string, unknown>;
}

export class AuditRecorder {
  private readonly logger: GatewayLogger;

  constructor(logger: GatewayLogger) {
    this.logger = logger;
  }

  record(input: AuditEventInput): void {
    const level =
      input.outcome === 'success'
        ? 'info'
        : input.outcome === 'denied'
          ? 'warn'
          : 'error';
    this.logger.log(level, {
      event: input.event,
      message: input.message,
      outcome: input.outcome,
      correlationId: input.correlationId,
      requestId: input.requestId,
      agentId: input.agentId,
      accountId: input.accountId,
      mcpServerId: input.mcpServerId,
      sessionId: input.sessionId,
      toolName: input.toolName,
      details: input.details,
    });
  }
}
