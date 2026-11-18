import crypto from 'node:crypto';
import { SECURITY_DEFAULTS } from '../config/security.ts';
import type { GatewaySession } from './authorization-context.ts';
import type { GatewayStateStore } from '../storage/interfaces.ts';

export function generateSessionId(): string {
  return `sess_${crypto.randomBytes(SECURITY_DEFAULTS.SESSION_ID_BYTE_LENGTH).toString('hex')}`;
}

export interface SessionValidationResult {
  valid: boolean;
  session?: GatewaySession;
  code?:
    | 'SESSION_NOT_FOUND'
    | 'SESSION_EXPIRED'
    | 'AUTHORIZATION_EXPIRED'
    | 'SESSION_REVOKED'
    | 'AGENT_MISMATCH'
    | 'ACCOUNT_MISMATCH'
    | 'SERVER_MISMATCH'
    | 'GATEWAY_MISMATCH'
    | 'TOOL_NOT_AUTHORIZED';
  reason?: string;
}

export class GatewaySessionManager {
  private readonly store: GatewayStateStore;
  private readonly gatewayId: string;
  private readonly mcpServerId: string;

  constructor(options: { store: GatewayStateStore; gatewayId: string; mcpServerId: string }) {
    this.store = options.store;
    this.gatewayId = options.gatewayId;
    this.mcpServerId = options.mcpServerId;
  }

  async validateActiveSession(params: {
    sessionId: string;
    agentId: string;
    accountId: string;
    mcpServerId: string;
    gatewayId: string;
    toolName?: string;
    nowMs?: number;
  }): Promise<SessionValidationResult> {
    const nowMs = params.nowMs ?? Date.now();
    const session = await this.store.getSession(params.sessionId);

    if (!session) {
      return { valid: false, code: 'SESSION_NOT_FOUND', reason: 'Authorization session does not exist' };
    }

    if (session.revokedAtMs !== null || session.status === 'revoked') {
      return {
        valid: false,
        session,
        code: 'SESSION_REVOKED',
        reason: `Authorization session revoked${session.revocationReason ? `: ${session.revocationReason}` : ''}`,
      };
    }

    if (nowMs > session.authorizationExpiresAtMs) {
      return {
        valid: false,
        session,
        code: 'AUTHORIZATION_EXPIRED',
        reason: 'Underlying AAMARVA authorization grant has expired',
      };
    }

    if (nowMs > session.expiresAtMs || session.status === 'expired') {
      return { valid: false, session, code: 'SESSION_EXPIRED', reason: 'Authorization session has expired' };
    }

    if (session.gatewayId !== this.gatewayId || session.gatewayId !== params.gatewayId) {
      return { valid: false, session, code: 'GATEWAY_MISMATCH', reason: 'Gateway installation binding mismatch' };
    }

    if (
      session.mcpServerId !== params.mcpServerId ||
      (!session.scope.connectionId && session.mcpServerId !== this.mcpServerId)
    ) {
      return { valid: false, session, code: 'SERVER_MISMATCH', reason: 'MCP server binding mismatch' };
    }

    if (session.agentId !== params.agentId) {
      return { valid: false, session, code: 'AGENT_MISMATCH', reason: 'Session is not bound to this agentId' };
    }

    if (session.accountId !== params.accountId) {
      return { valid: false, session, code: 'ACCOUNT_MISMATCH', reason: 'Session is not bound to this accountId' };
    }

    if (params.toolName !== undefined) {
      const allowed = session.scope.allowedTools.includes(params.toolName);
      if (!allowed) {
        return {
          valid: false,
          session,
          code: 'TOOL_NOT_AUTHORIZED',
          reason: `Tool "${params.toolName}" is outside the authorized scope for this session`,
        };
      }
    }

    await this.store.touchSession(session.sessionId, nowMs);
    return { valid: true, session };
  }

  async revokeSession(sessionId: string, reason: string, revokedBy: string): Promise<boolean> {
    return this.store.revokeSession(sessionId, reason, revokedBy, Date.now());
  }

  async listSessions(limit = 50): Promise<GatewaySession[]> {
    return this.store.listSessions(limit);
  }
}
