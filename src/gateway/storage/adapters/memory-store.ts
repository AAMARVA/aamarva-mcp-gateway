import crypto from 'node:crypto';
import type {
  GatewaySession,
  IssuedTokenRecord,
  SessionSyncOutboxItem,
  VerifiedMcpConnectionRecord,
} from '../../core/authorization-context.ts';
import type {
  AtomicRedeemParams,
  AtomicRedeemResult,
  GatewayStateStore,
} from '../interfaces.ts';

/**
 * In-memory state store strictly for isolated unit tests and non-production local checks.
 * Blocked in production by configuration validation.
 */
export class InMemoryGatewayStateStore implements GatewayStateStore {
  readonly driverName = 'memory';
  private readonly tokens = new Map<string, IssuedTokenRecord>();
  private readonly sessions = new Map<string, GatewaySession>();
  private readonly outbox = new Map<string, SessionSyncOutboxItem>();
  private readonly replayIds = new Map<string, number>();
  private readonly revocationIds = new Map<string, number>();
  private readonly handshakeChallenges = new Map<string, number>();
  private readonly verifiedConnections = new Map<string, VerifiedMcpConnectionRecord>();

  async init(): Promise<void> {}
  async close(): Promise<void> {
    this.tokens.clear();
    this.sessions.clear();
    this.outbox.clear();
    this.replayIds.clear();
    this.revocationIds.clear();
    this.handshakeChallenges.clear();
    this.verifiedConnections.clear();
  }
  async ping(): Promise<boolean> {
    return true;
  }

  async saveIssuedToken(record: IssuedTokenRecord): Promise<void> {
    this.tokens.set(record.tokenHash, {
      ...record,
      scope: { ...record.scope, allowedTools: [...record.scope.allowedTools] },
    });
  }

  async getIssuedTokenByHash(tokenHash: string): Promise<IssuedTokenRecord | null> {
    const record = this.tokens.get(tokenHash);
    if (!record) return null;
    return {
      ...record,
      scope: { ...record.scope, allowedTools: [...record.scope.allowedTools] },
    };
  }

  async redeemTokenAtomically(params: AtomicRedeemParams): Promise<AtomicRedeemResult> {
    const record = this.tokens.get(params.tokenHash);
    if (!record) {
      return { ok: false, code: 'TOKEN_NOT_FOUND', message: 'Invalid or unknown authorization token' };
    }
    if (record.revokedAtMs !== null) {
      return { ok: false, code: 'TOKEN_REVOKED', message: 'Authorization token has been revoked' };
    }
    if (record.redeemedAtMs !== null) {
      return { ok: false, code: 'TOKEN_ALREADY_REDEEMED', message: 'Authorization token has already been redeemed' };
    }
    const authExpMs =
      record.authorizationExpiresAtMs > 0 ? record.authorizationExpiresAtMs : record.expiresAtMs;
    if (params.nowMs > authExpMs) {
      return {
        ok: false,
        code: 'AUTHORIZATION_EXPIRED',
        message: 'Underlying AAMARVA authorization grant has expired',
      };
    }
    if (params.nowMs > record.expiresAtMs) {
      return { ok: false, code: 'TOKEN_EXPIRED', message: 'Authorization token has expired' };
    }
    if (params.agentId !== undefined && record.agentId !== params.agentId) {
      return { ok: false, code: 'AGENT_MISMATCH', message: 'Token agent binding mismatch' };
    }
    if (params.accountId !== undefined && record.accountId !== params.accountId) {
      return { ok: false, code: 'ACCOUNT_MISMATCH', message: 'Token account binding mismatch' };
    }
    if (params.mcpServerId !== undefined && record.mcpServerId !== params.mcpServerId) {
      return { ok: false, code: 'SERVER_MISMATCH', message: 'Token MCP server binding mismatch' };
    }
    if (record.gatewayId !== params.gatewayId) {
      return { ok: false, code: 'GATEWAY_MISMATCH', message: 'Token gateway installation binding mismatch' };
    }
    if (params.expectedAuthorizationId && record.authorizationId !== params.expectedAuthorizationId) {
      return {
        ok: false,
        code: 'AUTHORIZATION_MISMATCH',
        message: 'Token authorization/invocation binding mismatch',
      };
    }

    record.redeemedAtMs = params.nowMs;
    record.redeemedBySessionId = params.sessionId;

    const effectiveSessionExpiresAtMs = Math.min(params.sessionExpiresAtMs, authExpMs);

    const session: GatewaySession = {
      sessionId: params.sessionId,
      tokenId: record.tokenId,
      authorizationId: record.authorizationId,
      agentId: record.agentId,
      agentName: record.agentName,
      accountId: record.accountId,
      mcpServerId: record.mcpServerId,
      gatewayId: record.gatewayId,
      scope: { ...record.scope, allowedTools: [...record.scope.allowedTools] },
      status: 'active',
      createdAtMs: params.nowMs,
      expiresAtMs: effectiveSessionExpiresAtMs,
      authorizationExpiresAtMs: authExpMs,
      revokedAtMs: null,
      revocationReason: null,
      revokedBy: null,
      lastUsedAtMs: null,
    };

    const outboxItem: SessionSyncOutboxItem = {
      outboxId: `out_${crypto.randomBytes(12).toString('hex')}`,
      idempotencyKey: `sess_sync:${session.sessionId}`,
      sessionId: session.sessionId,
      tokenId: session.tokenId,
      authorizationId: session.authorizationId,
      agentId: session.agentId,
      accountId: session.accountId,
      gatewayId: session.gatewayId,
      mcpServerId: session.mcpServerId,
      sessionExpiresAtMs: session.expiresAtMs,
      authorizationExpiresAtMs: session.authorizationExpiresAtMs,
      scope: { ...session.scope, allowedTools: [...session.scope.allowedTools] },
      correlationId: params.correlationId,
      status: 'pending',
      attempts: 0,
      nextAttemptAtMs: params.nowMs,
      createdAtMs: params.nowMs,
      deliveredAtMs: null,
      lastError: null,
    };

    this.sessions.set(session.sessionId, session);
    this.outbox.set(outboxItem.outboxId, outboxItem);
    return { ok: true, session: { ...session }, tokenRecord: { ...record }, outboxItem: { ...outboxItem } };
  }

  async getSession(sessionId: string): Promise<GatewaySession | null> {
    const sess = this.sessions.get(sessionId);
    if (!sess) return null;
    const now = Date.now();
    const status =
      sess.revokedAtMs !== null
        ? 'revoked'
        : now > sess.expiresAtMs || now > sess.authorizationExpiresAtMs
          ? 'expired'
          : 'active';
    return { ...sess, status };
  }

  async touchSession(sessionId: string, usedAtMs: number): Promise<void> {
    const sess = this.sessions.get(sessionId);
    if (sess) sess.lastUsedAtMs = usedAtMs;
  }

  async revokeSession(
    sessionId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<boolean> {
    const sess = this.sessions.get(sessionId);
    if (!sess || sess.revokedAtMs !== null) return false;
    sess.status = 'revoked';
    sess.revokedAtMs = nowMs;
    sess.revocationReason = reason;
    sess.revokedBy = revokedBy;
    return true;
  }

  async revokeByAuthorization(
    authorizationId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<number> {
    for (const tok of this.tokens.values()) {
      if (tok.authorizationId === authorizationId && tok.revokedAtMs === null) {
        tok.revokedAtMs = nowMs;
      }
    }
    let count = 0;
    for (const sess of this.sessions.values()) {
      if (sess.authorizationId === authorizationId && sess.revokedAtMs === null) {
        sess.status = 'revoked';
        sess.revokedAtMs = nowMs;
        sess.revocationReason = reason;
        sess.revokedBy = revokedBy;
        count += 1;
      }
    }
    return count;
  }

  async revokeByAgent(
    agentId: string,
    accountId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<number> {
    for (const tok of this.tokens.values()) {
      if (tok.agentId === agentId && tok.accountId === accountId && tok.revokedAtMs === null) {
        tok.revokedAtMs = nowMs;
      }
    }
    let count = 0;
    for (const sess of this.sessions.values()) {
      if (sess.agentId === agentId && sess.accountId === accountId && sess.revokedAtMs === null) {
        sess.status = 'revoked';
        sess.revokedAtMs = nowMs;
        sess.revocationReason = reason;
        sess.revokedBy = revokedBy;
        count += 1;
      }
    }
    return count;
  }

  async revokeByAccount(
    accountId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<number> {
    for (const tok of this.tokens.values()) {
      if (tok.accountId === accountId && tok.revokedAtMs === null) {
        tok.revokedAtMs = nowMs;
      }
    }
    let count = 0;
    for (const sess of this.sessions.values()) {
      if (sess.accountId === accountId && sess.revokedAtMs === null) {
        sess.status = 'revoked';
        sess.revokedAtMs = nowMs;
        sess.revocationReason = reason;
        sess.revokedBy = revokedBy;
        count += 1;
      }
    }
    await this.revokeVerifiedConnectionsByAccount(accountId, reason, nowMs);
    return count;
  }

  async listSessions(limit = 50): Promise<GatewaySession[]> {
    const now = Date.now();
    const all = Array.from(this.sessions.values())
      .sort((a, b) => b.createdAtMs - a.createdAtMs)
      .slice(0, limit);
    return all.map((sess) => ({
      ...sess,
      status:
        sess.revokedAtMs !== null
          ? 'revoked'
          : now > sess.expiresAtMs || now > sess.authorizationExpiresAtMs
            ? 'expired'
            : 'active',
    }));
  }

  async claimRevocationId(revocationId: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    for (const [k, exp] of this.revocationIds.entries()) {
      if (exp < nowMs) this.revocationIds.delete(k);
    }
    if (this.revocationIds.has(revocationId)) return false;
    this.revocationIds.set(revocationId, expiresAtMs);
    return true;
  }

  async claimHandshakeChallenge(
    challenge: string,
    expiresAtMs: number,
    nowMs: number,
  ): Promise<boolean> {
    for (const [k, exp] of this.handshakeChallenges.entries()) {
      if (exp < nowMs) this.handshakeChallenges.delete(k);
    }
    if (this.handshakeChallenges.has(challenge)) return false;
    this.handshakeChallenges.set(challenge, expiresAtMs);
    return true;
  }

  async saveVerifiedConnection(record: VerifiedMcpConnectionRecord): Promise<void> {
    this.verifiedConnections.set(record.connectionId, {
      ...record,
      toolNames: [...record.toolNames],
      serverInfo: record.serverInfo ? { ...record.serverInfo } : undefined,
    });
  }

  private effectiveConnectionStatus(record: VerifiedMcpConnectionRecord): VerifiedMcpConnectionRecord {
    const now = Date.now();
    const status =
      record.revokedAtMs !== null
        ? 'revoked'
        : now > record.expiresAtMs
          ? 'expired'
          : 'active';
    return {
      ...record,
      toolNames: [...record.toolNames],
      serverInfo: record.serverInfo ? { ...record.serverInfo } : undefined,
      status,
    };
  }

  async getVerifiedConnection(connectionId: string): Promise<VerifiedMcpConnectionRecord | null> {
    const rec = this.verifiedConnections.get(connectionId);
    return rec ? this.effectiveConnectionStatus(rec) : null;
  }

  async getLatestVerifiedConnectionByIntegration(
    accountId: string,
    integrationId: string,
  ): Promise<VerifiedMcpConnectionRecord | null> {
    const matches = Array.from(this.verifiedConnections.values())
      .filter((r) => r.accountId === accountId && r.integrationId === integrationId)
      .sort((a, b) => b.verifiedAtMs - a.verifiedAtMs);
    return matches[0] ? this.effectiveConnectionStatus(matches[0]) : null;
  }

  async revokeVerifiedConnectionsByAccount(
    accountId: string,
    reason: string,
    nowMs: number,
  ): Promise<number> {
    let count = 0;
    for (const conn of this.verifiedConnections.values()) {
      if (conn.accountId === accountId && conn.revokedAtMs === null) {
        conn.status = 'revoked';
        conn.revokedAtMs = nowMs;
        conn.revocationReason = reason;
        count += 1;
      }
    }
    return count;
  }

  async getPendingOutboxItems(nowMs: number, limit = 25): Promise<SessionSyncOutboxItem[]> {
    return Array.from(this.outbox.values())
      .filter((item) => item.status === 'pending' && item.nextAttemptAtMs <= nowMs)
      .sort((a, b) => a.createdAtMs - b.createdAtMs)
      .slice(0, limit)
      .map((i) => ({ ...i }));
  }

  async getOutboxItemBySession(sessionId: string): Promise<SessionSyncOutboxItem | null> {
    for (const item of this.outbox.values()) {
      if (item.sessionId === sessionId) return { ...item };
    }
    return null;
  }

  async markOutboxDelivered(outboxId: string, deliveredAtMs: number): Promise<void> {
    const item = this.outbox.get(outboxId);
    if (item) {
      item.status = 'delivered';
      item.deliveredAtMs = deliveredAtMs;
      item.lastError = null;
    }
  }

  async markOutboxRetry(
    outboxId: string,
    nextAttemptAtMs: number,
    attempts: number,
    lastError: string,
    terminalFail = false,
  ): Promise<void> {
    const item = this.outbox.get(outboxId);
    if (item) {
      item.status = terminalFail ? 'failed' : 'pending';
      item.attempts = attempts;
      item.nextAttemptAtMs = nextAttemptAtMs;
      item.lastError = lastError;
    }
  }

  async claimRequestId(requestId: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    for (const [k, exp] of this.replayIds.entries()) {
      if (exp < nowMs) this.replayIds.delete(k);
    }
    if (this.replayIds.has(requestId)) return false;
    this.replayIds.set(requestId, expiresAtMs);
    return true;
  }
}
