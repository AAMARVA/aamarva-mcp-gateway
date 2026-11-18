import type {
  GatewaySession,
  IssuedTokenRecord,
  SessionSyncOutboxItem,
  VerifiedMcpConnectionRecord,
} from '../core/authorization-context.ts';

export type RedeemFailureCode =
  | 'TOKEN_NOT_FOUND'
  | 'TOKEN_EXPIRED'
  | 'AUTHORIZATION_EXPIRED'
  | 'TOKEN_ALREADY_REDEEMED'
  | 'TOKEN_REVOKED'
  | 'AGENT_MISMATCH'
  | 'ACCOUNT_MISMATCH'
  | 'SERVER_MISMATCH'
  | 'GATEWAY_MISMATCH'
  | 'AUTHORIZATION_MISMATCH';

export interface AtomicRedeemParams {
  tokenHash: string;
  agentId: string;
  accountId: string;
  mcpServerId: string;
  gatewayId: string;
  expectedAuthorizationId?: string;
  sessionId: string;
  sessionExpiresAtMs: number;
  correlationId: string;
  nowMs: number;
}

export type AtomicRedeemResult =
  | {
      ok: true;
      session: GatewaySession;
      tokenRecord: IssuedTokenRecord;
      outboxItem: SessionSyncOutboxItem;
    }
  | {
      ok: false;
      code: RedeemFailureCode;
      message: string;
    };

export interface GatewayStateStore {
  readonly driverName: string;
  init(): Promise<void>;
  close(): Promise<void>;
  ping(): Promise<boolean>;

  saveIssuedToken(record: IssuedTokenRecord): Promise<void>;
  redeemTokenAtomically(params: AtomicRedeemParams): Promise<AtomicRedeemResult>;

  getSession(sessionId: string): Promise<GatewaySession | null>;
  touchSession(sessionId: string, usedAtMs: number): Promise<void>;
  revokeSession(sessionId: string, reason: string, revokedBy: string, nowMs: number): Promise<boolean>;
  revokeByAuthorization(authorizationId: string, reason: string, revokedBy: string, nowMs: number): Promise<number>;
  revokeByAgent(agentId: string, accountId: string, reason: string, revokedBy: string, nowMs: number): Promise<number>;
  revokeByAccount(accountId: string, reason: string, revokedBy: string, nowMs: number): Promise<number>;
  listSessions(limit?: number): Promise<GatewaySession[]>;

  claimRevocationId(revocationId: string, expiresAtMs: number, nowMs: number): Promise<boolean>;

  claimHandshakeChallenge(challenge: string, expiresAtMs: number, nowMs: number): Promise<boolean>;
  saveVerifiedConnection(record: VerifiedMcpConnectionRecord): Promise<void>;
  getVerifiedConnection(connectionId: string): Promise<VerifiedMcpConnectionRecord | null>;
  getLatestVerifiedConnectionByIntegration(
    accountId: string,
    integrationId: string,
  ): Promise<VerifiedMcpConnectionRecord | null>;
  revokeVerifiedConnectionsByAccount(
    accountId: string,
    reason: string,
    nowMs: number,
  ): Promise<number>;

  getPendingOutboxItems(nowMs: number, limit?: number): Promise<SessionSyncOutboxItem[]>;
  getOutboxItemBySession(sessionId: string): Promise<SessionSyncOutboxItem | null>;
  markOutboxDelivered(outboxId: string, deliveredAtMs: number): Promise<void>;
  markOutboxRetry(
    outboxId: string,
    nextAttemptAtMs: number,
    attempts: number,
    lastError: string,
    terminalFail?: boolean,
  ): Promise<void>;

  /**
   * Atomically records a backend relay requestId for replay protection.
   * Returns true if the requestId is fresh (newly recorded), false if already seen.
   */
  claimRequestId(requestId: string, expiresAtMs: number, nowMs: number): Promise<boolean>;
}
