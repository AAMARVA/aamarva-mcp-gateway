import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type {
  AuthorizationScope,
  GatewaySession,
  IssuedTokenRecord,
  OutboxDeliveryStatus,
  SessionSyncOutboxItem,
  VerifiedMcpConnectionRecord,
} from '../../core/authorization-context.ts';
import type {
  AtomicRedeemParams,
  AtomicRedeemResult,
  GatewayStateStore,
} from '../interfaces.ts';

interface TokenRow {
  token_id: string;
  token_hash: string;
  authorization_id: string;
  agent_id: string;
  agent_name: string;
  account_id: string;
  mcp_server_id: string;
  gateway_id: string;
  scope_json: string;
  aamarva_key_id: string;
  issued_at_ms: number;
  expires_at_ms: number;
  authorization_expires_at_ms: number;
  redeemed_at_ms: number | null;
  redeemed_by_session_id: string | null;
  revoked_at_ms: number | null;
}

interface SessionRow {
  session_id: string;
  token_id: string;
  authorization_id: string;
  agent_id: string;
  agent_name: string;
  account_id: string;
  mcp_server_id: string;
  gateway_id: string;
  scope_json: string;
  status: string;
  created_at_ms: number;
  expires_at_ms: number;
  authorization_expires_at_ms: number;
  revoked_at_ms: number | null;
  revocation_reason: string | null;
  revoked_by: string | null;
  last_used_at_ms: number | null;
}

interface OutboxRow {
  outbox_id: string;
  idempotency_key: string;
  session_id: string;
  token_id: string;
  authorization_id: string;
  agent_id: string;
  account_id: string;
  gateway_id: string;
  mcp_server_id: string;
  session_expires_at_ms: number;
  authorization_expires_at_ms: number;
  scope_json: string;
  correlation_id: string;
  status: string;
  attempts: number;
  next_attempt_at_ms: number;
  created_at_ms: number;
  delivered_at_ms: number | null;
  last_error: string | null;
}

interface VerifiedConnectionRow {
  connection_id: string;
  attestation_id: string;
  account_id: string;
  integration_id: string;
  mcp_server_id: string;
  gateway_id: string;
  transport: string;
  canonical_endpoint: string;
  negotiated_protocol_version: string;
  server_info_json: string | null;
  tools_list_hash: string;
  tool_names_json: string;
  encrypted_credentials_json: string | null;
  status: string;
  verified_at_ms: number;
  expires_at_ms: number;
  revoked_at_ms: number | null;
  revocation_reason: string | null;
}

export class SqliteGatewayStateStore implements GatewayStateStore {
  readonly driverName = 'sqlite';
  private readonly dbPath: string;
  private db: DatabaseSync | null = null;

  constructor(dbPath: string) {
    this.dbPath = dbPath;
  }

  private ensureColumn(tableName: string, colName: string, definition: string): void {
    const db = this.requireDb();
    const cols = db.prepare(`PRAGMA table_info(${tableName})`).all() as Array<{ name: string }>;
    if (!cols.some((c) => c.name === colName)) {
      db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${colName} ${definition};`);
    }
  }

  async init(): Promise<void> {
    if (this.db) return;
    if (this.dbPath !== ':memory:') {
      const dir = path.dirname(this.dbPath);
      fs.mkdirSync(dir, { recursive: true });
    }
    this.db = new DatabaseSync(this.dbPath);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA busy_timeout = 5000;');
    this.db.exec('PRAGMA synchronous = NORMAL;');

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS issued_tokens (
        token_hash TEXT PRIMARY KEY,
        token_id TEXT NOT NULL UNIQUE,
        authorization_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        agent_name TEXT NOT NULL,
        account_id TEXT NOT NULL,
        mcp_server_id TEXT NOT NULL,
        gateway_id TEXT NOT NULL,
        scope_json TEXT NOT NULL,
        aamarva_key_id TEXT NOT NULL,
        issued_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        authorization_expires_at_ms INTEGER NOT NULL DEFAULT 0,
        redeemed_at_ms INTEGER,
        redeemed_by_session_id TEXT,
        revoked_at_ms INTEGER
      );

      CREATE INDEX IF NOT EXISTS idx_issued_tokens_auth ON issued_tokens(authorization_id);
      CREATE INDEX IF NOT EXISTS idx_issued_tokens_agent ON issued_tokens(agent_id, account_id);

      CREATE TABLE IF NOT EXISTS gateway_sessions (
        session_id TEXT PRIMARY KEY,
        token_id TEXT NOT NULL,
        authorization_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        agent_name TEXT NOT NULL,
        account_id TEXT NOT NULL,
        mcp_server_id TEXT NOT NULL,
        gateway_id TEXT NOT NULL,
        scope_json TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        authorization_expires_at_ms INTEGER NOT NULL DEFAULT 0,
        revoked_at_ms INTEGER,
        revocation_reason TEXT,
        revoked_by TEXT,
        last_used_at_ms INTEGER
      );

      CREATE INDEX IF NOT EXISTS idx_sessions_auth ON gateway_sessions(authorization_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_agent ON gateway_sessions(agent_id, account_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_account ON gateway_sessions(account_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_created ON gateway_sessions(created_at_ms DESC);

      CREATE TABLE IF NOT EXISTS session_sync_outbox (
        outbox_id TEXT PRIMARY KEY,
        idempotency_key TEXT NOT NULL UNIQUE,
        session_id TEXT NOT NULL UNIQUE,
        token_id TEXT NOT NULL,
        authorization_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        gateway_id TEXT NOT NULL,
        mcp_server_id TEXT NOT NULL,
        session_expires_at_ms INTEGER NOT NULL,
        authorization_expires_at_ms INTEGER NOT NULL,
        scope_json TEXT NOT NULL,
        correlation_id TEXT NOT NULL,
        status TEXT NOT NULL,
        attempts INTEGER NOT NULL,
        next_attempt_at_ms INTEGER NOT NULL,
        created_at_ms INTEGER NOT NULL,
        delivered_at_ms INTEGER,
        last_error TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_outbox_pending ON session_sync_outbox(status, next_attempt_at_ms);

      CREATE TABLE IF NOT EXISTS replay_requests (
        request_id TEXT PRIMARY KEY,
        expires_at_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS processed_revocations (
        revocation_id TEXT PRIMARY KEY,
        expires_at_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS handshake_challenges (
        challenge TEXT PRIMARY KEY,
        expires_at_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS verified_mcp_connections (
        connection_id TEXT PRIMARY KEY,
        attestation_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        integration_id TEXT NOT NULL,
        mcp_server_id TEXT NOT NULL,
        gateway_id TEXT NOT NULL,
        transport TEXT NOT NULL,
        canonical_endpoint TEXT NOT NULL,
        negotiated_protocol_version TEXT NOT NULL,
        server_info_json TEXT,
        tools_list_hash TEXT NOT NULL,
        tool_names_json TEXT NOT NULL,
        encrypted_credentials_json TEXT,
        status TEXT NOT NULL,
        verified_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL,
        revoked_at_ms INTEGER,
        revocation_reason TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_verified_conn_acct_int
        ON verified_mcp_connections(account_id, integration_id, verified_at_ms DESC);
    `);

    this.ensureColumn('issued_tokens', 'authorization_expires_at_ms', 'INTEGER NOT NULL DEFAULT 0');
    this.ensureColumn('gateway_sessions', 'authorization_expires_at_ms', 'INTEGER NOT NULL DEFAULT 0');
  }

  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  async ping(): Promise<boolean> {
    if (!this.db) return false;
    try {
      this.db.prepare('SELECT 1 AS ok').get();
      return true;
    } catch {
      return false;
    }
  }

  private requireDb(): DatabaseSync {
    if (!this.db) {
      throw new Error('SqliteGatewayStateStore has not been initialized');
    }
    return this.db;
  }

  async saveIssuedToken(record: IssuedTokenRecord): Promise<void> {
    const db = this.requireDb();
    db.prepare(`
      INSERT INTO issued_tokens (
        token_hash, token_id, authorization_id, agent_id, agent_name, account_id,
        mcp_server_id, gateway_id, scope_json, aamarva_key_id,
        issued_at_ms, expires_at_ms, authorization_expires_at_ms,
        redeemed_at_ms, redeemed_by_session_id, revoked_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      record.tokenHash,
      record.tokenId,
      record.authorizationId,
      record.agentId,
      record.agentName,
      record.accountId,
      record.mcpServerId,
      record.gatewayId,
      JSON.stringify(record.scope),
      record.aamarvaKeyId,
      record.issuedAtMs,
      record.expiresAtMs,
      record.authorizationExpiresAtMs,
      record.redeemedAtMs,
      record.redeemedBySessionId,
      record.revokedAtMs,
    );
  }

  async getIssuedTokenByHash(tokenHash: string): Promise<IssuedTokenRecord | null> {
    const db = this.requireDb();
    const row = db
      .prepare('SELECT * FROM issued_tokens WHERE token_hash = ?')
      .get(tokenHash) as TokenRow | undefined;
    if (!row) return null;
    const authExpMs =
      row.authorization_expires_at_ms > 0 ? row.authorization_expires_at_ms : row.expires_at_ms;
    return {
      tokenId: row.token_id,
      tokenHash: row.token_hash,
      authorizationId: row.authorization_id,
      agentId: row.agent_id,
      agentName: row.agent_name,
      accountId: row.account_id,
      mcpServerId: row.mcp_server_id,
      gatewayId: row.gateway_id,
      scope: JSON.parse(row.scope_json) as AuthorizationScope,
      aamarvaKeyId: row.aamarva_key_id,
      issuedAtMs: row.issued_at_ms,
      expiresAtMs: row.expires_at_ms,
      authorizationExpiresAtMs: authExpMs,
      redeemedAtMs: row.redeemed_at_ms,
      redeemedBySessionId: row.redeemed_by_session_id,
      revokedAtMs: row.revoked_at_ms,
    };
  }

  async redeemTokenAtomically(params: AtomicRedeemParams): Promise<AtomicRedeemResult> {
    const db = this.requireDb();
    db.exec('BEGIN IMMEDIATE;');
    try {
      const row = db
        .prepare('SELECT * FROM issued_tokens WHERE token_hash = ?')
        .get(params.tokenHash) as TokenRow | undefined;

      if (!row) {
        db.exec('ROLLBACK;');
        return { ok: false, code: 'TOKEN_NOT_FOUND', message: 'Invalid or unknown authorization token' };
      }

      if (row.revoked_at_ms !== null) {
        db.exec('ROLLBACK;');
        return { ok: false, code: 'TOKEN_REVOKED', message: 'Authorization token has been revoked' };
      }

      if (row.redeemed_at_ms !== null) {
        db.exec('ROLLBACK;');
        return {
          ok: false,
          code: 'TOKEN_ALREADY_REDEEMED',
          message: 'Authorization token has already been redeemed',
        };
      }

      const authExpMs =
        row.authorization_expires_at_ms > 0 ? row.authorization_expires_at_ms : row.expires_at_ms;

      if (params.nowMs > authExpMs) {
        db.exec('ROLLBACK;');
        return {
          ok: false,
          code: 'AUTHORIZATION_EXPIRED',
          message: 'Underlying AAMARVA authorization grant has expired',
        };
      }

      if (params.nowMs > row.expires_at_ms) {
        db.exec('ROLLBACK;');
        return { ok: false, code: 'TOKEN_EXPIRED', message: 'Authorization token has expired' };
      }

      if (params.agentId !== undefined && row.agent_id !== params.agentId) {
        db.exec('ROLLBACK;');
        return { ok: false, code: 'AGENT_MISMATCH', message: 'Token agent binding mismatch' };
      }

      if (params.accountId !== undefined && row.account_id !== params.accountId) {
        db.exec('ROLLBACK;');
        return { ok: false, code: 'ACCOUNT_MISMATCH', message: 'Token account binding mismatch' };
      }

      if (params.mcpServerId !== undefined && row.mcp_server_id !== params.mcpServerId) {
        db.exec('ROLLBACK;');
        return { ok: false, code: 'SERVER_MISMATCH', message: 'Token MCP server binding mismatch' };
      }

      if (row.gateway_id !== params.gatewayId) {
        db.exec('ROLLBACK;');
        return { ok: false, code: 'GATEWAY_MISMATCH', message: 'Token gateway installation binding mismatch' };
      }

      if (params.expectedAuthorizationId && row.authorization_id !== params.expectedAuthorizationId) {
        db.exec('ROLLBACK;');
        return {
          ok: false,
          code: 'AUTHORIZATION_MISMATCH',
          message: 'Token authorization/invocation binding mismatch',
        };
      }

      const updateResult = db
        .prepare(
          `UPDATE issued_tokens
           SET redeemed_at_ms = ?, redeemed_by_session_id = ?
           WHERE token_hash = ? AND redeemed_at_ms IS NULL AND revoked_at_ms IS NULL`,
        )
        .run(params.nowMs, params.sessionId, params.tokenHash);

      if (Number(updateResult.changes) !== 1) {
        db.exec('ROLLBACK;');
        return {
          ok: false,
          code: 'TOKEN_ALREADY_REDEEMED',
          message: 'Authorization token was concurrently redeemed',
        };
      }

      const effectiveSessionExpiresAtMs = Math.min(params.sessionExpiresAtMs, authExpMs);
      const scope = JSON.parse(row.scope_json) as AuthorizationScope;
      const session: GatewaySession = {
        sessionId: params.sessionId,
        tokenId: row.token_id,
        authorizationId: row.authorization_id,
        agentId: row.agent_id,
        agentName: row.agent_name,
        accountId: row.account_id,
        mcpServerId: row.mcp_server_id,
        gatewayId: row.gateway_id,
        scope,
        status: 'active',
        createdAtMs: params.nowMs,
        expiresAtMs: effectiveSessionExpiresAtMs,
        authorizationExpiresAtMs: authExpMs,
        revokedAtMs: null,
        revocationReason: null,
        revokedBy: null,
        lastUsedAtMs: null,
      };

      db.prepare(`
        INSERT INTO gateway_sessions (
          session_id, token_id, authorization_id, agent_id, agent_name, account_id,
          mcp_server_id, gateway_id, scope_json, status, created_at_ms, expires_at_ms,
          authorization_expires_at_ms, revoked_at_ms, revocation_reason, revoked_by, last_used_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        session.sessionId,
        session.tokenId,
        session.authorizationId,
        session.agentId,
        session.agentName,
        session.accountId,
        session.mcpServerId,
        session.gatewayId,
        JSON.stringify(session.scope),
        session.status,
        session.createdAtMs,
        session.expiresAtMs,
        session.authorizationExpiresAtMs,
        null,
        null,
        null,
        null,
      );

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
        scope: session.scope,
        correlationId: params.correlationId,
        status: 'pending',
        attempts: 0,
        nextAttemptAtMs: params.nowMs,
        createdAtMs: params.nowMs,
        deliveredAtMs: null,
        lastError: null,
      };

      db.prepare(`
        INSERT INTO session_sync_outbox (
          outbox_id, idempotency_key, session_id, token_id, authorization_id,
          agent_id, account_id, gateway_id, mcp_server_id,
          session_expires_at_ms, authorization_expires_at_ms, scope_json,
          correlation_id, status, attempts, next_attempt_at_ms, created_at_ms,
          delivered_at_ms, last_error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        outboxItem.outboxId,
        outboxItem.idempotencyKey,
        outboxItem.sessionId,
        outboxItem.tokenId,
        outboxItem.authorizationId,
        outboxItem.agentId,
        outboxItem.accountId,
        outboxItem.gatewayId,
        outboxItem.mcpServerId,
        outboxItem.sessionExpiresAtMs,
        outboxItem.authorizationExpiresAtMs,
        JSON.stringify(outboxItem.scope),
        outboxItem.correlationId,
        outboxItem.status,
        outboxItem.attempts,
        outboxItem.nextAttemptAtMs,
        outboxItem.createdAtMs,
        null,
        null,
      );

      db.exec('COMMIT;');

      return {
        ok: true,
        session,
        outboxItem,
        tokenRecord: {
          tokenId: row.token_id,
          tokenHash: row.token_hash,
          authorizationId: row.authorization_id,
          agentId: row.agent_id,
          agentName: row.agent_name,
          accountId: row.account_id,
          mcpServerId: row.mcp_server_id,
          gatewayId: row.gateway_id,
          scope,
          aamarvaKeyId: row.aamarva_key_id,
          issuedAtMs: row.issued_at_ms,
          expiresAtMs: row.expires_at_ms,
          authorizationExpiresAtMs: authExpMs,
          redeemedAtMs: params.nowMs,
          redeemedBySessionId: params.sessionId,
          revokedAtMs: row.revoked_at_ms,
        },
      };
    } catch (err) {
      try {
        db.exec('ROLLBACK;');
      } catch {
        // ignore rollback error
      }
      throw err;
    }
  }

  private mapSessionRow(row: SessionRow): GatewaySession {
    const now = Date.now();
    const authExpMs =
      row.authorization_expires_at_ms > 0 ? row.authorization_expires_at_ms : row.expires_at_ms;
    const effectiveStatus =
      row.revoked_at_ms !== null
        ? 'revoked'
        : now > row.expires_at_ms || now > authExpMs
          ? 'expired'
          : 'active';

    return {
      sessionId: row.session_id,
      tokenId: row.token_id,
      authorizationId: row.authorization_id,
      agentId: row.agent_id,
      agentName: row.agent_name,
      accountId: row.account_id,
      mcpServerId: row.mcp_server_id,
      gatewayId: row.gateway_id,
      scope: JSON.parse(row.scope_json) as AuthorizationScope,
      status: effectiveStatus,
      createdAtMs: row.created_at_ms,
      expiresAtMs: row.expires_at_ms,
      authorizationExpiresAtMs: authExpMs,
      revokedAtMs: row.revoked_at_ms,
      revocationReason: row.revocation_reason,
      revokedBy: row.revoked_by,
      lastUsedAtMs: row.last_used_at_ms,
    };
  }

  private mapOutboxRow(row: OutboxRow): SessionSyncOutboxItem {
    return {
      outboxId: row.outbox_id,
      idempotencyKey: row.idempotency_key,
      sessionId: row.session_id,
      tokenId: row.token_id,
      authorizationId: row.authorization_id,
      agentId: row.agent_id,
      accountId: row.account_id,
      gatewayId: row.gateway_id,
      mcpServerId: row.mcp_server_id,
      sessionExpiresAtMs: row.session_expires_at_ms,
      authorizationExpiresAtMs: row.authorization_expires_at_ms,
      scope: JSON.parse(row.scope_json) as AuthorizationScope,
      correlationId: row.correlation_id,
      status: row.status as OutboxDeliveryStatus,
      attempts: row.attempts,
      nextAttemptAtMs: row.next_attempt_at_ms,
      createdAtMs: row.created_at_ms,
      deliveredAtMs: row.delivered_at_ms,
      lastError: row.last_error,
    };
  }

  async getSession(sessionId: string): Promise<GatewaySession | null> {
    const db = this.requireDb();
    const row = db
      .prepare('SELECT * FROM gateway_sessions WHERE session_id = ?')
      .get(sessionId) as SessionRow | undefined;
    return row ? this.mapSessionRow(row) : null;
  }

  async touchSession(sessionId: string, usedAtMs: number): Promise<void> {
    const db = this.requireDb();
    db.prepare('UPDATE gateway_sessions SET last_used_at_ms = ? WHERE session_id = ?').run(
      usedAtMs,
      sessionId,
    );
  }

  async revokeSession(
    sessionId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<boolean> {
    const db = this.requireDb();
    const res = db
      .prepare(
        `UPDATE gateway_sessions
         SET status = 'revoked', revoked_at_ms = ?, revocation_reason = ?, revoked_by = ?
         WHERE session_id = ? AND revoked_at_ms IS NULL`,
      )
      .run(nowMs, reason, revokedBy, sessionId);
    return Number(res.changes) > 0;
  }

  async revokeByAuthorization(
    authorizationId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<number> {
    const db = this.requireDb();
    db.exec('BEGIN IMMEDIATE;');
    try {
      db.prepare(
        `UPDATE issued_tokens SET revoked_at_ms = ? WHERE authorization_id = ? AND revoked_at_ms IS NULL`,
      ).run(nowMs, authorizationId);
      const res = db
        .prepare(
          `UPDATE gateway_sessions
           SET status = 'revoked', revoked_at_ms = ?, revocation_reason = ?, revoked_by = ?
           WHERE authorization_id = ? AND revoked_at_ms IS NULL`,
        )
        .run(nowMs, reason, revokedBy, authorizationId);
      db.exec('COMMIT;');
      return Number(res.changes);
    } catch (err) {
      db.exec('ROLLBACK;');
      throw err;
    }
  }

  async revokeByAgent(
    agentId: string,
    accountId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<number> {
    const db = this.requireDb();
    db.exec('BEGIN IMMEDIATE;');
    try {
      db.prepare(
        `UPDATE issued_tokens SET revoked_at_ms = ? WHERE agent_id = ? AND account_id = ? AND revoked_at_ms IS NULL`,
      ).run(nowMs, agentId, accountId);
      const res = db
        .prepare(
          `UPDATE gateway_sessions
           SET status = 'revoked', revoked_at_ms = ?, revocation_reason = ?, revoked_by = ?
           WHERE agent_id = ? AND account_id = ? AND revoked_at_ms IS NULL`,
        )
        .run(nowMs, reason, revokedBy, agentId, accountId);
      db.exec('COMMIT;');
      return Number(res.changes);
    } catch (err) {
      db.exec('ROLLBACK;');
      throw err;
    }
  }

  async revokeByAccount(
    accountId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<number> {
    const db = this.requireDb();
    db.exec('BEGIN IMMEDIATE;');
    try {
      db.prepare(
        `UPDATE issued_tokens SET revoked_at_ms = ? WHERE account_id = ? AND revoked_at_ms IS NULL`,
      ).run(nowMs, accountId);
      const res = db
        .prepare(
          `UPDATE gateway_sessions
           SET status = 'revoked', revoked_at_ms = ?, revocation_reason = ?, revoked_by = ?
           WHERE account_id = ? AND revoked_at_ms IS NULL`,
        )
        .run(nowMs, reason, revokedBy, accountId);
      db.prepare(
        `UPDATE verified_mcp_connections
         SET status = 'revoked', revoked_at_ms = ?, revocation_reason = ?
         WHERE account_id = ? AND revoked_at_ms IS NULL`,
      ).run(nowMs, reason, accountId);
      db.exec('COMMIT;');
      return Number(res.changes);
    } catch (err) {
      db.exec('ROLLBACK;');
      throw err;
    }
  }

  async listSessions(limit = 50): Promise<GatewaySession[]> {
    const db = this.requireDb();
    const rows = db
      .prepare('SELECT * FROM gateway_sessions ORDER BY created_at_ms DESC LIMIT ?')
      .all(limit) as unknown as SessionRow[];
    return rows.map((r) => this.mapSessionRow(r));
  }

  async claimRevocationId(revocationId: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    const db = this.requireDb();
    db.exec('BEGIN IMMEDIATE;');
    try {
      db.prepare('DELETE FROM processed_revocations WHERE expires_at_ms < ?').run(nowMs);
      const existing = db
        .prepare('SELECT revocation_id FROM processed_revocations WHERE revocation_id = ?')
        .get(revocationId);
      if (existing) {
        db.exec('ROLLBACK;');
        return false;
      }
      db.prepare('INSERT INTO processed_revocations (revocation_id, expires_at_ms) VALUES (?, ?)').run(
        revocationId,
        expiresAtMs,
      );
      db.exec('COMMIT;');
      return true;
    } catch (err) {
      try {
        db.exec('ROLLBACK;');
      } catch {
        // ignore
      }
      throw err;
    }
  }

  private mapVerifiedConnectionRow(row: VerifiedConnectionRow): VerifiedMcpConnectionRecord {
    const now = Date.now();
    const effectiveStatus =
      row.revoked_at_ms !== null
        ? 'revoked'
        : now > row.expires_at_ms
          ? 'expired'
          : 'active';

    return {
      connectionId: row.connection_id,
      attestationId: row.attestation_id,
      accountId: row.account_id,
      integrationId: row.integration_id,
      mcpServerId: row.mcp_server_id,
      gatewayId: row.gateway_id,
      transport: row.transport as 'stdio' | 'streamable-http',
      canonicalEndpoint: row.canonical_endpoint,
      negotiatedProtocolVersion: row.negotiated_protocol_version,
      serverInfo: row.server_info_json
        ? (JSON.parse(row.server_info_json) as { name: string; version: string })
        : undefined,
      toolsListHash: row.tools_list_hash,
      toolNames: JSON.parse(row.tool_names_json) as string[],
      encryptedCredentialsJson: row.encrypted_credentials_json,
      status: effectiveStatus,
      verifiedAtMs: row.verified_at_ms,
      expiresAtMs: row.expires_at_ms,
      revokedAtMs: row.revoked_at_ms,
      revocationReason: row.revocation_reason,
    };
  }

  async claimHandshakeChallenge(
    challenge: string,
    expiresAtMs: number,
    nowMs: number,
  ): Promise<boolean> {
    const db = this.requireDb();
    db.exec('BEGIN IMMEDIATE;');
    try {
      db.prepare('DELETE FROM handshake_challenges WHERE expires_at_ms < ?').run(nowMs);
      const existing = db
        .prepare('SELECT challenge FROM handshake_challenges WHERE challenge = ?')
        .get(challenge);
      if (existing) {
        db.exec('ROLLBACK;');
        return false;
      }
      db.prepare('INSERT INTO handshake_challenges (challenge, expires_at_ms) VALUES (?, ?)').run(
        challenge,
        expiresAtMs,
      );
      db.exec('COMMIT;');
      return true;
    } catch (err) {
      try {
        db.exec('ROLLBACK;');
      } catch {
        // ignore
      }
      throw err;
    }
  }

  async saveVerifiedConnection(record: VerifiedMcpConnectionRecord): Promise<void> {
    const db = this.requireDb();
    db.prepare(`
      INSERT INTO verified_mcp_connections (
        connection_id, attestation_id, account_id, integration_id, mcp_server_id, gateway_id,
        transport, canonical_endpoint, negotiated_protocol_version, server_info_json,
        tools_list_hash, tool_names_json, encrypted_credentials_json, status,
        verified_at_ms, expires_at_ms, revoked_at_ms, revocation_reason
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      record.connectionId,
      record.attestationId,
      record.accountId,
      record.integrationId,
      record.mcpServerId,
      record.gatewayId,
      record.transport,
      record.canonicalEndpoint,
      record.negotiatedProtocolVersion,
      record.serverInfo ? JSON.stringify(record.serverInfo) : null,
      record.toolsListHash,
      JSON.stringify(record.toolNames),
      record.encryptedCredentialsJson,
      record.status,
      record.verifiedAtMs,
      record.expiresAtMs,
      record.revokedAtMs,
      record.revocationReason,
    );
  }

  async getVerifiedConnection(connectionId: string): Promise<VerifiedMcpConnectionRecord | null> {
    const db = this.requireDb();
    const row = db
      .prepare('SELECT * FROM verified_mcp_connections WHERE connection_id = ?')
      .get(connectionId) as VerifiedConnectionRow | undefined;
    return row ? this.mapVerifiedConnectionRow(row) : null;
  }

  async getLatestVerifiedConnectionByIntegration(
    accountId: string,
    integrationId: string,
  ): Promise<VerifiedMcpConnectionRecord | null> {
    const db = this.requireDb();
    const row = db
      .prepare(
        `SELECT * FROM verified_mcp_connections
         WHERE account_id = ? AND integration_id = ?
         ORDER BY verified_at_ms DESC LIMIT 1`,
      )
      .get(accountId, integrationId) as VerifiedConnectionRow | undefined;
    return row ? this.mapVerifiedConnectionRow(row) : null;
  }

  async revokeVerifiedConnectionsByAccount(
    accountId: string,
    reason: string,
    nowMs: number,
  ): Promise<number> {
    const db = this.requireDb();
    const res = db
      .prepare(
        `UPDATE verified_mcp_connections
         SET status = 'revoked', revoked_at_ms = ?, revocation_reason = ?
         WHERE account_id = ? AND revoked_at_ms IS NULL`,
      )
      .run(nowMs, reason, accountId);
    return Number(res.changes);
  }

  async getPendingOutboxItems(nowMs: number, limit = 25): Promise<SessionSyncOutboxItem[]> {
    const db = this.requireDb();
    const rows = db
      .prepare(
        `SELECT * FROM session_sync_outbox
         WHERE status = 'pending' AND next_attempt_at_ms <= ?
         ORDER BY created_at_ms ASC LIMIT ?`,
      )
      .all(nowMs, limit) as unknown as OutboxRow[];
    return rows.map((r) => this.mapOutboxRow(r));
  }

  async getOutboxItemBySession(sessionId: string): Promise<SessionSyncOutboxItem | null> {
    const db = this.requireDb();
    const row = db
      .prepare('SELECT * FROM session_sync_outbox WHERE session_id = ?')
      .get(sessionId) as OutboxRow | undefined;
    return row ? this.mapOutboxRow(row) : null;
  }

  async markOutboxDelivered(outboxId: string, deliveredAtMs: number): Promise<void> {
    const db = this.requireDb();
    db.prepare(
      `UPDATE session_sync_outbox
       SET status = 'delivered', delivered_at_ms = ?, last_error = NULL
       WHERE outbox_id = ?`,
    ).run(deliveredAtMs, outboxId);
  }

  async markOutboxRetry(
    outboxId: string,
    nextAttemptAtMs: number,
    attempts: number,
    lastError: string,
    terminalFail = false,
  ): Promise<void> {
    const db = this.requireDb();
    db.prepare(
      `UPDATE session_sync_outbox
       SET status = ?, attempts = ?, next_attempt_at_ms = ?, last_error = ?
       WHERE outbox_id = ?`,
    ).run(terminalFail ? 'failed' : 'pending', attempts, nextAttemptAtMs, lastError, outboxId);
  }

  async claimRequestId(requestId: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    const db = this.requireDb();
    db.exec('BEGIN IMMEDIATE;');
    try {
      db.prepare('DELETE FROM replay_requests WHERE expires_at_ms < ?').run(nowMs);
      const existing = db
        .prepare('SELECT request_id FROM replay_requests WHERE request_id = ?')
        .get(requestId);
      if (existing) {
        db.exec('ROLLBACK;');
        return false;
      }
      db.prepare('INSERT INTO replay_requests (request_id, expires_at_ms) VALUES (?, ?)').run(
        requestId,
        expiresAtMs,
      );
      db.exec('COMMIT;');
      return true;
    } catch (err) {
      try {
        db.exec('ROLLBACK;');
      } catch {
        // ignore
      }
      throw err;
    }
  }
}
