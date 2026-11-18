import crypto from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';
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
  RedeemFailureCode,
} from '../interfaces.ts';

function encodeRespCommand(args: string[]): Buffer {
  const parts: string[] = [`*${args.length}\r\n`];
  for (const arg of args) {
    const byteLen = Buffer.byteLength(arg, 'utf8');
    parts.push(`$${byteLen}\r\n${arg}\r\n`);
  }
  return Buffer.from(parts.join(''), 'utf8');
}

function parseRespReply(buf: Buffer): { value: unknown; bytesConsumed: number } | null {
  if (buf.length === 0) return null;
  const prefix = String.fromCharCode(buf[0]);
  const lineEnd = buf.indexOf('\r\n');
  if (lineEnd === -1) return null;
  const header = buf.subarray(1, lineEnd).toString('utf8');

  if (prefix === '+') {
    return { value: header, bytesConsumed: lineEnd + 2 };
  }
  if (prefix === '-') {
    throw new Error(`Redis error: ${header}`);
  }
  if (prefix === ':') {
    return { value: Number.parseInt(header, 10), bytesConsumed: lineEnd + 2 };
  }
  if (prefix === '$') {
    const len = Number.parseInt(header, 10);
    if (len === -1) return { value: null, bytesConsumed: lineEnd + 2 };
    const total = lineEnd + 2 + len + 2;
    if (buf.length < total) return null;
    return {
      value: buf.subarray(lineEnd + 2, lineEnd + 2 + len).toString('utf8'),
      bytesConsumed: total,
    };
  }
  if (prefix === '*') {
    const count = Number.parseInt(header, 10);
    if (count === -1) return { value: null, bytesConsumed: lineEnd + 2 };
    let offset = lineEnd + 2;
    const items: unknown[] = [];
    for (let i = 0; i < count; i += 1) {
      const sub = parseRespReply(buf.subarray(offset));
      if (!sub) return null;
      items.push(sub.value);
      offset += sub.bytesConsumed;
    }
    return { value: items, bytesConsumed: offset };
  }
  throw new Error(`Unsupported RESP prefix: ${prefix}`);
}

const ATOMIC_REDEEM_LUA = `
local raw = redis.call('GET', KEYS[1])
if not raw then
  return {'ERR', 'TOKEN_NOT_FOUND', 'Invalid or unknown authorization token'}
end
local tok = cjson.decode(raw)
if tok.revokedAtMs ~= cjson.null and tok.revokedAtMs ~= nil then
  return {'ERR', 'TOKEN_REVOKED', 'Authorization token has been revoked'}
end
if tok.redeemedAtMs ~= cjson.null and tok.redeemedAtMs ~= nil then
  return {'ERR', 'TOKEN_ALREADY_REDEEMED', 'Authorization token has already been redeemed'}
end
local nowMs = tonumber(ARGV[1])
local authExpMs = tonumber(tok.authorizationExpiresAtMs or tok.expiresAtMs)
if nowMs > authExpMs then
  return {'ERR', 'AUTHORIZATION_EXPIRED', 'Underlying AAMARVA authorization grant has expired'}
end
if nowMs > tonumber(tok.expiresAtMs) then
  return {'ERR', 'TOKEN_EXPIRED', 'Authorization token has expired'}
end
if tok.agentId ~= ARGV[2] then
  return {'ERR', 'AGENT_MISMATCH', 'Token agent binding mismatch'}
end
if tok.accountId ~= ARGV[3] then
  return {'ERR', 'ACCOUNT_MISMATCH', 'Token account binding mismatch'}
end
if tok.mcpServerId ~= ARGV[4] then
  return {'ERR', 'SERVER_MISMATCH', 'Token MCP server binding mismatch'}
end
if tok.gatewayId ~= ARGV[5] then
  return {'ERR', 'GATEWAY_MISMATCH', 'Token gateway installation binding mismatch'}
end
if ARGV[10] ~= '' and tok.authorizationId ~= ARGV[10] then
  return {'ERR', 'AUTHORIZATION_MISMATCH', 'Token authorization/invocation binding mismatch'}
end
tok.redeemedAtMs = nowMs
tok.redeemedBySessionId = ARGV[6]
redis.call('SET', KEYS[1], cjson.encode(tok), 'KEEPTTL')
local effectiveExp = math.min(tonumber(ARGV[7]), authExpMs)
local sess = {
  sessionId = ARGV[6],
  tokenId = tok.tokenId,
  authorizationId = tok.authorizationId,
  agentId = tok.agentId,
  agentName = tok.agentName,
  accountId = tok.accountId,
  mcpServerId = tok.mcpServerId,
  gatewayId = tok.gatewayId,
  scope = tok.scope,
  status = 'active',
  createdAtMs = nowMs,
  expiresAtMs = effectiveExp,
  authorizationExpiresAtMs = authExpMs,
  revokedAtMs = cjson.null,
  revocationReason = cjson.null,
  revokedBy = cjson.null,
  lastUsedAtMs = cjson.null
}
local sessJson = cjson.encode(sess)
local sessTtl = math.max(1, math.ceil((effectiveExp - nowMs) / 1000) + 3600)
redis.call('SET', KEYS[2], sessJson, 'EX', sessTtl)
redis.call('SADD', KEYS[3], ARGV[6])
redis.call('SADD', KEYS[4], ARGV[6])
redis.call('LPUSH', KEYS[5], ARGV[6])
redis.call('LTRIM', KEYS[5], 0, 499)
redis.call('SADD', KEYS[6], ARGV[6])
local outbox = {
  outboxId = ARGV[8],
  idempotencyKey = 'sess_sync:' .. ARGV[6],
  sessionId = ARGV[6],
  tokenId = tok.tokenId,
  authorizationId = tok.authorizationId,
  agentId = tok.agentId,
  accountId = tok.accountId,
  gatewayId = tok.gatewayId,
  mcpServerId = tok.mcpServerId,
  sessionExpiresAtMs = effectiveExp,
  authorizationExpiresAtMs = authExpMs,
  scope = tok.scope,
  correlationId = ARGV[9],
  status = 'pending',
  attempts = 0,
  nextAttemptAtMs = nowMs,
  createdAtMs = nowMs,
  deliveredAtMs = cjson.null,
  lastError = cjson.null
}
local outboxJson = cjson.encode(outbox)
redis.call('SET', KEYS[7], outboxJson)
redis.call('SET', KEYS[8], ARGV[8])
redis.call('SADD', KEYS[9], ARGV[8])
return {'OK', cjson.encode(tok), sessJson, outboxJson}
`;

/**
 * Distributed Redis state store using native TCP/TLS RESP2 + Lua atomic scripts
 * for multi-instance Gateway deployments without single-node memory lock-in.
 */
export class RedisGatewayStateStore implements GatewayStateStore {
  readonly driverName = 'redis';
  private readonly url: URL;
  private socket: net.Socket | tls.TLSSocket | null = null;
  private pending: Array<{ resolve: (v: unknown) => void; reject: (e: Error) => void }> = [];
  private buffer = Buffer.alloc(0);
  private commandQueue: Promise<unknown> = Promise.resolve();

  constructor(redisUrl: string) {
    this.url = new URL(redisUrl);
  }

  async init(): Promise<void> {
    await this.connect();
    await this.command(['PING']);
  }

  private connect(): Promise<void> {
    if (this.socket && !this.socket.destroyed) return Promise.resolve();
    const port = Number(this.url.port || (this.url.protocol === 'rediss:' ? 6380 : 6379));
    const host = this.url.hostname;

    return new Promise((resolve, reject) => {
      const sock =
        this.url.protocol === 'rediss:'
          ? tls.connect({ host, port, servername: host })
          : net.connect({ host, port });

      const onError = (err: Error) => {
        reject(err);
      };
      sock.once('error', onError);
      sock.once('connect', async () => {
        sock.off('error', onError);
        this.socket = sock;
        sock.on('data', (chunk: Buffer) => this.handleData(chunk));
        sock.on('close', () => {
          this.socket = null;
          while (this.pending.length > 0) {
            this.pending.shift()?.reject(new Error('Redis connection closed'));
          }
        });
        try {
          if (this.url.password) {
            const args = this.url.username
              ? ['AUTH', decodeURIComponent(this.url.username), decodeURIComponent(this.url.password)]
              : ['AUTH', decodeURIComponent(this.url.password)];
            await this.command(args);
          }
          resolve();
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  private handleData(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.pending.length > 0) {
      try {
        const parsed = parseRespReply(this.buffer);
        if (!parsed) break;
        this.buffer = this.buffer.subarray(parsed.bytesConsumed);
        this.pending.shift()?.resolve(parsed.value);
      } catch (err) {
        this.buffer = Buffer.alloc(0);
        this.pending.shift()?.reject(err instanceof Error ? err : new Error(String(err)));
      }
    }
  }

  private command(args: string[]): Promise<unknown> {
    const run = async () => {
      if (!this.socket || this.socket.destroyed) {
        await this.connect();
      }
      const sock = this.socket;
      if (!sock) throw new Error('Redis socket unavailable');
      return new Promise((resolve, reject) => {
        this.pending.push({ resolve, reject });
        sock.write(encodeRespCommand(args));
      });
    };
    const next = this.commandQueue.then(run, run);
    this.commandQueue = next.catch(() => undefined);
    return next;
  }

  async close(): Promise<void> {
    if (this.socket && !this.socket.destroyed) {
      this.socket.end();
      this.socket = null;
    }
  }

  async ping(): Promise<boolean> {
    try {
      const res = await this.command(['PING']);
      return res === 'PONG';
    } catch {
      return false;
    }
  }

  async saveIssuedToken(record: IssuedTokenRecord): Promise<void> {
    const ttlSec = Math.max(60, Math.ceil((record.expiresAtMs - Date.now()) / 1000) + 3600);
    await this.command([
      'SET',
      `agw:tok:${record.tokenHash}`,
      JSON.stringify(record),
      'EX',
      String(ttlSec),
    ]);
    await this.command(['SADD', `agw:auth_toks:${record.authorizationId}`, record.tokenHash]);
    await this.command(['SADD', `agw:agent_toks:${record.agentId}:${record.accountId}`, record.tokenHash]);
    await this.command(['SADD', `agw:acct_toks:${record.accountId}`, record.tokenHash]);
  }

  async redeemTokenAtomically(params: AtomicRedeemParams): Promise<AtomicRedeemResult> {
    const rawPre = (await this.command(['GET', `agw:tok:${params.tokenHash}`])) as string | null;
    if (!rawPre) {
      return { ok: false, code: 'TOKEN_NOT_FOUND', message: 'Invalid or unknown authorization token' };
    }
    const parsedPre = JSON.parse(rawPre) as IssuedTokenRecord;
    const outboxId = `out_${crypto.randomBytes(12).toString('hex')}`;
    const res = (await this.command([
      'EVAL',
      ATOMIC_REDEEM_LUA,
      '9',
      `agw:tok:${params.tokenHash}`,
      `agw:sess:${params.sessionId}`,
      `agw:auth_sess:${parsedPre.authorizationId}`,
      `agw:agent_sess:${parsedPre.agentId}:${parsedPre.accountId}`,
      'agw:sessions:recent',
      `agw:acct_sess:${parsedPre.accountId}`,
      `agw:outbox:${outboxId}`,
      `agw:outbox_by_sess:${params.sessionId}`,
      'agw:outbox:pending',
      String(params.nowMs),
      params.agentId,
      params.accountId,
      params.mcpServerId,
      params.gatewayId,
      params.sessionId,
      String(params.sessionExpiresAtMs),
      outboxId,
      params.correlationId,
      params.expectedAuthorizationId ?? '',
    ])) as string[];

    if (res[0] === 'ERR') {
      return {
        ok: false,
        code: res[1] as RedeemFailureCode,
        message: res[2],
      };
    }

    return {
      ok: true,
      tokenRecord: JSON.parse(res[1]) as IssuedTokenRecord,
      session: JSON.parse(res[2]) as GatewaySession,
      outboxItem: JSON.parse(res[3]) as SessionSyncOutboxItem,
    };
  }

  async getSession(sessionId: string): Promise<GatewaySession | null> {
    const raw = (await this.command(['GET', `agw:sess:${sessionId}`])) as string | null;
    if (!raw) return null;
    const sess = JSON.parse(raw) as GatewaySession;
    const now = Date.now();
    if (sess.revokedAtMs !== null) {
      sess.status = 'revoked';
    } else if (now > sess.expiresAtMs || now > sess.authorizationExpiresAtMs) {
      sess.status = 'expired';
    }
    return sess;
  }

  async touchSession(sessionId: string, usedAtMs: number): Promise<void> {
    const sess = await this.getSession(sessionId);
    if (!sess) return;
    sess.lastUsedAtMs = usedAtMs;
    await this.command(['SET', `agw:sess:${sessionId}`, JSON.stringify(sess), 'KEEPTTL']);
  }

  async revokeSession(
    sessionId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<boolean> {
    const sess = await this.getSession(sessionId);
    if (!sess || sess.revokedAtMs !== null) return false;
    sess.status = 'revoked';
    sess.revokedAtMs = nowMs;
    sess.revocationReason = reason;
    sess.revokedBy = revokedBy;
    await this.command(['SET', `agw:sess:${sessionId}`, JSON.stringify(sess), 'KEEPTTL']);
    return true;
  }

  async revokeByAuthorization(
    authorizationId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<number> {
    const tokenHashes = (await this.command(['SMEMBERS', `agw:auth_toks:${authorizationId}`])) as string[];
    for (const hash of tokenHashes) {
      const raw = (await this.command(['GET', `agw:tok:${hash}`])) as string | null;
      if (raw) {
        const tok = JSON.parse(raw) as IssuedTokenRecord;
        if (tok.revokedAtMs === null) {
          tok.revokedAtMs = nowMs;
          await this.command(['SET', `agw:tok:${hash}`, JSON.stringify(tok), 'KEEPTTL']);
        }
      }
    }
    const sessionIds = (await this.command(['SMEMBERS', `agw:auth_sess:${authorizationId}`])) as string[];
    let revoked = 0;
    for (const sid of sessionIds) {
      if (await this.revokeSession(sid, reason, revokedBy, nowMs)) revoked += 1;
    }
    return revoked;
  }

  async revokeByAgent(
    agentId: string,
    accountId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<number> {
    const tokenHashes = (await this.command(['SMEMBERS', `agw:agent_toks:${agentId}:${accountId}`])) as string[];
    for (const hash of tokenHashes) {
      const raw = (await this.command(['GET', `agw:tok:${hash}`])) as string | null;
      if (raw) {
        const tok = JSON.parse(raw) as IssuedTokenRecord;
        if (tok.revokedAtMs === null) {
          tok.revokedAtMs = nowMs;
          await this.command(['SET', `agw:tok:${hash}`, JSON.stringify(tok), 'KEEPTTL']);
        }
      }
    }
    const sessionIds = (await this.command(['SMEMBERS', `agw:agent_sess:${agentId}:${accountId}`])) as string[];
    let revoked = 0;
    for (const sid of sessionIds) {
      if (await this.revokeSession(sid, reason, revokedBy, nowMs)) revoked += 1;
    }
    return revoked;
  }

  async revokeByAccount(
    accountId: string,
    reason: string,
    revokedBy: string,
    nowMs: number,
  ): Promise<number> {
    const tokenHashes = (await this.command(['SMEMBERS', `agw:acct_toks:${accountId}`])) as string[];
    for (const hash of tokenHashes) {
      const raw = (await this.command(['GET', `agw:tok:${hash}`])) as string | null;
      if (raw) {
        const tok = JSON.parse(raw) as IssuedTokenRecord;
        if (tok.revokedAtMs === null) {
          tok.revokedAtMs = nowMs;
          await this.command(['SET', `agw:tok:${hash}`, JSON.stringify(tok), 'KEEPTTL']);
        }
      }
    }
    const sessionIds = (await this.command(['SMEMBERS', `agw:acct_sess:${accountId}`])) as string[];
    let revoked = 0;
    for (const sid of sessionIds) {
      if (await this.revokeSession(sid, reason, revokedBy, nowMs)) revoked += 1;
    }
    await this.revokeVerifiedConnectionsByAccount(accountId, reason, nowMs);
    return revoked;
  }

  async listSessions(limit = 50): Promise<GatewaySession[]> {
    const ids = (await this.command(['LRANGE', 'agw:sessions:recent', '0', String(limit - 1)])) as string[];
    const results: GatewaySession[] = [];
    for (const id of ids) {
      const sess = await this.getSession(id);
      if (sess) results.push(sess);
    }
    return results;
  }

  async claimRevocationId(revocationId: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    const ttlSec = Math.max(60, Math.ceil((expiresAtMs - nowMs) / 1000));
    const res = await this.command(['SET', `agw:rev:${revocationId}`, '1', 'EX', String(ttlSec), 'NX']);
    return res === 'OK';
  }

  async claimHandshakeChallenge(
    challenge: string,
    expiresAtMs: number,
    nowMs: number,
  ): Promise<boolean> {
    const ttlSec = Math.max(60, Math.ceil((expiresAtMs - nowMs) / 1000));
    const res = await this.command(['SET', `agw:hs_chal:${challenge}`, '1', 'EX', String(ttlSec), 'NX']);
    return res === 'OK';
  }

  async saveVerifiedConnection(record: VerifiedMcpConnectionRecord): Promise<void> {
    const ttlSec = Math.max(60, Math.ceil((record.expiresAtMs - Date.now()) / 1000) + 3600);
    await this.command([
      'SET',
      `agw:vconn:${record.connectionId}`,
      JSON.stringify(record),
      'EX',
      String(ttlSec),
    ]);
    await this.command([
      'SET',
      `agw:vconn_latest:${record.accountId}:${record.integrationId}`,
      record.connectionId,
      'EX',
      String(ttlSec),
    ]);
    await this.command(['SADD', `agw:acct_vconn:${record.accountId}`, record.connectionId]);
  }

  private normalizeConnection(conn: VerifiedMcpConnectionRecord): VerifiedMcpConnectionRecord {
    const now = Date.now();
    if (conn.revokedAtMs !== null) {
      conn.status = 'revoked';
    } else if (now > conn.expiresAtMs) {
      conn.status = 'expired';
    }
    return conn;
  }

  async getVerifiedConnection(connectionId: string): Promise<VerifiedMcpConnectionRecord | null> {
    const raw = (await this.command(['GET', `agw:vconn:${connectionId}`])) as string | null;
    if (!raw) return null;
    return this.normalizeConnection(JSON.parse(raw) as VerifiedMcpConnectionRecord);
  }

  async getLatestVerifiedConnectionByIntegration(
    accountId: string,
    integrationId: string,
  ): Promise<VerifiedMcpConnectionRecord | null> {
    const connId = (await this.command([
      'GET',
      `agw:vconn_latest:${accountId}:${integrationId}`,
    ])) as string | null;
    if (!connId) return null;
    return this.getVerifiedConnection(connId);
  }

  async revokeVerifiedConnectionsByAccount(
    accountId: string,
    reason: string,
    nowMs: number,
  ): Promise<number> {
    const connIds = (await this.command(['SMEMBERS', `agw:acct_vconn:${accountId}`])) as string[];
    let count = 0;
    for (const cid of connIds) {
      const conn = await this.getVerifiedConnection(cid);
      if (conn && conn.revokedAtMs === null) {
        conn.status = 'revoked';
        conn.revokedAtMs = nowMs;
        conn.revocationReason = reason;
        await this.command(['SET', `agw:vconn:${cid}`, JSON.stringify(conn), 'KEEPTTL']);
        count += 1;
      }
    }
    return count;
  }

  async getPendingOutboxItems(nowMs: number, limit = 25): Promise<SessionSyncOutboxItem[]> {
    const ids = (await this.command(['SMEMBERS', 'agw:outbox:pending'])) as string[];
    const items: SessionSyncOutboxItem[] = [];
    for (const id of ids) {
      const raw = (await this.command(['GET', `agw:outbox:${id}`])) as string | null;
      if (raw) {
        const parsed = JSON.parse(raw) as SessionSyncOutboxItem;
        if (parsed.status === 'pending' && parsed.nextAttemptAtMs <= nowMs) {
          items.push(parsed);
        }
      }
    }
    return items.sort((a, b) => a.createdAtMs - b.createdAtMs).slice(0, limit);
  }

  async getOutboxItemBySession(sessionId: string): Promise<SessionSyncOutboxItem | null> {
    const outboxId = (await this.command(['GET', `agw:outbox_by_sess:${sessionId}`])) as string | null;
    if (!outboxId) return null;
    const raw = (await this.command(['GET', `agw:outbox:${outboxId}`])) as string | null;
    return raw ? (JSON.parse(raw) as SessionSyncOutboxItem) : null;
  }

  async markOutboxDelivered(outboxId: string, deliveredAtMs: number): Promise<void> {
    const raw = (await this.command(['GET', `agw:outbox:${outboxId}`])) as string | null;
    if (!raw) return;
    const item = JSON.parse(raw) as SessionSyncOutboxItem;
    item.status = 'delivered';
    item.deliveredAtMs = deliveredAtMs;
    item.lastError = null;
    await this.command(['SET', `agw:outbox:${outboxId}`, JSON.stringify(item), 'EX', '86400']);
    await this.command(['SREM', 'agw:outbox:pending', outboxId]);
  }

  async markOutboxRetry(
    outboxId: string,
    nextAttemptAtMs: number,
    attempts: number,
    lastError: string,
    terminalFail = false,
  ): Promise<void> {
    const raw = (await this.command(['GET', `agw:outbox:${outboxId}`])) as string | null;
    if (!raw) return;
    const item = JSON.parse(raw) as SessionSyncOutboxItem;
    item.status = terminalFail ? 'failed' : 'pending';
    item.attempts = attempts;
    item.nextAttemptAtMs = nextAttemptAtMs;
    item.lastError = lastError;
    await this.command(['SET', `agw:outbox:${outboxId}`, JSON.stringify(item)]);
    if (terminalFail) {
      await this.command(['SREM', 'agw:outbox:pending', outboxId]);
    }
  }

  async claimRequestId(requestId: string, expiresAtMs: number, nowMs: number): Promise<boolean> {
    const ttlSec = Math.max(10, Math.ceil((expiresAtMs - nowMs) / 1000));
    const res = await this.command(['SET', `agw:req:${requestId}`, '1', 'EX', String(ttlSec), 'NX']);
    return res === 'OK';
  }
}
