import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { LocalTestAamarvaBackendClient } from '../../src/gateway/aamarva/aamarva-client.ts';
import { validateGatewayConfig } from '../../src/gateway/config/validation.ts';
import type { AuthorizationContext } from '../../src/gateway/core/authorization-context.ts';
import { GatewaySessionManager } from '../../src/gateway/core/gateway-session.ts';
import {
  GatewayIdentityKeyManager,
  verifyGatewayResponseSignature,
} from '../../src/gateway/crypto/gateway-keypair.ts';
import { AuditRecorder } from '../../src/gateway/observability/audit.ts';
import { GatewayLogger } from '../../src/gateway/observability/logger.ts';
import { GatewayMetrics } from '../../src/gateway/observability/metrics.ts';
import {
  InsufficientGrantValidityError,
  RedemptionService,
} from '../../src/gateway/redemption/redemption-service.ts';
import { RedemptionStore } from '../../src/gateway/redemption/redemption-store.ts';
import { SessionSyncOutboxProcessor } from '../../src/gateway/redemption/session-sync-outbox.ts';
import { SqliteGatewayStateStore } from '../../src/gateway/storage/adapters/sqlite-store.ts';
import { decryptTokenAsAgent } from '../fixtures/agent-decryption-harness.ts';

describe('One-Time Atomic Token Redemption, Expiration Clamping & Session Sync Outbox', () => {
  let tmpDir: string;
  let dbPath: string;
  let store: SqliteGatewayStateStore;
  let gatewayIdentity: GatewayIdentityKeyManager;
  let mockClient: LocalTestAamarvaBackendClient;
  let outboxProcessor: SessionSyncOutboxProcessor;
  let service: RedemptionService;
  let sessionManager: GatewaySessionManager;
  let metrics: GatewayMetrics;
  let agentKeys: { publicKey: string; privateKey: string };
  let gatewayKeys: { publicKey: string; privateKey: string };

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agw-test-'));
    dbPath = path.join(tmpDir, 'state.db');
    store = new SqliteGatewayStateStore(dbPath);
    await store.init();

    gatewayKeys = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    gatewayIdentity = new GatewayIdentityKeyManager({
      activeKeyId: 'gw-test-k1',
      signingKeys: {
        'gw-test-k1': {
          privateKeyPem: gatewayKeys.privateKey,
          publicKeyPem: gatewayKeys.publicKey,
        },
      },
    });

    const logger = new GatewayLogger({ gatewayId: 'gw_test', silent: true });
    const audit = new AuditRecorder(logger);
    metrics = new GatewayMetrics();
    mockClient = new LocalTestAamarvaBackendClient();
    outboxProcessor = new SessionSyncOutboxProcessor({
      store,
      aamarvaClient: mockClient,
      audit,
      metrics,
      maxAttempts: 3,
      baseRetryDelayMs: 50,
    });

    service = new RedemptionService({
      store: new RedemptionStore(store),
      gatewayId: 'gw_test',
      mcpServerId: 'mcp_test',
      tokenTtlSeconds: 120,
      sessionTtlSeconds: 600,
      gatewayIdentity,
      outboxProcessor,
      audit,
      metrics,
    });

    sessionManager = new GatewaySessionManager({
      store,
      gatewayId: 'gw_test',
      mcpServerId: 'mcp_test',
    });

    agentKeys = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
  });

  afterEach(async () => {
    outboxProcessor.stop();
    await store.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function makeAuthContext(overrides: Partial<AuthorizationContext> = {}): AuthorizationContext {
    const now = Date.now();
    return {
      authorizationId: 'auth_001',
      agentId: 'agent_alpha',
      agentName: 'Alpha Agent',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
      gatewayId: 'gw_test',
      scope: { allowedTools: ['inventory_lookup', 'calculate_quote'], floorApproved: true },
      aamarvaKeyId: 'key-1',
      issuedAtMs: now,
      expiresAtMs: now + 900_000,
      ...overrides,
    };
  }

  it('redeems a valid token once, returns gateway public key & signature, and blocks replay attempts', async () => {
    const issued = await service.issueAndEncryptToken({
      context: makeAuthContext(),
      agentPublicKeyPem: agentKeys.publicKey,
      correlationId: 'corr_1',
    });

    expect(issued.gatewayPublicKey.keyId).toBe('gw-test-k1');
    expect(issued.gatewayPublicKey.fingerprint).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(issued.gatewayPublicKey.publicKey).not.toBe(agentKeys.publicKey);
    expect(JSON.stringify(issued)).not.toContain(gatewayKeys.privateKey);
    expect(
      verifyGatewayResponseSignature({
        payload: {
          tokenId: issued.tokenId,
          expiresAt: issued.expiresAt,
          gatewayId: 'gw_test',
          mcpServerId: 'mcp_test',
          redemptionEndpoint: '/api/v1/redeem',
          encryptedToken: issued.encryptedToken,
          gatewayPublicKey: issued.gatewayPublicKey,
          correlationId: 'corr_1',
        },
        signatureBase64: issued.gatewaySignature.signature,
        gatewayPublicKey: issued.gatewayPublicKey,
      }),
    ).toBe(true);

    const decrypted = decryptTokenAsAgent(issued.encryptedToken, agentKeys.privateKey);

    const first = await service.redeemToken({
      token: decrypted.token,
      agentId: 'agent_alpha',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
      correlationId: 'corr_redeem_1',
    });
    expect(first.ok).toBe(true);
    if (first.ok) {
      expect(first.session.agentId).toBe('agent_alpha');
      expect(first.session.scope.allowedTools).toEqual(['inventory_lookup', 'calculate_quote']);
      expect(first.sessionSyncStatus).toBe('delivered');
      expect(mockClient.syncedSessions.size).toBe(1);
    }

    // Second redemption (replay) MUST fail with 409 TOKEN_ALREADY_REDEEMED
    const second = await service.redeemToken({
      token: decrypted.token,
      agentId: 'agent_alpha',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
    });
    expect(second.ok).toBe(false);
    if (!second.ok) {
      expect(second.code).toBe('TOKEN_ALREADY_REDEEMED');
      expect(second.statusCode).toBe(409);
    }
  });

  it('supports Gateway signing key rotation while preserving distinct keyId and fingerprint', async () => {
    const k2 = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const firstIssued = await service.issueAndEncryptToken({
      context: makeAuthContext({ authorizationId: 'auth_rot_1' }),
      agentPublicKeyPem: agentKeys.publicKey,
      correlationId: 'corr_rot_1',
    });
    expect(firstIssued.gatewayPublicKey.keyId).toBe('gw-test-k1');

    gatewayIdentity.rotateActiveKey('gw-test-k2', {
      privateKeyPem: k2.privateKey,
      publicKeyPem: k2.publicKey,
    });

    const secondIssued = await service.issueAndEncryptToken({
      context: makeAuthContext({ authorizationId: 'auth_rot_2' }),
      agentPublicKeyPem: agentKeys.publicKey,
      correlationId: 'corr_rot_2',
    });
    expect(secondIssued.gatewayPublicKey.keyId).toBe('gw-test-k2');
    expect(secondIssued.gatewayPublicKey.fingerprint).not.toBe(
      firstIssued.gatewayPublicKey.fingerprint,
    );
  });

  it('clamps token and session expiration strictly to authorization grant expiry and rejects <15s grants', async () => {
    const now = Date.now();
    // Grant with < 15s remaining must be rejected cleanly (never extended)
    await expect(
      service.issueAndEncryptToken({
        context: makeAuthContext({ expiresAtMs: now + 10_000 }),
        agentPublicKeyPem: agentKeys.publicKey,
        correlationId: 'corr_short_grant',
      }),
    ).rejects.toBeInstanceOf(InsufficientGrantValidityError);

    // Grant with 45s remaining: tokenTtlSeconds=120 & sessionTtlSeconds=600 MUST be clamped to <= 45s
    const authExpiry = now + 45_000;
    const issued = await service.issueAndEncryptToken({
      context: makeAuthContext({ expiresAtMs: authExpiry }),
      agentPublicKeyPem: agentKeys.publicKey,
      correlationId: 'corr_clamped',
    });
    expect(Date.parse(issued.expiresAt)).toBeLessThanOrEqual(authExpiry);

    const decrypted = decryptTokenAsAgent(issued.encryptedToken, agentKeys.privateKey);
    const redeemed = await service.redeemToken({
      token: decrypted.token,
      agentId: 'agent_alpha',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
    });
    expect(redeemed.ok).toBe(true);
    if (!redeemed.ok) return;

    expect(redeemed.session.authorizationExpiresAtMs).toBe(authExpiry);
    expect(redeemed.session.expiresAtMs).toBeLessThanOrEqual(authExpiry);

    // Validation after authorization grant expires MUST fail with AUTHORIZATION_EXPIRED
    const afterAuthExpiry = await sessionManager.validateActiveSession({
      sessionId: redeemed.session.sessionId,
      agentId: 'agent_alpha',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
      gatewayId: 'gw_test',
      nowMs: authExpiry + 1000,
    });
    expect(afterAuthExpiry.valid).toBe(false);
    expect(afterAuthExpiry.code).toBe('AUTHORIZATION_EXPIRED');
  });

  it('persists session sync outbox durably, retries transient failures idempotently, and recovers after restart', async () => {
    // 1. Transient outage on first attempt -> outbox remains pending_retry, then recovers on flush
    mockClient.setFailNextSessionSyncs(1);
    const issued1 = await service.issueAndEncryptToken({
      context: makeAuthContext({ authorizationId: 'auth_sync_1' }),
      agentPublicKeyPem: agentKeys.publicKey,
      correlationId: 'corr_sync_1',
    });
    const dec1 = decryptTokenAsAgent(issued1.encryptedToken, agentKeys.privateKey);
    const redeem1 = await service.redeemToken({
      token: dec1.token,
      agentId: 'agent_alpha',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
      correlationId: 'corr_sync_1',
    });
    expect(redeem1.ok).toBe(true);
    if (!redeem1.ok) return;
    expect(redeem1.sessionSyncStatus).toBe('pending_retry');

    const pendingOutbox = await store.getOutboxItemBySession(redeem1.session.sessionId);
    expect(pendingOutbox?.status).toBe('pending');
    expect(pendingOutbox?.attempts).toBe(1);

    // Simulate Gateway process restart: close current store, reopen SQLite DB, and flush outbox
    await store.close();
    store = new SqliteGatewayStateStore(dbPath);
    await store.init();
    const restartedLogger = new GatewayLogger({ gatewayId: 'gw_test', silent: true });
    const restartedProcessor = new SessionSyncOutboxProcessor({
      store,
      aamarvaClient: mockClient,
      audit: new AuditRecorder(restartedLogger),
      metrics,
      maxAttempts: 3,
      baseRetryDelayMs: 50,
    });

    const processed = await restartedProcessor.flushPending(Date.now() + 5000);
    expect(processed).toBe(1);
    const deliveredOutbox = await store.getOutboxItemBySession(redeem1.session.sessionId);
    expect(deliveredOutbox?.status).toBe('delivered');
    expect(mockClient.syncedSessions.has(`sess_sync:${redeem1.session.sessionId}`)).toBe(true);

    // Re-running flush must NOT duplicate delivered notifications
    const secondFlush = await restartedProcessor.flushPending(Date.now() + 10_000);
    expect(secondFlush).toBe(0);

    // 2. Permanent failure after maxAttempts marks outbox failed and increments metric
    mockClient.setAlwaysFailSessionSync(true);
    const restartedService = new RedemptionService({
      store: new RedemptionStore(store),
      gatewayId: 'gw_test',
      mcpServerId: 'mcp_test',
      tokenTtlSeconds: 120,
      sessionTtlSeconds: 600,
      gatewayIdentity,
      outboxProcessor: restartedProcessor,
      audit: new AuditRecorder(restartedLogger),
      metrics,
    });
    const issued2 = await restartedService.issueAndEncryptToken({
      context: makeAuthContext({ authorizationId: 'auth_sync_2' }),
      agentPublicKeyPem: agentKeys.publicKey,
      correlationId: 'corr_sync_2',
    });
    const dec2 = decryptTokenAsAgent(issued2.encryptedToken, agentKeys.privateKey);
    const redeem2 = await restartedService.redeemToken({
      token: dec2.token,
      agentId: 'agent_alpha',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
    });
    expect(redeem2.ok).toBe(true);
    if (!redeem2.ok) return;

    await restartedProcessor.flushPending(Date.now() + 5000);
    await restartedProcessor.flushPending(Date.now() + 15_000);
    const failedOutbox = await store.getOutboxItemBySession(redeem2.session.sessionId);
    expect(failedOutbox?.status).toBe('failed');
    expect(failedOutbox?.attempts).toBe(3);
    expect(metrics.snapshot().sessionSyncFailed).toBe(1);
  });

  it('guarantees atomic single-use under 10 simultaneous concurrent redemption attempts', async () => {
    const issued = await service.issueAndEncryptToken({
      context: makeAuthContext(),
      agentPublicKeyPem: agentKeys.publicKey,
      correlationId: 'corr_race',
    });
    const decrypted = decryptTokenAsAgent(issued.encryptedToken, agentKeys.privateKey);

    const attempts = await Promise.all(
      Array.from({ length: 10 }, () =>
        service.redeemToken({
          token: decrypted.token,
          agentId: 'agent_alpha',
          accountId: 'acct_100',
          mcpServerId: 'mcp_test',
        }),
      ),
    );

    const successes = attempts.filter((a) => a.ok);
    const failures = attempts.filter((a) => !a.ok);

    expect(successes).toHaveLength(1);
    expect(failures).toHaveLength(9);
  });

  it('rejects agent, account, and MCP server mismatches', async () => {
    const issued = await service.issueAndEncryptToken({
      context: makeAuthContext(),
      agentPublicKeyPem: agentKeys.publicKey,
      correlationId: 'corr_mismatch',
    });
    const decrypted = decryptTokenAsAgent(issued.encryptedToken, agentKeys.privateKey);

    const wrongAgent = await service.redeemToken({
      token: decrypted.token,
      agentId: 'agent_imposter',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
    });
    expect(wrongAgent.ok).toBe(false);
    if (!wrongAgent.ok) expect(wrongAgent.code).toBe('AGENT_MISMATCH');

    const wrongAccount = await service.redeemToken({
      token: decrypted.token,
      agentId: 'agent_alpha',
      accountId: 'acct_999',
      mcpServerId: 'mcp_test',
    });
    expect(wrongAccount.ok).toBe(false);
    if (!wrongAccount.ok) expect(wrongAccount.code).toBe('ACCOUNT_MISMATCH');

    const wrongServer = await service.redeemToken({
      token: decrypted.token,
      agentId: 'agent_alpha',
      accountId: 'acct_100',
      mcpServerId: 'mcp_other',
    });
    expect(wrongServer.ok).toBe(false);
    if (!wrongServer.ok) expect(wrongServer.code).toBe('SERVER_MISMATCH');
  });

  it('rejects expired tokens and enforces session expiration & revocation', async () => {
    const now = Date.now();
    const issued = await service.issueAndEncryptToken({
      context: makeAuthContext({ expiresAtMs: now + 1_200_000 }),
      agentPublicKeyPem: agentKeys.publicKey,
      correlationId: 'corr_exp',
    });
    const decrypted = decryptTokenAsAgent(issued.encryptedToken, agentKeys.privateKey);

    // Manually test redemption at a future timestamp beyond 120s token TTL
    const expRes = await store.redeemTokenAtomically({
      tokenHash: crypto.createHash('sha256').update(decrypted.token).digest('hex'),
      agentId: 'agent_alpha',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
      gatewayId: 'gw_test',
      sessionId: 'sess_expired_test',
      sessionExpiresAtMs: now + 600_000,
      correlationId: 'corr_exp_check',
      nowMs: now + 300_000,
    });
    expect(expRes.ok).toBe(false);
    if (!expRes.ok) expect(expRes.code).toBe('TOKEN_EXPIRED');

    // Redeem normally and test session expiry + revocation
    const redeemed = await service.redeemToken({
      token: decrypted.token,
      agentId: 'agent_alpha',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
    });
    expect(redeemed.ok).toBe(true);
    if (!redeemed.ok) return;

    const expiredSessionCheck = await sessionManager.validateActiveSession({
      sessionId: redeemed.session.sessionId,
      agentId: 'agent_alpha',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
      gatewayId: 'gw_test',
      nowMs: redeemed.session.expiresAtMs + 1000,
    });
    expect(expiredSessionCheck.valid).toBe(false);
    expect(expiredSessionCheck.code).toBe('SESSION_EXPIRED');

    await sessionManager.revokeSession(
      redeemed.session.sessionId,
      'AAMARVA permission revoked',
      'aamarva-core',
    );
    const revokedCheck = await sessionManager.validateActiveSession({
      sessionId: redeemed.session.sessionId,
      agentId: 'agent_alpha',
      accountId: 'acct_100',
      mcpServerId: 'mcp_test',
      gatewayId: 'gw_test',
    });
    expect(revokedCheck.valid).toBe(false);
    expect(revokedCheck.code).toBe('SESSION_REVOKED');
  });

  it('fails closed on insecure production configuration', () => {
    const { publicKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    expect(() =>
      validateGatewayConfig({
        nodeEnv: 'production',
        port: 3000,
        gatewayId: 'gw_prod',
        mcpServerId: 'mcp_prod',
        gatewayPublicUrl: 'https://gw.example.com',
        gatewayIdentity: {
          activeSigningKeyId: 'gw-k1',
          signingKeys: { 'gw-k1': { privateKeyPem: gatewayKeys.privateKey } },
        },
        aamarva: {
          baseUrl: 'https://api.aamarva.example.com',
          backendAuthSecret: 'strong-secret-over-16-chars',
          trustedSigningKeys: { k1: publicKey },
          maxClockSkewSeconds: 60,
          onlineRevocationCheck: false,
          allowOfflineRevocationInProd: false,
        },
        security: {
          tokenTtlSeconds: 120,
          sessionTtlSeconds: 900,
          requireTls: false,
          trustedProxies: [],
          allowInMemoryStore: true,
          maxRequestBodyBytes: 1048576,
          redeemRateLimitMax: 30,
          redeemRateLimitWindowMs: 60000,
          relayRateLimitMax: 300,
          relayRateLimitWindowMs: 60000,
        },
        storage: { driver: 'memory', sqliteDbPath: './data/test.db' },
        mcp: { transport: 'stdio', stdioCommand: 'node', stdioArgs: ['server.js'], requestTimeoutMs: 15000 },
        features: { enableOperatorConsole: false, enableSandbox: true },
      }),
    ).toThrow();
  });
});
