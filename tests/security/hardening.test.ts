import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import { afterEach, describe, expect, it } from 'vitest';
import { LocalTestAamarvaBackendClient } from '../../src/gateway/aamarva/aamarva-client.ts';
import { AamarvaAuthorizationAdapter } from '../../src/gateway/aamarva/authorization-adapter.ts';
import { AamarvaSignatureVerifier } from '../../src/gateway/aamarva/signature-verifier.ts';
import { loadGatewayConfig } from '../../src/gateway/config/environment.ts';
import { validateGatewayConfig } from '../../src/gateway/config/validation.ts';
import { AamarvaMcpGateway } from '../../src/gateway/core/gateway.ts';
import { GatewaySessionManager } from '../../src/gateway/core/gateway-session.ts';
import {
  GatewayIdentityKeyManager,
  verifyGatewayResponseSignature,
} from '../../src/gateway/crypto/gateway-keypair.ts';
import type { McpUpstreamAdapter } from '../../src/gateway/mcp/mcp-transport.ts';
import { createTlsEnforcementMiddleware } from '../../src/gateway/middleware/request-validation.ts';
import { AuditRecorder } from '../../src/gateway/observability/audit.ts';
import { GatewayLogger } from '../../src/gateway/observability/logger.ts';
import { GatewayMetrics } from '../../src/gateway/observability/metrics.ts';
import { SessionValidator } from '../../src/gateway/proxy/session-validator.ts';
import { createOperatorConsoleRouter } from '../../src/gateway/routes/console-routes.ts';
import { InMemoryGatewayStateStore } from '../../src/gateway/storage/adapters/memory-store.ts';
import { signPayloadAsMockAamarva } from '../fixtures/agent-decryption-harness.ts';

function invokeTlsMiddleware(params: {
  requireTls: boolean;
  trustedProxies: string[];
  remoteAddress?: string;
  socketEncrypted?: boolean;
  xForwardedProto?: string;
}) {
  const middleware = createTlsEnforcementMiddleware({
    requireTls: params.requireTls,
    trustedProxies: params.trustedProxies,
  });

  let statusCode = 200;
  let body: unknown = null;
  let nextCalled = false;

  const req = {
    socket: {
      remoteAddress: params.remoteAddress,
      encrypted: params.socketEncrypted ?? false,
    },
    header: (name: string) =>
      name.toLowerCase() === 'x-forwarded-proto' ? params.xForwardedProto : undefined,
  } as unknown as express.Request;

  const res = {
    status(code: number) {
      statusCode = code;
      return this;
    },
    json(payload: unknown) {
      body = payload;
      return this;
    },
  } as unknown as express.Response;

  middleware(req, res, () => {
    nextCalled = true;
  });

  return { nextCalled, statusCode, body };
}

describe('Security Hardening: TLS/Proxy, Console Auth, Gateway Identity & Revocation', () => {
  const cleanupDirs: string[] = [];

  afterEach(() => {
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop();
      if (dir) fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('enforces TLS strictly against direct TLS, trusted proxies, and spoofed X-Forwarded-Proto', () => {
    // 1. Direct TLS socket -> allowed even without X-Forwarded-Proto
    expect(
      invokeTlsMiddleware({
        requireTls: true,
        trustedProxies: [],
        remoteAddress: '203.0.113.10',
        socketEncrypted: true,
      }).nextCalled,
    ).toBe(true);

    // 2. Direct HTTP without TLS -> rejected 403
    const directHttp = invokeTlsMiddleware({
      requireTls: true,
      trustedProxies: ['10.0.0.5'],
      remoteAddress: '203.0.113.10',
      socketEncrypted: false,
    });
    expect(directHttp.nextCalled).toBe(false);
    expect(directHttp.statusCode).toBe(403);

    // 3. Spoofed X-Forwarded-Proto: https with empty trustedProxies -> rejected 403
    const spoofedEmpty = invokeTlsMiddleware({
      requireTls: true,
      trustedProxies: [],
      remoteAddress: '127.0.0.1',
      socketEncrypted: false,
      xForwardedProto: 'https',
    });
    expect(spoofedEmpty.nextCalled).toBe(false);
    expect(spoofedEmpty.statusCode).toBe(403);

    // 4. Request from trusted proxy IP with X-Forwarded-Proto: https -> accepted
    expect(
      invokeTlsMiddleware({
        requireTls: true,
        trustedProxies: ['10.0.0.5'],
        remoteAddress: '::ffff:10.0.0.5',
        socketEncrypted: false,
        xForwardedProto: 'https',
      }).nextCalled,
    ).toBe(true);

    // 5. Request from untrusted peer IP with X-Forwarded-Proto: https -> rejected 403
    const untrustedPeer = invokeTlsMiddleware({
      requireTls: true,
      trustedProxies: ['10.0.0.5'],
      remoteAddress: '198.51.100.44',
      socketEncrypted: false,
      xForwardedProto: 'https',
    });
    expect(untrustedPeer.nextCalled).toBe(false);
    expect(untrustedPeer.statusCode).toBe(403);
  });

  it('rejects live HTTP requests carrying spoofed X-Forwarded-Proto unless peer matches TRUSTED_PROXY_IPS', async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agw-tls-'));
    cleanupDirs.push(tmpDir);

    const aamarvaPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const gwPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const cfg = validateGatewayConfig({
      nodeEnv: 'test',
      port: 3000,
      gatewayId: 'gw_tls_test',
      mcpServerId: 'mcp_tls_test',
      gatewayPublicUrl: 'https://gw.example.com',
      gatewayIdentity: {
        activeSigningKeyId: 'gw-k1',
        signingKeys: { 'gw-k1': { privateKeyPem: gwPair.privateKey } },
      },
      aamarva: {
        baseUrl: 'https://api.aamarva.example.com',
        backendAuthSecret: 'secret-value-at-least-16-chars',
        trustedSigningKeys: { 'aa-k1': aamarvaPair.publicKey },
        maxClockSkewSeconds: 60,
        onlineRevocationCheck: false,
        allowOfflineRevocationInProd: false,
      },
      security: {
        tokenTtlSeconds: 120,
        sessionTtlSeconds: 600,
        requireTls: true,
        trustedProxies: [], // No trusted proxies configured
        allowInMemoryStore: true,
        maxRequestBodyBytes: 1_048_576,
        redeemRateLimitMax: 30,
        redeemRateLimitWindowMs: 60_000,
        relayRateLimitMax: 100,
        relayRateLimitWindowMs: 60_000,
      },
      storage: { driver: 'memory', sqliteDbPath: path.join(tmpDir, 'db.sqlite') },
      mcp: {
        transport: 'streamable-http',
        httpUrl: 'http://127.0.0.1:49999/mcp',
        requestTimeoutMs: 5000,
      },
      features: { enableOperatorConsole: false, enableSandbox: false },
    });

    const dummyMcp: McpUpstreamAdapter = {
      connect: async () => {},
      disconnect: async () => {},
      isConnected: () => true,
      getStatus: () => ({ connected: true, transport: 'stdio', activeRequests: 0 }),
      listTools: async () => [],
      callTool: async () => ({ content: [] }),
    };

    const gw = new AamarvaMcpGateway(cfg, {
      mcpAdapter: dummyMcp,
      aamarvaClient: new LocalTestAamarvaBackendClient(),
      silentLogger: true,
    });
    await gw.start({ connectMcpOnBoot: false });

    const app = gw.createStandaloneApp();
    expect(app.get('trust proxy')).toBe(false);

    const server = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const port = (server.address() as { port: number }).port;

    try {
      const resp = await fetch(`http://127.0.0.1:${port}/execute`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-forwarded-proto': 'https',
        },
        body: JSON.stringify({
          token: 'agw1.tok_fake.secret',
          agentId: 'a1',
          accountId: 'acct1',
          mcpServerId: 'mcp_tls_test',
        }),
      });
      expect(resp.status).toBe(403);
      const data = (await resp.json()) as { error: string };
      expect(data.error).toBe('TLS_REQUIRED');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await gw.stop();
    }
  });

  it('disables Operator Console by default in production and enforces Bearer auth when enabled', async () => {
    const aamarvaPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const gwPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const baseProdEnv: NodeJS.ProcessEnv = {
      NODE_ENV: 'production',
      GATEWAY_ID: 'gw_prod_01',
      MCP_SERVER_ID: 'mcp_prod_01',
      GATEWAY_PUBLIC_URL: 'https://gw.example.com',
      GATEWAY_ACTIVE_SIGNING_KEY_ID: 'gw-prod-k1',
      GATEWAY_SIGNING_KEYS_JSON: JSON.stringify({
        'gw-prod-k1': { privateKeyPem: gwPair.privateKey },
      }),
      AAMARVA_BASE_URL: 'https://api.aamarva.example.com',
      AAMARVA_BACKEND_AUTH_SECRET: 'prod-hmac-secret-at-least-32-chars!!',
      AAMARVA_TRUSTED_SIGNING_KEYS_JSON: JSON.stringify({ 'aa-prod-k1': aamarvaPair.publicKey }),
      MCP_TRANSPORT: 'stdio',
      MCP_STDIO_COMMAND: 'node',
    };

    // 1. Default production config: console disabled, sandbox disabled, online revocation enabled
    const prodCfg = loadGatewayConfig(baseProdEnv);
    expect(prodCfg.features.enableOperatorConsole).toBe(false);
    expect(prodCfg.features.enableSandbox).toBe(false);
    expect(prodCfg.aamarva.onlineRevocationCheck).toBe(true);

    // 2. Enabling operator console in production without OPERATOR_CONSOLE_AUTH_TOKEN MUST fail closed
    expect(() =>
      loadGatewayConfig({
        ...baseProdEnv,
        ENABLE_OPERATOR_CONSOLE: 'true',
      }),
    ).toThrow(/OPERATOR_CONSOLE_AUTH_TOKEN/);

    // 3. Disabling online revocation in production without override MUST fail closed
    expect(() =>
      loadGatewayConfig({
        ...baseProdEnv,
        AAMARVA_ONLINE_REVOCATION_CHECK: 'false',
      }),
    ).toThrow(/online revocation verification/i);

    // 4. With valid >=32-char operatorAuthToken, unauthenticated console requests return 401 and authorized succeed
    const operatorToken = 'op_prod_token_0123456789abcdef0123456789abcdef';
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agw-op-'));
    cleanupDirs.push(tmpDir);

    const enabledProdCfg = loadGatewayConfig({
      ...baseProdEnv,
      SQLITE_DB_PATH: path.join(tmpDir, 'op.db'),
      ENABLE_OPERATOR_CONSOLE: 'true',
      OPERATOR_CONSOLE_AUTH_TOKEN: operatorToken,
      AAMARVA_ONLINE_REVOCATION_CHECK: 'false',
      ALLOW_OFFLINE_REVOCATION_IN_PROD: 'true',
    });

    const dummyMcp: McpUpstreamAdapter = {
      connect: async () => {},
      disconnect: async () => {},
      isConnected: () => true,
      getStatus: () => ({ connected: true, transport: 'stdio', activeRequests: 0 }),
      listTools: async () => [],
      callTool: async () => ({ content: [] }),
    };

    const gw = new AamarvaMcpGateway(enabledProdCfg, {
      mcpAdapter: dummyMcp,
      aamarvaClient: new LocalTestAamarvaBackendClient(),
      silentLogger: true,
    });
    await gw.start({ connectMcpOnBoot: false });

    const app = express();
    app.use('/api/console', createOperatorConsoleRouter(gw));
    const server: http.Server = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const port = (server.address() as { port: number }).port;

    try {
      const unauth = await fetch(`http://127.0.0.1:${port}/api/console/status`);
      expect(unauth.status).toBe(401);

      const wrongAuth = await fetch(`http://127.0.0.1:${port}/api/console/status`, {
        headers: { authorization: 'Bearer wrong-token' },
      });
      expect(wrongAuth.status).toBe(401);

      const validAuth = await fetch(`http://127.0.0.1:${port}/api/console/status`, {
        headers: { authorization: `Bearer ${operatorToken}` },
      });
      expect(validAuth.status).toBe(200);
      const statusJson = (await validAuth.json()) as { gateway: { gatewayPublicKey: { keyId: string } } };
      expect(statusJson.gateway.gatewayPublicKey.keyId).toBe('gw-prod-k1');

      const auditEvents = gw.logger.getRecentEntries(20).map((e) => e.event);
      expect(auditEvents).toContain('OPERATOR_AUTH_FAILED');
      expect(auditEvents).toContain('OPERATOR_AUTH_SUCCEEDED');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await gw.stop();
    }
  });

  it('deduplicates revocations idempotently, supports account-level revocation, and fails closed on online check errors', async () => {
    const aamarvaPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const store = new InMemoryGatewayStateStore();
    await store.init();

    const now = Date.now();
    await store.saveIssuedToken({
      tokenId: 'tok_acct_1',
      tokenHash: 'hash_acct_1',
      authorizationId: 'auth_acct_1',
      agentId: 'agent_1',
      agentName: 'Agent 1',
      accountId: 'acct_shared',
      mcpServerId: 'mcp_1',
      gatewayId: 'gw_1',
      scope: { allowedTools: ['inventory_lookup'] },
      aamarvaKeyId: 'aa-k1',
      issuedAtMs: now,
      expiresAtMs: now + 60_000,
      authorizationExpiresAtMs: now + 300_000,
      redeemedAtMs: null,
      redeemedBySessionId: null,
      revokedAtMs: null,
    });
    const redeemed = await store.redeemTokenAtomically({
      tokenHash: 'hash_acct_1',
      agentId: 'agent_1',
      accountId: 'acct_shared',
      mcpServerId: 'mcp_1',
      gatewayId: 'gw_1',
      sessionId: 'sess_acct_1',
      sessionExpiresAtMs: now + 300_000,
      correlationId: 'corr_acct_1',
      nowMs: now,
    });
    expect(redeemed.ok).toBe(true);

    // Create a second active session in the same account to test account-level webhook revocation
    await store.saveIssuedToken({
      tokenId: 'tok_acct_2',
      tokenHash: 'hash_acct_2',
      authorizationId: 'auth_acct_2',
      agentId: 'agent_2',
      agentName: 'Agent 2',
      accountId: 'acct_shared',
      mcpServerId: 'mcp_1',
      gatewayId: 'gw_1',
      scope: { allowedTools: ['inventory_lookup'] },
      aamarvaKeyId: 'aa-k1',
      issuedAtMs: now,
      expiresAtMs: now + 60_000,
      authorizationExpiresAtMs: now + 300_000,
      redeemedAtMs: null,
      redeemedBySessionId: null,
      revokedAtMs: null,
    });
    const redeemed2 = await store.redeemTokenAtomically({
      tokenHash: 'hash_acct_2',
      agentId: 'agent_2',
      accountId: 'acct_shared',
      mcpServerId: 'mcp_1',
      gatewayId: 'gw_1',
      sessionId: 'sess_acct_2',
      sessionExpiresAtMs: now + 300_000,
      correlationId: 'corr_acct_2',
      nowMs: now,
    });
    expect(redeemed2.ok).toBe(true);

    const logger = new GatewayLogger({ gatewayId: 'gw_1', silent: true });
    const audit = new AuditRecorder(logger);
    const metrics = new GatewayMetrics();
    const verifier = new AamarvaSignatureVerifier({
      trustedSigningKeys: { 'aa-k1': aamarvaPair.publicKey },
      backendAuthSecret: 'secret-1234567890',
      maxClockSkewSeconds: 60,
    });
    const adapter = new AamarvaAuthorizationAdapter({
      verifier,
      store,
      gatewayId: 'gw_1',
      mcpServerId: 'mcp_1',
      audit,
      metrics,
    });

    // Online revocation fail-closed test revokes sess_acct_1 immediately
    const sessionManager = new GatewaySessionManager({
      store,
      gatewayId: 'gw_1',
      mcpServerId: 'mcp_1',
    });
    const failingBackendClient = new LocalTestAamarvaBackendClient();
    failingBackendClient.markRevoked('auth_acct_1');
    const validator = new SessionValidator({
      sessionManager,
      onlineRevocationCheck: true,
      aamarvaClient: failingBackendClient,
    });
    const onlineCheck = await validator.validate({
      sessionId: 'sess_acct_1',
      agentId: 'agent_1',
      accountId: 'acct_shared',
      mcpServerId: 'mcp_1',
      gatewayId: 'gw_1',
    });
    expect(onlineCheck.valid).toBe(false);
    expect(onlineCheck.code).toBe('SESSION_REVOKED');

    // Invalid revocation signature must be rejected 401 and must NOT consume revocationId
    const revClaims = {
      revocationId: 'rev_acct_001',
      accountId: 'acct_shared',
      reason: 'Account suspended',
      revokedBy: 'security-admin',
      revokedAt: new Date(now).toISOString(),
    };
    const badSigRes = await adapter.processRevocation(
      { claims: revClaims, keyId: 'aa-k1', signature: Buffer.alloc(64, 0xaa).toString('base64') },
      'corr_bad_rev',
    );
    expect(badSigRes.statusCode).toBe(401);

    // Valid account-level revocation succeeds & revokes session
    const validSig = signPayloadAsMockAamarva(revClaims, aamarvaPair.privateKey);
    const firstRev = await adapter.processRevocation(
      { claims: revClaims, keyId: 'aa-k1', signature: validSig },
      'corr_rev_1',
    );
    expect(firstRev.ok).toBe(true);
    expect(firstRev.revokedCount).toBe(1);
    expect(firstRev.duplicate).toBe(false);

    // Duplicate delivery of the same revocationId is idempotent (0 double-count)
    const dupRev = await adapter.processRevocation(
      { claims: revClaims, keyId: 'aa-k1', signature: validSig },
      'corr_rev_2',
    );
    expect(dupRev.ok).toBe(true);
    expect(dupRev.duplicate).toBe(true);
    expect(dupRev.revokedCount).toBe(0);
    expect(metrics.snapshot().sessionsRevoked).toBe(1);
  });

  it('detects tampered Gateway response payloads with verifyGatewayResponseSignature', () => {
    const gwPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const manager = new GatewayIdentityKeyManager({
      activeKeyId: 'gw-k1',
      signingKeys: { 'gw-k1': { privateKeyPem: gwPair.privateKey } },
    });
    const pubMeta = manager.getPublicKeyMetadata();
    const payload = { tokenId: 'tok_1', encryptedToken: { ciphertextBase64: 'abc' } };
    const sig = manager.signResponsePayload(payload);

    expect(
      verifyGatewayResponseSignature({
        payload,
        signatureBase64: sig.signature,
        gatewayPublicKey: pubMeta,
      }),
    ).toBe(true);

    expect(
      verifyGatewayResponseSignature({
        payload: { tokenId: 'tok_tampered', encryptedToken: { ciphertextBase64: 'abc' } },
        signatureBase64: sig.signature,
        gatewayPublicKey: pubMeta,
      }),
    ).toBe(false);
  });
});
