import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LocalTestAamarvaBackendClient } from '../../src/gateway/aamarva/aamarva-client.ts';
import { validateGatewayConfig } from '../../src/gateway/config/validation.ts';
import { AamarvaMcpGateway } from '../../src/gateway/core/gateway.ts';
import type { EncryptedTokenEnvelope } from '../../src/gateway/crypto/envelope-encryption.ts';
import type { GatewayPublicKeyMetadata } from '../../src/gateway/crypto/gateway-keypair.ts';
import { verifyGatewayResponseSignature } from '../../src/gateway/crypto/gateway-keypair.ts';
import {
  decryptTokenAsAgent,
  signPayloadAsMockAamarva,
} from '../fixtures/agent-decryption-harness.ts';

async function httpJson(
  baseUrl: string,
  reqPath: string,
  options: { method?: string; headers?: Record<string, string>; body?: unknown } = {},
) {
  const rawBody = options.body !== undefined ? JSON.stringify(options.body) : undefined;
  const resp = await fetch(`${baseUrl}${reqPath}`, {
    method: options.method ?? 'POST',
    headers: {
      'content-type': 'application/json',
      'x-forwarded-proto': 'https',
      ...(options.headers ?? {}),
    },
    body: rawBody,
  });
  let json: Record<string, unknown> = {};
  try {
    json = (await resp.json()) as Record<string, unknown>;
  } catch {
    // non-json 404
  }
  return { status: resp.status, json };
}

describe('Architectural & End-to-End Lifecycle Verification', () => {
  let tmpDir: string;
  let gateway: AamarvaMcpGateway;
  let server: http.Server;
  let baseUrl: string;
  let mockAamarvaClient: LocalTestAamarvaBackendClient;

  const backendSecret = 'aamarva-backend-hmac-secret-test-123456';
  const aamarvaKeys = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const gatewayKeys = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const agentKeys = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agw-e2e-'));
    mockAamarvaClient = new LocalTestAamarvaBackendClient();

    const cfg = validateGatewayConfig({
      nodeEnv: 'test',
      port: 3000,
      gatewayId: 'gw_arch_01',
      mcpServerId: 'mcp_arch_01',
      gatewayPublicUrl: 'https://gw.example.com',
      gatewayIdentity: {
        activeSigningKeyId: 'gw-arch-key-1',
        signingKeys: {
          'gw-arch-key-1': {
            privateKeyPem: gatewayKeys.privateKey,
            publicKeyPem: gatewayKeys.publicKey,
          },
        },
      },
      aamarva: {
        baseUrl: 'https://api.aamarva.example.com',
        backendAuthSecret: backendSecret,
        trustedSigningKeys: { 'aamarva-k1': aamarvaKeys.publicKey },
        maxClockSkewSeconds: 60,
        onlineRevocationCheck: true,
        allowOfflineRevocationInProd: false,
      },
      security: {
        tokenTtlSeconds: 120,
        sessionTtlSeconds: 600,
        requireTls: true,
        trustedProxies: ['127.0.0.1'],
        allowInMemoryStore: false,
        maxRequestBodyBytes: 1_048_576,
        redeemRateLimitMax: 100,
        redeemRateLimitWindowMs: 60_000,
        relayRateLimitMax: 500,
        relayRateLimitWindowMs: 60_000,
      },
      storage: {
        driver: 'sqlite',
        sqliteDbPath: path.join(tmpDir, 'arch.db'),
      },
      mcp: {
        transport: 'stdio',
        stdioCommand: 'node',
        stdioArgs: [path.resolve(process.cwd(), 'examples/sample-mcp-stdio.ts')],
        requestTimeoutMs: 10_000,
      },
      features: {
        enableOperatorConsole: false,
        enableSandbox: false,
      },
    });

    gateway = new AamarvaMcpGateway(cfg, {
      aamarvaClient: mockAamarvaClient,
      silentLogger: true,
    });
    await gateway.start();

    const app = gateway.createStandaloneApp();
    server = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve) => server.once('listening', resolve));
    const addr = server.address();
    const port = typeof addr === 'object' && addr ? addr.port : 3000;
    baseUrl = `http://127.0.0.1:${port}`;
  }, 20_000);

  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    if (gateway) {
      await gateway.stop();
    }
    if (tmpDir) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  function signedBackendHeaders(reqPath: string, bodyObj: unknown) {
    const rawBody = JSON.stringify(bodyObj);
    const timestamp = String(Date.now());
    const requestId = `req_${crypto.randomBytes(8).toString('hex')}`;
    const hmac = gateway.signatureVerifier.computeBackendRequestHmac({
      method: 'POST',
      path: reqPath,
      timestamp,
      requestId,
      rawBody,
    });
    return {
      'x-aamarva-gateway-id': 'gw_arch_01',
      'x-aamarva-timestamp': timestamp,
      'x-aamarva-request-id': requestId,
      'x-aamarva-hmac-sha256': hmac,
    };
  }

  it('proves the complete 7-phase lifecycle and enforces strict two-path boundaries', async () => {
    // 0. Health endpoints expose no secrets
    const health = await fetch(`${baseUrl}/healthz`).then((r) => r.json() as Promise<Record<string, unknown>>);
    expect(health.status).toBe('ok');
    expect(JSON.stringify(health)).not.toContain(backendSecret);
    expect(JSON.stringify(health)).not.toContain('PRIVATE KEY');

    // 1. Plaintext HTTP (without TLS) to /api/v1/redeem is rejected when REQUIRE_TLS=true
    const noTlsResp = await fetch(`${baseUrl}/api/v1/redeem`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: 'x', agentId: 'a', accountId: 'b', mcpServerId: 'c' }),
    });
    expect(noTlsResp.status).toBe(403);

    // 2. Architectural Boundary: No direct MCP, registration, messaging, or FLOOR endpoints exist for agents
    for (const forbiddenPath of [
      '/mcp',
      '/api/v1/mcp/tools/call',
      '/api/v1/agents/register',
      '/api/v1/agents/message',
      '/api/v1/floor/approve',
    ]) {
      const r = await httpJson(baseUrl, forbiddenPath, { body: {} });
      expect(r.status).toBe(404);
    }

    // 3. Architectural Boundary: Agent cannot call AAMARVA backend relay directly without backend HMAC
    const unauthRelay = await httpJson(baseUrl, '/api/v1/aamarva/mcp/tools/call', {
      body: {
        requestId: 'req_forged_1',
        sessionId: 'sess_123456',
        agentId: 'agent_1',
        accountId: 'acct_1',
        mcpServerId: 'mcp_arch_01',
        gatewayId: 'gw_arch_01',
        toolName: 'inventory_lookup',
        arguments: {},
        timestamp: new Date().toISOString(),
      },
    });
    expect(unauthRelay.status).toBe(401);

    // Phase 1-5: AAMARVA backend submits signed authorization grant -> Gateway verifies, issues & encrypts token
    // and returns Gateway's own public key + response signature
    const now = Date.now();
    const authId = `auth_${crypto.randomBytes(4).toString('hex')}`;
    const claims = {
      authorizationId: authId,
      agentId: 'agent_procure_77',
      agentName: 'Procurement Agent 77',
      accountId: 'acct_acme_01',
      agentPublicKeyPem: agentKeys.publicKey,
      mcpServerId: 'mcp_arch_01',
      gatewayId: 'gw_arch_01',
      allowedTools: ['inventory_lookup', 'calculate_quote'],
      floorApproved: true,
      floorApprovalId: 'floor_901',
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 300_000).toISOString(),
    };
    const grantSig = signPayloadAsMockAamarva(claims, aamarvaKeys.privateKey);
    const issueBody = { claims, keyId: 'aamarva-k1', signature: grantSig };
    const issueRes = await httpJson(baseUrl, '/api/v1/aamarva/authorizations/issue-token', {
      headers: signedBackendHeaders('/api/v1/aamarva/authorizations/issue-token', issueBody),
      body: issueBody,
    });
    expect(issueRes.status).toBe(201);
    const envelope = issueRes.json.encryptedToken as EncryptedTokenEnvelope;
    expect(envelope.algorithm).toBe('X25519-HKDF-SHA256-AES-256-GCM');

    // Verify Gateway's own public key is present, distinct from agent key, and validly signs response
    const gwPubKey = issueRes.json.gatewayPublicKey as GatewayPublicKeyMetadata;
    const gwSig = issueRes.json.gatewaySignature as { keyId: string; algorithm: string; signature: string };
    expect(gwPubKey.keyId).toBe('gw-arch-key-1');
    expect(gwPubKey.purpose).toBe('gateway-response-signing');
    expect(gwPubKey.publicKey).not.toBe(agentKeys.publicKey);
    expect(JSON.stringify(issueRes.json)).not.toContain('PRIVATE KEY');

    const unsignedPortion = {
      tokenId: issueRes.json.tokenId,
      expiresAt: issueRes.json.expiresAt,
      gatewayId: issueRes.json.gatewayId,
      mcpServerId: issueRes.json.mcpServerId,
      redemptionEndpoint: issueRes.json.redemptionEndpoint,
      encryptedToken: issueRes.json.encryptedToken,
      gatewayPublicKey: issueRes.json.gatewayPublicKey,
      correlationId: issueRes.json.correlationId,
    };
    expect(
      verifyGatewayResponseSignature({
        payload: unsignedPortion,
        signatureBase64: gwSig.signature,
        gatewayPublicKey: gwPubKey,
      }),
    ).toBe(true);

    // Phase 5: Agent decrypts token locally using its private key (Gateway never does this)
    const decrypted = decryptTokenAsAgent(envelope, agentKeys.privateKey);

    // Phase 6: Agent contacts Gateway ONCE to redeem decrypted token -> Gateway syncs session to AAMARVA
    const redeemRes = await httpJson(baseUrl, '/api/v1/redeem', {
      body: {
        token: decrypted.token,
        agentId: 'agent_procure_77',
        accountId: 'acct_acme_01',
        mcpServerId: 'mcp_arch_01',
      },
    });
    expect(redeemRes.status).toBe(200);
    expect(redeemRes.json.redeemed).toBe(true);
    expect(redeemRes.json.sessionSyncStatus).toBe('delivered');
    const sessionId = redeemRes.json.sessionId as string;
    expect(sessionId.startsWith('sess_')).toBe(true);
    expect(mockAamarvaClient.syncedSessions.get(`sess_sync:${sessionId}`)).toMatchObject({
      sessionId,
      authorizationId: authId,
      agentId: 'agent_procure_77',
      accountId: 'acct_acme_01',
      gatewayId: 'gw_arch_01',
      mcpServerId: 'mcp_arch_01',
    });

    // Token replay MUST fail
    const replayRedeem = await httpJson(baseUrl, '/api/v1/redeem', {
      body: {
        token: decrypted.token,
        agentId: 'agent_procure_77',
        accountId: 'acct_acme_01',
        mcpServerId: 'mcp_arch_01',
      },
    });
    expect(replayRedeem.status).toBe(409);

    // Phase 7: Subsequent MCP tools/list & tools/call routed ONLY through authenticated AAMARVA backend
    const listBody = {
      requestId: `req_${crypto.randomBytes(6).toString('hex')}`,
      sessionId,
      agentId: 'agent_procure_77',
      accountId: 'acct_acme_01',
      mcpServerId: 'mcp_arch_01',
      gatewayId: 'gw_arch_01',
      timestamp: new Date().toISOString(),
    };
    const listRes = await httpJson(baseUrl, '/api/v1/aamarva/mcp/tools/list', {
      headers: signedBackendHeaders('/api/v1/aamarva/mcp/tools/list', listBody),
      body: listBody,
    });
    expect(listRes.status).toBe(200);
    expect((listRes.json.tools as Array<{ name: string }>).map((t) => t.name)).toEqual([
      'inventory_lookup',
      'calculate_quote',
    ]);

    const callBody = {
      requestId: `req_${crypto.randomBytes(6).toString('hex')}`,
      sessionId,
      agentId: 'agent_procure_77',
      accountId: 'acct_acme_01',
      mcpServerId: 'mcp_arch_01',
      gatewayId: 'gw_arch_01',
      toolName: 'inventory_lookup',
      arguments: { sku: 'SKU-SENSOR-X2' },
      timestamp: new Date().toISOString(),
    };
    const callRes = await httpJson(baseUrl, '/api/v1/aamarva/mcp/tools/call', {
      headers: signedBackendHeaders('/api/v1/aamarva/mcp/tools/call', callBody),
      body: callBody,
    });
    expect(callRes.status).toBe(200);
    const callResult = callRes.json.result as { content: Array<{ text: string }> };
    expect(JSON.parse(callResult.content[0].text)).toMatchObject({
      found: true,
      sku: 'SKU-SENSOR-X2',
      stock: 128,
    });

    // Cross-agent session hijack attempt through relay MUST fail
    const hijackBody = {
      ...callBody,
      requestId: `req_${crypto.randomBytes(6).toString('hex')}`,
      agentId: 'agent_hijacker_99',
    };
    const hijackRes = await httpJson(baseUrl, '/api/v1/aamarva/mcp/tools/call', {
      headers: signedBackendHeaders('/api/v1/aamarva/mcp/tools/call', hijackBody),
      body: hijackBody,
    });
    expect(hijackRes.status).toBe(403);
    expect(hijackRes.json.error).toBe('AGENT_MISMATCH');

    // Online revocation in AAMARVA Core immediately blocks subsequent execution (fail-closed)
    mockAamarvaClient.markRevoked(authId);
    const postRevokeBody = {
      ...callBody,
      requestId: `req_${crypto.randomBytes(6).toString('hex')}`,
    };
    const postRevokeRes = await httpJson(baseUrl, '/api/v1/aamarva/mcp/tools/call', {
      headers: signedBackendHeaders('/api/v1/aamarva/mcp/tools/call', postRevokeBody),
      body: postRevokeBody,
    });
    expect(postRevokeRes.status).toBe(401);
    expect(postRevokeRes.json.error).toBe('SESSION_REVOKED');

    // Verify Gateway package.json does not depend on any agent ADK
    const pkg = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>;
    };
    const depNames = Object.keys(pkg.dependencies);
    expect(depNames.some((d) => d.toLowerCase().includes('aamarva-adk'))).toBe(false);
  });
});
