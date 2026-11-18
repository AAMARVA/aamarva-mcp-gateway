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
  const agentKeys = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const agentKeyFingerprint = `sha256:${crypto
    .createHash('sha256')
    .update(crypto.createPublicKey(agentKeys.publicKey).export({ type: 'spki', format: 'der' }))
    .digest('hex')}`;

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

  it('proves the complete 7-phase lifecycle and enforces strict three-endpoint boundaries', async () => {
    // 0. Non-allowlisted endpoints (including /, /healthz, /readyz) are rejected with 404
    for (const blockedGet of ['/', '/healthz', '/readyz', '/api/console/status']) {
      const r = await fetch(`${baseUrl}${blockedGet}`);
      expect(r.status).toBe(404);
    }

    // 1. Plaintext HTTP (without TLS) to /execute is rejected when REQUIRE_TLS=true
    const noTlsResp = await fetch(`${baseUrl}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: 'x', agentId: 'a', accountId: 'b', mcpServerId: 'c' }),
    });
    expect(noTlsResp.status).toBe(403);

    // 2. Architectural Boundary: No direct MCP, registration, messaging, or legacy public endpoints exist
    for (const forbiddenPath of [
      '/mcp',
      '/api/v1/redeem',
      '/api/v1/mcp/tools/call',
      '/api/v1/aamarva/mcp/tools/call',
      '/api/v1/aamarva/mcp/tools/list',
      '/api/v1/aamarva/authorizations/issue-token',
      '/api/v1/aamarva/authorizations/revoke',
      '/api/v1/aamarva/mcp/handshake',
      '/api/v1/agents/register',
      '/api/v1/agents/message',
      '/api/v1/floor/approve',
    ]) {
      const r = await httpJson(baseUrl, forbiddenPath, { body: {} });
      expect(r.status).toBe(404);
    }

    // Unsupported HTTP methods on the three allowed endpoints MUST be rejected (405)
    for (const ep of ['/handshake', '/issuetoken', '/execute']) {
      const getResp = await httpJson(baseUrl, ep, { method: 'GET' });
      expect(getResp.status).toBe(405);
      const putResp = await httpJson(baseUrl, ep, { method: 'PUT', body: {} });
      expect(putResp.status).toBe(405);
    }

    // 3. Architectural Boundary: Agent cannot call AAMARVA backend control endpoints directly without backend HMAC
    for (const controlPath of ['/handshake', '/issuetoken']) {
      const unauthCtrl = await httpJson(baseUrl, controlPath, {
        body: { claims: {}, keyId: 'k', signature: 's'.repeat(32) },
      });
      expect(unauthCtrl.status).toBe(401);
    }

    // Phase 0: Mandatory initial MCP verification handshake establishes verified connection & tool catalog
    const nowHs = Date.now();
    const hsClaims = {
      challenge: `chl_arch_${crypto.randomBytes(12).toString('hex')}`,
      accountId: 'acct_acme_01',
      integrationId: 'int_arch_erp',
      mcpServerId: 'mcp_arch_01',
      gatewayId: 'gw_arch_01',
      transport: 'stdio' as const,
      endpoint: 'stdio://mcp_arch_01',
      issuedAt: new Date(nowHs).toISOString(),
      expiresAt: new Date(nowHs + 120_000).toISOString(),
    };
    const hsBody = {
      claims: hsClaims,
      keyId: 'aamarva-k1',
      signature: signPayloadAsMockAamarva(hsClaims, aamarvaKeys.privateKey),
    };
    const hsRes = await httpJson(baseUrl, '/handshake', {
      headers: signedBackendHeaders('/handshake', hsBody),
      body: hsBody,
    });
    expect(hsRes.status).toBe(200);
    expect(hsRes.json.verified).toBe(true);
    const connectionId = (hsRes.json.attestation as { connectionId: string }).connectionId;

    // Phase 1-5: AAMARVA backend submits signed canonical /issuetoken request -> Gateway verifies, issues & encrypts token
    // and returns Gateway's own public key + response signature
    const now = Date.now();
    const authId = `auth_${crypto.randomBytes(4).toString('hex')}`;
    const claims = {
      authorizationId: authId,
      invocationId: authId,
      agentId: 'agent_procure_77',
      agentName: 'Procurement Agent 77',
      accountId: 'acct_acme_01',
      integrationId: 'int_arch_erp',
      connectionId,
      agentPublicKeyPem: agentKeys.publicKey,
      agentPublicKeyFingerprint: agentKeyFingerprint,
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
    const issueRes = await httpJson(baseUrl, '/issuetoken', {
      headers: signedBackendHeaders('/issuetoken', issueBody),
      body: issueBody,
    });
    expect(issueRes.status).toBe(201);
    const envelope = issueRes.json.encryptedToken as EncryptedTokenEnvelope;
    expect(envelope.algorithm).toBe('P256-HKDF-SHA256-AES-256-GCM');

    // Verify Gateway's own public key is present, distinct from agent key, and validly signs response
    const gwPubKey = issueRes.json.gatewayPublicKey as GatewayPublicKeyMetadata;
    const gwSig = issueRes.json.gatewaySignature as { keyId: string; algorithm: string; signature: string };
    expect(gwPubKey.keyId).toBe('gw-arch-key-1');
    expect(gwPubKey.purpose).toBe('gateway-response-signing');
    expect(gwPubKey.publicKey).not.toBe(agentKeys.publicKey);
    expect(JSON.stringify(issueRes.json)).not.toContain('PRIVATE KEY');

    const { gatewaySignature: _sig, ...unsignedPortion } = issueRes.json;
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
    const redeemRes = await httpJson(baseUrl, '/execute', {
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
    const replayRedeem = await httpJson(baseUrl, '/execute', {
      body: {
        token: decrypted.token,
        agentId: 'agent_procure_77',
        accountId: 'acct_acme_01',
        mcpServerId: 'mcp_arch_01',
      },
    });
    expect(replayRedeem.status).toBe(409);

    // Phase 7: Alternate public tool-list and tool-call endpoints are removed and return 404
    const list404 = await httpJson(baseUrl, '/api/v1/aamarva/mcp/tools/list', { body: {} });
    expect(list404.status).toBe(404);

    const call404 = await httpJson(baseUrl, '/api/v1/aamarva/mcp/tools/call', { body: {} });
    expect(call404.status).toBe(404);

    // Verify Gateway package.json does not depend on any agent ADK
    const pkg = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>;
    };
    const depNames = Object.keys(pkg.dependencies);
    expect(depNames.some((d) => d.toLowerCase().includes('aamarva-adk'))).toBe(false);
  });
});
