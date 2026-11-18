import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import express from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LocalTestAamarvaBackendClient } from '../../src/gateway/aamarva/aamarva-client.ts';
import { loadGatewayConfig } from '../../src/gateway/config/environment.ts';
import {
  resolveConfiguredSubjectMcpTarget,
  resolveGatewayReachableBaseUrl,
} from '../../src/gateway/config/gateway-url.ts';
import { sha256Hex } from '../../src/gateway/config/security.ts';
import { validateGatewayConfig, type GatewayConfig } from '../../src/gateway/config/validation.ts';
import type { GatewayVerificationAttestation } from '../../src/gateway/core/authorization-context.ts';
import { AamarvaMcpGateway } from '../../src/gateway/core/gateway.ts';
import { encryptHandshakeCredentialEnvelope } from '../../src/gateway/crypto/credential-vault.ts';
import type { EncryptedTokenEnvelope } from '../../src/gateway/crypto/envelope-encryption.ts';
import {
  verifyGatewayAttestation,
  verifyGatewayResponseSignature,
  type GatewayPublicKeyMetadata,
} from '../../src/gateway/crypto/gateway-keypair.ts';
import {
  decryptTokenAsAgent,
  signPayloadAsMockAamarva,
} from '../fixtures/agent-decryption-harness.ts';

async function startCustomerSubjectMcpServer(options: {
  serverName: string;
  requiredAuthHeader?: string;
  failToolsList?: boolean;
  failInitialize?: boolean;
}): Promise<{ url: string; close: () => Promise<void> }> {
  const app = express();
  app.use(express.json());

  app.post('/mcp', async (req, res) => {
    if (options.failInitialize) {
      res.status(503).json({ error: 'Upstream MCP server unavailable during initialize' });
      return;
    }

    if (options.requiredAuthHeader) {
      const auth = req.header('authorization');
      if (auth !== options.requiredAuthHeader) {
        res.status(401).json({ error: 'Unauthorized Subject MCP Server call' });
        return;
      }
    }

    const server = new Server(
      { name: options.serverName, version: '3.1.0' },
      { capabilities: { tools: {} } },
    );

    server.setRequestHandler(ListToolsRequestSchema, async () => {
      if (options.failToolsList) {
        throw new Error('Simulated tools/list discovery failure');
      }
      return {
        tools: [
          {
            name: 'subject_echo',
            description: 'Echoes text from the customer Subject MCP Server',
            inputSchema: {
              type: 'object',
              properties: { text: { type: 'string' } },
              required: ['text'],
            },
          },
          {
            name: 'subject_status',
            description: 'Returns Subject MCP Server operational summary',
            inputSchema: { type: 'object', properties: {} },
          },
          {
            name: 'subject_admin_reset',
            description: 'Privileged tool never granted to normal agents',
            inputSchema: { type: 'object', properties: {} },
          },
        ],
      };
    });

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      if (request.params.name === 'subject_echo') {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                echo: String(request.params.arguments?.text ?? ''),
                server: options.serverName,
              }),
            },
          ],
        };
      }
      if (request.params.name === 'subject_status') {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ ok: true, server: options.serverName }),
            },
          ],
        };
      }
      return {
        isError: true,
        content: [{ type: 'text', text: `Unknown tool ${request.params.name}` }],
      };
    });

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  const httpServer = http.createServer(app);
  await new Promise<void>((resolve) => {
    httpServer.listen(0, '127.0.0.1', () => resolve());
  });
  const addr = httpServer.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}

function generateP256KeyPair() {
  const pair = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const der = crypto.createPublicKey(pair.publicKey).export({ type: 'spki', format: 'der' }) as Buffer;
  const fingerprint = `sha256:${sha256Hex(der)}`;
  return { ...pair, fingerprint };
}

describe('AAMARVA Three Integration Endpoints (/handshake, /issuetoken, /execute) & Configured Subject MCP Server URL', () => {
  let tmpDir: string;
  let sqlitePath: string;
  let subjectServer: { url: string; close: () => Promise<void> };
  let failInitServer: { url: string; close: () => Promise<void> };
  let failToolsServer: { url: string; close: () => Promise<void> };
  let gateway: AamarvaMcpGateway;
  let gatewayServer: http.Server;
  let gatewayBaseUrl: string;
  let aamarvaClient: LocalTestAamarvaBackendClient;
  let config: GatewayConfig;

  const aamarvaPair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const gatewaySigningPair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const backendAuthSecret = 'super-secret-aamarva-three-endpoints-hmac-key-01';
  const subjectMcpAuthToken = 'Bearer customer-subject-mcp-secret-9988';

  function signBackendHeaders(endpointPath: string, bodyObj: unknown) {
    const rawBody = JSON.stringify(bodyObj);
    const timestamp = String(Date.now());
    const requestId = `req_${crypto.randomBytes(8).toString('hex')}`;
    const hmac = gateway.signatureVerifier.computeBackendRequestHmac({
      method: 'POST',
      path: endpointPath,
      timestamp,
      requestId,
      rawBody,
    });
    return {
      rawBody,
      headers: {
        'content-type': 'application/json',
        'x-aamarva-gateway-id': config.gatewayId,
        'x-aamarva-timestamp': timestamp,
        'x-aamarva-request-id': requestId,
        'x-aamarva-hmac-sha256': hmac,
      },
    };
  }

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aamarva-3ep-'));
    sqlitePath = path.join(tmpDir, 'gateway.db');

    subjectServer = await startCustomerSubjectMcpServer({
      serverName: 'customer-subject-mcp',
      requiredAuthHeader: subjectMcpAuthToken,
    });
    failInitServer = await startCustomerSubjectMcpServer({
      serverName: 'fail-init-mcp',
      failInitialize: true,
    });
    failToolsServer = await startCustomerSubjectMcpServer({
      serverName: 'fail-tools-mcp',
      failToolsList: true,
    });

    // Intentionally leave gatewayPublicUrl undefined to verify NO invented localhost/example URL!
    config = validateGatewayConfig({
      nodeEnv: 'test',
      port: 3000,
      gatewayId: 'gw_three_endpoints_01',
      mcpServerId: 'mcp_subject_srv_01',
      gatewayPublicUrl: undefined,
      gatewayIdentity: {
        activeSigningKeyId: 'gw-ed25519-key-1',
        signingKeys: {
          'gw-ed25519-key-1': {
            privateKeyPem: gatewaySigningPair.privateKey,
            publicKeyPem: gatewaySigningPair.publicKey,
          },
        },
      },
      aamarva: {
        baseUrl: 'https://api.aamarva.test.internal',
        backendAuthSecret,
        trustedSigningKeys: {
          'aamarva-core-key-1': aamarvaPair.publicKey,
        },
        maxClockSkewSeconds: 60,
        onlineRevocationCheck: true,
        allowOfflineRevocationInProd: false,
      },
      security: {
        tokenTtlSeconds: 120,
        sessionTtlSeconds: 600,
        requireTls: false,
        allowLoopbackHttp: true,
        trustedProxies: ['127.0.0.1'],
        allowInMemoryStore: false,
        maxRequestBodyBytes: 1_048_576,
        redeemRateLimitMax: 500,
        redeemRateLimitWindowMs: 60_000,
        relayRateLimitMax: 500,
        relayRateLimitWindowMs: 60_000,
      },
      storage: {
        driver: 'sqlite',
        sqliteDbPath: sqlitePath,
      },
      mcp: {
        transport: 'streamable-http',
        httpUrl: subjectServer.url,
        upstreamAuthHeader: subjectMcpAuthToken,
        stdioCommand: 'node',
        stdioArgs: [],
        requestTimeoutMs: 5000,
      },
      features: {
        enableOperatorConsole: false,
        enableSandbox: false,
      },
    });

    aamarvaClient = new LocalTestAamarvaBackendClient();
    gateway = new AamarvaMcpGateway(config, {
      aamarvaClient,
      silentLogger: true,
    });
    await gateway.start({ connectMcpOnBoot: false });

    const app = gateway.createStandaloneApp();
    gatewayServer = http.createServer(app);
    await new Promise<void>((resolve) => {
      gatewayServer.listen(0, '127.0.0.1', () => resolve());
    });
    const addr = gatewayServer.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    gatewayBaseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    if (gatewayServer) {
      await new Promise<void>((resolve) => gatewayServer.close(() => resolve()));
    }
    if (gateway) await gateway.stop();
    if (subjectServer) await subjectServer.close();
    if (failInitServer) await failInitServer.close();
    if (failToolsServer) await failToolsServer.close();
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('1. Never invents Gateway URL and separates Gateway URL from Subject MCP Server URL', () => {
    const loadedUnconfigured = loadGatewayConfig({
      NODE_ENV: 'test',
      MCP_TRANSPORT: 'streamable-http',
      MCP_HTTP_URL: 'https://subject-mcp.customer.example/mcp',
    });
    expect(loadedUnconfigured.gatewayPublicUrl).toBeUndefined();
    expect(loadedUnconfigured.mcp.httpUrl).toBe('https://subject-mcp.customer.example/mcp');

    const unresolved = resolveGatewayReachableBaseUrl(loadedUnconfigured);
    expect(unresolved.baseUrl).toBeNull();
    expect(unresolved.source).toBe('unconfigured');
    expect(unresolved.warning).toContain('GATEWAY_PUBLIC_URL');

    const subjectTarget = resolveConfiguredSubjectMcpTarget(loadedUnconfigured);
    expect(subjectTarget).toEqual({
      transport: 'streamable-http',
      endpoint: 'https://subject-mcp.customer.example/mcp',
      configuredFromSubjectUrl: true,
    });

    const configuredGw = loadGatewayConfig({
      NODE_ENV: 'test',
      GATEWAY_PUBLIC_URL: 'https://gateway.customer-edge.example/',
      MCP_TRANSPORT: 'streamable-http',
      MCP_HTTP_URL: 'https://subject-mcp.customer.example/mcp',
    });
    const resolvedGw = resolveGatewayReachableBaseUrl(configuredGw);
    expect(resolvedGw).toEqual({
      baseUrl: 'https://gateway.customer-edge.example',
      source: 'config',
    });
    // Subject MCP URL and Gateway URL stay strictly independent
    expect(resolvedGw.baseUrl).not.toBe(configuredGw.mcp.httpUrl);
  });

  it('2. POST /handshake verifies AAMARVA signature, uses configured Subject MCP Server URL when endpoint omitted, discovers tools, and issues signed attestation', async () => {
    const now = Date.now();
    const challenge = `ch_subject_${crypto.randomBytes(8).toString('hex')}`;
    const nonce = `nonce_${crypto.randomBytes(8).toString('hex')}`;
    const claims = {
      challenge,
      nonce,
      gatewayId: config.gatewayId,
      accountId: 'acc_cust_01',
      integrationId: 'int_subject_01',
      // Intentionally omit transport, endpoint, and mcpServerId so Gateway uses customer's configured Subject MCP Server!
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 120_000).toISOString(),
    };
    const body = {
      keyId: 'aamarva-core-key-1',
      claims,
      signature: signPayloadAsMockAamarva(claims, aamarvaPair.privateKey),
    };
    const signed = signBackendHeaders('/handshake', body);

    const resp = await fetch(`${gatewayBaseUrl}/handshake`, {
      method: 'POST',
      headers: signed.headers,
      body: signed.rawBody,
    });

    expect(resp.status).toBe(200);
    const json = (await resp.json()) as {
      verified: boolean;
      gatewayKeyId: string;
      gatewayPublicKeyFingerprint: string;
      attestation: GatewayVerificationAttestation;
      gatewayPublicKey: GatewayPublicKeyMetadata;
      gatewaySignature: string;
      tools: Array<{ name: string }>;
    };

    expect(json.verified).toBe(true);
    expect(json.gatewayKeyId).toBe(json.gatewayPublicKey.keyId);
    expect(json.gatewayPublicKeyFingerprint).toBe(json.gatewayPublicKey.fingerprint);
    expect(json.attestation.canonicalEndpoint).toBe(subjectServer.url);
    expect(json.attestation.mcpServerId).toBe(config.mcpServerId);
    expect(json.tools.map((t) => t.name).sort()).toEqual([
      'subject_admin_reset',
      'subject_echo',
      'subject_status',
    ]);

    const attVerify = verifyGatewayAttestation({
      attestation: json.attestation,
      signatureBase64: json.gatewaySignature,
      trustedGatewayKeys: {
        [gateway.gatewayIdentity.getActiveKeyId()]: gateway.gatewayIdentity.getPublicKeyMetadata(),
      },
      expectedChallenge: challenge,
      expectedAccountId: 'acc_cust_01',
      expectedIntegrationId: 'int_subject_01',
      expectedGatewayId: config.gatewayId,
      expectedCanonicalEndpoint: subjectServer.url,
    });
    expect(attVerify.valid).toBe(true);

    // Replay of exact nonce/challenge with fresh HTTP requestId must be rejected cleanly with 409
    const replayClaims = {
      ...claims,
      issuedAt: new Date(now + 1000).toISOString(),
    };
    const replayBody = {
      keyId: 'aamarva-core-key-1',
      claims: replayClaims,
      signature: signPayloadAsMockAamarva(replayClaims, aamarvaPair.privateKey),
    };
    const replayHdr = signBackendHeaders('/handshake', replayBody);
    const replayResp = await fetch(`${gatewayBaseUrl}/handshake`, {
      method: 'POST',
      headers: replayHdr.headers,
      body: replayHdr.rawBody,
    });
    expect(replayResp.status).toBe(409);
  });

  it('3. POST /handshake enforces endpoint match against configured Subject MCP URL, SSRF protections, signatures, expiry, and upstream failures', async () => {
    const now = Date.now();

    // Missing backend HMAC headers -> 401
    const noAuth = await fetch(`${gatewayBaseUrl}/handshake`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(noAuth.status).toBe(401);

    // Invalid body signature -> 401
    const badSigClaims = {
      challenge: `ch_${crypto.randomBytes(8).toString('hex')}`,
      gatewayId: config.gatewayId,
      accountId: 'acc_cust_01',
      integrationId: 'int_subject_01',
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
    };
    const badSigBody = {
      keyId: 'aamarva-core-key-1',
      claims: badSigClaims,
      signature: crypto.randomBytes(64).toString('base64'),
    };
    const badSigHdr = signBackendHeaders('/handshake', badSigBody);
    const badSigResp = await fetch(`${gatewayBaseUrl}/handshake`, {
      method: 'POST',
      headers: badSigHdr.headers,
      body: badSigHdr.rawBody,
    });
    expect(badSigResp.status).toBe(401);

    // Expired challenge -> 401
    const expiredClaims = {
      challenge: `ch_${crypto.randomBytes(8).toString('hex')}`,
      gatewayId: config.gatewayId,
      accountId: 'acc_cust_01',
      integrationId: 'int_subject_01',
      issuedAt: new Date(now - 300_000).toISOString(),
      expiresAt: new Date(now - 10_000).toISOString(),
    };
    const expiredBody = {
      keyId: 'aamarva-core-key-1',
      claims: expiredClaims,
      signature: signPayloadAsMockAamarva(expiredClaims, aamarvaPair.privateKey),
    };
    const expiredHdr = signBackendHeaders('/handshake', expiredBody);
    const expiredResp = await fetch(`${gatewayBaseUrl}/handshake`, {
      method: 'POST',
      headers: expiredHdr.headers,
      body: expiredHdr.rawBody,
    });
    expect(expiredResp.status).toBe(401);

    // Wrong Gateway ID -> 403
    const wrongGwClaims = {
      challenge: `ch_${crypto.randomBytes(8).toString('hex')}`,
      gatewayId: 'gw_wrong_other',
      accountId: 'acc_cust_01',
      integrationId: 'int_subject_01',
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
    };
    const wrongGwBody = {
      keyId: 'aamarva-core-key-1',
      claims: wrongGwClaims,
      signature: signPayloadAsMockAamarva(wrongGwClaims, aamarvaPair.privateKey),
    };
    const wrongGwHdr = signBackendHeaders('/handshake', wrongGwBody);
    const wrongGwResp = await fetch(`${gatewayBaseUrl}/handshake`, {
      method: 'POST',
      headers: wrongGwHdr.headers,
      body: wrongGwHdr.rawBody,
    });
    expect(wrongGwResp.status).toBe(403);

    // SSRF cloud metadata target blocked -> 403
    const ssrfClaims = {
      challenge: `ch_${crypto.randomBytes(8).toString('hex')}`,
      gatewayId: config.gatewayId,
      accountId: 'acc_cust_01',
      integrationId: 'int_subject_01',
      transport: 'streamable-http',
      endpoint: 'http://169.254.169.254/latest/meta-data/',
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
    };
    const ssrfBody = {
      keyId: 'aamarva-core-key-1',
      claims: ssrfClaims,
      signature: signPayloadAsMockAamarva(ssrfClaims, aamarvaPair.privateKey),
    };
    const ssrfHdr = signBackendHeaders('/handshake', ssrfBody);
    const ssrfResp = await fetch(`${gatewayBaseUrl}/handshake`, {
      method: 'POST',
      headers: ssrfHdr.headers,
      body: ssrfHdr.rawBody,
    });
    expect(ssrfResp.status).toBe(403);

    // Mismatched non-configured Subject MCP Server URL -> 403 ENDPOINT_MISMATCH
    const mismatchClaims = {
      challenge: `ch_${crypto.randomBytes(8).toString('hex')}`,
      gatewayId: config.gatewayId,
      accountId: 'acc_cust_01',
      integrationId: 'int_subject_01',
      transport: 'streamable-http',
      endpoint: 'https://rogue-mcp.external.example/mcp',
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
    };
    const mismatchBody = {
      keyId: 'aamarva-core-key-1',
      claims: mismatchClaims,
      signature: signPayloadAsMockAamarva(mismatchClaims, aamarvaPair.privateKey),
    };
    const mismatchHdr = signBackendHeaders('/handshake', mismatchBody);
    const mismatchResp = await fetch(`${gatewayBaseUrl}/handshake`, {
      method: 'POST',
      headers: mismatchHdr.headers,
      body: mismatchHdr.rawBody,
    });
    expect(mismatchResp.status).toBe(403);
    const mismatchJson = (await mismatchResp.json()) as { error: string };
    expect(mismatchJson.error).toBe('ENDPOINT_MISMATCH');
  });

  it('4. POST /handshake returns 502 and emits no attestation if MCP initialize or tools/list fails', async () => {
    for (const badTarget of [failInitServer.url, failToolsServer.url]) {
      const gwTmp = new AamarvaMcpGateway(
        {
          ...config,
          mcp: { ...config.mcp, httpUrl: badTarget, upstreamAuthHeader: undefined },
          storage: { driver: 'memory', sqliteDbPath: ':memory:' },
          security: { ...config.security, allowInMemoryStore: true },
        },
        { aamarvaClient, silentLogger: true },
      );
      await gwTmp.start({ connectMcpOnBoot: false });
      const srv = http.createServer(gwTmp.createStandaloneApp());
      await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', () => resolve()));
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;

      const now = Date.now();
      const claims = {
        challenge: `ch_fail_${crypto.randomBytes(6).toString('hex')}`,
        gatewayId: config.gatewayId,
        accountId: 'acc_fail_01',
        integrationId: 'int_fail_01',
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + 60_000).toISOString(),
      };
      const bodyObj = {
        keyId: 'aamarva-core-key-1',
        claims,
        signature: signPayloadAsMockAamarva(claims, aamarvaPair.privateKey),
      };
      const rawBody = JSON.stringify(bodyObj);
      const ts = String(Date.now());
      const reqId = `req_${crypto.randomBytes(6).toString('hex')}`;
      const hmac = gwTmp.signatureVerifier.computeBackendRequestHmac({
        method: 'POST',
        path: '/handshake',
        timestamp: ts,
        requestId: reqId,
        rawBody,
      });

      const resp = await fetch(`http://127.0.0.1:${port}/handshake`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-aamarva-gateway-id': config.gatewayId,
          'x-aamarva-timestamp': ts,
          'x-aamarva-request-id': reqId,
          'x-aamarva-hmac-sha256': hmac,
        },
        body: rawBody,
      });
      expect(resp.status).toBe(502);
      const json = (await resp.json()) as { verified: boolean; attestation?: unknown };
      expect(json.verified).toBe(false);
      expect(json.attestation).toBeUndefined();

      await new Promise<void>((resolve) => srv.close(() => resolve()));
      await gwTmp.stop();
    }
  });

  it('5. POST /issuetoken validates P-256 key + fingerprint, discovered tools, encrypts token, signs response, stores only token hash, and never leaks plaintext token', async () => {
    const agentKeys = generateP256KeyPair();
    const now = Date.now();
    const authorizationId = `auth_3ep_${crypto.randomBytes(6).toString('hex')}`;
    const invocationId = `inv_3ep_${crypto.randomBytes(6).toString('hex')}`;

    const claims = {
      authorizationId,
      invocationId,
      gatewayId: config.gatewayId,
      accountId: 'acc_cust_01',
      integrationId: 'int_subject_01',
      agentId: 'agent_3ep_01',
      agentPublicKeyPem: agentKeys.publicKey,
      agentPublicKeyFingerprint: agentKeys.fingerprint,
      allowedTools: ['subject_echo', 'subject_status'],
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 300_000).toISOString(),
    };
    const issueBody = {
      keyId: 'aamarva-core-key-1',
      claims,
      signature: signPayloadAsMockAamarva(claims, aamarvaPair.privateKey),
    };
    const signedHdr = signBackendHeaders('/issuetoken', issueBody);

    const resp = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: signedHdr.headers,
      body: signedHdr.rawBody,
    });
    expect(resp.status).toBe(201);
    const json = (await resp.json()) as Record<string, unknown> & {
      tokenId: string;
      expiresAt: string;
      gatewayId: string;
      mcpServerId: string;
      agentId: string;
      accountId: string;
      authorizationId: string;
      invocationId: string;
      redemptionEndpoint: string;
      encryptionAlgorithm: string;
      envelopeVersion: string;
      encryptedToken: EncryptedTokenEnvelope;
      gatewayKeyId: string;
      gatewayPublicKeyFingerprint: string;
      gatewayPublicKey: GatewayPublicKeyMetadata;
      gatewaySignature: { keyId: string; algorithm: string; signature: string };
      correlationId: string;
    };

    expect(json.agentId).toBe('agent_3ep_01');
    expect(json.accountId).toBe('acc_cust_01');
    expect(json.authorizationId).toBe(authorizationId);
    expect(json.invocationId).toBe(invocationId);
    expect(json.redemptionEndpoint).toBe('/execute');
    expect(json.encryptionAlgorithm).toBe('P256-HKDF-SHA256-AES-256-GCM');
    expect(json.gatewayKeyId).toBe(json.gatewayPublicKey.keyId);
    expect(json.gatewayPublicKeyFingerprint).toBe(json.gatewayPublicKey.fingerprint);
    expect(JSON.stringify(json)).not.toContain('agw1.');

    // Verify complete Gateway signature over entire response object (excluding gatewaySignature)
    const { gatewaySignature, ...unsignedPayload } = json;
    expect(
      verifyGatewayResponseSignature({
        payload: unsignedPayload,
        signatureBase64: gatewaySignature.signature,
        gatewayPublicKey: gateway.gatewayIdentity.getPublicKeyMetadata(),
      }),
    ).toBe(true);

    // Agent decrypts envelope using its P-256 private key
    const decrypted = decryptTokenAsAgent(json.encryptedToken, agentKeys.privateKey);
    expect(decrypted.token.startsWith('agw1.')).toBe(true);
    expect(decrypted.tokenId).toBe(json.tokenId);

    // Verify SQLite stores ONLY token_hash (never plaintext)
    const db = new DatabaseSync(sqlitePath, { readOnly: true });
    const row = db
      .prepare('SELECT token_hash, agent_id, account_id, authorization_id FROM issued_tokens WHERE token_id = ?')
      .get(json.tokenId) as { token_hash: string; agent_id: string; account_id: string; authorization_id: string };
    db.close();
    expect(row.token_hash).toBe(sha256Hex(decrypted.token));
    expect(row.token_hash).not.toContain(decrypted.token);

    // Negative /issuetoken tests:
    // a) Missing agent public key -> 400 MISSING_AGENT_PUBLIC_KEY
    const noKeyClaims = {
      ...claims,
      invocationId: `inv_nokey_${crypto.randomBytes(4).toString('hex')}`,
    };
    delete (noKeyClaims as Record<string, unknown>).agentPublicKeyPem;
    const noKeyBody = {
      keyId: 'aamarva-core-key-1',
      claims: noKeyClaims,
      signature: signPayloadAsMockAamarva(noKeyClaims, aamarvaPair.privateKey),
    };
    const noKeyHdr = signBackendHeaders('/issuetoken', noKeyBody);
    const noKeyResp = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: noKeyHdr.headers,
      body: noKeyHdr.rawBody,
    });
    expect(noKeyResp.status).toBe(400);
    expect(((await noKeyResp.json()) as { error: string }).error).toBe('MISSING_AGENT_PUBLIC_KEY');

    // b) Non-P256 key (X25519) -> 400 INVALID_AGENT_PUBLIC_KEY
    const x25519Pair = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const xDer = crypto.createPublicKey(x25519Pair.publicKey).export({ type: 'spki', format: 'der' }) as Buffer;
    const nonP256Claims = {
      ...claims,
      invocationId: `inv_x25519_${crypto.randomBytes(4).toString('hex')}`,
      agentPublicKeyPem: x25519Pair.publicKey,
      agentPublicKeyFingerprint: `sha256:${sha256Hex(xDer)}`,
    };
    const nonP256Body = {
      keyId: 'aamarva-core-key-1',
      claims: nonP256Claims,
      signature: signPayloadAsMockAamarva(nonP256Claims, aamarvaPair.privateKey),
    };
    const nonP256Hdr = signBackendHeaders('/issuetoken', nonP256Body);
    const nonP256Resp = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: nonP256Hdr.headers,
      body: nonP256Hdr.rawBody,
    });
    expect(nonP256Resp.status).toBe(400);
    expect(((await nonP256Resp.json()) as { error: string }).error).toBe('INVALID_AGENT_PUBLIC_KEY');

    // c) Wrong fingerprint -> 400 AGENT_KEY_FINGERPRINT_MISMATCH
    const badFpClaims = {
      ...claims,
      invocationId: `inv_fp_${crypto.randomBytes(4).toString('hex')}`,
      agentPublicKeyFingerprint: `sha256:${'a'.repeat(64)}`,
    };
    const badFpBody = {
      keyId: 'aamarva-core-key-1',
      claims: badFpClaims,
      signature: signPayloadAsMockAamarva(badFpClaims, aamarvaPair.privateKey),
    };
    const badFpHdr = signBackendHeaders('/issuetoken', badFpBody);
    const badFpResp = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: badFpHdr.headers,
      body: badFpHdr.rawBody,
    });
    expect(badFpResp.status).toBe(400);
    expect(((await badFpResp.json()) as { error: string }).error).toBe('AGENT_KEY_FINGERPRINT_MISMATCH');

    // d) Unauthorized tool not in discovered handshake list -> 403 TOOL_NOT_AUTHORIZED
    const badToolClaims = {
      ...claims,
      invocationId: `inv_tool_${crypto.randomBytes(4).toString('hex')}`,
      allowedTools: ['subject_echo', 'nonexistent_super_tool'],
    };
    const badToolBody = {
      keyId: 'aamarva-core-key-1',
      claims: badToolClaims,
      signature: signPayloadAsMockAamarva(badToolClaims, aamarvaPair.privateKey),
    };
    const badToolHdr = signBackendHeaders('/issuetoken', badToolBody);
    const badToolResp = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: badToolHdr.headers,
      body: badToolHdr.rawBody,
    });
    expect(badToolResp.status).toBe(403);
    expect(((await badToolResp.json()) as { error: string }).error).toBe('TOOL_NOT_AUTHORIZED');

    // e) Expired invocation -> 401 INVOCATION_EXPIRED
    const expClaims = {
      ...claims,
      invocationId: `inv_exp_${crypto.randomBytes(4).toString('hex')}`,
      issuedAt: new Date(now - 300_000).toISOString(),
      expiresAt: new Date(now - 10_000).toISOString(),
    };
    const expBody = {
      keyId: 'aamarva-core-key-1',
      claims: expClaims,
      signature: signPayloadAsMockAamarva(expClaims, aamarvaPair.privateKey),
    };
    const expHdr = signBackendHeaders('/issuetoken', expBody);
    const expResp = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: expHdr.headers,
      body: expHdr.rawBody,
    });
    expect(expResp.status).toBe(401);
    expect(((await expResp.json()) as { error: string }).error).toBe('INVOCATION_EXPIRED');
  });

  it('6. POST /execute redeems one-time token atomically, blocks replay/races/mismatches/MCP calls, mediates tool calls, and retries session sync', async () => {
    const agentKeys = generateP256KeyPair();
    const issueAndDecrypt = async (authId: string, toolScope: string[] = ['subject_echo']) => {
      const now = Date.now();
      const claims = {
        authorizationId: authId,
        invocationId: authId,
        gatewayId: config.gatewayId,
        accountId: 'acc_cust_01',
        integrationId: 'int_subject_01',
        agentId: 'agent_exec_01',
        agentPublicKeyPem: agentKeys.publicKey,
        agentPublicKeyFingerprint: agentKeys.fingerprint,
        allowedTools: toolScope,
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + 120_000).toISOString(),
      };
      const body = {
        keyId: 'aamarva-core-key-1',
        claims,
        signature: signPayloadAsMockAamarva(claims, aamarvaPair.privateKey),
      };
      const hdr = signBackendHeaders('/issuetoken', body);
      const r = await fetch(`${gatewayBaseUrl}/issuetoken`, {
        method: 'POST',
        headers: hdr.headers,
        body: hdr.rawBody,
      });
      expect(r.status).toBe(201);
      const data = (await r.json()) as { encryptedToken: EncryptedTokenEnvelope };
      return decryptTokenAsAgent(data.encryptedToken, agentKeys.privateKey);
    };

    // a) Direct MCP execution payload on /execute must be rejected (400)
    const mcpAbuseResp = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: 'agw1.tok_dummy.' + 'x'.repeat(32),
        agentId: 'agent_exec_01',
        accountId: 'acc_cust_01',
        mcpServerId: config.mcpServerId,
        toolName: 'subject_echo',
        arguments: { text: 'bypass' },
      }),
    });
    expect(mcpAbuseResp.status).toBe(400);

    // b) Invalid token format -> 400
    const badTokResp = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: 'not-a-valid-aamarva-token-string',
        agentId: 'agent_exec_01',
        accountId: 'acc_cust_01',
        mcpServerId: config.mcpServerId,
      }),
    });
    expect(badTokResp.status).toBe(400);

    // c) Mismatched agent, account, mcpServerId, and authorizationId checks without consuming valid token
    const tok1 = await issueAndDecrypt(`auth_exec_1_${crypto.randomBytes(4).toString('hex')}`);
    const wrongAgent = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: tok1.token,
        agentId: 'wrong_agent',
        accountId: 'acc_cust_01',
        mcpServerId: config.mcpServerId,
      }),
    });
    expect(wrongAgent.status).toBe(403);

    const wrongAccount = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: tok1.token,
        agentId: 'agent_exec_01',
        accountId: 'wrong_account',
        mcpServerId: config.mcpServerId,
      }),
    });
    expect(wrongAccount.status).toBe(403);

    const wrongServer = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: tok1.token,
        agentId: 'agent_exec_01',
        accountId: 'acc_cust_01',
        mcpServerId: 'wrong_mcp_server',
      }),
    });
    expect(wrongServer.status).toBe(403);

    const wrongAuthId = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: tok1.token,
        agentId: 'agent_exec_01',
        accountId: 'acc_cust_01',
        mcpServerId: config.mcpServerId,
        authorizationId: 'auth_wrong_id',
      }),
    });
    expect(wrongAuthId.status).toBe(403);

    // d) Transient session sync failure triggers pending_retry & outbox recovery; concurrent /execute race allows only 1 winner!
    aamarvaClient.setFailNextSessionSyncs(1);
    const raceResults = await Promise.all(
      Array.from({ length: 5 }, () =>
        fetch(`${gatewayBaseUrl}/execute`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            token: tok1.token,
            agentId: 'agent_exec_01',
            accountId: 'acc_cust_01',
            mcpServerId: config.mcpServerId,
          }),
        }),
      ),
    );
    const statuses = raceResults.map((r) => r.status).sort((a, b) => a - b);
    expect(statuses).toEqual([200, 409, 409, 409, 409]);

    const winnerIdx = raceResults.findIndex((r) => r.status === 200);
    const winJson = (await raceResults[winnerIdx].json()) as {
      redeemed: boolean;
      sessionId: string;
      sessionSyncStatus: string;
      gatewayPublicUrl?: string;
    };
    expect(winJson.redeemed).toBe(true);
    expect(winJson.sessionSyncStatus).toBe('pending_retry');
    expect(JSON.stringify(winJson)).not.toContain(subjectMcpAuthToken);

    // Retry queue delivers idempotently when flushed after backoff window
    await gateway.outboxProcessor.flushPending(Date.now() + 5000);
    expect(Array.from(aamarvaClient.syncedSessions.values()).some((s) => s.sessionId === winJson.sessionId)).toBe(true);

    // e) Explicit replay blocked -> 409
    const replayResp = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: tok1.token,
        agentId: 'agent_exec_01',
        accountId: 'acc_cust_01',
        mcpServerId: config.mcpServerId,
      }),
    });
    expect(replayResp.status).toBe(409);

    // f) Alternate tool-call endpoint /api/v1/aamarva/mcp/tools/call is removed and returns 404
    const call404 = await fetch(`${gatewayBaseUrl}/api/v1/aamarva/mcp/tools/call`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    expect(call404.status).toBe(404);

    // g) Legacy revoke route returns 404; internal revocation blocks /execute redemption -> 401 TOKEN_REVOKED
    const authRevId = `auth_rev_${crypto.randomBytes(4).toString('hex')}`;
    const tokRev = await issueAndDecrypt(authRevId);
    const revClaims = {
      revocationId: `rev_${crypto.randomBytes(6).toString('hex')}`,
      authorizationId: authRevId,
      reason: 'User revoked agent access',
      revokedBy: 'floor-operator',
      revokedAt: new Date().toISOString(),
    };
    const revBody = {
      keyId: 'aamarva-core-key-1',
      claims: revClaims,
      signature: signPayloadAsMockAamarva(revClaims, aamarvaPair.privateKey),
    };
    const revHdr = signBackendHeaders('/api/v1/aamarva/authorizations/revoke', revBody);
    const revHttpResp = await fetch(`${gatewayBaseUrl}/api/v1/aamarva/authorizations/revoke`, {
      method: 'POST',
      headers: revHdr.headers,
      body: revHdr.rawBody,
    });
    expect(revHttpResp.status).toBe(404);

    const revInternal = await gateway.authAdapter.processRevocation(revBody, 'corr_rev_test');
    expect(revInternal.ok).toBe(true);
    expect(revInternal.statusCode).toBe(200);

    const execRevResp = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: tokRev.token,
        agentId: 'agent_exec_01',
        accountId: 'acc_cust_01',
        mcpServerId: config.mcpServerId,
      }),
    });
    expect(execRevResp.status).toBe(401);
  });
});
