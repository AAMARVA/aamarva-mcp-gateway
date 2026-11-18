import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import express from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LocalTestAamarvaBackendClient } from '../../src/gateway/aamarva/aamarva-client.ts';
import { canonicalizeJson, sha256Hex } from '../../src/gateway/config/security.ts';
import { validateGatewayConfig, type GatewayConfig } from '../../src/gateway/config/validation.ts';
import type { GatewayVerificationAttestation } from '../../src/gateway/core/authorization-context.ts';
import { AamarvaMcpGateway } from '../../src/gateway/core/gateway.ts';
import { encryptHandshakeCredentialEnvelope } from '../../src/gateway/crypto/credential-vault.ts';
import type { EncryptedTokenEnvelope } from '../../src/gateway/crypto/envelope-encryption.ts';
import {
  verifyGatewayResponseSignature,
  type GatewayPublicKeyMetadata,
} from '../../src/gateway/crypto/gateway-keypair.ts';
import {
  decryptTokenAsAgent,
  signPayloadAsMockAamarva,
} from '../fixtures/agent-decryption-harness.ts';

async function startCustomHttpMcpServer(options: {
  serverName: string;
  tenantTag: string;
  requiredAuthHeader: string;
  requiredCustomHeaderKey?: string;
  requiredCustomHeaderVal?: string;
}): Promise<{ url: string; close: () => Promise<void> }> {
  const app = express();
  app.use(express.json());

  app.post('/mcp', async (req, res) => {
    const auth = req.header('authorization');
    if (auth !== options.requiredAuthHeader) {
      res.status(401).json({ error: 'Unauthorized external MCP client' });
      return;
    }
    if (options.requiredCustomHeaderKey) {
      const val = req.header(options.requiredCustomHeaderKey.toLowerCase());
      if (val !== options.requiredCustomHeaderVal) {
        res.status(403).json({ error: 'Invalid tenant custom header' });
        return;
      }
    }

    const server = new Server(
      { name: options.serverName, version: '2.4.0' },
      { capabilities: { tools: {} } },
    );

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'tenant_whoami',
          description: 'Returns verified upstream tenant identity',
          inputSchema: { type: 'object', properties: {} },
        },
        {
          name: 'inventory_lookup',
          description: 'Looks up SKU stock in external tenant warehouse',
          inputSchema: {
            type: 'object',
            properties: { sku: { type: 'string' } },
            required: ['sku'],
          },
        },
        {
          name: 'restricted_admin_wipe',
          description: 'Dangerous admin tool outside normal agent scope',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      if (request.params.name === 'tenant_whoami') {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                serverName: options.serverName,
                tenantTag: options.tenantTag,
              }),
            },
          ],
        };
      }
      if (request.params.name === 'inventory_lookup') {
        const sku = String(request.params.arguments?.sku ?? '');
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                tenantTag: options.tenantTag,
                sku,
                available: 84,
              }),
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

async function startBrokenHttpServer(): Promise<{ url: string; close: () => Promise<void> }> {
  const srv = http.createServer((_req, res) => {
    res.statusCode = 200;
    res.setHeader('content-type', 'text/plain');
    res.end('not an mcp server');
  });
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', () => resolve()));
  const addr = srv.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    close: async () => {
      await new Promise<void>((resolve, reject) => srv.close((err) => (err ? reject(err) : resolve())));
    },
  };
}

async function postJson(
  baseUrl: string,
  reqPath: string,
  body: unknown,
  headers: Record<string, string> = {},
) {
  const resp = await fetch(`${baseUrl}${reqPath}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-forwarded-proto': 'https',
      ...headers,
    },
    body: JSON.stringify(body),
  });
  const json = (await resp.json().catch(() => ({}))) as Record<string, unknown>;
  return { status: resp.status, json };
}

describe('Mandatory Initial MCP Gateway Handshake & Cryptographic Attestation', () => {
  let tmpDir: string;
  let dbPath: string;
  let config: GatewayConfig;
  let gateway: AamarvaMcpGateway;
  let gatewayHttp: http.Server;
  let baseUrl: string;
  let mockAamarvaClient: LocalTestAamarvaBackendClient;

  let mcpServerA: { url: string; close: () => Promise<void> };
  let mcpServerB: { url: string; close: () => Promise<void> };
  let brokenServer: { url: string; close: () => Promise<void> };

  const secretA = 'Bearer ext-mcp-secret-account-alpha-9911';
  const customKeyA = 'x-tenant-api-key';
  const customValA = 'tenant-alpha-secret-token-777';
  const secretB = 'Bearer ext-mcp-secret-account-beta-4422';

  const backendSecret = 'aamarva-backend-hmac-secret-handshake-001';
  const aamarvaKeys = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const gatewayKeys = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  function makeP256AgentKeys() {
    const pair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const der = crypto.createPublicKey(pair.publicKey).export({ type: 'spki', format: 'der' }) as Buffer;
    return {
      ...pair,
      fingerprint: `sha256:${sha256Hex(der)}`,
    };
  }
  const agentKeysA = makeP256AgentKeys();
  const agentKeysB = makeP256AgentKeys();

  function signBackendHeaders(gw: AamarvaMcpGateway, reqPath: string, body: unknown) {
    const rawBody = JSON.stringify(body);
    const timestamp = String(Date.now());
    const requestId = `req_${crypto.randomBytes(8).toString('hex')}`;
    const hmac = gw.signatureVerifier.computeBackendRequestHmac({
      method: 'POST',
      path: reqPath,
      timestamp,
      requestId,
      rawBody,
    });
    return {
      'x-aamarva-gateway-id': gw.config.gatewayId,
      'x-aamarva-timestamp': timestamp,
      'x-aamarva-request-id': requestId,
      'x-aamarva-hmac-sha256': hmac,
    };
  }

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agw-handshake-'));
    dbPath = path.join(tmpDir, 'handshake.db');
    mockAamarvaClient = new LocalTestAamarvaBackendClient();

    mcpServerA = await startCustomHttpMcpServer({
      serverName: 'ext-warehouse-alpha',
      tenantTag: 'tenant-alpha',
      requiredAuthHeader: secretA,
      requiredCustomHeaderKey: customKeyA,
      requiredCustomHeaderVal: customValA,
    });
    mcpServerB = await startCustomHttpMcpServer({
      serverName: 'ext-warehouse-beta',
      tenantTag: 'tenant-beta',
      requiredAuthHeader: secretB,
    });
    brokenServer = await startBrokenHttpServer();

    config = validateGatewayConfig({
      nodeEnv: 'test',
      port: 3000,
      gatewayId: 'gw_hs_01',
      mcpServerId: 'mcp_default_stdio',
      gatewayPublicUrl: 'https://gw.example.com',
      gatewayIdentity: {
        activeSigningKeyId: 'gw-hs-key-1',
        signingKeys: {
          'gw-hs-key-1': {
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
        allowLoopbackHttp: true,
        maxRequestBodyBytes: 1_048_576,
        redeemRateLimitMax: 200,
        redeemRateLimitWindowMs: 60_000,
        relayRateLimitMax: 500,
        relayRateLimitWindowMs: 60_000,
      },
      storage: {
        driver: 'sqlite',
        sqliteDbPath: dbPath,
      },
      mcp: {
        transport: 'stdio',
        stdioCommand: 'node',
        stdioArgs: [path.resolve(process.cwd(), 'examples/sample-mcp-stdio.ts')],
        requestTimeoutMs: 5_000,
      },
      features: {
        enableOperatorConsole: false,
        enableSandbox: false,
      },
    });

    gateway = new AamarvaMcpGateway(config, {
      aamarvaClient: mockAamarvaClient,
      silentLogger: true,
    });
    await gateway.start({ connectMcpOnBoot: false });

    const app = gateway.createStandaloneApp();
    gatewayHttp = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve) => gatewayHttp.once('listening', resolve));
    const addr = gatewayHttp.address();
    const port = typeof addr === 'object' && addr ? addr.port : 3000;
    baseUrl = `http://127.0.0.1:${port}`;
  }, 20_000);

  afterAll(async () => {
    await new Promise<void>((resolve) => gatewayHttp.close(() => resolve()));
    await gateway.stop();
    await mcpServerA.close();
    await mcpServerB.close();
    await brokenServer.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function buildSignedHandshake(overrides: {
    challenge?: string;
    accountId?: string;
    integrationId?: string;
    mcpServerId?: string;
    transport?: 'streamable-http' | 'stdio';
    endpoint?: string;
    expectedEndpoint?: string;
    issuedAt?: string;
    expiresAt?: string;
    encryptedCredentials?: ReturnType<typeof encryptHandshakeCredentialEnvelope>;
  }) {
    const now = Date.now();
    const challenge = overrides.challenge ?? `chl_${crypto.randomBytes(16).toString('hex')}`;
    const claims = {
      challenge,
      accountId: overrides.accountId ?? 'acct_alpha',
      integrationId: overrides.integrationId ?? 'int_alpha_warehouse',
      mcpServerId: overrides.mcpServerId ?? 'mcp_alpha_srv',
      gatewayId: 'gw_hs_01',
      transport: overrides.transport ?? ('streamable-http' as const),
      endpoint: overrides.endpoint ?? mcpServerA.url,
      attestationTtlSeconds: 1800,
      issuedAt: overrides.issuedAt ?? new Date(now).toISOString(),
      expiresAt: overrides.expiresAt ?? new Date(now + 120_000).toISOString(),
    };
    const signature = signPayloadAsMockAamarva(claims, aamarvaKeys.privateKey);
    return {
      claims,
      keyId: 'aamarva-k1',
      signature,
      ...(overrides.expectedEndpoint ? { expectedEndpoint: overrides.expectedEndpoint } : {}),
      ...(overrides.encryptedCredentials ? { encryptedCredentials: overrides.encryptedCredentials } : {}),
    };
  }

  it('1-6: executes real outbound MCP handshake, initialize + tools/list, and returns independently verifiable signed attestation', async () => {
    const challenge = `chl_verify_${crypto.randomBytes(12).toString('hex')}`;
    const encryptedCredentials = encryptHandshakeCredentialEnvelope({
      credentials: {
        authorizationHeader: secretA,
        customHeaders: { [customKeyA]: customValA },
      },
      backendAuthSecret: backendSecret,
      gatewayId: 'gw_hs_01',
      accountId: 'acct_alpha',
      integrationId: 'int_alpha_warehouse',
      challenge,
    });

    const body = buildSignedHandshake({
      challenge,
      accountId: 'acct_alpha',
      integrationId: 'int_alpha_warehouse',
      mcpServerId: 'mcp_alpha_srv',
      endpoint: mcpServerA.url,
      expectedEndpoint: mcpServerA.url,
      encryptedCredentials,
    });

    const res = await postJson(
      baseUrl,
      '/handshake',
      body,
      signBackendHeaders(gateway, '/handshake', body),
    );

    expect(res.status).toBe(200);
    expect(res.json.verified).toBe(true);

    const attestation = res.json.attestation as GatewayVerificationAttestation;
    const gwPubKey = res.json.gatewayPublicKey as GatewayPublicKeyMetadata;
    const gwSig = res.json.gatewaySignature as string;
    const tools = res.json.tools as Array<Record<string, unknown>>;

    // Item 3 & 4: Actual initialize & tools/list discovery verified
    expect(attestation.version).toBe('AAMARVA-GW-ATTEST-V1');
    expect(attestation.gatewayId).toBe('gw_hs_01');
    expect(attestation.gatewayKeyId).toBe('gw-hs-key-1');
    expect(attestation.gatewayPublicKeyFingerprint).toBe(gwPubKey.fingerprint);
    expect(attestation.challenge).toBe(challenge);
    expect(attestation.accountId).toBe('acct_alpha');
    expect(attestation.integrationId).toBe('int_alpha_warehouse');
    expect(attestation.mcpServerId).toBe('mcp_alpha_srv');
    expect(attestation.canonicalEndpoint).toBe(new URL(mcpServerA.url).toString());
    expect(attestation.transport).toBe('streamable-http');
    expect(attestation.mcpInitialized).toBe(true);
    expect(attestation.negotiatedProtocolVersion.length).toBeGreaterThan(0);
    expect(attestation.serverInfo?.name).toBe('ext-warehouse-alpha');
    expect(attestation.toolsDiscoverySuccess).toBe(true);
    expect(attestation.toolCount).toBe(3);
    expect(attestation.connectionId.startsWith('mcpc_')).toBe(true);
    expect(attestation.attestationId.startsWith('att_')).toBe(true);
    expect(Date.parse(attestation.expiresAt)).toBeGreaterThan(Date.parse(attestation.handshakeTimestamp));

    // Confirm toolsListHash equals SHA-256 of canonicalized discovered tools
    const expectedHash = `sha256:${sha256Hex(canonicalizeJson(tools))}`;
    expect(attestation.toolsListHash).toBe(expectedHash);

    // Item 6: Independent AAMARVA Core verification succeeds & rejects tampering
    expect(
      verifyGatewayResponseSignature({
        payload: attestation,
        signatureBase64: gwSig,
        gatewayPublicKey: gwPubKey,
      }),
    ).toBe(true);

    expect(
      verifyGatewayResponseSignature({
        payload: { ...attestation, canonicalEndpoint: 'https://evil-attacker.example.com/mcp' },
        signatureBase64: gwSig,
        gatewayPublicKey: gwPubKey,
      }),
    ).toBe(false);

    // Item 12 (response & logs): Upstream credentials must never appear in HTTP response or Gateway logs
    const serializedRes = JSON.stringify(res.json);
    expect(serializedRes).not.toContain(secretA);
    expect(serializedRes).not.toContain(customValA);
    expect(serializedRes).not.toContain('PRIVATE KEY');

    const logsJson = JSON.stringify(gateway.logger.getRecentEntries(200));
    expect(logsJson).not.toContain(secretA);
    expect(logsJson).not.toContain(customValA);
  });

  it('7-8: rejects invalid challenges, expired challenges, bad signatures, spoofed verified flags, and challenge replay', async () => {
    // Missing backend HMAC -> 401
    const unauth = await postJson(baseUrl, '/handshake', {});
    expect(unauth.status).toBe(401);

    // Short / whitespace challenge -> 400
    const badChallengeBody = buildSignedHandshake({ challenge: 'short bad' });
    const badChallengeRes = await postJson(
      baseUrl,
      '/handshake',
      badChallengeBody,
      signBackendHeaders(gateway, '/handshake', badChallengeBody),
    );
    expect(badChallengeRes.status).toBe(400);
    expect(badChallengeRes.json.verified).toBe(false);

    // Spoofed client flag (verified: true in request body) -> rejected strictly 400
    const validBase = buildSignedHandshake({});
    const spoofedBody = { ...validBase, verified: true };
    const spoofedRes = await postJson(
      baseUrl,
      '/handshake',
      spoofedBody,
      signBackendHeaders(gateway, '/handshake', spoofedBody),
    );
    expect(spoofedRes.status).toBe(400);
    expect(spoofedRes.json.verified).toBe(false);

    // Expired challenge -> 401 HANDSHAKE_CHALLENGE_EXPIRED
    const expiredBody = buildSignedHandshake({
      issuedAt: new Date(Date.now() - 120_000).toISOString(),
      expiresAt: new Date(Date.now() - 10_000).toISOString(),
    });
    const expiredRes = await postJson(
      baseUrl,
      '/handshake',
      expiredBody,
      signBackendHeaders(gateway, '/handshake', expiredBody),
    );
    expect(expiredRes.status).toBe(401);
    expect(expiredRes.json.error).toBe('HANDSHAKE_CHALLENGE_EXPIRED');

    // Invalid signature -> 401 INVALID_AAMARVA_SIGNATURE
    const badSigBody = {
      ...buildSignedHandshake({}),
      signature: Buffer.alloc(64, 0x11).toString('base64'),
    };
    const badSigRes = await postJson(
      baseUrl,
      '/handshake',
      badSigBody,
      signBackendHeaders(gateway, '/handshake', badSigBody),
    );
    expect(badSigRes.status).toBe(401);
    expect(badSigRes.json.error).toBe('INVALID_AAMARVA_SIGNATURE');

    // Challenge replay protection -> first succeeds, second rejected 409 HANDSHAKE_CHALLENGE_REPLAYED
    const replayChallenge = `chl_once_${crypto.randomBytes(12).toString('hex')}`;
    const cred1 = encryptHandshakeCredentialEnvelope({
      credentials: { authorizationHeader: secretB },
      backendAuthSecret: backendSecret,
      gatewayId: 'gw_hs_01',
      accountId: 'acct_replay_check',
      integrationId: 'int_replay',
      challenge: replayChallenge,
    });
    const firstBody = buildSignedHandshake({
      challenge: replayChallenge,
      accountId: 'acct_replay_check',
      integrationId: 'int_replay',
      mcpServerId: 'mcp_beta_srv',
      endpoint: mcpServerB.url,
      encryptedCredentials: cred1,
    });
    const firstRes = await postJson(
      baseUrl,
      '/handshake',
      firstBody,
      signBackendHeaders(gateway, '/handshake', firstBody),
    );
    expect(firstRes.status).toBe(200);

    const secondRes = await postJson(
      baseUrl,
      '/handshake',
      firstBody,
      signBackendHeaders(gateway, '/handshake', firstBody),
    );
    expect(secondRes.status).toBe(409);
    expect(secondRes.json.verified).toBe(false);
    expect(secondRes.json.error).toBe('HANDSHAKE_CHALLENGE_REPLAYED');
  });

  it('10: failed MCP initialization (wrong auth, unreachable server, non-MCP HTTP) never produces attestation', async () => {
    // Wrong upstream secret (encrypted envelope) -> 502 MCP_UPSTREAM_AUTH_FAILED
    const badCredsChallenge = `chl_badauth_${crypto.randomBytes(8).toString('hex')}`;
    const badCredsBody = buildSignedHandshake({
      challenge: badCredsChallenge,
      accountId: 'acct_fail_case',
      integrationId: 'int_fail_auth',
      mcpServerId: 'mcp_fail_srv',
      endpoint: mcpServerB.url,
      encryptedCredentials: encryptHandshakeCredentialEnvelope({
        credentials: { authorizationHeader: 'Bearer wrong-token' },
        backendAuthSecret: backendSecret,
        gatewayId: 'gw_hs_01',
        accountId: 'acct_fail_case',
        integrationId: 'int_fail_auth',
        challenge: badCredsChallenge,
      }),
    });
    const wrongAuthRes = await postJson(
      baseUrl,
      '/handshake',
      badCredsBody,
      signBackendHeaders(gateway, '/handshake', badCredsBody),
    );
    expect(wrongAuthRes.status).toBe(502);
    expect(wrongAuthRes.json.verified).toBe(false);
    expect(wrongAuthRes.json.error).toBe('MCP_UPSTREAM_AUTH_FAILED');
    expect(wrongAuthRes.json.attestation).toBeUndefined();
    expect(wrongAuthRes.json.gatewaySignature).toBeUndefined();
    expect(
      await gateway.store.getLatestVerifiedConnectionByIntegration('acct_fail_case', 'int_fail_auth'),
    ).toBeNull();

    // Unreachable port -> 502, no attestation stored
    const unreachableBody = buildSignedHandshake({
      accountId: 'acct_fail_case',
      integrationId: 'int_fail_net',
      mcpServerId: 'mcp_fail_srv',
      endpoint: 'http://127.0.0.1:59997/mcp',
    });
    const unreachRes = await postJson(
      baseUrl,
      '/handshake',
      unreachableBody,
      signBackendHeaders(gateway, '/handshake', unreachableBody),
    );
    expect(unreachRes.status).toBe(502);
    expect(unreachRes.json.verified).toBe(false);
    expect(unreachRes.json.attestation).toBeUndefined();

    // Non-MCP HTTP endpoint -> 502, no attestation stored
    const brokenBody = buildSignedHandshake({
      accountId: 'acct_fail_case',
      integrationId: 'int_fail_proto',
      mcpServerId: 'mcp_fail_srv',
      endpoint: brokenServer.url,
    });
    const brokenRes = await postJson(
      baseUrl,
      '/handshake',
      brokenBody,
      signBackendHeaders(gateway, '/handshake', brokenBody),
    );
    expect(brokenRes.status).toBe(502);
    expect(brokenRes.json.verified).toBe(false);
    expect(brokenRes.json.attestation).toBeUndefined();
    expect(
      await gateway.store.getLatestVerifiedConnectionByIntegration('acct_fail_case', 'int_fail_proto'),
    ).toBeNull();

    // Endpoint substitution in handshake request -> 403 ENDPOINT_MISMATCH
    const substHsBody = buildSignedHandshake({
      accountId: 'acct_fail_case',
      integrationId: 'int_fail_subst',
      endpoint: mcpServerB.url,
      expectedEndpoint: mcpServerA.url,
    });
    const substHsRes = await postJson(
      baseUrl,
      '/handshake',
      substHsBody,
      signBackendHeaders(gateway, '/handshake', substHsBody),
    );
    expect(substHsRes.status).toBe(403);
    expect(substHsRes.json.error).toBe('ENDPOINT_MISMATCH');
  });

  it('9,11,12,13: enforces endpoint/session substitution, multi-account isolation, Gateway-mediated MCP calls, and encrypted credential persistence', async () => {
    // Perform verified handshake for Account A and Account B on their respective MCP servers
    const chlA = `chl_a_${crypto.randomBytes(12).toString('hex')}`;
    const hsBodyA = buildSignedHandshake({
      challenge: chlA,
      accountId: 'acct_A',
      integrationId: 'int_A',
      mcpServerId: 'mcp_srv_A',
      endpoint: mcpServerA.url,
      encryptedCredentials: encryptHandshakeCredentialEnvelope({
        credentials: {
          authorizationHeader: secretA,
          customHeaders: { [customKeyA]: customValA },
        },
        backendAuthSecret: backendSecret,
        gatewayId: 'gw_hs_01',
        accountId: 'acct_A',
        integrationId: 'int_A',
        challenge: chlA,
      }),
    });
    const hsResA = await postJson(
      baseUrl,
      '/handshake',
      hsBodyA,
      signBackendHeaders(gateway, '/handshake', hsBodyA),
    );
    expect(hsResA.status).toBe(200);
    const attA = hsResA.json.attestation as GatewayVerificationAttestation;

    const chlB = `chl_b_${crypto.randomBytes(12).toString('hex')}`;
    const hsBodyB = buildSignedHandshake({
      challenge: chlB,
      accountId: 'acct_B',
      integrationId: 'int_B',
      mcpServerId: 'mcp_srv_B',
      endpoint: mcpServerB.url,
      encryptedCredentials: encryptHandshakeCredentialEnvelope({
        credentials: { authorizationHeader: secretB },
        backendAuthSecret: backendSecret,
        gatewayId: 'gw_hs_01',
        accountId: 'acct_B',
        integrationId: 'int_B',
        challenge: chlB,
      }),
    });
    const hsResB = await postJson(
      baseUrl,
      '/handshake',
      hsBodyB,
      signBackendHeaders(gateway, '/handshake', hsBodyB),
    );
    expect(hsResB.status).toBe(200);
    const attB = hsResB.json.attestation as GatewayVerificationAttestation;

    // Item 12 (at-rest SQLite encryption): plaintext secrets must NEVER exist in SQLite DB bytes
    const rawDbBytes = fs.readFileSync(dbPath);
    expect(rawDbBytes.includes(Buffer.from(secretA, 'utf8'))).toBe(false);
    expect(rawDbBytes.includes(Buffer.from(customValA, 'utf8'))).toBe(false);
    expect(rawDbBytes.includes(Buffer.from(secretB, 'utf8'))).toBe(false);

    // Item 13: Cross-account grant using Account A's connectionId under Account B MUST be blocked 403
    const now = Date.now();
    const crossAcctClaims = {
      authorizationId: `auth_x_${crypto.randomBytes(4).toString('hex')}`,
      agentId: 'agent_B',
      agentName: 'Agent B',
      accountId: 'acct_B',
      agentPublicKeyPem: agentKeysB.publicKey,
      agentPublicKeyFingerprint: agentKeysB.fingerprint,
      mcpServerId: 'mcp_srv_A',
      gatewayId: 'gw_hs_01',
      integrationId: 'int_A',
      connectionId: attA.connectionId,
      allowedTools: ['tenant_whoami'],
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 300_000).toISOString(),
    };
    const crossAcctBody = {
      claims: crossAcctClaims,
      keyId: 'aamarva-k1',
      signature: signPayloadAsMockAamarva(crossAcctClaims, aamarvaKeys.privateKey),
      expires_in_minutes: 5,
    };
    const crossAcctRes = await postJson(
      baseUrl,
      '/issuetoken',
      crossAcctBody,
      signBackendHeaders(gateway, '/issuetoken', crossAcctBody),
    );
    expect(crossAcctRes.status).toBe(403);
    expect(crossAcctRes.json.error).toBe('ACCOUNT_MISMATCH');

    // Item 9: Grant endpoint substitution MUST be blocked 403 ENDPOINT_MISMATCH
    const substGrantClaims = {
      authorizationId: `auth_subst_${crypto.randomBytes(4).toString('hex')}`,
      agentId: 'agent_A',
      agentName: 'Agent A',
      accountId: 'acct_A',
      agentPublicKeyPem: agentKeysA.publicKey,
      agentPublicKeyFingerprint: agentKeysA.fingerprint,
      mcpServerId: 'mcp_srv_A',
      gatewayId: 'gw_hs_01',
      integrationId: 'int_A',
      connectionId: attA.connectionId,
      endpoint: mcpServerB.url, // swapped endpoint!
      allowedTools: ['tenant_whoami'],
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 300_000).toISOString(),
    };
    const substGrantBody = {
      claims: substGrantClaims,
      keyId: 'aamarva-k1',
      signature: signPayloadAsMockAamarva(substGrantClaims, aamarvaKeys.privateKey),
      expires_in_minutes: 5,
    };
    const substGrantRes = await postJson(
      baseUrl,
      '/issuetoken',
      substGrantBody,
      signBackendHeaders(gateway, '/issuetoken', substGrantBody),
    );
    expect(substGrantRes.status).toBe(403);
    expect(substGrantRes.json.error).toBe('ENDPOINT_MISMATCH');

    // Issue + Redeem valid session for Account A and Account B
    async function establishSession(opts: {
      accountId: string;
      agentId: string;
      agentKeys: { publicKey: string; privateKey: string; fingerprint: string };
      att: GatewayVerificationAttestation;
    }): Promise<string> {
      const t = Date.now();
      const claims = {
        authorizationId: `auth_${opts.accountId}_${crypto.randomBytes(4).toString('hex')}`,
        agentId: opts.agentId,
        agentName: opts.agentId,
        accountId: opts.accountId,
        agentPublicKeyPem: opts.agentKeys.publicKey,
        agentPublicKeyFingerprint: opts.agentKeys.fingerprint,
        mcpServerId: opts.att.mcpServerId,
        gatewayId: 'gw_hs_01',
        integrationId: opts.att.integrationId,
        connectionId: opts.att.connectionId,
        endpoint: opts.att.canonicalEndpoint,
        allowedTools: ['tenant_whoami', 'inventory_lookup'],
        issuedAt: new Date(t).toISOString(),
        expiresAt: new Date(t + 300_000).toISOString(),
      };
      const reqBody = {
        claims,
        keyId: 'aamarva-k1',
        signature: signPayloadAsMockAamarva(claims, aamarvaKeys.privateKey),
        expires_in_minutes: 5,
      };
      const issueRes = await postJson(
        baseUrl,
        '/issuetoken',
        reqBody,
        signBackendHeaders(gateway, '/issuetoken', reqBody),
      );
      expect(issueRes.status).toBe(201);

      const gwPub = issueRes.json.gatewayPublicKey as GatewayPublicKeyMetadata;
      const { gatewaySignature: gwSigRaw, ...unsignedIssuePayload } = issueRes.json;
      const gwSig = gwSigRaw as { signature: string };
      expect(
        verifyGatewayResponseSignature({
          payload: unsignedIssuePayload,
          signatureBase64: gwSig.signature,
          gatewayPublicKey: gwPub,
        }),
      ).toBe(true);

      const dec = decryptTokenAsAgent(
        issueRes.json.encryptedToken as EncryptedTokenEnvelope,
        opts.agentKeys.privateKey,
      );
      const redeemRes = await postJson(baseUrl, '/execute', {
        token: dec.token,
        agentId: opts.agentId,
        accountId: opts.accountId,
        mcpServerId: opts.att.mcpServerId,
      });
      expect(redeemRes.status).toBe(200);
      expect(redeemRes.json.connectionId).toBe(opts.att.connectionId);
      return redeemRes.json.sessionId as string;
    }

    const sessA = await establishSession({
      accountId: 'acct_A',
      agentId: 'agent_A',
      agentKeys: agentKeysA,
      att: attA,
    });
    const sessB = await establishSession({
      accountId: 'acct_B',
      agentId: 'agent_B',
      agentKeys: agentKeysB,
      att: attB,
    });

    // Legacy HTTP relay routes are removed and return 404
    for (const removedRoute of [
      '/api/v1/aamarva/mcp/tools/list',
      '/api/v1/aamarva/mcp/tools/call',
      '/api/v1/aamarva/authorizations/revoke',
    ]) {
      const r404 = await postJson(baseUrl, removedRoute, {});
      expect(r404.status).toBe(404);
    }

    // Item 11 & 13: internal Gateway tools/list & tools/call route cleanly to each account's own verified external MCP server
    const listResA = await gateway.executionProxy.listAuthorizedTools({
      requestId: `req_list_a_${crypto.randomBytes(6).toString('hex')}`,
      sessionId: sessA,
      agentId: 'agent_A',
      accountId: 'acct_A',
      mcpServerId: 'mcp_srv_A',
      gatewayId: 'gw_hs_01',
      connectionId: attA.connectionId,
      integrationId: 'int_A',
      expectedEndpoint: mcpServerA.url,
    });
    expect(listResA.statusCode).toBe(200);
    expect((listResA.body.tools as Array<{ name: string }>).map((t) => t.name)).toEqual([
      'tenant_whoami',
      'inventory_lookup',
    ]);

    const callBodyA = {
      requestId: `req_call_a_${crypto.randomBytes(6).toString('hex')}`,
      sessionId: sessA,
      agentId: 'agent_A',
      accountId: 'acct_A',
      mcpServerId: 'mcp_srv_A',
      gatewayId: 'gw_hs_01',
      connectionId: attA.connectionId,
      toolName: 'tenant_whoami',
      arguments: {},
    };
    const callResA = await gateway.executionProxy.executeAuthorizedTool(callBodyA);
    expect(callResA.statusCode).toBe(200);
    const whoA = JSON.parse(
      ((callResA.body.result as { content: Array<{ text: string }> }).content[0]).text,
    );
    expect(whoA).toEqual({ serverName: 'ext-warehouse-alpha', tenantTag: 'tenant-alpha' });

    const callBodyB = {
      requestId: `req_call_b_${crypto.randomBytes(6).toString('hex')}`,
      sessionId: sessB,
      agentId: 'agent_B',
      accountId: 'acct_B',
      mcpServerId: 'mcp_srv_B',
      gatewayId: 'gw_hs_01',
      connectionId: attB.connectionId,
      toolName: 'tenant_whoami',
      arguments: {},
    };
    const callResB = await gateway.executionProxy.executeAuthorizedTool(callBodyB);
    expect(callResB.statusCode).toBe(200);
    const whoB = JSON.parse(
      ((callResB.body.result as { content: Array<{ text: string }> }).content[0]).text,
    );
    expect(whoB).toEqual({ serverName: 'ext-warehouse-beta', tenantTag: 'tenant-beta' });

    // Unauthorized tool blocked 403
    const deniedToolRes = await gateway.executionProxy.executeAuthorizedTool({
      ...callBodyA,
      requestId: `req_deny_${crypto.randomBytes(6).toString('hex')}`,
      toolName: 'restricted_admin_wipe',
    });
    expect(deniedToolRes.statusCode).toBe(403);
    expect(deniedToolRes.body.error).toBe('TOOL_NOT_AUTHORIZED');

    // Item 9: Session substitution (Account A's sessionId with Account B's connectionId) blocked 403
    const sessSubRes = await gateway.executionProxy.executeAuthorizedTool({
      ...callBodyA,
      requestId: `req_sess_sub_${crypto.randomBytes(6).toString('hex')}`,
      connectionId: attB.connectionId,
    });
    expect(sessSubRes.statusCode).toBe(403);
    expect(sessSubRes.body.error).toBe('SESSION_SUBSTITUTION_BLOCKED');

    // Item 9: Endpoint substitution in relay payload blocked 403
    const epSubRes = await gateway.executionProxy.executeAuthorizedTool({
      ...callBodyA,
      requestId: `req_ep_sub_${crypto.randomBytes(6).toString('hex')}`,
      expectedEndpoint: mcpServerB.url,
    });
    expect(epSubRes.statusCode).toBe(403);
    expect(epSubRes.body.error).toBe('ENDPOINT_MISMATCH');

    // Simulate Gateway restart against same SQLite DB: empty in-memory pool must reconnect using AES-256-GCM stored credentials!
    const restartedGateway = new AamarvaMcpGateway(config, {
      aamarvaClient: mockAamarvaClient,
      silentLogger: true,
    });
    await restartedGateway.start({ connectMcpOnBoot: false });

    try {
      const postRestartRes = await restartedGateway.executionProxy.executeAuthorizedTool({
        ...callBodyA,
        requestId: `req_restart_${crypto.randomBytes(6).toString('hex')}`,
        toolName: 'inventory_lookup',
        arguments: { sku: 'SKU-RESTART-101' },
      });
      expect(postRestartRes.statusCode).toBe(200);
      const parsedRestart = JSON.parse(
        ((postRestartRes.body.result as { content: Array<{ text: string }> }).content[0]).text,
      );
      expect(parsedRestart).toEqual({
        tenantTag: 'tenant-alpha',
        sku: 'SKU-RESTART-101',
        available: 84,
      });

      // Verify logs on restarted instance also contain zero external credentials
      const restartedLogs = JSON.stringify(restartedGateway.logger.getRecentEntries(200));
      expect(restartedLogs).not.toContain(secretA);
      expect(restartedLogs).not.toContain(customValA);
    } finally {
      await restartedGateway.stop();
    }

    // Account revocation revokes Account A's connection without affecting Account B
    const revClaims = {
      revocationId: `rev_${crypto.randomBytes(6).toString('hex')}`,
      accountId: 'acct_A',
      reason: 'Tenant A access revoked',
      revokedBy: 'security-ops',
      revokedAt: new Date().toISOString(),
    };
    const revBody = {
      claims: revClaims,
      keyId: 'aamarva-k1',
      signature: signPayloadAsMockAamarva(revClaims, aamarvaKeys.privateKey),
    };
    const revRes = await gateway.authAdapter.processRevocation(revBody, 'corr_hs_rev');
    expect(revRes.statusCode).toBe(200);
    expect(revRes.ok).toBe(true);

    const revokedConnA = await gateway.store.getVerifiedConnection(attA.connectionId);
    expect(revokedConnA?.status).toBe('revoked');

    // Account B's verified connection & session continue working unaffected
    const postRevResB = await gateway.executionProxy.executeAuthorizedTool({
      ...callBodyB,
      requestId: `req_postrev_b_${crypto.randomBytes(6).toString('hex')}`,
    });
    expect(postRevResB.statusCode).toBe(200);
  }, 25_000);

  it('rejects remote insecure http:// endpoints under TLS, rejects unverified connectionId grants, and verifies STDIO handshake', async () => {
    // Remote plaintext http:// (non-loopback) MUST be rejected when requireTls=true
    const remoteHttpBody = buildSignedHandshake({
      accountId: 'acct_tls_check',
      integrationId: 'int_remote_http',
      mcpServerId: 'mcp_remote_http',
      endpoint: 'http://external-mcp.example.com/mcp',
    });
    const remoteHttpRes = await postJson(
      baseUrl,
      '/handshake',
      remoteHttpBody,
      signBackendHeaders(gateway, '/handshake', remoteHttpBody),
    );
    expect(remoteHttpRes.status).toBe(400);
    expect(remoteHttpRes.json.verified).toBe(false);
    expect(remoteHttpRes.json.error).toBe('INVALID_MCP_ENDPOINT');

    // Grant referencing nonexistent/unverified connectionId MUST be blocked 403 CONNECTION_NOT_VERIFIED
    const now = Date.now();
    const unverifiedGrantClaims = {
      authorizationId: `auth_unv_${crypto.randomBytes(4).toString('hex')}`,
      agentId: 'agent_unv',
      agentName: 'Agent Unverified',
      accountId: 'acct_unv',
      agentPublicKeyPem: agentKeysA.publicKey,
      agentPublicKeyFingerprint: agentKeysA.fingerprint,
      mcpServerId: 'mcp_unv',
      gatewayId: 'gw_hs_01',
      integrationId: 'int_unv',
      connectionId: 'mcpc_does_not_exist_1234',
      allowedTools: ['tenant_whoami'],
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 300_000).toISOString(),
    };
    const unverifiedGrantBody = {
      claims: unverifiedGrantClaims,
      keyId: 'aamarva-k1',
      signature: signPayloadAsMockAamarva(unverifiedGrantClaims, aamarvaKeys.privateKey),
      expires_in_minutes: 5,
    };
    const unverifiedGrantRes = await postJson(
      baseUrl,
      '/issuetoken',
      unverifiedGrantBody,
      signBackendHeaders(gateway, '/issuetoken', unverifiedGrantBody),
    );
    expect(unverifiedGrantRes.status).toBe(403);
    expect(unverifiedGrantRes.json.error).toBe('CONNECTION_NOT_VERIFIED');

    // STDIO MCP handshake verification against pre-configured STDIO server
    const stdioBody = buildSignedHandshake({
      accountId: 'acct_stdio',
      integrationId: 'int_stdio_erp',
      mcpServerId: 'mcp_default_stdio',
      transport: 'stdio',
      endpoint: 'stdio://mcp_default_stdio',
    });
    const stdioRes = await postJson(
      baseUrl,
      '/handshake',
      stdioBody,
      signBackendHeaders(gateway, '/handshake', stdioBody),
    );
    expect(stdioRes.status).toBe(200);
    expect(stdioRes.json.verified).toBe(true);
    const stdioAtt = stdioRes.json.attestation as GatewayVerificationAttestation;
    expect(stdioAtt.transport).toBe('stdio');
    expect(stdioAtt.mcpInitialized).toBe(true);
    expect(stdioAtt.toolsDiscoverySuccess).toBe(true);
    expect(stdioAtt.toolCount).toBeGreaterThanOrEqual(3);
  }, 20_000);
});
