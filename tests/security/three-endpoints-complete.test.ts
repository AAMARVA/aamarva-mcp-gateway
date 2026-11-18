import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import express from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { LocalTestAamarvaBackendClient } from '../../src/gateway/aamarva/aamarva-client.ts';
import { sha256Hex } from '../../src/gateway/config/security.ts';
import { validateGatewayConfig, type GatewayConfig } from '../../src/gateway/config/validation.ts';
import { AamarvaMcpGateway } from '../../src/gateway/core/gateway.ts';
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

async function startUpstreamSubjectMcpServer(options: {
  serverName: string;
  requiredAuthHeader: string;
  upstreamCallsLog: Array<{ tool: string; args: Record<string, unknown> }>;
}): Promise<{ url: string; close: () => Promise<void> }> {
  const app = express();
  app.use(express.json());

  app.post('/mcp', async (req, res) => {
    if (req.header('authorization') !== options.requiredAuthHeader) {
      res.status(401).json({ error: 'Unauthorized direct access' });
      return;
    }

    const server = new Server(
      { name: options.serverName, version: '4.2.0' },
      { capabilities: { tools: { listChanged: false } } },
    );

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'subject_echo',
          description: 'Echoes input from upstream MCP server',
          inputSchema: {
            type: 'object',
            properties: { text: { type: 'string' } },
            required: ['text'],
          },
        },
        {
          name: 'subject_math_add',
          description: 'Adds two integers or returns tool error on negative numbers',
          inputSchema: {
            type: 'object',
            properties: { a: { type: 'number' }, b: { type: 'number' } },
            required: ['a', 'b'],
          },
        },
        {
          name: 'subject_protocol_fail',
          description: 'Raises an authentic upstream McpError',
          inputSchema: { type: 'object', properties: {} },
        },
        {
          name: 'subject_admin_danger',
          description: 'Restricted administrative tool not granted to agents',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const toolName = request.params.name;
      const args = (request.params.arguments ?? {}) as Record<string, unknown>;
      options.upstreamCallsLog.push({ tool: toolName, args });

      if (toolName === 'subject_echo') {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                echoed: String(args.text ?? ''),
                upstream: options.serverName,
              }),
            },
          ],
        };
      }

      if (toolName === 'subject_math_add') {
        const a = Number(args.a);
        const b = Number(args.b);
        if (a < 0 || b < 0) {
          return {
            isError: true,
            content: [{ type: 'text', text: 'Negative operands are disallowed by upstream server' }],
          };
        }
        return {
          content: [{ type: 'text', text: JSON.stringify({ sum: a + b }) }],
        };
      }

      if (toolName === 'subject_protocol_fail') {
        throw new McpError(ErrorCode.InvalidParams, 'Upstream rejected parameters on subject_protocol_fail');
      }

      return {
        isError: true,
        content: [{ type: 'text', text: `Unknown upstream tool ${toolName}` }],
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
  await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
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

describe('Complete Three-Endpoint Implementation (G1 /handshake, G2 /issuetoken, G3 /execute)', () => {
  let tmpDir: string;
  let sqlitePath: string;
  let upstreamServer: { url: string; close: () => Promise<void> };
  const upstreamCallsLog: Array<{ tool: string; args: Record<string, unknown> }> = [];
  let gateway: AamarvaMcpGateway;
  let gatewayHttp: http.Server;
  let gatewayBaseUrl: string;
  let aamarvaClient: LocalTestAamarvaBackendClient;
  let config: GatewayConfig;

  const upstreamSecretHeader = 'Bearer upstream-complete-secret-7733';
  const backendAuthSecret = 'aamarva-complete-three-endpoints-hmac-secret-01';

  const aamarvaPair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const gatewayPair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

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
      'content-type': 'application/json',
      'x-aamarva-gateway-id': config.gatewayId,
      'x-aamarva-timestamp': timestamp,
      'x-aamarva-request-id': requestId,
      'x-aamarva-hmac-sha256': hmac,
    };
  }

  async function issueAgentToken(params: {
    agentId: string;
    agentName: string;
    agentKeys: ReturnType<typeof generateP256KeyPair>;
    allowedTools: string[];
    accountId?: string;
    connectionId?: string;
    ttlMs?: number;
    expiresInMinutes?: number;
  }) {
    const now = Date.now();
    const authId = `auth_${crypto.randomBytes(6).toString('hex')}`;
    const expiresInMinutes = params.expiresInMinutes ?? 2;
    const claims = {
      authorizationId: authId,
      invocationId: authId,
      gatewayId: config.gatewayId,
      accountId: params.accountId ?? 'acc_complete_01',
      integrationId: 'int_complete_01',
      ...(params.connectionId ? { connectionId: params.connectionId } : {}),
      agentId: params.agentId,
      agentName: params.agentName,
      agentPublicKeyPem: params.agentKeys.publicKey,
      agentPublicKeyFingerprint: params.agentKeys.fingerprint,
      allowedTools: params.allowedTools,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + (params.ttlMs ?? 120_000)).toISOString(),
    };
    const body = {
      keyId: 'aamarva-core-k1',
      claims,
      signature: signPayloadAsMockAamarva(claims, aamarvaPair.privateKey),
      expires_in_minutes: expiresInMinutes,
    };
    const headers = signBackendHeaders('/issuetoken', body);
    const resp = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    const json = (await resp.json()) as Record<string, unknown>;
    return { status: resp.status, json, authorizationId: authId };
  }

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agw-complete-'));
    sqlitePath = path.join(tmpDir, 'complete.db');

    upstreamServer = await startUpstreamSubjectMcpServer({
      serverName: 'real-customer-subject-mcp',
      requiredAuthHeader: upstreamSecretHeader,
      upstreamCallsLog,
    });

    config = validateGatewayConfig({
      nodeEnv: 'test',
      port: 3000,
      gatewayId: 'gw_complete_01',
      mcpServerId: 'mcp_complete_01',
      gatewayPublicUrl: undefined,
      gatewayIdentity: {
        activeSigningKeyId: 'gw-complete-key-1',
        signingKeys: {
          'gw-complete-key-1': {
            privateKeyPem: gatewayPair.privateKey,
            publicKeyPem: gatewayPair.publicKey,
          },
        },
      },
      aamarva: {
        adapterEnabled: true,
        baseUrl: 'https://api.aamarva.test.internal',
        backendAuthSecret,
        trustedSigningKeys: { 'aamarva-core-k1': aamarvaPair.publicKey },
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
        httpUrl: upstreamServer.url,
        upstreamAuthHeader: upstreamSecretHeader,
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

    gatewayHttp = http.createServer(gateway.createStandaloneApp());
    await new Promise<void>((resolve) => gatewayHttp.listen(0, '127.0.0.1', resolve));
    const addr = gatewayHttp.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    gatewayBaseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    if (gatewayHttp) {
      await new Promise<void>((resolve) => gatewayHttp.close(() => resolve()));
    }
    if (gateway) await gateway.stop();
    if (upstreamServer) await upstreamServer.close();
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('G1 POST /handshake returns real upstream initialization metadata, capabilities, tools, and signed attestation', async () => {
    const now = Date.now();
    const challenge = `chl_g1_${crypto.randomBytes(10).toString('hex')}`;
    const claims = {
      challenge,
      gatewayId: config.gatewayId,
      accountId: 'acc_complete_01',
      integrationId: 'int_complete_01',
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 120_000).toISOString(),
    };
    const body = {
      keyId: 'aamarva-core-k1',
      claims,
      signature: signPayloadAsMockAamarva(claims, aamarvaPair.privateKey),
    };
    const headers = signBackendHeaders('/handshake', body);

    const resp = await fetch(`${gatewayBaseUrl}/handshake`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    expect(resp.status).toBe(200);
    const json = (await resp.json()) as {
      verified: boolean;
      protocolVersion: string;
      serverInfo: { name: string; version?: string };
      capabilities: Record<string, unknown>;
      serverCapabilities: Record<string, unknown>;
      mcpInitialize: {
        protocolVersion: string;
        serverInfo?: { name: string; version?: string };
        capabilities: Record<string, unknown>;
      };
      tools: Array<{ name: string; description?: string; inputSchema: unknown }>;
      attestation: Record<string, unknown>;
      gatewayPublicKey: GatewayPublicKeyMetadata;
      gatewaySignature: string;
    };

    expect(json.verified).toBe(true);
    expect(json.protocolVersion.length).toBeGreaterThan(0);
    expect(json.serverInfo).toEqual({ name: 'real-customer-subject-mcp', version: '4.2.0' });
    expect(json.capabilities).toEqual({ tools: { listChanged: false } });
    expect(json.serverCapabilities).toEqual({ tools: { listChanged: false } });
    expect(json.mcpInitialize.protocolVersion).toBe(json.protocolVersion);
    expect(json.mcpInitialize.serverInfo).toEqual(json.serverInfo);
    expect(json.mcpInitialize.capabilities).toEqual(json.capabilities);
    expect(json.tools.map((t) => t.name).sort()).toEqual([
      'subject_admin_danger',
      'subject_echo',
      'subject_math_add',
      'subject_protocol_fail',
    ]);

    const attCheck = verifyGatewayAttestation({
      attestation: json.attestation as never,
      signatureBase64: json.gatewaySignature,
      trustedGatewayKeys: { [json.gatewayPublicKey.keyId]: json.gatewayPublicKey },
      expectedChallenge: challenge,
      expectedAccountId: 'acc_complete_01',
      expectedIntegrationId: 'int_complete_01',
      expectedGatewayId: config.gatewayId,
      expectedCanonicalEndpoint: upstreamServer.url,
    });
    expect(attCheck.valid).toBe(true);
    expect(JSON.stringify(json)).not.toContain(upstreamSecretHeader);
  });

  it('G2 POST /issuetoken requires agentName, agentId, valid P-256 public key, verifies AAMARVA signature, and binds encrypted envelope exclusively to that agent key', async () => {
    const agentKeys = generateP256KeyPair();
    const otherAgentKeys = generateP256KeyPair();
    const now = Date.now();
    const baseClaims = {
      authorizationId: `auth_g2_${crypto.randomBytes(6).toString('hex')}`,
      invocationId: `inv_g2_${crypto.randomBytes(6).toString('hex')}`,
      gatewayId: config.gatewayId,
      accountId: 'acc_complete_01',
      integrationId: 'int_complete_01',
      agentId: 'agent_g2_01',
      agentName: 'Procurement Assistant G2',
      agentPublicKeyPem: agentKeys.publicKey,
      agentPublicKeyFingerprint: agentKeys.fingerprint,
      allowedTools: ['subject_echo'],
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 120_000).toISOString(),
    };

    // 1. Missing agentName -> 400 MISSING_AGENT_NAME
    const missingNameClaims = { ...baseClaims, invocationId: `inv_noname_${crypto.randomBytes(4).toString('hex')}` };
    delete (missingNameClaims as Record<string, unknown>).agentName;
    const missingNameBody = {
      keyId: 'aamarva-core-k1',
      claims: missingNameClaims,
      signature: signPayloadAsMockAamarva(missingNameClaims, aamarvaPair.privateKey),
      expires_in_minutes: 2,
    };
    const missingNameRes = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: signBackendHeaders('/issuetoken', missingNameBody),
      body: JSON.stringify(missingNameBody),
    });
    expect(missingNameRes.status).toBe(400);
    expect(((await missingNameRes.json()) as { error: string }).error).toBe('MISSING_AGENT_NAME');

    // 2. Blank agentId -> 400 MISSING_AGENT_ID
    const blankIdClaims = {
      ...baseClaims,
      agentId: '   ',
      invocationId: `inv_noid_${crypto.randomBytes(4).toString('hex')}`,
    };
    const blankIdBody = {
      keyId: 'aamarva-core-k1',
      claims: blankIdClaims,
      signature: signPayloadAsMockAamarva(blankIdClaims, aamarvaPair.privateKey),
      expires_in_minutes: 2,
    };
    const blankIdRes = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: signBackendHeaders('/issuetoken', blankIdBody),
      body: JSON.stringify(blankIdBody),
    });
    expect(blankIdRes.status).toBe(400);
    expect(((await blankIdRes.json()) as { error: string }).error).toBe('MISSING_AGENT_ID');

    // 3. Invalid AAMARVA signature -> 401 INVALID_AAMARVA_SIGNATURE
    const badSigBody = {
      keyId: 'aamarva-core-k1',
      claims: baseClaims,
      signature: crypto.randomBytes(64).toString('base64'),
      expires_in_minutes: 2,
    };
    const badSigRes = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: signBackendHeaders('/issuetoken', badSigBody),
      body: JSON.stringify(badSigBody),
    });
    expect(badSigRes.status).toBe(401);
    expect(((await badSigRes.json()) as { error: string }).error).toBe('INVALID_AAMARVA_SIGNATURE');

    // 4. Valid request succeeds and only the target agent's private key can decrypt
    const validRes = await issueAgentToken({
      agentId: 'agent_g2_01',
      agentName: 'Procurement Assistant G2',
      agentKeys,
      allowedTools: ['subject_echo'],
    });
    expect(validRes.status).toBe(201);
    expect(JSON.stringify(validRes.json)).not.toContain('agw1.');

    const { gatewaySignature, ...unsignedPayload } = validRes.json as {
      gatewaySignature: { signature: string };
      gatewayPublicKey: GatewayPublicKeyMetadata;
      encryptedToken: EncryptedTokenEnvelope;
    } & Record<string, unknown>;
    expect(
      verifyGatewayResponseSignature({
        payload: unsignedPayload,
        signatureBase64: gatewaySignature.signature,
        gatewayPublicKey: unsignedPayload.gatewayPublicKey,
      }),
    ).toBe(true);

    // Wrong private key CANNOT decrypt
    expect(() =>
      decryptTokenAsAgent(unsignedPayload.encryptedToken, otherAgentKeys.privateKey),
    ).toThrow();

    // Target private key CAN decrypt
    const decrypted = decryptTokenAsAgent(unsignedPayload.encryptedToken, agentKeys.privateKey);
    expect(decrypted.token.startsWith('agw1.')).toBe(true);
  });

  it('G3 POST /execute acts as full authenticated MCP interface for @modelcontextprotocol/sdk Client + StreamableHTTPClientTransport and isolates upstream tools', async () => {
    const agentKeys = generateP256KeyPair();
    const issued = await issueAgentToken({
      agentId: 'agent_sdk_01',
      agentName: 'MCP SDK Client Agent',
      agentKeys,
      allowedTools: ['subject_echo', 'subject_math_add', 'subject_protocol_fail'],
    });
    expect(issued.status).toBe(201);
    const decrypted = decryptTokenAsAgent(
      issued.json.encryptedToken as EncryptedTokenEnvelope,
      agentKeys.privateKey,
    );

    const callsBefore = upstreamCallsLog.length;

    const transport = new StreamableHTTPClientTransport(new URL(`${gatewayBaseUrl}/execute`), {
      requestInit: {
        headers: {
          Authorization: `Bearer ${decrypted.token}`,
          'x-aamarva-agent-id': 'agent_sdk_01',
        },
      },
    });
    const client = new Client(
      { name: 'test-agent-client', version: '1.0.0' },
      { capabilities: {} },
    );

    await client.connect(transport);
    try {
      // 1. tools/list returns real upstream tool metadata strictly filtered to allowedTools (subject_admin_danger omitted!)
      const listed = await client.listTools();
      expect(listed.tools.map((t) => t.name).sort()).toEqual([
        'subject_echo',
        'subject_math_add',
        'subject_protocol_fail',
      ]);

      // 2. tools/call executes authorized tool against real upstream MCP server
      const echoRes = await client.callTool({
        name: 'subject_echo',
        arguments: { text: 'hello via StreamableHTTPClientTransport' },
      });
      const echoText = (echoRes.content as Array<{ type: string; text: string }>)[0].text;
      expect(JSON.parse(echoText)).toEqual({
        echoed: 'hello via StreamableHTTPClientTransport',
        upstream: 'real-customer-subject-mcp',
      });
      expect(JSON.stringify(echoRes)).not.toContain(upstreamSecretHeader);
      expect(JSON.stringify(echoRes)).not.toContain(upstreamServer.url);

      // 3. Upstream tool-level error (isError: true) propagates cleanly
      const negAddRes = await client.callTool({
        name: 'subject_math_add',
        arguments: { a: -5, b: 10 },
      });
      expect(negAddRes.isError).toBe(true);
      expect((negAddRes.content as Array<{ text: string }>)[0].text).toContain('Negative operands');

      // 4. Upstream McpError propagates cleanly
      await expect(
        client.callTool({
          name: 'subject_protocol_fail',
          arguments: {},
        }),
      ).rejects.toThrow(/Upstream rejected parameters/);

      // 5. Unauthorized tool NOT in allowedTools is blocked at Gateway BEFORE reaching upstream
      const logLenBeforeDenied = upstreamCallsLog.length;
      await expect(
        client.callTool({
          name: 'subject_admin_danger',
          arguments: {},
        }),
      ).rejects.toThrow(/TOOL_NOT_AUTHORIZED|outside the authorized scope/i);
      expect(upstreamCallsLog.length).toBe(logLenBeforeDenied);

      // Confirm earlier valid calls genuinely reached upstream MCP server
      expect(upstreamCallsLog.length).toBeGreaterThan(callsBefore);
    } finally {
      await client.close();
    }
  });

  it('G3 POST /execute enforces single-shot replay protection, agent/session binding, expiry, revocation, and rejects invalid tokens', async () => {
    const agentKeysA = generateP256KeyPair();
    const agentKeysB = generateP256KeyPair();

    const issuedA1 = await issueAgentToken({
      agentId: 'agent_g3_a',
      agentName: 'Agent G3 A',
      agentKeys: agentKeysA,
      allowedTools: ['subject_echo'],
    });
    expect(issuedA1.status).toBe(201);
    const tokenA1 = decryptTokenAsAgent(
      issuedA1.json.encryptedToken as EncryptedTokenEnvelope,
      agentKeysA.privateKey,
    ).token;

    const issuedA2 = await issueAgentToken({
      agentId: 'agent_g3_a',
      agentName: 'Agent G3 A',
      agentKeys: agentKeysA,
      allowedTools: ['subject_echo'],
    });
    const tokenA2 = decryptTokenAsAgent(
      issuedA2.json.encryptedToken as EncryptedTokenEnvelope,
      agentKeysA.privateKey,
    ).token;

    const issuedB = await issueAgentToken({
      agentId: 'agent_g3_b',
      agentName: 'Agent G3 B',
      agentKeys: agentKeysB,
      allowedTools: ['subject_echo'],
    });
    const tokenB = decryptTokenAsAgent(
      issuedB.json.encryptedToken as EncryptedTokenEnvelope,
      agentKeysB.privateKey,
    ).token;

    // 1. Missing token & session -> 401 MISSING_EXECUTION_TOKEN
    const noTokRes = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
    });
    expect(noTokRes.status).toBe(401);

    // 2. Forged/nonexistent well-formed token -> 403 TOKEN_NOT_FOUND
    const forgedToken = `agw1.tok_${'a'.repeat(32)}.${'A'.repeat(43)}`;
    const forgedRes = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${forgedToken}`,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
    });
    expect(forgedRes.status).toBe(403);

    // 3. Wrong agentId claim rejected BEFORE consuming valid token -> 403 AGENT_MISMATCH
    const wrongAgentRes = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${tokenA1}`,
        'x-aamarva-agent-id': 'agent_imposter',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 3,
        method: 'tools/call',
        params: { name: 'subject_echo', arguments: { text: 'should-fail' } },
      }),
    });
    expect(wrongAgentRes.status).toBe(403);

    // 4. Single-shot JSON-RPC tools/call succeeds once with Bearer token (returns mcp-session-id)
    const singleShotRes = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${tokenA1}`,
        'x-aamarva-agent-id': 'agent_g3_a',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 4,
        method: 'tools/call',
        params: { name: 'subject_echo', arguments: { text: 'one-shot' } },
      }),
    });
    expect(singleShotRes.status).toBe(200);
    const sessionA1 = singleShotRes.headers.get('mcp-session-id');
    expect(sessionA1).toBeTruthy();
    const singleShotJson = (await singleShotRes.json()) as {
      jsonrpc: string;
      id: number;
      result: { content: Array<{ text: string }> };
    };
    expect(JSON.parse(singleShotJson.result.content[0].text)).toEqual({
      echoed: 'one-shot',
      upstream: 'real-customer-subject-mcp',
    });

    // 5. Replaying same token WITHOUT mcp-session-id is blocked with 409 TOKEN_ALREADY_REDEEMED
    const replayRes = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${tokenA1}`,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'tools/list', params: {} }),
    });
    expect(replayRes.status).toBe(409);

    // 6. Presenting another agent's token (tokenB) against sessionA1 is blocked -> 403 SESSION_TOKEN_MISMATCH
    const crossSessionRes = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${tokenB}`,
        'mcp-session-id': sessionA1!,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 6, method: 'tools/list', params: {} }),
    });
    expect(crossSessionRes.status).toBe(403);

    // 7. Unsupported MCP method fails closed with -32601
    const badMethodRes = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${tokenA1}`,
        'mcp-session-id': sessionA1!,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 7, method: 'resources/read', params: { uri: 'file:///etc/passwd' } }),
    });
    expect(badMethodRes.status).toBe(400);
    const badMethodJson = (await badMethodRes.json()) as { error: { code: number } };
    expect(badMethodJson.error.code).toBe(-32601);

    // 8. Session revocation immediately blocks subsequent MCP calls on sessionA1 -> 401
    await gateway.sessionManager.revokeSession(sessionA1!, 'Revoked in G3 test', 'test-admin');
    const afterRevokeRes = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${tokenA1}`,
        'mcp-session-id': sessionA1!,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 8, method: 'tools/list', params: {} }),
    });
    expect(afterRevokeRes.status).toBe(401);

    // 9. Authorization grant revocation before redemption blocks tokenA2 -> 401
    const revClaims = {
      revocationId: `rev_g3_${crypto.randomBytes(6).toString('hex')}`,
      authorizationId: issuedA2.authorizationId,
      reason: 'Authorization revoked prior to use',
      revokedBy: 'security-ops',
      revokedAt: new Date().toISOString(),
    };
    await gateway.authAdapter.processRevocation(
      {
        keyId: 'aamarva-core-k1',
        claims: revClaims,
        signature: signPayloadAsMockAamarva(revClaims, aamarvaPair.privateKey),
      },
      'corr_rev_g3',
    );
    const revokedTokenRes = await fetch(`${gatewayBaseUrl}/execute`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${tokenA2}`,
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/list', params: {} }),
    });
    expect(revokedTokenRes.status).toBe(401);
  });

  it('G2 POST /issuetoken requires top-level positive safe integer expires_in_minutes, rejects missing/claims-only/invalid/conflicting values with no fallback, and configures token expiration from it', async () => {
    const agentKeys = generateP256KeyPair();

    const makeBaseClaims = () => {
      const now = Date.now();
      const authId = `auth_exp_${crypto.randomBytes(5).toString('hex')}`;
      return {
        authorizationId: authId,
        invocationId: authId,
        gatewayId: config.gatewayId,
        accountId: 'acc_complete_01',
        integrationId: 'int_complete_01',
        agentId: 'agent_exp_01',
        agentName: 'Expiration Validation Agent',
        agentPublicKeyPem: agentKeys.publicKey,
        agentPublicKeyFingerprint: agentKeys.fingerprint,
        allowedTools: ['subject_echo'],
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + 60 * 60_000).toISOString(),
      };
    };

    // 1. Missing top-level expires_in_minutes -> 400 MISSING_EXPIRES_IN_MINUTES
    const missingClaims = makeBaseClaims();
    const missingBody = {
      keyId: 'aamarva-core-k1',
      claims: missingClaims,
      signature: signPayloadAsMockAamarva(missingClaims, aamarvaPair.privateKey),
    };
    const missingRes = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: signBackendHeaders('/issuetoken', missingBody),
      body: JSON.stringify(missingBody),
    });
    expect(missingRes.status).toBe(400);
    expect(((await missingRes.json()) as { error: string }).error).toBe('MISSING_EXPIRES_IN_MINUTES');

    // 2. Omitting top-level expires_in_minutes EVEN WHEN claims.expires_in_minutes is present -> 400 MISSING_EXPIRES_IN_MINUTES
    const claimsOnly = { ...makeBaseClaims(), expires_in_minutes: 7 };
    const claimsOnlyBody = {
      keyId: 'aamarva-core-k1',
      claims: claimsOnly,
      signature: signPayloadAsMockAamarva(claimsOnly, aamarvaPair.privateKey),
    };
    const claimsOnlyRes = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: signBackendHeaders('/issuetoken', claimsOnlyBody),
      body: JSON.stringify(claimsOnlyBody),
    });
    expect(claimsOnlyRes.status).toBe(400);
    expect(((await claimsOnlyRes.json()) as { error: string }).error).toBe('MISSING_EXPIRES_IN_MINUTES');

    // 3. Zero, negative, decimal, string, boolean, null, object/array, unsafe integer/overflow -> 400 INVALID_EXPIRES_IN_MINUTES
    const invalidValues: unknown[] = [
      0,
      -1,
      -15,
      1.5,
      '5',
      '',
      null,
      true,
      false,
      [],
      {},
      Number.MAX_SAFE_INTEGER,
      9999999999999,
    ];
    for (const badVal of invalidValues) {
      const c = makeBaseClaims();
      const badBody = {
        keyId: 'aamarva-core-k1',
        claims: c,
        signature: signPayloadAsMockAamarva(c, aamarvaPair.privateKey),
        expires_in_minutes: badVal,
      };
      const badRes = await fetch(`${gatewayBaseUrl}/issuetoken`, {
        method: 'POST',
        headers: signBackendHeaders('/issuetoken', badBody),
        body: JSON.stringify(badBody),
      });
      expect(badRes.status).toBe(400);
      expect(((await badRes.json()) as { error: string }).error).toBe('INVALID_EXPIRES_IN_MINUTES');
    }

    // 4. Conflicting expires_in_minutes between top-level body and claims -> 400 INVALID_EXPIRES_IN_MINUTES
    const conflictClaims = { ...makeBaseClaims(), expires_in_minutes: 5 };
    const conflictBody = {
      keyId: 'aamarva-core-k1',
      claims: conflictClaims,
      signature: signPayloadAsMockAamarva(conflictClaims, aamarvaPair.privateKey),
      expires_in_minutes: 10,
    };
    const conflictRes = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: signBackendHeaders('/issuetoken', conflictBody),
      body: JSON.stringify(conflictBody),
    });
    expect(conflictRes.status).toBe(400);
    expect(((await conflictRes.json()) as { error: string }).error).toBe('INVALID_EXPIRES_IN_MINUTES');

    // 5. Positive integer top-level expires_in_minutes configures issued token expiration accurately (no default/fallback)
    for (const minutes of [1, 5, 15]) {
      const beforeMs = Date.now();
      const issued = await issueAgentToken({
        agentId: 'agent_exp_01',
        agentName: 'Expiration Validation Agent',
        agentKeys,
        allowedTools: ['subject_echo'],
        ttlMs: 60 * 60_000,
        expiresInMinutes: minutes,
      });
      const afterMs = Date.now();

      expect(issued.status).toBe(201);
      const expiresAtMs = Date.parse(String(issued.json.expiresAt));
      const expectedMinMs = beforeMs + minutes * 60_000 - 1_500;
      const expectedMaxMs = afterMs + minutes * 60_000 + 1_500;
      expect(expiresAtMs).toBeGreaterThanOrEqual(expectedMinMs);
      expect(expiresAtMs).toBeLessThanOrEqual(expectedMaxMs);

      const env = issued.json.encryptedToken as EncryptedTokenEnvelope;
      expect(env.expiresAt).toBe(issued.json.expiresAt);
      const dec = decryptTokenAsAgent(env, agentKeys.privateKey);
      expect(dec.expiresAt).toBe(issued.json.expiresAt);
    }

    // 6. Matching top-level and claims.expires_in_minutes succeeds and uses top-level value
    const beforeMatchMs = Date.now();
    const matchingClaims = { ...makeBaseClaims(), expires_in_minutes: 7 };
    const matchingBody = {
      keyId: 'aamarva-core-k1',
      claims: matchingClaims,
      signature: signPayloadAsMockAamarva(matchingClaims, aamarvaPair.privateKey),
      expires_in_minutes: 7,
    };
    const matchingRes = await fetch(`${gatewayBaseUrl}/issuetoken`, {
      method: 'POST',
      headers: signBackendHeaders('/issuetoken', matchingBody),
      body: JSON.stringify(matchingBody),
    });
    const afterMatchMs = Date.now();
    expect(matchingRes.status).toBe(201);
    const matchingJson = (await matchingRes.json()) as { expiresAt: string };
    const matchingExpMs = Date.parse(matchingJson.expiresAt);
    expect(matchingExpMs).toBeGreaterThanOrEqual(beforeMatchMs + 7 * 60_000 - 1_500);
    expect(matchingExpMs).toBeLessThanOrEqual(afterMatchMs + 7 * 60_000 + 1_500);
  });
});
