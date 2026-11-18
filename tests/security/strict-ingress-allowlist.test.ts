import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import express from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServerApp } from '../../server.ts';
import { LocalTestAamarvaBackendClient } from '../../src/gateway/aamarva/aamarva-client.ts';
import { sha256Hex } from '../../src/gateway/config/security.ts';
import { validateGatewayConfig, type GatewayConfig } from '../../src/gateway/config/validation.ts';
import { AamarvaMcpGateway } from '../../src/gateway/core/gateway.ts';
import type { EncryptedTokenEnvelope } from '../../src/gateway/crypto/envelope-encryption.ts';
import { createGatewayApp } from '../../src/gateway/index.ts';
import {
  decryptTokenAsAgent,
  signPayloadAsMockAamarva,
} from '../fixtures/agent-decryption-harness.ts';

function rawHttpRequest(
  baseUrl: string,
  options: {
    method: string;
    rawPath: string;
    headers?: Record<string, string>;
    body?: string;
  },
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  const parsed = new URL(baseUrl);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: Number(parsed.port),
        method: options.method,
        path: options.rawPath,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.on('error', reject);
    if (options.body !== undefined) {
      req.write(options.body);
    }
    req.end();
  });
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

async function startSubjectMcpServer(secretHeader: string): Promise<{ url: string; close: () => Promise<void> }> {
  const app = express();
  app.use(express.json());

  app.post('/mcp', async (req, res) => {
    if (req.header('authorization') !== secretHeader) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const server = new Server(
      { name: 'strict-ingress-subject-mcp', version: '1.0.0' },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'subject_ping',
          description: 'Ping tool',
          inputSchema: { type: 'object', properties: { msg: { type: 'string' } } },
        },
      ],
    }));
    server.setRequestHandler(CallToolRequestSchema, async (request) => ({
      content: [{ type: 'text', text: JSON.stringify({ pong: request.params.arguments?.msg ?? 'ok' }) }],
    }));

    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on('close', () => {
      void transport.close();
      void server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}

describe('Strict Three-Endpoint-Only Public Access Enforcement Across All Entrypoints', () => {
  let tmpDir: string;
  let distDir: string;
  let subjectServer: { url: string; close: () => Promise<void> };

  const aamarvaPair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const gatewayPair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const backendAuthSecret = 'strict-ingress-hmac-secret-1234567890';
  const subjectSecretHeader = 'Bearer super-secret-upstream-token-never-leak';

  function buildConfig(overrides: {
    sqliteFile: string;
    adapterEnabled?: boolean;
    enableOperatorConsole?: boolean;
    httpUrl?: string;
  }): GatewayConfig {
    return validateGatewayConfig({
      nodeEnv: 'test',
      port: 3000,
      gatewayId: 'gw_strict_01',
      mcpServerId: 'mcp_strict_01',
      gatewayPublicUrl: 'https://gateway.strict.example',
      gatewayIdentity: {
        activeSigningKeyId: 'gw-strict-key-1',
        signingKeys: {
          'gw-strict-key-1': {
            privateKeyPem: gatewayPair.privateKey,
            publicKeyPem: gatewayPair.publicKey,
          },
        },
      },
      aamarva: {
        adapterEnabled: overrides.adapterEnabled ?? true,
        baseUrl: 'https://api.aamarva.test.internal',
        backendAuthSecret,
        trustedSigningKeys: { 'aamarva-k1': aamarvaPair.publicKey },
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
        sqliteDbPath: overrides.sqliteFile,
      },
      mcp: {
        transport: 'streamable-http',
        httpUrl: overrides.httpUrl ?? subjectServer.url,
        upstreamAuthHeader: subjectSecretHeader,
        stdioCommand: 'node',
        stdioArgs: [],
        requestTimeoutMs: 2500,
      },
      features: {
        enableOperatorConsole: overrides.enableOperatorConsole ?? true,
        enableSandbox: false,
      },
    });
  }

  function signBackendHeaders(gateway: AamarvaMcpGateway, reqPath: string, bodyObj: unknown) {
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
      rawBody,
      headers: {
        'content-type': 'application/json',
        'x-aamarva-gateway-id': gateway.config.gatewayId,
        'x-aamarva-timestamp': timestamp,
        'x-aamarva-request-id': requestId,
        'x-aamarva-hmac-sha256': hmac,
      },
    };
  }

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agw-strict-'));
    distDir = path.join(tmpDir, 'dist');
    fs.mkdirSync(path.join(distDir, 'assets'), { recursive: true });
    fs.writeFileSync(
      path.join(distDir, 'index.html'),
      '<!doctype html><html><body>Operator Console SPA</body></html>',
      'utf8',
    );
    fs.writeFileSync(path.join(distDir, 'assets', 'app.js'), 'console.log("operator-ui");', 'utf8');
    subjectServer = await startSubjectMcpServer(subjectSecretHeader);
  });

  afterAll(async () => {
    if (subjectServer) await subjectServer.close();
    if (tmpDir) fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  for (const entrypointName of ['server.ts (createServerApp)', 'src/gateway/index.ts (createGatewayApp)'] as const) {
    it(`enforces strict three-endpoint-only ingress on ${entrypointName}`, async () => {
      const cfg = buildConfig({
        sqliteFile: path.join(tmpDir, `${entrypointName.replace(/[^a-z]/gi, '_')}.db`),
        adapterEnabled: true,
        enableOperatorConsole: true,
      });
      const aamarvaClient = new LocalTestAamarvaBackendClient();
      const gateway = new AamarvaMcpGateway(cfg, { aamarvaClient, silentLogger: true });
      await gateway.start({ connectMcpOnBoot: false });

      const built =
        entrypointName === 'server.ts (createServerApp)'
          ? await createServerApp({ config: cfg, gateway, distDir, forceProdStatic: true })
          : await createGatewayApp({ config: cfg, gateway });

      const httpServer = http.createServer(built.app);
      await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
      const addr = httpServer.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      const baseUrl = `http://127.0.0.1:${port}`;

      try {
        // 1. Root /, health, readiness, console, static files, SPA fallback, legacy & unknown routes -> 404 without HTML or redirects
        const blocked404Requests: Array<{ method: string; rawPath: string }> = [
          { method: 'GET', rawPath: '/' },
          { method: 'POST', rawPath: '/' },
          { method: 'GET', rawPath: '/healthz' },
          { method: 'GET', rawPath: '/readyz' },
          { method: 'GET', rawPath: '/api/console/status' },
          { method: 'POST', rawPath: '/api/console/sessions/sess_1/revoke' },
          { method: 'POST', rawPath: '/api/console/sandbox/issue-token' },
          { method: 'GET', rawPath: '/index.html' },
          { method: 'GET', rawPath: '/assets/app.js' },
          { method: 'GET', rawPath: '/some-spa-view' },
          { method: 'GET', rawPath: '/dashboard' },
          { method: 'POST', rawPath: '/api/v1/redeem' },
          { method: 'POST', rawPath: '/api/v1/aamarva/mcp/tools/list' },
          { method: 'POST', rawPath: '/api/v1/aamarva/mcp/tools/call' },
          { method: 'POST', rawPath: '/api/v1/aamarva/mcp/handshake' },
          { method: 'POST', rawPath: '/api/v1/aamarva/authorizations/issue-token' },
          { method: 'POST', rawPath: '/api/v1/aamarva/authorizations/revoke' },
          { method: 'POST', rawPath: '/mcp' },
          { method: 'POST', rawPath: '/v1/handshake' },
          { method: 'GET', rawPath: '/metrics' },
          { method: 'GET', rawPath: '/docs' },
          { method: 'GET', rawPath: '/status' },
          // Encoding, trailing slash, case, and dot-segment variations -> 404
          { method: 'POST', rawPath: '/handshake/' },
          { method: 'POST', rawPath: '/issuetoken/' },
          { method: 'POST', rawPath: '/execute/' },
          { method: 'POST', rawPath: '/%68andshake' },
          { method: 'POST', rawPath: '/%69ssuetoken' },
          { method: 'POST', rawPath: '/%65xecute' },
          { method: 'POST', rawPath: '/./handshake' },
          { method: 'POST', rawPath: '//handshake' },
          { method: 'POST', rawPath: '/a/../handshake' },
          { method: 'POST', rawPath: '/Handshake' },
          { method: 'POST', rawPath: '/IssueToken' },
          { method: 'POST', rawPath: '/Execute' },
          { method: 'POST', rawPath: '/%ZZ' },
        ];

        for (const testCase of blocked404Requests) {
          const r = await rawHttpRequest(baseUrl, {
            method: testCase.method,
            rawPath: testCase.rawPath,
            headers: testCase.method === 'POST' ? { 'content-type': 'application/json' } : undefined,
            body: testCase.method === 'POST' ? '{}' : undefined,
          });
          expect(r.status, `${testCase.method} ${testCase.rawPath} expected 404`).toBe(404);
          expect(r.headers.location).toBeUndefined();
          expect(r.body).not.toContain('Operator Console SPA');
          expect(r.body).not.toContain('operator-ui');
        }

        // 2. Unsupported HTTP methods on the three permitted exact paths -> 405 Method Not Allowed
        for (const ep of ['/handshake', '/issuetoken', '/execute']) {
          for (const method of ['GET', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
            const r = await rawHttpRequest(baseUrl, {
              method,
              rawPath: ep,
              headers: method === 'PUT' || method === 'PATCH' ? { 'content-type': 'application/json' } : undefined,
              body: method === 'PUT' || method === 'PATCH' ? '{}' : undefined,
            });
            expect(r.status, `${method} ${ep} expected 405`).toBe(405);
            expect(r.headers.allow).toBe('POST');
            expect(r.headers.location).toBeUndefined();
          }
        }

        // 3. Untrusted headers / query params / body fields CANNOT disable adapterEnabled strict ingress
        const bypassAttempts: Array<{
          method: string;
          rawPath: string;
          headers?: Record<string, string>;
          body?: string;
        }> = [
          {
            method: 'GET',
            rawPath: '/healthz?adapter=disabled&adapterEnabled=false',
            headers: {
              'x-aamarva-adapter': 'false',
              'x-adapter-enabled': 'false',
            },
          },
          {
            method: 'GET',
            rawPath: '/api/console/status?enableOperatorConsole=true',
            headers: {
              'x-aamarva-adapter': '0',
            },
          },
          {
            method: 'POST',
            rawPath: '/api/console/status',
            headers: {
              'content-type': 'application/json',
              'x-aamarva-adapter': 'false',
            },
            body: JSON.stringify({ adapterEnabled: false }),
          },
        ];
        for (const bypassAttempt of bypassAttempts) {
          const r = await rawHttpRequest(baseUrl, bypassAttempt);
          expect(r.status).toBe(404);
        }

        // 4. Positive canonical workflow on POST /handshake -> POST /issuetoken -> POST /execute
        const now = Date.now();
        const hsClaims = {
          challenge: `chl_strict_${crypto.randomBytes(6).toString('hex')}`,
          gatewayId: cfg.gatewayId,
          accountId: 'acc_strict_01',
          integrationId: 'int_strict_01',
          issuedAt: new Date(now).toISOString(),
          expiresAt: new Date(now + 120_000).toISOString(),
        };
        const hsBody = {
          keyId: 'aamarva-k1',
          claims: hsClaims,
          signature: signPayloadAsMockAamarva(hsClaims, aamarvaPair.privateKey),
        };
        const hsSigned = signBackendHeaders(gateway, '/handshake', hsBody);
        const hsRes = await fetch(`${baseUrl}/handshake`, {
          method: 'POST',
          headers: hsSigned.headers,
          body: hsSigned.rawBody,
        });
        expect(hsRes.status).toBe(200);
        const hsJson = (await hsRes.json()) as { verified: boolean; attestation: { connectionId: string } };
        expect(hsJson.verified).toBe(true);

        // Reject legacy non-canonical /issuetoken payload (X25519 / missing canonical fields)
        const x25519 = crypto.generateKeyPairSync('x25519', {
          publicKeyEncoding: { type: 'spki', format: 'pem' },
          privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        const legacyClaims = {
          authorizationId: `auth_legacy_${crypto.randomBytes(4).toString('hex')}`,
          agentId: 'agent_legacy',
          agentPublicKeyPem: x25519.publicKey,
          mcpServerId: cfg.mcpServerId,
          gatewayId: cfg.gatewayId,
          allowedTools: ['subject_ping'],
          issuedAt: new Date(now).toISOString(),
          expiresAt: new Date(now + 60_000).toISOString(),
        };
        const legacyBody = {
          keyId: 'aamarva-k1',
          claims: legacyClaims,
          signature: signPayloadAsMockAamarva(legacyClaims, aamarvaPair.privateKey),
        };
        const legacySigned = signBackendHeaders(gateway, '/issuetoken', legacyBody);
        const legacyRes = await fetch(`${baseUrl}/issuetoken`, {
          method: 'POST',
          headers: legacySigned.headers,
          body: legacySigned.rawBody,
        });
        expect(legacyRes.status).toBe(400);

        // Canonical P-256 /issuetoken succeeds
        const agentKeys = generateP256KeyPair();
        const authId = `auth_strict_${crypto.randomBytes(4).toString('hex')}`;
        const issueClaims = {
          authorizationId: authId,
          invocationId: authId,
          gatewayId: cfg.gatewayId,
          accountId: 'acc_strict_01',
          integrationId: 'int_strict_01',
          agentId: 'agent_strict_01',
          agentName: 'Strict Agent 01',
          agentPublicKeyPem: agentKeys.publicKey,
          agentPublicKeyFingerprint: agentKeys.fingerprint,
          allowedTools: ['subject_ping'],
          issuedAt: new Date(now).toISOString(),
          expiresAt: new Date(now + 120_000).toISOString(),
        };
        const issueBody = {
          keyId: 'aamarva-k1',
          claims: issueClaims,
          signature: signPayloadAsMockAamarva(issueClaims, aamarvaPair.privateKey),
          expires_in_minutes: 2,
        };
        const issueSigned = signBackendHeaders(gateway, '/issuetoken', issueBody);
        const issueRes = await fetch(`${baseUrl}/issuetoken`, {
          method: 'POST',
          headers: issueSigned.headers,
          body: issueSigned.rawBody,
        });
        expect(issueRes.status).toBe(201);
        const issueJson = (await issueRes.json()) as { encryptedToken: EncryptedTokenEnvelope };
        const decrypted = decryptTokenAsAgent(issueJson.encryptedToken, agentKeys.privateKey);

        // /execute redeems token
        const execRes = await fetch(`${baseUrl}/execute`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            token: decrypted.token,
            agentId: 'agent_strict_01',
            accountId: 'acc_strict_01',
            mcpServerId: cfg.mcpServerId,
          }),
        });
        expect(execRes.status).toBe(200);
        const execJson = (await execRes.json()) as { redeemed: boolean; sessionId: string };
        expect(execJson.redeemed).toBe(true);
        expect(execJson.sessionId.startsWith('sess_')).toBe(true);
      } finally {
        await new Promise<void>((resolve) => httpServer.close(() => resolve()));
        await gateway.stop();
      }
    });
  }

  it('sanitizes upstream MCP failures in HTTP responses without leaking Subject MCP URL or credentials', async () => {
    // Bind a closed ephemeral port so upstream TCP connection fails deterministically with ECONNREFUSED
    const deadPort = await new Promise<number>((resolve) => {
      const probe = http.createServer();
      probe.listen(0, '127.0.0.1', () => {
        const addr = probe.address();
        const port = typeof addr === 'object' && addr ? addr.port : 0;
        probe.close(() => resolve(port));
      });
    });
    const deadSubjectUrl = `http://127.0.0.1:${deadPort}/private-upstream-mcp-secret-path`;
    const cfg = buildConfig({
      sqliteFile: path.join(tmpDir, 'sanitized_error.db'),
      adapterEnabled: true,
      httpUrl: deadSubjectUrl,
    });
    const aamarvaClient = new LocalTestAamarvaBackendClient();
    const gateway = new AamarvaMcpGateway(cfg, { aamarvaClient, silentLogger: true });
    await gateway.start({ connectMcpOnBoot: false });
    const built = await createServerApp({ config: cfg, gateway, distDir, forceProdStatic: true });

    const httpServer = http.createServer(built.app);
    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    const addr = httpServer.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      const now = Date.now();
      const claims = {
        challenge: `chl_err_${crypto.randomBytes(6).toString('hex')}`,
        gatewayId: cfg.gatewayId,
        accountId: 'acc_err_01',
        integrationId: 'int_err_01',
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + 60_000).toISOString(),
      };
      const body = {
        keyId: 'aamarva-k1',
        claims,
        signature: signPayloadAsMockAamarva(claims, aamarvaPair.privateKey),
      };
      const signed = signBackendHeaders(gateway, '/handshake', body);
      const resp = await fetch(`${baseUrl}/handshake`, {
        method: 'POST',
        headers: signed.headers,
        body: signed.rawBody,
      });

      expect(resp.status).toBe(502);
      const text = await resp.text();
      expect(text).not.toContain(deadSubjectUrl);
      expect(text).not.toContain('private-upstream-mcp-secret-path');
      expect(text).not.toContain(`127.0.0.1:${deadPort}`);
      expect(text).not.toContain('ECONNREFUSED');
      expect(text).not.toContain(subjectSecretHeader);
      expect(text).not.toContain('super-secret-upstream-token-never-leak');

      // Audit/structured log keeps detailed internal diagnostics for operator debugging
      const failureEvent = gateway.logger
        .getRecentEntries(20)
        .find((e) => e.event === 'MCP_HANDSHAKE_FAILED');
      expect(failureEvent).toBeDefined();
    } finally {
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
      await gateway.stop();
    }
  });

  it('preserves Operator Console UI and health endpoints when server-side adapterEnabled=false', async () => {
    const cfg = buildConfig({
      sqliteFile: path.join(tmpDir, 'adapter_disabled.db'),
      adapterEnabled: false,
      enableOperatorConsole: true,
    });
    const aamarvaClient = new LocalTestAamarvaBackendClient();
    const gateway = new AamarvaMcpGateway(cfg, { aamarvaClient, silentLogger: true });
    await gateway.start({ connectMcpOnBoot: false });
    const built = await createServerApp({ config: cfg, gateway, distDir, forceProdStatic: true });

    const httpServer = http.createServer(built.app);
    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    const addr = httpServer.address();
    const port = typeof addr === 'object' && addr ? addr.port : 0;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      const healthResp = await fetch(`${baseUrl}/healthz`);
      expect(healthResp.status).toBe(200);

      const readyResp = await fetch(`${baseUrl}/readyz`);
      expect([200, 503]).toContain(readyResp.status);

      const consoleStatusResp = await fetch(`${baseUrl}/api/console/status`);
      expect(consoleStatusResp.status).toBe(200);

      const rootResp = await fetch(`${baseUrl}/`);
      expect(rootResp.status).toBe(200);
      const html = await rootResp.text();
      expect(html).toContain('Operator Console SPA');
    } finally {
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
      await gateway.stop();
    }
  });
});
