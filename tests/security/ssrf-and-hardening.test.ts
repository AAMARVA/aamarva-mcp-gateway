import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
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
import { loadGatewayConfig } from '../../src/gateway/config/environment.ts';
import { validateGatewayConfig, type GatewayConfig } from '../../src/gateway/config/validation.ts';
import type { GatewayVerificationAttestation } from '../../src/gateway/core/authorization-context.ts';
import { AamarvaMcpGateway } from '../../src/gateway/core/gateway.ts';
import { encryptHandshakeCredentialEnvelope } from '../../src/gateway/crypto/credential-vault.ts';
import type { EncryptedTokenEnvelope } from '../../src/gateway/crypto/envelope-encryption.ts';
import {
  verifyGatewayAttestation,
  type GatewayPublicKeyMetadata,
} from '../../src/gateway/crypto/gateway-keypair.ts';
import {
  SsrfBlockedError,
  createSsrfSafeFetch,
  resolveAndValidateMcpDestination,
  validateAndCanonicalizeMcpUrl,
  type DnsResolvedAddress,
} from '../../src/gateway/security/ssrf-guard.ts';
import {
  decryptTokenAsAgent,
  signPayloadAsMockAamarva,
} from '../fixtures/agent-decryption-harness.ts';

async function startTestMcpHttpServer(options: {
  serverName: string;
  requiredAuthHeader?: string;
}): Promise<{
  url: string;
  port: number;
  handler: express.Express;
  close: () => Promise<void>;
}> {
  const app = express();
  app.use(express.json());

  app.post('/mcp', async (req, res) => {
    if (options.requiredAuthHeader) {
      const auth = req.header('authorization');
      if (auth !== options.requiredAuthHeader) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }
    }

    const server = new Server(
      { name: options.serverName, version: '1.0.0' },
      { capabilities: { tools: {} } },
    );

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'public_ping',
          description: 'Returns pong from public external MCP server',
          inputSchema: { type: 'object', properties: { tag: { type: 'string' } } },
        },
        {
          name: 'admin_only_tool',
          description: 'Restricted tool',
          inputSchema: { type: 'object', properties: {} },
        },
      ],
    }));

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      if (request.params.name === 'public_ping') {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                ok: true,
                server: options.serverName,
                tag: request.params.arguments?.tag ?? 'default',
              }),
            },
          ],
        };
      }
      return {
        isError: true,
        content: [{ type: 'text', text: 'Unknown tool' }],
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

  const srv = http.createServer(app);
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', () => resolve()));
  const addr = srv.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;

  return {
    url: `http://127.0.0.1:${port}/mcp`,
    port,
    handler: app,
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

describe('Final Security Hardening — SSRF, DNS Rebinding, Redirects, Encrypted Envelopes & Attestation Verification', () => {
  let tmpDir: string;
  let dbPath: string;
  let config: GatewayConfig;
  let gateway: AamarvaMcpGateway;
  let gatewayHttp: http.Server;
  let baseUrl: string;
  let mockAamarvaClient: LocalTestAamarvaBackendClient;
  let publicMcpServer: Awaited<ReturnType<typeof startTestMcpHttpServer>>;
  let noAuthMcpServer: Awaited<ReturnType<typeof startTestMcpHttpServer>>;
  let redirectServer: http.Server;
  let redirectServerPort: number;

  // Mutable DNS table controlled per test to test public resolution & DNS rebinding accurately
  const dnsMap = new Map<string, DnsResolvedAddress[]>();
  let outboundAttempts: string[] = [];

  const backendSecret = 'aamarva-backend-hmac-secret-ssrf-hardening-001';
  const publicMcpSecret = 'Bearer public-external-mcp-secret-2026';

  const aamarvaKeys = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const gatewayKeys = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const untrustedKeys = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const rawAgentPair = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const agentKeys = {
    ...rawAgentPair,
    fingerprint: `sha256:${crypto
      .createHash('sha256')
      .update(crypto.createPublicKey(rawAgentPair.publicKey).export({ type: 'spki', format: 'der' }))
      .digest('hex')}`,
  };

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

  function signHandshakePayload(overrides: {
    challenge?: string;
    accountId?: string;
    integrationId?: string;
    mcpServerId?: string;
    endpoint: string;
    expectedEndpoint?: string;
    encryptedCredentials?: ReturnType<typeof encryptHandshakeCredentialEnvelope>;
    extraTopLevel?: Record<string, unknown>;
    extraClaims?: Record<string, unknown>;
  }) {
    const now = Date.now();
    const challenge = overrides.challenge ?? `chl_${crypto.randomBytes(16).toString('hex')}`;
    const claims = {
      challenge,
      accountId: overrides.accountId ?? 'acct_ssrf_test',
      integrationId: overrides.integrationId ?? 'int_ssrf_test',
      mcpServerId: overrides.mcpServerId ?? 'mcp_ssrf_test',
      gatewayId: 'gw_sec_01',
      transport: 'streamable-http' as const,
      endpoint: overrides.endpoint,
      attestationTtlSeconds: 1800,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 120_000).toISOString(),
      ...(overrides.extraClaims ?? {}),
    };
    const signature = signPayloadAsMockAamarva(claims, aamarvaKeys.privateKey);
    return {
      claims,
      keyId: 'aamarva-k1',
      signature,
      ...(overrides.expectedEndpoint ? { expectedEndpoint: overrides.expectedEndpoint } : {}),
      ...(overrides.encryptedCredentials ? { encryptedCredentials: overrides.encryptedCredentials } : {}),
      ...(overrides.extraTopLevel ?? {}),
    };
  }

  const testDnsLookup = async (hostname: string): Promise<DnsResolvedAddress[]> => {
    const entry = dnsMap.get(hostname.toLowerCase());
    if (!entry) {
      throw new Error(`ENOTFOUND ${hostname}`);
    }
    return entry;
  };

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agw-sec-'));
    dbPath = path.join(tmpDir, 'hardening.db');
    mockAamarvaClient = new LocalTestAamarvaBackendClient();

    publicMcpServer = await startTestMcpHttpServer({
      serverName: 'public-vendor-mcp',
      requiredAuthHeader: publicMcpSecret,
    });
    noAuthMcpServer = await startTestMcpHttpServer({
      serverName: 'noauth-vendor-mcp',
    });

    redirectServer = http.createServer((_req, res) => {
      res.statusCode = 302;
      res.setHeader('Location', 'http://169.254.169.254/latest/meta-data/');
      res.end('redirecting');
    });
    await new Promise<void>((resolve) => redirectServer.listen(0, '127.0.0.1', () => resolve()));
    const rAddr = redirectServer.address();
    redirectServerPort = typeof rAddr === 'object' && rAddr ? rAddr.port : 0;

    // Seed legitimate public domains resolving to non-private public IP 93.184.216.34
    dnsMap.set('mcp.public-vendor.example', [{ address: '93.184.216.34', family: 4 }]);
    dnsMap.set('noauth.public-vendor.example', [{ address: '93.184.216.34', family: 4 }]);
    dnsMap.set('rebind.public-vendor.example', [{ address: '93.184.216.34', family: 4 }]);
    dnsMap.set('priv-dns.attacker.example', [{ address: '10.0.0.1', family: 4 }]);
    dnsMap.set('mixed-dns.attacker.example', [
      { address: '93.184.216.34', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]);
    dnsMap.set('ipv6-ula-dns.attacker.example', [{ address: 'fd00::1', family: 6 }]);
    dnsMap.set('ipv4-mapped-dns.attacker.example', [{ address: '::ffff:169.254.169.254', family: 6 }]);

    // Production SSRF validation wrapper + in-sandbox routing to our local MCP server AFTER full SSRF validation passes
    const fetchWithSsrfGuardAndLocalBridge = async (
      input: string | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const rawUrl = typeof input === 'string' ? input : input.toString();
      // ALWAYS run full Gateway SSRF validation + DNS resolution first (with strict allowLoopbackHttp: false!)
      const validated = await resolveAndValidateMcpDestination(rawUrl, {
        allowInsecureHttp: false,
        allowLoopbackHttp: false,
        dnsLookup: testDnsLookup,
      });
      outboundAttempts.push(`${validated.normalizedHost}->${validated.pinnedAddress.address}`);

      // Once strictly validated as a public HTTPS endpoint resolving to 93.184.216.34, forward to in-process test server
      const targetPort =
        validated.normalizedHost === 'noauth.public-vendor.example'
          ? noAuthMcpServer.port
          : publicMcpServer.port;
      const rewritten = new URL(validated.url.toString());
      rewritten.protocol = 'http:';
      rewritten.hostname = '127.0.0.1';
      rewritten.port = String(targetPort);

      return createSsrfSafeFetch({
        allowInsecureHttp: true,
        allowLoopbackHttp: true,
      })(rewritten, init);
    };

    config = validateGatewayConfig({
      nodeEnv: 'test',
      port: 3000,
      gatewayId: 'gw_sec_01',
      mcpServerId: 'mcp_default',
      gatewayPublicUrl: 'https://gw.example.com',
      gatewayIdentity: {
        activeSigningKeyId: 'gw-sec-key-1',
        signingKeys: {
          'gw-sec-key-1': {
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
        allowLoopbackHttp: false, // STRICT: loopback NOT enabled!
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
      dnsLookup: testDnsLookup,
      fetchOverride: fetchWithSsrfGuardAndLocalBridge,
      silentLogger: true,
    });
    await gateway.start({ connectMcpOnBoot: false });

    const app = gateway.createStandaloneApp();
    gatewayHttp = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve) => gatewayHttp.once('listening', resolve));
    const gAddr = gatewayHttp.address();
    const gPort = typeof gAddr === 'object' && gAddr ? gAddr.port : 3000;
    baseUrl = `http://127.0.0.1:${gPort}`;
  }, 20_000);

  afterAll(async () => {
    await new Promise<void>((resolve) => gatewayHttp.close(() => resolve()));
    await gateway.stop();
    await publicMcpServer.close();
    await noAuthMcpServer.close();
    await new Promise<void>((resolve) => redirectServer.close(() => resolve()));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // =========================================================================
  // 1-13: SSRF, DNS REBINDING & REDIRECT PROTECTION
  // =========================================================================

  it('1 & 13: accepts legitimate public HTTPS MCP endpoints and executes full handshake + token + tools/list + tools/call workflow', async () => {
    outboundAttempts = [];
    const challenge = `chl_pub_${crypto.randomBytes(12).toString('hex')}`;
    const body = signHandshakePayload({
      challenge,
      accountId: 'acct_pub',
      integrationId: 'int_pub',
      mcpServerId: 'mcp_pub',
      endpoint: 'https://mcp.public-vendor.example/mcp',
      encryptedCredentials: encryptHandshakeCredentialEnvelope({
        credentials: { authorizationHeader: publicMcpSecret },
        backendAuthSecret: backendSecret,
        gatewayId: 'gw_sec_01',
        accountId: 'acct_pub',
        integrationId: 'int_pub',
        challenge,
      }),
    });

    const hsRes = await postJson(
      baseUrl,
      '/handshake',
      body,
      signBackendHeaders(gateway, '/handshake', body),
    );
    expect(hsRes.status).toBe(200);
    expect(hsRes.json.verified).toBe(true);
    expect(outboundAttempts).toContain('mcp.public-vendor.example->93.184.216.34');

    const att = hsRes.json.attestation as GatewayVerificationAttestation;
    const gwPub = hsRes.json.gatewayPublicKey as GatewayPublicKeyMetadata;
    const gwSig = hsRes.json.gatewaySignature as string;

    const attCheck = verifyGatewayAttestation({
      attestation: att,
      signatureBase64: gwSig,
      trustedGatewayKeys: { [gwPub.keyId]: gwPub },
      expectedChallenge: challenge,
      expectedAccountId: 'acct_pub',
      expectedIntegrationId: 'int_pub',
      expectedGatewayId: 'gw_sec_01',
      expectedCanonicalEndpoint: 'https://mcp.public-vendor.example/mcp',
    });
    expect(attCheck.valid).toBe(true);

    // Issue token, redeem, and invoke tools/list + tools/call through public verified connection
    const now = Date.now();
    const grantClaims = {
      authorizationId: `auth_pub_${crypto.randomBytes(4).toString('hex')}`,
      agentId: 'agent_pub',
      agentName: 'Public Agent',
      accountId: 'acct_pub',
      agentPublicKeyPem: agentKeys.publicKey,
      agentPublicKeyFingerprint: agentKeys.fingerprint,
      mcpServerId: 'mcp_pub',
      gatewayId: 'gw_sec_01',
      integrationId: 'int_pub',
      connectionId: att.connectionId,
      endpoint: att.canonicalEndpoint,
      allowedTools: ['public_ping'],
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 300_000).toISOString(),
    };
    const grantBody = {
      claims: grantClaims,
      keyId: 'aamarva-k1',
      signature: signPayloadAsMockAamarva(grantClaims, aamarvaKeys.privateKey),
      expires_in_minutes: 5,
    };
    const issueRes = await postJson(
      baseUrl,
      '/issuetoken',
      grantBody,
      signBackendHeaders(gateway, '/issuetoken', grantBody),
    );
    expect(issueRes.status).toBe(201);

    const dec = decryptTokenAsAgent(
      issueRes.json.encryptedToken as EncryptedTokenEnvelope,
      agentKeys.privateKey,
    );
    const redeemRes = await postJson(baseUrl, '/execute', {
      token: dec.token,
      agentId: 'agent_pub',
      accountId: 'acct_pub',
      mcpServerId: 'mcp_pub',
    });
    expect(redeemRes.status).toBe(200);
    const sessionId = redeemRes.json.sessionId as string;

    const callRes = await gateway.executionProxy.executeAuthorizedTool({
      requestId: `req_pub_${crypto.randomBytes(6).toString('hex')}`,
      sessionId,
      agentId: 'agent_pub',
      accountId: 'acct_pub',
      mcpServerId: 'mcp_pub',
      gatewayId: 'gw_sec_01',
      connectionId: att.connectionId,
      toolName: 'public_ping',
      arguments: { tag: 'prod-ssrf-verified' },
    });
    expect(callRes.statusCode).toBe(200);
    const parsedCall = JSON.parse(
      ((callRes.body.result as { content: Array<{ text: string }> }).content[0]).text,
    );
    expect(parsedCall).toEqual({
      ok: true,
      server: 'public-vendor-mcp',
      tag: 'prod-ssrf-verified',
    });
  });

  it('2-8 & 12: rejects IPv4 loopback, RFC1918, link-local, unspecified/reserved, IPv6 private/loopback/link-local/unspecified, IPv4-mapped IPv6, cloud metadata, and obfuscated IP encodings', async () => {
    const blockedHttpsTargets: Array<{ label: string; endpoint: string; expectedStatus?: number }> = [
      // 2. IPv4 loopback
      { label: 'IPv4 loopback 127.0.0.1', endpoint: 'https://127.0.0.1/mcp' },
      { label: 'IPv4 loopback 127.0.0.2', endpoint: 'https://127.0.0.2:8443/mcp' },
      { label: 'localhost hostname', endpoint: 'https://localhost:8443/mcp' },
      // 3. IPv4 private RFC1918
      { label: 'RFC1918 10.0.0.1', endpoint: 'https://10.0.0.1/mcp' },
      { label: 'RFC1918 172.16.0.5', endpoint: 'https://172.16.0.5/mcp' },
      { label: 'RFC1918 192.168.1.10', endpoint: 'https://192.168.1.10/mcp' },
      // 4. IPv4 link-local
      { label: 'Link-local 169.254.1.1', endpoint: 'https://169.254.1.1/mcp' },
      // 5. IPv4 unspecified & reserved
      { label: 'Unspecified 0.0.0.0', endpoint: 'https://0.0.0.0/mcp' },
      { label: 'CGNAT 100.64.0.1', endpoint: 'https://100.64.0.1/mcp' },
      { label: 'Multicast 224.0.0.1', endpoint: 'https://224.0.0.1/mcp' },
      { label: 'Reserved 240.0.0.1', endpoint: 'https://240.0.0.1/mcp' },
      // 6. IPv6 loopback, private ULA, link-local, unspecified
      { label: 'IPv6 loopback ::1', endpoint: 'https://[::1]/mcp' },
      { label: 'IPv6 ULA fc00::1', endpoint: 'https://[fc00::1]/mcp' },
      { label: 'IPv6 ULA fd12:3456::1', endpoint: 'https://[fd12:3456::1]/mcp' },
      { label: 'IPv6 link-local fe80::1', endpoint: 'https://[fe80::1]/mcp' },
      { label: 'IPv6 unspecified ::', endpoint: 'https://[::]/mcp' },
      // 7. IPv4-mapped IPv6 representations
      { label: 'IPv4-mapped ::ffff:127.0.0.1', endpoint: 'https://[::ffff:127.0.0.1]/mcp' },
      { label: 'IPv4-mapped ::ffff:7f00:1', endpoint: 'https://[::ffff:7f00:1]/mcp' },
      { label: 'IPv4-mapped ::ffff:169.254.169.254', endpoint: 'https://[::ffff:169.254.169.254]/mcp' },
      { label: 'IPv4-mapped ::ffff:10.0.0.1', endpoint: 'https://[::ffff:10.0.0.1]/mcp' },
      { label: 'IPv4-mapped ::ffff:192.168.1.1', endpoint: 'https://[::ffff:192.168.1.1]/mcp' },
      // 8. Cloud metadata endpoints
      { label: 'AWS/GCP/Azure metadata IP', endpoint: 'https://169.254.169.254/latest/meta-data/' },
      { label: 'AWS IPv6 metadata', endpoint: 'https://[fd00:ec2::254]/latest/meta-data/' },
      { label: 'GCP metadata hostname', endpoint: 'https://metadata.google.internal/computeMetadata/v1/' },
      { label: 'Alibaba metadata IP', endpoint: 'https://100.100.100.200/latest/meta-data/' },
      { label: 'Internal suffix .local', endpoint: 'https://vault.corp.local/mcp' },
      { label: 'Single-label internal host', endpoint: 'https://redis/mcp' },
      // 12. Alternative/obfuscated IP forms & embedded credentials
      { label: 'Decimal IP 2130706433', endpoint: 'https://2130706433/mcp' },
      { label: 'Hex IP 0x7f000001', endpoint: 'https://0x7f000001/mcp' },
      { label: 'Octal IP 0177.0.0.1', endpoint: 'https://0177.0.0.1/mcp' },
      { label: 'Shortened IP 127.1', endpoint: 'https://127.1/mcp' },
      { label: 'Hex-octet IP 0x7f.0.0.1', endpoint: 'https://0x7f.0.0.1/mcp' },
      { label: 'Embedded userinfo@host', endpoint: 'https://public.example@127.0.0.1/mcp' },
      { label: 'IPv6 zone ID %eth0', endpoint: 'https://[fe80::1%eth0]/mcp' },
    ];

    const attemptsBefore = outboundAttempts.length;
    for (const target of blockedHttpsTargets) {
      const hsBody = signHandshakePayload({
        accountId: 'acct_ssrf_blocked',
        integrationId: 'int_ssrf_blocked',
        endpoint: target.endpoint,
      });
      const res = await postJson(
        baseUrl,
        '/handshake',
        hsBody,
        signBackendHeaders(gateway, '/handshake', hsBody),
      );
      expect(res.status, `Expected SSRF block for ${target.label}`).toBe(403);
      expect(res.json.verified).toBe(false);
    }

    // Plaintext HTTP metadata endpoint also rejected before any outbound request
    expect(() =>
      validateAndCanonicalizeMcpUrl('http://metadata.google.internal/computeMetadata/v1/', {
        allowInsecureHttp: false,
        allowLoopbackHttp: false,
      }),
    ).toThrow(SsrfBlockedError);

    expect(outboundAttempts.length).toBe(attemptsBefore);
  });

  it('9: blocks public hostnames resolving to private, mixed-private, IPv6 ULA, or IPv4-mapped IPv6 addresses', async () => {
    const dnsAttackHosts = [
      'https://priv-dns.attacker.example/mcp',
      'https://mixed-dns.attacker.example/mcp',
      'https://ipv6-ula-dns.attacker.example/mcp',
      'https://ipv4-mapped-dns.attacker.example/mcp',
    ];

    for (const endpoint of dnsAttackHosts) {
      const hsBody = signHandshakePayload({
        accountId: 'acct_dns_ssrf',
        integrationId: 'int_dns_ssrf',
        endpoint,
      });
      const res = await postJson(
        baseUrl,
        '/handshake',
        hsBody,
        signBackendHeaders(gateway, '/handshake', hsBody),
      );
      expect(res.status, `Expected DNS SSRF block for ${endpoint}`).toBe(403);
      expect(res.json.error).toBe('SSRF_BLOCKED_DESTINATION');
    }

    // Even when allowLoopbackHttp=true (dev mode), a non-loopback hostname resolving to 127.0.0.1 is STILL blocked!
    await expect(
      resolveAndValidateMcpDestination('https://mixed-dns.attacker.example/mcp', {
        allowInsecureHttp: false,
        allowLoopbackHttp: true,
        dnsLookup: testDnsLookup,
      }),
    ).rejects.toMatchObject({ code: 'SSRF_BLOCKED_DESTINATION' });
  });

  it('10: prevents DNS rebinding both between DNS validation and TCP/TLS dial AND across pooled connection reuse', async () => {
    // Part A: Socket-level DNS pinning inside createSsrfSafeFetch prevents TOCTOU rebinding between validation & dial
    let lookupCalls = 0;
    const pinnedRequests: Array<{ hostname?: string; pinnedIp?: string }> = [];
    const spyingLookup = async (hostname: string): Promise<DnsResolvedAddress[]> => {
      lookupCalls += 1;
      if (lookupCalls === 1) {
        return [{ address: '93.184.216.34', family: 4 }];
      }
      // Attacker rebinds immediately on any second lookup!
      return [{ address: '127.0.0.1', family: 4 }];
    };

    const reqSpy = https.request;
    const origHttpsRequest = https.request;
    const seenLookups: string[] = [];
    // Intercept https.request in test to observe exact pinned lookup IP passed to Node's socket layer
    (https as { request: typeof https.request }).request = ((
      opts: https.RequestOptions,
      cb?: (res: http.IncomingMessage) => void,
    ) => {
      if (typeof opts.lookup === 'function') {
        opts.lookup('toctou.rebind.example', { all: true } as never, ((
          _err: unknown,
          addrs: unknown,
        ) => {
          if (Array.isArray(addrs) && addrs[0]) {
            seenLookups.push((addrs[0] as { address: string }).address);
            pinnedRequests.push({ hostname: opts.hostname ?? undefined, pinnedIp: (addrs[0] as { address: string }).address });
          }
        }) as never);
      }
      const mockReq = new http.ClientRequest({ host: '127.0.0.1', port: 1 });
      mockReq.destroy(new Error('TEST_SOCKET_SPY_STOP'));
      if (cb) {
        // never invoked
      }
      return mockReq;
    }) as typeof https.request;

    try {
      const guardedFetch = createSsrfSafeFetch({
        allowInsecureHttp: false,
        allowLoopbackHttp: false,
        dnsLookup: spyingLookup,
      });
      await expect(guardedFetch('https://toctou.rebind.example/mcp')).rejects.toThrow('TEST_SOCKET_SPY_STOP');
      expect(lookupCalls).toBe(1);
      expect(seenLookups).toEqual(['93.184.216.34']);
      expect(pinnedRequests[0]?.pinnedIp).toBe('93.184.216.34');
    } finally {
      (https as { request: typeof https.request }).request = origHttpsRequest;
      void reqSpy;
    }

    // Part B: Full Gateway lifecycle DNS rebinding test across pooled connections!
    dnsMap.set('rebind.public-vendor.example', [{ address: '93.184.216.34', family: 4 }]);
    const chl = `chl_rebind_${crypto.randomBytes(12).toString('hex')}`;
    const hsBody = signHandshakePayload({
      challenge: chl,
      accountId: 'acct_rebind',
      integrationId: 'int_rebind',
      mcpServerId: 'mcp_rebind',
      endpoint: 'https://rebind.public-vendor.example/mcp',
      encryptedCredentials: encryptHandshakeCredentialEnvelope({
        credentials: { authorizationHeader: publicMcpSecret },
        backendAuthSecret: backendSecret,
        gatewayId: 'gw_sec_01',
        accountId: 'acct_rebind',
        integrationId: 'int_rebind',
        challenge: chl,
      }),
    });
    const hsRes = await postJson(
      baseUrl,
      '/handshake',
      hsBody,
      signBackendHeaders(gateway, '/handshake', hsBody),
    );
    expect(hsRes.status).toBe(200);
    const att = hsRes.json.attestation as GatewayVerificationAttestation;

    // Issue + redeem session while DNS is legitimate
    const now = Date.now();
    const gClaims = {
      authorizationId: `auth_reb_${crypto.randomBytes(4).toString('hex')}`,
      agentId: 'agent_reb',
      agentName: 'Rebind Agent',
      accountId: 'acct_rebind',
      agentPublicKeyPem: agentKeys.publicKey,
      agentPublicKeyFingerprint: agentKeys.fingerprint,
      mcpServerId: 'mcp_rebind',
      gatewayId: 'gw_sec_01',
      integrationId: 'int_rebind',
      connectionId: att.connectionId,
      endpoint: att.canonicalEndpoint,
      allowedTools: ['public_ping'],
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 300_000).toISOString(),
    };
    const gBody = {
      claims: gClaims,
      keyId: 'aamarva-k1',
      signature: signPayloadAsMockAamarva(gClaims, aamarvaKeys.privateKey),
      expires_in_minutes: 5,
    };
    const issueRes = await postJson(
      baseUrl,
      '/issuetoken',
      gBody,
      signBackendHeaders(gateway, '/issuetoken', gBody),
    );
    expect(issueRes.status).toBe(201);
    const dec = decryptTokenAsAgent(issueRes.json.encryptedToken as EncryptedTokenEnvelope, agentKeys.privateKey);
    const redeemRes = await postJson(baseUrl, '/execute', {
      token: dec.token,
      agentId: 'agent_reb',
      accountId: 'acct_rebind',
      mcpServerId: 'mcp_rebind',
    });
    expect(redeemRes.status).toBe(200);
    const sessionId = redeemRes.json.sessionId as string;

    // Now attacker flips DNS record to cloud metadata 169.254.169.254!
    dnsMap.set('rebind.public-vendor.example', [{ address: '169.254.169.254', family: 4 }]);
    const attemptsBeforeRebind = outboundAttempts.length;

    const callBody = {
      requestId: `req_reb_${crypto.randomBytes(6).toString('hex')}`,
      sessionId,
      agentId: 'agent_reb',
      accountId: 'acct_rebind',
      mcpServerId: 'mcp_rebind',
      gatewayId: 'gw_sec_01',
      connectionId: att.connectionId,
      toolName: 'public_ping',
      arguments: { tag: 'rebound' },
      timestamp: new Date().toISOString(),
    };
    const legacyHttp404 = await postJson(
      baseUrl,
      '/api/v1/aamarva/mcp/tools/call',
      callBody,
      signBackendHeaders(gateway, '/api/v1/aamarva/mcp/tools/call', callBody),
    );
    expect(legacyHttp404.status).toBe(404);

    const reboundRes = await gateway.executionProxy.executeAuthorizedTool({
      requestId: callBody.requestId,
      sessionId: callBody.sessionId,
      agentId: callBody.agentId,
      accountId: callBody.accountId,
      mcpServerId: callBody.mcpServerId,
      gatewayId: callBody.gatewayId,
      connectionId: callBody.connectionId,
      toolName: callBody.toolName,
      arguments: callBody.arguments,
    });
    expect(reboundRes.statusCode).toBe(403);
    expect(reboundRes.body.error).toBe('SSRF_BLOCKED_DESTINATION');
    // Pooled connection must NOT make any HTTP call to the rebound destination
    expect(outboundAttempts.length).toBe(attemptsBeforeRebind);
  });

  it('11: blocks HTTP 3xx redirects so redirects to internal/metadata endpoints cannot bypass SSRF protection', async () => {
    const ssrfFetch = createSsrfSafeFetch({
      allowInsecureHttp: true,
      allowLoopbackHttp: true, // even when local loopback target itself is reachable for this test
    });

    await expect(ssrfFetch(`http://127.0.0.1:${redirectServerPort}/start`)).rejects.toMatchObject({
      code: 'SSRF_REDIRECT_BLOCKED',
    });
  });

  it('13b: rejects ALLOW_LOOPBACK_MCP_IN_DEV=true in production configuration', () => {
    const prodPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    expect(() =>
      loadGatewayConfig({
        NODE_ENV: 'production',
        GATEWAY_ID: 'gw_prod_check',
        MCP_SERVER_ID: 'mcp_prod',
        GATEWAY_PUBLIC_URL: 'https://gw.example.com',
        GATEWAY_ACTIVE_SIGNING_KEY_ID: 'gw-1',
        GATEWAY_SIGNING_KEYS_JSON: JSON.stringify({
          'gw-1': { privateKeyPem: prodPair.privateKey, publicKeyPem: prodPair.publicKey },
        }),
        AAMARVA_BASE_URL: 'https://api.aamarva.example.com',
        AAMARVA_BACKEND_AUTH_SECRET: 'super-strong-prod-secret-min-32-chars!!',
        AAMARVA_TRUSTED_SIGNING_KEYS_JSON: JSON.stringify({ k1: aamarvaKeys.publicKey }),
        ALLOW_LOOPBACK_MCP_IN_DEV: 'true',
      }),
    ).toThrow(/prohibited in production/i);
  });

  // =========================================================================
  // 14-22: MANDATORY ENCRYPTED CREDENTIAL ENVELOPES
  // =========================================================================

  it('15-17: rejects plaintext authorizationHeader and customHeaders (alone or alongside encryptedCredentials) and audits attempt', async () => {
    const validChl = `chl_plain_mix_${crypto.randomBytes(12).toString('hex')}`;
    const encCred = encryptHandshakeCredentialEnvelope({
      credentials: { authorizationHeader: publicMcpSecret },
      backendAuthSecret: backendSecret,
      gatewayId: 'gw_sec_01',
      accountId: 'acct_plain',
      integrationId: 'int_plain',
      challenge: validChl,
    });

    const cases: Array<{ label: string; payload: unknown }> = [
      {
        label: 'plaintext authorizationHeader alone',
        payload: signHandshakePayload({
          accountId: 'acct_plain',
          integrationId: 'int_plain',
          endpoint: 'https://mcp.public-vendor.example/mcp',
          extraTopLevel: { authorizationHeader: 'Bearer leaked-plaintext' },
        }),
      },
      {
        label: 'plaintext customHeaders alone',
        payload: signHandshakePayload({
          accountId: 'acct_plain',
          integrationId: 'int_plain',
          endpoint: 'https://mcp.public-vendor.example/mcp',
          extraTopLevel: { customHeaders: { 'x-api-key': 'leaked-plaintext' } },
        }),
      },
      {
        label: 'plaintext authorizationHeader alongside encryptedCredentials',
        payload: signHandshakePayload({
          challenge: validChl,
          accountId: 'acct_plain',
          integrationId: 'int_plain',
          endpoint: 'https://mcp.public-vendor.example/mcp',
          encryptedCredentials: encCred,
          extraTopLevel: { authorizationHeader: 'Bearer bypass-attempt' },
        }),
      },
    ];

    for (const c of cases) {
      const res = await postJson(
        baseUrl,
        '/handshake',
        c.payload,
        signBackendHeaders(gateway, '/handshake', c.payload),
      );
      expect(res.status, `Expected 400 for ${c.label}`).toBe(400);
      expect(res.json.verified).toBe(false);
      expect(res.json.error).toBe('PLAINTEXT_CREDENTIALS_FORBIDDEN');
    }

    const recentAudit = gateway.logger.getRecentEntries(100);
    expect(recentAudit.some((e) => e.event === 'PLAINTEXT_CREDENTIALS_REJECTED')).toBe(true);
  });

  it('18-21: rejects encrypted credential envelopes bound to wrong accountId, wrong integrationId, wrong challenge, or tampered ciphertext before connecting', async () => {
    const chl = `chl_aad_${crypto.randomBytes(12).toString('hex')}`;
    const validEnvelope = encryptHandshakeCredentialEnvelope({
      credentials: { authorizationHeader: publicMcpSecret },
      backendAuthSecret: backendSecret,
      gatewayId: 'gw_sec_01',
      accountId: 'acct_owner_true',
      integrationId: 'int_owner_true',
      challenge: chl,
    });

    const attemptsBefore = outboundAttempts.length;

    // 18: Wrong accountId
    const wrongAcct = signHandshakePayload({
      challenge: chl,
      accountId: 'acct_attacker_other',
      integrationId: 'int_owner_true',
      endpoint: 'https://mcp.public-vendor.example/mcp',
      encryptedCredentials: validEnvelope,
    });
    const wrongAcctRes = await postJson(
      baseUrl,
      '/handshake',
      wrongAcct,
      signBackendHeaders(gateway, '/handshake', wrongAcct),
    );
    expect(wrongAcctRes.status).toBe(400);
    expect(wrongAcctRes.json.error).toBe('CREDENTIAL_DECRYPTION_FAILED');

    // 19: Wrong integrationId
    const wrongInt = signHandshakePayload({
      challenge: `chl_aad_2_${crypto.randomBytes(8).toString('hex')}`,
      accountId: 'acct_owner_true',
      integrationId: 'int_attacker_other',
      endpoint: 'https://mcp.public-vendor.example/mcp',
      encryptedCredentials: validEnvelope,
    });
    const wrongIntRes = await postJson(
      baseUrl,
      '/handshake',
      wrongInt,
      signBackendHeaders(gateway, '/handshake', wrongInt),
    );
    expect(wrongIntRes.status).toBe(400);
    expect(wrongIntRes.json.error).toBe('CREDENTIAL_DECRYPTION_FAILED');

    // 20: Wrong challenge
    const wrongChl = signHandshakePayload({
      challenge: `chl_different_${crypto.randomBytes(8).toString('hex')}`,
      accountId: 'acct_owner_true',
      integrationId: 'int_owner_true',
      endpoint: 'https://mcp.public-vendor.example/mcp',
      encryptedCredentials: validEnvelope,
    });
    const wrongChlRes = await postJson(
      baseUrl,
      '/handshake',
      wrongChl,
      signBackendHeaders(gateway, '/handshake', wrongChl),
    );
    expect(wrongChlRes.status).toBe(400);
    expect(wrongChlRes.json.error).toBe('CREDENTIAL_DECRYPTION_FAILED');

    // 21: Tampered ciphertext
    const chlTamper = `chl_tamper_${crypto.randomBytes(8).toString('hex')}`;
    const tamperEnv = encryptHandshakeCredentialEnvelope({
      credentials: { authorizationHeader: publicMcpSecret },
      backendAuthSecret: backendSecret,
      gatewayId: 'gw_sec_01',
      accountId: 'acct_owner_true',
      integrationId: 'int_owner_true',
      challenge: chlTamper,
    });
    const ctBuf = Buffer.from(tamperEnv.ciphertext, 'base64');
    ctBuf[0] ^= 0xff;
    tamperEnv.ciphertext = ctBuf.toString('base64');

    const tamperBody = signHandshakePayload({
      challenge: chlTamper,
      accountId: 'acct_owner_true',
      integrationId: 'int_owner_true',
      endpoint: 'https://mcp.public-vendor.example/mcp',
      encryptedCredentials: tamperEnv,
    });
    const tamperRes = await postJson(
      baseUrl,
      '/handshake',
      tamperBody,
      signBackendHeaders(gateway, '/handshake', tamperBody),
    );
    expect(tamperRes.status).toBe(400);
    expect(tamperRes.json.error).toBe('CREDENTIAL_DECRYPTION_FAILED');

    // Zero outbound MCP connections were attempted on any failed decryption
    expect(outboundAttempts.length).toBe(attemptsBefore);
  });

  it('22: supports no-auth public MCP handshakes without credentials and never leaks secrets in logs, responses, or SQLite', async () => {
    const chl = `chl_noauth_${crypto.randomBytes(12).toString('hex')}`;
    const body = signHandshakePayload({
      challenge: chl,
      accountId: 'acct_noauth',
      integrationId: 'int_noauth',
      mcpServerId: 'mcp_noauth',
      endpoint: 'https://noauth.public-vendor.example/mcp',
    });

    const res = await postJson(
      baseUrl,
      '/handshake',
      body,
      signBackendHeaders(gateway, '/handshake', body),
    );
    expect(res.status).toBe(200);
    expect(res.json.verified).toBe(true);

    // Confirm publicMcpSecret from test #1 never leaked to disk or logs
    const dbBytes = fs.readFileSync(dbPath);
    expect(dbBytes.includes(Buffer.from(publicMcpSecret, 'utf8'))).toBe(false);
    const logsText = JSON.stringify(gateway.logger.getRecentEntries(300));
    expect(logsText).not.toContain(publicMcpSecret);
  });

  // =========================================================================
  // 23-29: COMPLETE CRYPTOGRAPHIC ATTESTATION VERIFICATION
  // =========================================================================

  it('23-29: verifyGatewayAttestation verifies authentic attestations and rejects tampering, expiry, untrusted keys, and missing discovery flags', async () => {
    const chl = `chl_att_${crypto.randomBytes(12).toString('hex')}`;
    const body = signHandshakePayload({
      challenge: chl,
      accountId: 'acct_att',
      integrationId: 'int_att',
      mcpServerId: 'mcp_att',
      endpoint: 'https://mcp.public-vendor.example/mcp',
      encryptedCredentials: encryptHandshakeCredentialEnvelope({
        credentials: { authorizationHeader: publicMcpSecret },
        backendAuthSecret: backendSecret,
        gatewayId: 'gw_sec_01',
        accountId: 'acct_att',
        integrationId: 'int_att',
        challenge: chl,
      }),
    });

    const res = await postJson(
      baseUrl,
      '/handshake',
      body,
      signBackendHeaders(gateway, '/handshake', body),
    );
    expect(res.status).toBe(200);

    const att = res.json.attestation as GatewayVerificationAttestation;
    const gwPub = res.json.gatewayPublicKey as GatewayPublicKeyMetadata;
    const gwSig = res.json.gatewaySignature as string;
    const trustedKeys = { [gwPub.keyId]: gwPub };

    // 23: Valid attestation passes
    expect(
      verifyGatewayAttestation({
        attestation: att,
        signatureBase64: gwSig,
        trustedGatewayKeys: trustedKeys,
        expectedChallenge: chl,
        expectedAccountId: 'acct_att',
        expectedIntegrationId: 'int_att',
        expectedGatewayId: 'gw_sec_01',
        expectedCanonicalEndpoint: 'https://mcp.public-vendor.example/mcp',
      }).valid,
    ).toBe(true);

    // 24: Tampered endpoint fails
    expect(
      verifyGatewayAttestation({
        attestation: { ...att, canonicalEndpoint: 'https://evil.example/mcp' },
        signatureBase64: gwSig,
        trustedGatewayKeys: trustedKeys,
        expectedChallenge: chl,
        expectedAccountId: 'acct_att',
        expectedIntegrationId: 'int_att',
        expectedGatewayId: 'gw_sec_01',
      }).valid,
    ).toBe(false);

    // 25: Tampered accountId, integrationId, challenge, toolsListHash, connectionId, protocolVersion fail
    const tamperedVariants: Array<Partial<GatewayVerificationAttestation>> = [
      { accountId: 'acct_spoofed' },
      { integrationId: 'int_spoofed' },
      { challenge: 'chl_spoofed_1234567890' },
      { gatewayId: 'gw_spoofed' },
      { toolsListHash: `sha256:${'a'.repeat(64)}` },
      { connectionId: 'mcpc_spoofed' },
      { negotiatedProtocolVersion: '1999-01-01' },
    ];
    for (const patch of tamperedVariants) {
      expect(
        verifyGatewayAttestation({
          attestation: { ...att, ...patch },
          signatureBase64: gwSig,
          trustedGatewayKeys: trustedKeys,
          expectedChallenge: chl,
          expectedAccountId: 'acct_att',
          expectedIntegrationId: 'int_att',
          expectedGatewayId: 'gw_sec_01',
        }).valid,
      ).toBe(false);
    }

    // 26: Expired attestation fails
    expect(
      verifyGatewayAttestation({
        attestation: att,
        signatureBase64: gwSig,
        trustedGatewayKeys: trustedKeys,
        expectedChallenge: chl,
        expectedAccountId: 'acct_att',
        expectedIntegrationId: 'int_att',
        expectedGatewayId: 'gw_sec_01',
        nowMs: Date.parse(att.expiresAt) + 5_000,
      }),
    ).toMatchObject({ valid: false });

    // 27: Attacker signs a forged attestation with their own untrusted keypair -> MUST fail against trustedGatewayKeys!
    const forgedSig = signPayloadAsMockAamarva(
      att as unknown as Record<string, unknown>,
      untrustedKeys.privateKey,
    );
    expect(
      verifyGatewayAttestation({
        attestation: att,
        signatureBase64: forgedSig,
        trustedGatewayKeys: trustedKeys,
        expectedChallenge: chl,
        expectedAccountId: 'acct_att',
        expectedIntegrationId: 'int_att',
        expectedGatewayId: 'gw_sec_01',
      }).valid,
    ).toBe(false);

    // Unknown gatewayKeyId fails
    expect(
      verifyGatewayAttestation({
        attestation: { ...att, gatewayKeyId: 'rogue-key-id' },
        signatureBase64: gwSig,
        trustedGatewayKeys: trustedKeys,
        expectedChallenge: chl,
        expectedAccountId: 'acct_att',
        expectedIntegrationId: 'int_att',
        expectedGatewayId: 'gw_sec_01',
      }).valid,
    ).toBe(false);

    // 29: Re-signed by trusted key but missing mcpInitialized or toolsDiscoverySuccess must also fail policy verification
    const uninitAtt = { ...att, mcpInitialized: false };
    const uninitSig = gateway.gatewayIdentity.signResponsePayload(uninitAtt).signature;
    expect(
      verifyGatewayAttestation({
        attestation: uninitAtt,
        signatureBase64: uninitSig,
        trustedGatewayKeys: trustedKeys,
        expectedChallenge: chl,
        expectedAccountId: 'acct_att',
        expectedIntegrationId: 'int_att',
        expectedGatewayId: 'gw_sec_01',
      }).valid,
    ).toBe(false);

    const noToolsAtt = { ...att, toolsDiscoverySuccess: false };
    const noToolsSig = gateway.gatewayIdentity.signResponsePayload(noToolsAtt).signature;
    expect(
      verifyGatewayAttestation({
        attestation: noToolsAtt,
        signatureBase64: noToolsSig,
        trustedGatewayKeys: trustedKeys,
        expectedChallenge: chl,
        expectedAccountId: 'acct_att',
        expectedIntegrationId: 'int_att',
        expectedGatewayId: 'gw_sec_01',
      }).valid,
    ).toBe(false);
  });
});
