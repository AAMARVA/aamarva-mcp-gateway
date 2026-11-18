import crypto from 'node:crypto';
import { validateGatewayConfig } from './validation.ts';
import type { GatewayConfig } from './validation.ts';

function parseBool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value === '') return fallback;
  return value.toLowerCase() === 'true' || value === '1';
}

function parseIntVal(value: string | undefined, fallback: number): number {
  if (value === undefined || value === '') return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseJsonRecord(value: string | undefined): Record<string, string> {
  if (!value || value.trim() === '') return {};
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Expected JSON object for AAMARVA_TRUSTED_SIGNING_KEYS_JSON');
  }
  return parsed as Record<string, string>;
}

function parseJsonArray(value: string | undefined, fallback: string[]): string[] {
  if (!value || value.trim() === '') return fallback;
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed)) {
    throw new Error('Expected JSON array for MCP_STDIO_ARGS_JSON');
  }
  return parsed.map(String);
}

export interface EphemeralDevKeys {
  signingKeyId: string;
  signingPublicKeyPem: string;
  signingPrivateKeyPem: string;
  gatewayKeyId: string;
  gatewayPublicKeyPem: string;
  gatewayPrivateKeyPem: string;
  backendAuthSecret: string;
}

let cachedDevKeys: EphemeralDevKeys | null = null;

/**
 * Generates ephemeral local dev keys ONLY when running in non-production
 * without explicit keys configured, so local dev/sandbox can start cleanly
 * while production fails closed if keys are missing.
 */
export function getOrCreateEphemeralDevKeys(): EphemeralDevKeys {
  if (cachedDevKeys) return cachedDevKeys;
  const aamarvaPair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const gatewayPair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  cachedDevKeys = {
    signingKeyId: 'aamarva-dev-sandbox-key-1',
    signingPublicKeyPem: aamarvaPair.publicKey,
    signingPrivateKeyPem: aamarvaPair.privateKey,
    gatewayKeyId: 'gw-signing-dev-2026-01',
    gatewayPublicKeyPem: gatewayPair.publicKey,
    gatewayPrivateKeyPem: gatewayPair.privateKey,
    backendAuthSecret: crypto.randomBytes(32).toString('hex'),
  };
  return cachedDevKeys;
}

function parseGatewaySigningKeys(
  value: string | undefined,
): Record<string, { privateKeyPem: string; publicKeyPem?: string }> {
  if (!value || value.trim() === '') return {};
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Expected JSON object for GATEWAY_SIGNING_KEYS_JSON');
  }
  return parsed as Record<string, { privateKeyPem: string; publicKeyPem?: string }>;
}

function parseCsvList(value: string | undefined): string[] {
  if (!value || value.trim() === '') return [];
  return value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

export function loadGatewayConfig(env: NodeJS.ProcessEnv = process.env): GatewayConfig {
  const nodeEnv = (env.NODE_ENV ?? 'development') as 'development' | 'test' | 'production';
  const isProd = nodeEnv === 'production';

  let trustedSigningKeys = parseJsonRecord(env.AAMARVA_TRUSTED_SIGNING_KEYS_JSON);
  let backendAuthSecret = env.AAMARVA_BACKEND_AUTH_SECRET ?? '';
  let gatewaySigningKeys = parseGatewaySigningKeys(env.GATEWAY_SIGNING_KEYS_JSON);
  let activeGatewayKeyId = env.GATEWAY_ACTIVE_SIGNING_KEY_ID ?? '';

  if (!isProd) {
    const devKeys = getOrCreateEphemeralDevKeys();
    if (Object.keys(trustedSigningKeys).length === 0) {
      trustedSigningKeys = {
        [devKeys.signingKeyId]: devKeys.signingPublicKeyPem,
      };
    }
    if (!backendAuthSecret) {
      backendAuthSecret = devKeys.backendAuthSecret;
    }
    if (Object.keys(gatewaySigningKeys).length === 0) {
      gatewaySigningKeys = {
        [devKeys.gatewayKeyId]: {
          privateKeyPem: devKeys.gatewayPrivateKeyPem,
          publicKeyPem: devKeys.gatewayPublicKeyPem,
        },
      };
    }
    if (!activeGatewayKeyId) {
      activeGatewayKeyId = devKeys.gatewayKeyId;
    }
  }

  const effectivePort =
    env.GATEWAY_PORT ||
    (env.NGINX_PORT && env.PORT === env.NGINX_PORT
      ? env.DEFAULT_APP_PORT || '3000'
      : env.PORT);

  const rawConfig = {
    nodeEnv,
    port: parseIntVal(effectivePort, 3000),
    gatewayId: env.GATEWAY_ID ?? 'gw_aamarva_local_01',
    mcpServerId: env.MCP_SERVER_ID ?? 'mcp_srv_local_01',
    gatewayPublicUrl: (env.GATEWAY_PUBLIC_URL || env.APP_URL || '').trim() || undefined,
    gatewayIdentity: {
      activeSigningKeyId: activeGatewayKeyId || Object.keys(gatewaySigningKeys)[0] || '',
      signingKeys: gatewaySigningKeys,
    },
    aamarva: {
      adapterEnabled: parseBool(env.ENABLE_AAMARVA_ADAPTER ?? env.AAMARVA_ADAPTER_ENABLED, true),
      baseUrl: env.AAMARVA_BASE_URL ?? 'https://api.aamarva.example.com',
      backendAuthSecret,
      trustedSigningKeys,
      maxClockSkewSeconds: parseIntVal(env.AAMARVA_MAX_CLOCK_SKEW_SECONDS, 60),
      onlineRevocationCheck: parseBool(env.AAMARVA_ONLINE_REVOCATION_CHECK, isProd),
      allowOfflineRevocationInProd: parseBool(env.ALLOW_OFFLINE_REVOCATION_IN_PROD, false),
    },
    security: {
      tokenTtlSeconds: parseIntVal(env.TOKEN_TTL_SECONDS, 120),
      sessionTtlSeconds: parseIntVal(env.SESSION_TTL_SECONDS, 900),
      requireTls: parseBool(env.REQUIRE_TLS, isProd),
      allowLoopbackHttp: parseBool(env.ALLOW_LOOPBACK_MCP_IN_DEV, false),
      trustedProxies: parseCsvList(env.TRUSTED_PROXY_IPS),
      allowInMemoryStore: parseBool(env.ALLOW_IN_MEMORY_STORE, false),
      maxRequestBodyBytes: parseIntVal(env.MAX_REQUEST_BODY_BYTES, 1_048_576),
      redeemRateLimitMax: parseIntVal(env.REDEEM_RATE_LIMIT_MAX, 30),
      redeemRateLimitWindowMs: parseIntVal(env.REDEEM_RATE_LIMIT_WINDOW_MS, 60_000),
      relayRateLimitMax: parseIntVal(env.RELAY_RATE_LIMIT_MAX, 300),
      relayRateLimitWindowMs: parseIntVal(env.RELAY_RATE_LIMIT_WINDOW_MS, 60_000),
    },
    storage: {
      driver: (env.STATE_STORE_DRIVER ?? 'sqlite') as 'sqlite' | 'redis' | 'memory',
      sqliteDbPath: env.SQLITE_DB_PATH ?? './data/gateway-state.db',
      redisUrl: env.REDIS_URL || undefined,
    },
    mcp: {
      transport: (env.MCP_TRANSPORT ?? 'stdio') as 'stdio' | 'streamable-http',
      stdioCommand: env.MCP_STDIO_COMMAND ?? 'node',
      stdioArgs: parseJsonArray(env.MCP_STDIO_ARGS_JSON, ['examples/sample-mcp-stdio.ts']),
      stdioCwd: env.MCP_STDIO_CWD || undefined,
      httpUrl: env.MCP_HTTP_URL || undefined,
      upstreamAuthHeader: env.MCP_UPSTREAM_AUTH_HEADER || undefined,
      requestTimeoutMs: parseIntVal(env.MCP_REQUEST_TIMEOUT_MS, 15_000),
    },
    features: {
      enableOperatorConsole: parseBool(env.ENABLE_OPERATOR_CONSOLE, !isProd),
      operatorAuthToken: env.OPERATOR_CONSOLE_AUTH_TOKEN || undefined,
      enableSandbox: parseBool(env.ENABLE_SANDBOX, !isProd),
    },
  };

  return validateGatewayConfig(rawConfig);
}
