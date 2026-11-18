import { z } from 'zod';
import { SECURITY_DEFAULTS } from './security.ts';

export const GatewayConfigSchema = z
  .object({
    nodeEnv: z.enum(['development', 'test', 'production']).default('development'),
    port: z.number().int().min(1).max(65535).default(3000),
    gatewayId: z.string().min(3).max(128),
    mcpServerId: z.string().min(3).max(128),
    gatewayPublicUrl: z.string().url().optional(),
    gatewayIdentity: z.object({
      activeSigningKeyId: z.string().min(1).max(128),
      signingKeys: z.record(
        z.string().min(1),
        z.object({
          privateKeyPem: z.string().min(32),
          publicKeyPem: z.string().min(32).optional(),
        }),
      ),
    }),
    aamarva: z.object({
      baseUrl: z.string().url(),
      backendAuthSecret: z.string().min(16),
      trustedSigningKeys: z.record(z.string().min(1), z.string().min(32)),
      maxClockSkewSeconds: z.number().int().min(5).max(300).default(60),
      onlineRevocationCheck: z.boolean().default(true),
      allowOfflineRevocationInProd: z.boolean().default(false),
    }),
    security: z.object({
      tokenTtlSeconds: z
        .number()
        .int()
        .min(SECURITY_DEFAULTS.MIN_TOKEN_TTL_SECONDS)
        .max(SECURITY_DEFAULTS.MAX_TOKEN_TTL_SECONDS),
      sessionTtlSeconds: z
        .number()
        .int()
        .min(SECURITY_DEFAULTS.MIN_SESSION_TTL_SECONDS)
        .max(SECURITY_DEFAULTS.MAX_SESSION_TTL_SECONDS),
      requireTls: z.boolean(),
      allowLoopbackHttp: z.boolean().default(false),
      trustedProxies: z.array(z.string().min(1)).default([]),
      allowInMemoryStore: z.boolean(),
      maxRequestBodyBytes: z.number().int().min(1024).max(10_485_760),
      redeemRateLimitMax: z.number().int().min(1).max(10_000),
      redeemRateLimitWindowMs: z.number().int().min(1000).max(3_600_000),
      relayRateLimitMax: z.number().int().min(1).max(100_000),
      relayRateLimitWindowMs: z.number().int().min(1000).max(3_600_000),
    }),
    storage: z.object({
      driver: z.enum(['sqlite', 'redis', 'memory']),
      sqliteDbPath: z.string().min(1),
      redisUrl: z.string().optional(),
    }),
    mcp: z.object({
      transport: z.enum(['stdio', 'streamable-http']),
      stdioCommand: z.string().optional(),
      stdioArgs: z.array(z.string()).default([]),
      stdioCwd: z.string().optional(),
      httpUrl: z.string().url().optional(),
      upstreamAuthHeader: z.string().optional(),
      requestTimeoutMs: z.number().int().min(500).max(300_000),
    }),
    features: z.object({
      enableOperatorConsole: z.boolean(),
      operatorAuthToken: z.string().min(32).optional(),
      enableSandbox: z.boolean(),
    }),
  })
  .superRefine((cfg, ctx) => {
    if (!cfg.gatewayIdentity.signingKeys[cfg.gatewayIdentity.activeSigningKeyId]) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['gatewayIdentity', 'activeSigningKeyId'],
        message: 'Active Gateway signing keyId must exist in gatewayIdentity.signingKeys.',
      });
    }

    if (Object.keys(cfg.aamarva.trustedSigningKeys).length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['aamarva', 'trustedSigningKeys'],
        message: 'At least one trusted AAMARVA signing public key must be configured.',
      });
    }

    if (cfg.nodeEnv === 'production') {
      if (cfg.storage.driver === 'memory' || cfg.security.allowInMemoryStore) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['storage', 'driver'],
          message: 'In-memory state store is strictly prohibited in production.',
        });
      }
      if (!cfg.security.requireTls) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['security', 'requireTls'],
          message: 'TLS enforcement (REQUIRE_TLS=true) is mandatory in production.',
        });
      }
      if (cfg.security.allowLoopbackHttp) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['security', 'allowLoopbackHttp'],
          message: 'Loopback MCP HTTP access (ALLOW_LOOPBACK_MCP_IN_DEV) is strictly prohibited in production.',
        });
      }
      if (cfg.features.enableSandbox) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['features', 'enableSandbox'],
          message: 'Local mock sandbox must be disabled in production (ENABLE_SANDBOX=false).',
        });
      }
      if (cfg.features.enableOperatorConsole && !cfg.features.operatorAuthToken) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['features', 'operatorAuthToken'],
          message:
            'OPERATOR_CONSOLE_AUTH_TOKEN (>=32 chars) is mandatory if ENABLE_OPERATOR_CONSOLE=true in production.',
        });
      }
      if (!cfg.aamarva.onlineRevocationCheck && !cfg.aamarva.allowOfflineRevocationInProd) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['aamarva', 'onlineRevocationCheck'],
          message:
            'Production requires online revocation verification (AAMARVA_ONLINE_REVOCATION_CHECK=true) unless explicitly overridden.',
        });
      }
    }

    if (cfg.storage.driver === 'redis' && !cfg.storage.redisUrl) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['storage', 'redisUrl'],
        message: 'REDIS_URL is required when STATE_STORE_DRIVER=redis.',
      });
    }

    if (cfg.mcp.transport === 'stdio' && !cfg.mcp.stdioCommand) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['mcp', 'stdioCommand'],
        message: 'MCP_STDIO_COMMAND is required when MCP_TRANSPORT=stdio.',
      });
    }

    if (cfg.mcp.transport === 'streamable-http' && !cfg.mcp.httpUrl) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['mcp', 'httpUrl'],
        message: 'MCP_HTTP_URL is required when MCP_TRANSPORT=streamable-http.',
      });
    }
  });

export type GatewayConfig = z.infer<typeof GatewayConfigSchema>;

export function validateGatewayConfig(raw: unknown): GatewayConfig {
  return GatewayConfigSchema.parse(raw);
}
