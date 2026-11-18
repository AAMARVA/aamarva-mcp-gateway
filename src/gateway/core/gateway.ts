import express from 'express';
import type { Express } from 'express';
import { HttpAamarvaBackendClient } from '../aamarva/aamarva-client.ts';
import type { AamarvaBackendClient } from '../aamarva/aamarva-client.ts';
import { AamarvaAuthorizationAdapter } from '../aamarva/authorization-adapter.ts';
import { AamarvaBackendRelay } from '../aamarva/backend-relay.ts';
import { AamarvaSignatureVerifier } from '../aamarva/signature-verifier.ts';
import type { GatewayConfig } from '../config/validation.ts';
import { GatewayIdentityKeyManager } from '../crypto/gateway-keypair.ts';
import { createAamarvaBackendAuthMiddleware } from '../middleware/authentication.ts';
import type { RequestWithRawBody } from '../middleware/authentication.ts';
import { createErrorHandlerMiddleware } from '../middleware/error-handler.ts';
import { createRateLimitMiddleware } from '../middleware/rate-limit.ts';
import {
  createJsonContentTypeMiddleware,
  createTlsEnforcementMiddleware,
} from '../middleware/request-validation.ts';
import { McpConnectionManager } from '../mcp/connection-manager.ts';
import type { McpUpstreamAdapter } from '../mcp/mcp-transport.ts';
import { ResponseForwarder } from '../mcp/response-forwarder.ts';
import { StdioMcpTransportAdapter } from '../mcp/stdio-adapter.ts';
import { StreamableHttpMcpTransportAdapter } from '../mcp/streamable-http-adapter.ts';
import { ToolDiscoveryService } from '../mcp/tool-discovery.ts';
import { ToolExecutionService } from '../mcp/tool-execution.ts';
import { AuditRecorder } from '../observability/audit.ts';
import { GatewayLogger } from '../observability/logger.ts';
import { GatewayMetrics } from '../observability/metrics.ts';
import { ExecutionProxy } from '../proxy/execution-proxy.ts';
import { ProxyResponseHandler } from '../proxy/response-handler.ts';
import { SessionValidator } from '../proxy/session-validator.ts';
import { RedemptionController } from '../redemption/redemption-controller.ts';
import { RedemptionService } from '../redemption/redemption-service.ts';
import { RedemptionStore } from '../redemption/redemption-store.ts';
import { ReplayProtection } from '../redemption/replay-protection.ts';
import { SessionSyncOutboxProcessor } from '../redemption/session-sync-outbox.ts';
import { createAamarvaRouter } from '../routes/aamarva-routes.ts';
import { createHealthRouter } from '../routes/health-routes.ts';
import { createRedemptionRouter } from '../routes/redemption-routes.ts';
import type { DnsLookupFn } from '../security/ssrf-guard.ts';
import { InMemoryGatewayStateStore } from '../storage/adapters/memory-store.ts';
import { RedisGatewayStateStore } from '../storage/adapters/redis-store.ts';
import { SqliteGatewayStateStore } from '../storage/adapters/sqlite-store.ts';
import type { GatewayStateStore } from '../storage/interfaces.ts';
import { GatewaySessionManager } from './gateway-session.ts';

export interface GatewayOverrides {
  store?: GatewayStateStore;
  mcpAdapter?: McpUpstreamAdapter;
  aamarvaClient?: AamarvaBackendClient;
  dnsLookup?: DnsLookupFn;
  fetchOverride?: (input: string | URL, init?: RequestInit) => Promise<Response>;
  silentLogger?: boolean;
  outboxBaseRetryDelayMs?: number;
  outboxPollIntervalMs?: number;
}

export class AamarvaMcpGateway {
  public readonly config: GatewayConfig;
  public readonly logger: GatewayLogger;
  public readonly audit: AuditRecorder;
  public readonly metrics: GatewayMetrics;
  public readonly store: GatewayStateStore;
  public readonly mcpAdapter: McpUpstreamAdapter;
  public readonly gatewayIdentity: GatewayIdentityKeyManager;
  public readonly signatureVerifier: AamarvaSignatureVerifier;
  public readonly aamarvaClient: AamarvaBackendClient;
  public readonly sessionManager: GatewaySessionManager;
  public readonly outboxProcessor: SessionSyncOutboxProcessor;
  public readonly redemptionService: RedemptionService;
  public readonly replayProtection: ReplayProtection;
  public readonly executionProxy: ExecutionProxy;
  public readonly toolDiscovery: ToolDiscoveryService;
  public readonly connectionManager: McpConnectionManager;
  public readonly backendRelay: AamarvaBackendRelay;
  public readonly redemptionController: RedemptionController;

  constructor(config: GatewayConfig, overrides: GatewayOverrides = {}) {
    this.config = config;
    this.logger = new GatewayLogger({
      gatewayId: config.gatewayId,
      silent: overrides.silentLogger ?? false,
    });
    this.audit = new AuditRecorder(this.logger);
    this.metrics = new GatewayMetrics();

    this.gatewayIdentity = new GatewayIdentityKeyManager({
      activeKeyId: config.gatewayIdentity.activeSigningKeyId,
      signingKeys: config.gatewayIdentity.signingKeys,
    });

    if (overrides.store) {
      this.store = overrides.store;
    } else if (config.storage.driver === 'redis' && config.storage.redisUrl) {
      this.store = new RedisGatewayStateStore(config.storage.redisUrl);
    } else if (config.storage.driver === 'memory') {
      if (config.nodeEnv === 'production' || !config.security.allowInMemoryStore) {
        throw new Error('In-memory state store is not allowed unless ALLOW_IN_MEMORY_STORE=true in non-production');
      }
      this.store = new InMemoryGatewayStateStore();
    } else {
      this.store = new SqliteGatewayStateStore(config.storage.sqliteDbPath);
    }

    const allowLoopbackHttp =
      Boolean(config.security.allowLoopbackHttp) && config.nodeEnv !== 'production';

    if (overrides.mcpAdapter) {
      this.mcpAdapter = overrides.mcpAdapter;
    } else if (config.mcp.transport === 'streamable-http' && config.mcp.httpUrl) {
      this.mcpAdapter = new StreamableHttpMcpTransportAdapter({
        endpointUrl: config.mcp.httpUrl,
        upstreamAuthHeader: config.mcp.upstreamAuthHeader,
        defaultTimeoutMs: config.mcp.requestTimeoutMs,
        allowInsecureHttp: !config.security.requireTls,
        allowLoopbackHttp,
        dnsLookup: overrides.dnsLookup,
        fetchOverride: overrides.fetchOverride,
        audit: this.audit,
      });
    } else {
      this.mcpAdapter = new StdioMcpTransportAdapter({
        command: config.mcp.stdioCommand ?? 'node',
        args: config.mcp.stdioArgs,
        cwd: config.mcp.stdioCwd,
        defaultTimeoutMs: config.mcp.requestTimeoutMs,
        audit: this.audit,
      });
    }

    this.signatureVerifier = new AamarvaSignatureVerifier({
      trustedSigningKeys: config.aamarva.trustedSigningKeys,
      backendAuthSecret: config.aamarva.backendAuthSecret,
      maxClockSkewSeconds: config.aamarva.maxClockSkewSeconds,
    });

    this.aamarvaClient =
      overrides.aamarvaClient ??
      new HttpAamarvaBackendClient({
        baseUrl: config.aamarva.baseUrl,
        gatewayId: config.gatewayId,
        verifier: this.signatureVerifier,
        allowInsecureHttp: !config.security.requireTls,
        allowLoopbackHttp,
        dnsLookup: overrides.dnsLookup,
        fetchOverride: overrides.fetchOverride,
      });

    this.sessionManager = new GatewaySessionManager({
      store: this.store,
      gatewayId: config.gatewayId,
      mcpServerId: config.mcpServerId,
    });

    this.outboxProcessor = new SessionSyncOutboxProcessor({
      store: this.store,
      aamarvaClient: this.aamarvaClient,
      audit: this.audit,
      metrics: this.metrics,
      baseRetryDelayMs: overrides.outboxBaseRetryDelayMs,
      pollIntervalMs: overrides.outboxPollIntervalMs,
    });

    const redemptionStore = new RedemptionStore(this.store);
    this.redemptionService = new RedemptionService({
      store: redemptionStore,
      gatewayId: config.gatewayId,
      mcpServerId: config.mcpServerId,
      tokenTtlSeconds: config.security.tokenTtlSeconds,
      sessionTtlSeconds: config.security.sessionTtlSeconds,
      gatewayIdentity: this.gatewayIdentity,
      outboxProcessor: this.outboxProcessor,
      audit: this.audit,
      metrics: this.metrics,
    });

    this.replayProtection = new ReplayProtection({
      store: this.store,
      maxClockSkewSeconds: config.aamarva.maxClockSkewSeconds,
    });

    this.connectionManager = new McpConnectionManager({
      gatewayId: config.gatewayId,
      defaultMcpServerId: config.mcpServerId,
      defaultMcpAdapter: this.mcpAdapter,
      store: this.store,
      gatewayIdentity: this.gatewayIdentity,
      backendAuthSecret: config.aamarva.backendAuthSecret,
      requireTls: config.security.requireTls,
      allowLoopbackHttp,
      configuredSubjectAuthHeader:
        config.mcp.transport === 'streamable-http' &&
        config.mcp.httpUrl &&
        config.mcp.upstreamAuthHeader
          ? {
              httpUrl: config.mcp.httpUrl,
              authorizationHeader: config.mcp.upstreamAuthHeader,
            }
          : undefined,
      dnsLookup: overrides.dnsLookup,
      fetchOverride: overrides.fetchOverride,
      defaultTimeoutMs: config.mcp.requestTimeoutMs,
      audit: this.audit,
      metrics: this.metrics,
    });

    const authAdapter = new AamarvaAuthorizationAdapter({
      verifier: this.signatureVerifier,
      store: this.store,
      gatewayId: config.gatewayId,
      mcpServerId: config.mcpServerId,
      requireTls: config.security.requireTls,
      allowLoopbackHttp,
      mcpConfig: {
        transport: config.mcp.transport,
        httpUrl: config.mcp.httpUrl,
      },
      audit: this.audit,
      metrics: this.metrics,
      onAccountRevoked: async (accountId) => {
        await this.connectionManager.disconnectAccount(accountId);
      },
    });

    this.toolDiscovery = new ToolDiscoveryService(this.mcpAdapter);
    const toolExecution = new ToolExecutionService(this.mcpAdapter);
    const forwarder = new ResponseForwarder();
    const responseHandler = new ProxyResponseHandler();
    const sessionValidator = new SessionValidator({
      sessionManager: this.sessionManager,
      onlineRevocationCheck: config.aamarva.onlineRevocationCheck,
      aamarvaClient: this.aamarvaClient,
    });

    this.executionProxy = new ExecutionProxy({
      gatewayId: config.gatewayId,
      mcpServerId: config.mcpServerId,
      sessionValidator,
      toolDiscovery: this.toolDiscovery,
      toolExecution,
      forwarder,
      responseHandler,
      audit: this.audit,
      metrics: this.metrics,
      aamarvaClient: this.aamarvaClient,
      connectionManager: this.connectionManager,
    });

    this.backendRelay = new AamarvaBackendRelay({
      authAdapter,
      redemptionService: this.redemptionService,
      executionProxy: this.executionProxy,
      replayProtection: this.replayProtection,
      connectionManager: this.connectionManager,
      gatewayId: config.gatewayId,
      mcpServerId: config.mcpServerId,
      config,
      audit: this.audit,
    });

    this.redemptionController = new RedemptionController({
      service: this.redemptionService,
      gatewayId: config.gatewayId,
      mcpServerId: config.mcpServerId,
      config,
    });
  }

  async start(options: { connectMcpOnBoot?: boolean } = {}): Promise<void> {
    await this.store.init();
    this.outboxProcessor.start();

    if (options.connectMcpOnBoot ?? true) {
      try {
        await this.mcpAdapter.connect();
      } catch (err) {
        this.logger.warn({
          event: 'MCP_UPSTREAM_DEFERRED',
          outcome: 'failure',
          message: `Upstream MCP server unavailable during boot (fail-closed until connected): ${
            err instanceof Error ? err.message : 'error'
          }`,
        });
      }
    }

    this.audit.record({
      event: 'GATEWAY_STARTUP',
      outcome: 'success',
      message: 'AAMARVA MCP Gateway initialized',
      mcpServerId: this.config.mcpServerId,
      details: {
        transport: this.config.mcp.transport,
        storageDriver: this.store.driverName,
        requireTls: this.config.security.requireTls,
        trustedProxies: this.config.security.trustedProxies,
        onlineRevocationCheck: this.config.aamarva.onlineRevocationCheck,
        gatewayKeyId: this.gatewayIdentity.getActiveKeyId(),
        trustedKeyIds: this.signatureVerifier.listTrustedKeyIds(),
        gatewayPublicUrlConfigured: Boolean(this.config.gatewayPublicUrl),
      },
    });
  }

  async stop(): Promise<void> {
    this.outboxProcessor.stop();
    this.audit.record({
      event: 'GATEWAY_SHUTDOWN',
      outcome: 'success',
      message: 'AAMARVA MCP Gateway shutting down cleanly',
    });
    await this.connectionManager.disconnectAll();
    await this.mcpAdapter.disconnect();
    await this.store.close();
  }

  /**
   * Builds the strict Gateway Express application containing:
   * - Health checks (/healthz, /readyz)
   * - Primary AAMARVA integration endpoints:
   *   - POST /execute (agent one-time token redemption)
   *   - POST /handshake (AAMARVA Core initial verification handshake)
   *   - POST /issuetoken (AAMARVA Core agent-specific encrypted token issuance)
   * - Preserved compatibility/operations routes (/api/v1/redeem, /api/v1/aamarva/*)
   */
  attachGatewayRoutes(app: Express): void {
    app.use(
      express.json({
        limit: this.config.security.maxRequestBodyBytes,
        verify: (req, _res, buf) => {
          (req as RequestWithRawBody).rawBody = buf;
        },
      }),
    );

    const tlsMiddleware = createTlsEnforcementMiddleware({
      requireTls: this.config.security.requireTls,
      trustedProxies: this.config.security.trustedProxies,
    });
    const jsonTypeMiddleware = createJsonContentTypeMiddleware();
    const redeemRateLimit = createRateLimitMiddleware({
      maxRequests: this.config.security.redeemRateLimitMax,
      windowMs: this.config.security.redeemRateLimitWindowMs,
      keyPrefix: 'redeem',
    });
    const relayRateLimit = createRateLimitMiddleware({
      maxRequests: this.config.security.relayRateLimitMax,
      windowMs: this.config.security.relayRateLimitWindowMs,
      keyPrefix: 'aamarva-relay',
    });
    const backendAuthMiddleware = createAamarvaBackendAuthMiddleware({
      verifier: this.signatureVerifier,
      replayProtection: this.replayProtection,
      gatewayId: this.config.gatewayId,
      audit: this.audit,
    });

    app.use(
      '/',
      createHealthRouter({
        gatewayId: this.config.gatewayId,
        mcpServerId: this.config.mcpServerId,
        store: this.store,
        mcpAdapter: this.mcpAdapter,
      }),
    );

    // Primary three AAMARVA integration endpoints
    app.post(
      '/execute',
      tlsMiddleware,
      redeemRateLimit,
      jsonTypeMiddleware,
      this.redemptionController.handleExecute,
    );
    app.post(
      '/handshake',
      tlsMiddleware,
      relayRateLimit,
      jsonTypeMiddleware,
      backendAuthMiddleware,
      this.backendRelay.handleMcpHandshake,
    );
    app.post(
      '/issuetoken',
      tlsMiddleware,
      relayRateLimit,
      jsonTypeMiddleware,
      backendAuthMiddleware,
      this.backendRelay.handleIssueTokenEndpoint,
    );

    app.use(
      '/api/v1',
      createRedemptionRouter({
        controller: this.redemptionController,
        tlsMiddleware,
        rateLimitMiddleware: redeemRateLimit,
        jsonTypeMiddleware,
      }),
    );

    app.use(
      '/api/v1/aamarva',
      createAamarvaRouter({
        relay: this.backendRelay,
        tlsMiddleware,
        rateLimitMiddleware: relayRateLimit,
        jsonTypeMiddleware,
        backendAuthMiddleware,
      }),
    );
  }

  createStandaloneApp(): Express {
    const app = express();
    app.set(
      'trust proxy',
      this.config.security.trustedProxies.length > 0 ? this.config.security.trustedProxies : false,
    );
    app.disable('x-powered-by');
    this.attachGatewayRoutes(app);
    app.use(createErrorHandlerMiddleware(this.logger));
    return app;
  }
}
