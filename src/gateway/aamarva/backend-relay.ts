import type { Request, Response } from 'express';
import { resolveGatewayReachableBaseUrl } from '../config/gateway-url.ts';
import type { GatewayConfig } from '../config/validation.ts';
import { createExecutionContext } from '../core/execution-context.ts';
import {
  HandshakeVerificationError,
  type McpConnectionManager,
} from '../mcp/connection-manager.ts';
import type { AuditRecorder } from '../observability/audit.ts';
import type { ExecutionProxy } from '../proxy/execution-proxy.ts';
import {
  InsufficientGrantValidityError,
  type RedemptionService,
} from '../redemption/redemption-service.ts';
import type { ReplayProtection } from '../redemption/replay-protection.ts';
import { SsrfBlockedError } from '../security/ssrf-guard.ts';
import type { AamarvaAuthorizationAdapter } from './authorization-adapter.ts';
import {
  AamarvaMcpToolCallRelaySchema,
  AamarvaMcpToolsListRelaySchema,
} from './contracts.ts';

/**
 * Handles requests arriving strictly from the authenticated AAMARVA Core backend:
 * 0. Initial MCP Verification Handshake (POST /handshake)
 * 1. Agent-specific Encrypted Token Issuance (POST /issuetoken)
 * 2. Internal revocation & MCP mediation helpers (not exposed as extra public HTTP routes)
 */
export class AamarvaBackendRelay {
  private readonly authAdapter: AamarvaAuthorizationAdapter;
  private readonly redemptionService: RedemptionService;
  private readonly executionProxy: ExecutionProxy;
  private readonly replayProtection: ReplayProtection;
  private readonly connectionManager: McpConnectionManager;
  private readonly gatewayId: string;
  private readonly mcpServerId: string;
  private readonly config?: GatewayConfig;
  private readonly audit: AuditRecorder;

  constructor(options: {
    authAdapter: AamarvaAuthorizationAdapter;
    redemptionService: RedemptionService;
    executionProxy: ExecutionProxy;
    replayProtection: ReplayProtection;
    connectionManager: McpConnectionManager;
    gatewayId: string;
    mcpServerId: string;
    config?: GatewayConfig;
    audit: AuditRecorder;
  }) {
    this.authAdapter = options.authAdapter;
    this.redemptionService = options.redemptionService;
    this.executionProxy = options.executionProxy;
    this.replayProtection = options.replayProtection;
    this.connectionManager = options.connectionManager;
    this.gatewayId = options.gatewayId;
    this.mcpServerId = options.mcpServerId;
    this.config = options.config;
    this.audit = options.audit;
  }

  handleMcpHandshake = async (req: Request, res: Response): Promise<void> => {
    const ctx = createExecutionContext({
      gatewayId: this.gatewayId,
      mcpServerId: this.mcpServerId,
    });

    const verified = await this.authAdapter.verifyHandshakeRequest(req.body, ctx.correlationId);
    if (!verified.ok) {
      res.status(verified.statusCode).json({
        verified: false,
        error: verified.code,
        message: verified.message,
        correlationId: ctx.correlationId,
      });
      return;
    }

    const { claims, encryptedCredentials } = verified.request;

    try {
      const response = await this.connectionManager.performHandshakeAndAttest({
        accountId: claims.accountId,
        integrationId: claims.integrationId,
        mcpServerId: verified.resolvedMcpServerId,
        challenge: claims.challenge,
        transport: verified.resolvedTransport,
        endpoint: verified.resolvedEndpoint,
        encryptedCredentials,
        attestationTtlSeconds: claims.attestationTtlSeconds,
        correlationId: ctx.correlationId,
      });

      res.status(200).json({
        ...response,
        gatewayKeyId: response.gatewayPublicKey.keyId,
        gatewayPublicKeyFingerprint: response.gatewayPublicKey.fingerprint,
      });
    } catch (err) {
      if (err instanceof HandshakeVerificationError) {
        res.status(err.statusCode).json({
          verified: false,
          error: err.code,
          message: err.message,
          correlationId: ctx.correlationId,
        });
        return;
      }

      if (err instanceof SsrfBlockedError) {
        this.audit.record({
          event: 'SSRF_BLOCKED',
          outcome: 'denied',
          message: err.message,
          correlationId: ctx.correlationId,
          accountId: claims.accountId,
          mcpServerId: verified.resolvedMcpServerId,
          details: { code: err.code, statusCode: err.statusCode },
        });
        const safeMessage =
          err.statusCode === 502
            ? 'Upstream MCP destination resolution failed'
            : err.statusCode === 400
              ? 'Invalid upstream MCP endpoint configuration'
              : 'Upstream MCP destination blocked by SSRF security policy';
        res.status(err.statusCode).json({
          verified: false,
          error: err.code,
          message: safeMessage,
          correlationId: ctx.correlationId,
        });
        return;
      }

      this.audit.record({
        event: 'MCP_HANDSHAKE_FAILED',
        outcome: 'failure',
        message: err instanceof Error ? err.message : 'External MCP verification failed',
        correlationId: ctx.correlationId,
        accountId: claims.accountId,
        mcpServerId: verified.resolvedMcpServerId,
      });

      res.status(502).json({
        verified: false,
        error: 'MCP_HANDSHAKE_FAILED',
        message: 'External MCP verification failed',
        correlationId: ctx.correlationId,
      });
    }
  };

  handleIssuetoken = async (req: Request, res: Response): Promise<void> => {
    return this.handleIssueTokenEndpoint(req, res);
  };

  handleIssueTokenEndpoint = async (req: Request, res: Response): Promise<void> => {
    const ctx = createExecutionContext({
      gatewayId: this.gatewayId,
      mcpServerId: this.mcpServerId,
    });

    const verified = await this.authAdapter.verifyIssueTokenEndpointRequest(
      req.body,
      ctx.correlationId,
    );
    if (!verified.ok) {
      res.status(verified.statusCode).json({
        error: verified.code,
        message: verified.message,
        correlationId: ctx.correlationId,
      });
      return;
    }

    const gatewayUrlInfo = this.config
      ? resolveGatewayReachableBaseUrl(this.config, req)
      : { baseUrl: null, source: 'unconfigured' as const };

    try {
      const issued = await this.redemptionService.issueAndEncryptToken({
        context: verified.context,
        agentPublicKeyPem: verified.agentPublicKeyPem,
        correlationId: ctx.correlationId,
        invocationId: verified.invocationId,
        redemptionEndpoint: '/execute',
        gatewayPublicUrl: gatewayUrlInfo.baseUrl,
        extendedSignedPayload: true,
      });

      this.audit.record({
        event: 'TOKEN_ENCRYPTED',
        outcome: 'success',
        message: 'Encrypted short-lived token and Gateway public key returned via /issuetoken',
        correlationId: ctx.correlationId,
        agentId: verified.context.agentId,
        accountId: verified.context.accountId,
        mcpServerId: verified.context.mcpServerId,
        details: {
          tokenId: issued.tokenId,
          authorizationId: verified.context.authorizationId,
          invocationId: verified.invocationId,
          algorithm: issued.encryptedToken.algorithm,
          gatewayKeyId: issued.gatewayPublicKey.keyId,
          connectionId: verified.context.scope.connectionId,
        },
      });

      res.status(201).json({
        ...(issued.unsignedResponse ?? {}),
        gatewaySignature: issued.gatewaySignature,
      });
    } catch (err) {
      if (err instanceof InsufficientGrantValidityError) {
        res.status(err.statusCode).json({
          error: err.code,
          message: err.message,
          correlationId: ctx.correlationId,
        });
        return;
      }

      this.audit.record({
        event: 'TOKEN_ENCRYPTION_FAILED',
        outcome: 'failure',
        message: err instanceof Error ? err.message : 'Failed to encrypt token for agent',
        correlationId: ctx.correlationId,
        agentId: verified.context.agentId,
        accountId: verified.context.accountId,
        mcpServerId: verified.context.mcpServerId,
      });

      res.status(400).json({
        error: 'TOKEN_ENCRYPTION_FAILED',
        message: 'Failed to encrypt token for agent',
        correlationId: ctx.correlationId,
      });
    }
  };

  handleRevocation = async (req: Request, res: Response): Promise<void> => {
    const ctx = createExecutionContext({
      gatewayId: this.gatewayId,
      mcpServerId: this.mcpServerId,
    });

    const result = await this.authAdapter.processRevocation(req.body, ctx.correlationId);
    res.status(result.statusCode).json({
      revoked: result.ok,
      revokedCount: result.revokedCount,
      message: result.message,
      correlationId: ctx.correlationId,
    });
  };

  handleToolsList = async (req: Request, res: Response): Promise<void> => {
    const parsed = AamarvaMcpToolsListRelaySchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'INVALID_RELAY_REQUEST',
        message: 'Invalid tools/list relay payload',
      });
      return;
    }

    const data = parsed.data;
    const replayCheck = await this.replayProtection.verifyAndClaimRequest({
      requestId: data.requestId,
      timestampMs: Date.parse(data.timestamp),
    });

    if (!replayCheck.ok) {
      res.status(409).json({
        error: 'REPLAY_OR_STALE_REQUEST',
        message: replayCheck.reason,
      });
      return;
    }

    const result = await this.executionProxy.listAuthorizedTools({
      requestId: data.requestId,
      sessionId: data.sessionId,
      agentId: data.agentId,
      accountId: data.accountId,
      mcpServerId: data.mcpServerId,
      gatewayId: data.gatewayId,
      integrationId: data.integrationId,
      connectionId: data.connectionId,
      expectedEndpoint: data.expectedEndpoint,
    });

    res.status(result.statusCode).json(result.body);
  };

  handleToolCall = async (req: Request, res: Response): Promise<void> => {
    const parsed = AamarvaMcpToolCallRelaySchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: 'INVALID_RELAY_REQUEST',
        message: 'Invalid tools/call relay payload',
      });
      return;
    }

    const data = parsed.data;
    const replayCheck = await this.replayProtection.verifyAndClaimRequest({
      requestId: data.requestId,
      timestampMs: Date.parse(data.timestamp),
    });

    if (!replayCheck.ok) {
      res.status(409).json({
        error: 'REPLAY_OR_STALE_REQUEST',
        message: replayCheck.reason,
      });
      return;
    }

    const result = await this.executionProxy.executeAuthorizedTool({
      requestId: data.requestId,
      sessionId: data.sessionId,
      agentId: data.agentId,
      accountId: data.accountId,
      mcpServerId: data.mcpServerId,
      gatewayId: data.gatewayId,
      integrationId: data.integrationId,
      connectionId: data.connectionId,
      expectedEndpoint: data.expectedEndpoint,
      toolName: data.toolName,
      arguments: data.arguments,
    });

    res.status(result.statusCode).json(result.body);
  };
}
