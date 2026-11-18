import crypto from 'node:crypto';
import type { Request, Response } from 'express';
import { z } from 'zod';
import { resolveGatewayReachableBaseUrl } from '../config/gateway-url.ts';
import type { GatewayConfig } from '../config/validation.ts';
import type { GatewaySession } from '../core/authorization-context.ts';
import { createExecutionContext } from '../core/execution-context.ts';
import { validateAndHashToken } from '../crypto/token-validator.ts';
import type { AuditRecorder } from '../observability/audit.ts';
import type { GatewayMetrics } from '../observability/metrics.ts';
import type { ExecutionProxy } from '../proxy/execution-proxy.ts';
import type { SessionValidator } from '../proxy/session-validator.ts';
import type { GatewayStateStore } from '../storage/interfaces.ts';
import type { RedemptionService } from './redemption-service.ts';

const RedeemRequestBodySchema = z
  .object({
    token: z.string().min(1).max(512),
    agentId: z.string().min(1).max(128),
    accountId: z.string().min(1).max(128),
    mcpServerId: z.string().min(1).max(128),
    authorizationId: z.string().min(1).max(128).optional(),
    invocationId: z.string().min(1).max(128).optional(),
  })
  .strict();

function isPlainRecord(val: unknown): val is Record<string, unknown> {
  return typeof val === 'object' && val !== null && !Array.isArray(val);
}

function mapErrorCodeToJsonRpc(statusCode: number, errorCode: string, mcpErrorCode?: number): number {
  if (typeof mcpErrorCode === 'number') return mcpErrorCode;
  if (errorCode === 'METHOD_NOT_FOUND') return -32601;
  if (statusCode === 400) return -32602;
  if (statusCode === 401 || statusCode === 403) return -32001;
  if (statusCode === 409) return -32002;
  if (statusCode === 504) return -32004;
  return -32603;
}

export class RedemptionController {
  private readonly service: RedemptionService;
  private readonly gatewayId: string;
  private readonly mcpServerId: string;
  private readonly config?: GatewayConfig;
  private readonly executionProxy?: ExecutionProxy;
  private readonly sessionValidator?: SessionValidator;
  private readonly store?: GatewayStateStore;
  private readonly audit?: AuditRecorder;
  private readonly metrics?: GatewayMetrics;

  constructor(options: {
    service: RedemptionService;
    gatewayId: string;
    mcpServerId: string;
    config?: GatewayConfig;
    executionProxy?: ExecutionProxy;
    sessionValidator?: SessionValidator;
    store?: GatewayStateStore;
    audit?: AuditRecorder;
    metrics?: GatewayMetrics;
  }) {
    this.service = options.service;
    this.gatewayId = options.gatewayId;
    this.mcpServerId = options.mcpServerId;
    this.config = options.config;
    this.executionProxy = options.executionProxy;
    this.sessionValidator = options.sessionValidator;
    this.store = options.store;
    this.audit = options.audit;
    this.metrics = options.metrics;
  }

  private sendError(
    res: Response,
    options: {
      isJsonRpc: boolean;
      rpcId?: string | number | null;
      statusCode: number;
      errorCode: string;
      message: string;
      correlationId?: string;
      mcpErrorCode?: number;
    },
  ): void {
    if (options.isJsonRpc) {
      res.status(options.statusCode).json({
        jsonrpc: '2.0',
        id: options.rpcId ?? null,
        error: {
          code: mapErrorCodeToJsonRpc(options.statusCode, options.errorCode, options.mcpErrorCode),
          message: options.message,
          data: {
            error: options.errorCode,
            ...(options.correlationId ? { correlationId: options.correlationId } : {}),
            ...(options.mcpErrorCode !== undefined ? { mcpErrorCode: options.mcpErrorCode } : {}),
          },
        },
      });
      return;
    }

    res.status(options.statusCode).json({
      redeemed: false,
      error: options.errorCode,
      message: options.message,
      ...(options.mcpErrorCode !== undefined ? { mcpErrorCode: options.mcpErrorCode } : {}),
      ...(options.correlationId ? { correlationId: options.correlationId } : {}),
    });
  }

  private async resolveAuthorizedSession(params: {
    presentedToken?: string;
    presentedSessionId?: string;
    claimedAgentId?: string;
    claimedAccountId?: string;
    claimedMcpServerId?: string;
    expectedAuthorizationId?: string;
    correlationId: string;
    isInitialize: boolean;
  }): Promise<
    | {
        ok: true;
        session: GatewaySession;
        sessionSyncStatus?: 'delivered' | 'pending_retry' | 'failed';
      }
    | {
        ok: false;
        statusCode: number;
        code: string;
        message: string;
      }
  > {
    if (!params.presentedSessionId) {
      if (!params.presentedToken) {
        this.metrics?.incRedemptionsRejected();
        return {
          ok: false,
          statusCode: 401,
          code: 'MISSING_EXECUTION_TOKEN',
          message:
            'Execution token is required via Authorization Bearer header or token field',
        };
      }

      const redeemed = await this.service.redeemToken({
        token: params.presentedToken,
        agentId: params.claimedAgentId,
        accountId: params.claimedAccountId,
        mcpServerId: params.claimedMcpServerId,
        expectedAuthorizationId: params.expectedAuthorizationId,
        correlationId: params.correlationId,
      });

      if (!redeemed.ok) {
        return {
          ok: false,
          statusCode: redeemed.statusCode,
          code: redeemed.code,
          message: redeemed.message,
        };
      }

      return {
        ok: true,
        session: redeemed.session,
        sessionSyncStatus: redeemed.sessionSyncStatus,
      };
    }

    if (params.isInitialize) {
      return {
        ok: false,
        statusCode: 400,
        code: 'SESSION_ALREADY_INITIALIZED',
        message: 'initialize must establish a new session using an unconsumed execution token without mcp-session-id',
      };
    }

    if (!this.store || !this.sessionValidator) {
      return {
        ok: false,
        statusCode: 500,
        code: 'GATEWAY_MISCONFIGURED',
        message: 'Session validator is unavailable',
      };
    }

    if (params.presentedToken) {
      const parsedToken = validateAndHashToken(params.presentedToken);
      if (!parsedToken) {
        this.metrics?.incRedemptionsRejected();
        return {
          ok: false,
          statusCode: 400,
          code: 'INVALID_TOKEN_FORMAT',
          message: 'Invalid authorization token format',
        };
      }

      const issuedToken = await this.service.getIssuedTokenByHash(parsedToken.tokenHash);
      if (!issuedToken) {
        this.metrics?.incRedemptionsRejected();
        return {
          ok: false,
          statusCode: 403,
          code: 'TOKEN_NOT_FOUND',
          message: 'Invalid or unknown authorization token',
        };
      }

      const nowMs = Date.now();
      if (issuedToken.revokedAtMs !== null) {
        return {
          ok: false,
          statusCode: 401,
          code: 'TOKEN_REVOKED',
          message: 'Authorization token has been revoked',
        };
      }
      if (nowMs > issuedToken.authorizationExpiresAtMs) {
        return {
          ok: false,
          statusCode: 401,
          code: 'AUTHORIZATION_EXPIRED',
          message: 'Underlying AAMARVA authorization grant has expired',
        };
      }
      if (params.claimedAgentId !== undefined && issuedToken.agentId !== params.claimedAgentId) {
        return {
          ok: false,
          statusCode: 403,
          code: 'AGENT_MISMATCH',
          message: 'Token agent binding mismatch',
        };
      }
      if (params.claimedAccountId !== undefined && issuedToken.accountId !== params.claimedAccountId) {
        return {
          ok: false,
          statusCode: 403,
          code: 'ACCOUNT_MISMATCH',
          message: 'Token account binding mismatch',
        };
      }
      if (params.claimedMcpServerId !== undefined && issuedToken.mcpServerId !== params.claimedMcpServerId) {
        return {
          ok: false,
          statusCode: 403,
          code: 'SERVER_MISMATCH',
          message: 'Token MCP server binding mismatch',
        };
      }
      if (issuedToken.redeemedBySessionId !== params.presentedSessionId) {
        this.metrics?.incRedemptionsRejected();
        return {
          ok: false,
          statusCode: 403,
          code: 'SESSION_TOKEN_MISMATCH',
          message: 'Presented execution token is not bound to the supplied MCP session',
        };
      }
    }

    const storedSession = await this.store.getSession(params.presentedSessionId);
    if (!storedSession) {
      return {
        ok: false,
        statusCode: 401,
        code: 'SESSION_NOT_FOUND',
        message: 'MCP session does not exist or has expired',
      };
    }

    if (
      params.expectedAuthorizationId !== undefined &&
      storedSession.authorizationId !== params.expectedAuthorizationId
    ) {
      return {
        ok: false,
        statusCode: 403,
        code: 'AUTHORIZATION_MISMATCH',
        message: 'Session authorization binding mismatch',
      };
    }

    const sessionCheck = await this.sessionValidator.validate({
      sessionId: storedSession.sessionId,
      agentId: params.claimedAgentId ?? storedSession.agentId,
      accountId: params.claimedAccountId ?? storedSession.accountId,
      mcpServerId: params.claimedMcpServerId ?? storedSession.mcpServerId,
      gatewayId: this.gatewayId,
    });

    if (!sessionCheck.valid || !sessionCheck.session) {
      const statusCode =
        sessionCheck.code === 'SESSION_EXPIRED' ||
        sessionCheck.code === 'AUTHORIZATION_EXPIRED' ||
        sessionCheck.code === 'SESSION_REVOKED' ||
        sessionCheck.code === 'SESSION_NOT_FOUND'
          ? 401
          : 403;
      return {
        ok: false,
        statusCode,
        code: sessionCheck.code ?? 'SESSION_INVALID',
        message: sessionCheck.reason ?? 'MCP session is invalid',
      };
    }

    return { ok: true, session: sessionCheck.session };
  }

  private async processRedemption(req: Request, res: Response, isExecuteEndpoint: boolean): Promise<void> {
    if (!isPlainRecord(req.body)) {
      this.sendError(res, {
        isJsonRpc: false,
        statusCode: 400,
        errorCode: 'INVALID_REQUEST',
        message: 'Request body must be a JSON object',
      });
      return;
    }

    const body = req.body;
    const isJsonRpc = body.jsonrpc === '2.0';
    const rawRpcId = body.id;
    const rpcId: string | number | null | undefined =
      typeof rawRpcId === 'string' || typeof rawRpcId === 'number' || rawRpcId === null
        ? rawRpcId
        : undefined;

    const ctx = createExecutionContext({
      gatewayId: this.gatewayId,
      mcpServerId: typeof body.mcpServerId === 'string' && body.mcpServerId ? body.mcpServerId : this.mcpServerId,
      agentId: typeof body.agentId === 'string' && body.agentId ? body.agentId : undefined,
      accountId: typeof body.accountId === 'string' && body.accountId ? body.accountId : undefined,
    });

    // 1. Parse and validate token headers vs body
    const rawAuthHeader = req.header('authorization');
    let authBearerToken: string | undefined;
    if (rawAuthHeader !== undefined) {
      const m = /^Bearer\s+(\S+)$/i.exec(rawAuthHeader.trim());
      if (!m) {
        this.sendError(res, {
          isJsonRpc,
          rpcId,
          statusCode: 401,
          errorCode: 'INVALID_AUTHORIZATION_HEADER',
          message: 'Authorization header must use Bearer token scheme',
          correlationId: ctx.correlationId,
        });
        return;
      }
      authBearerToken = m[1].trim();
    }

    const rawHeaderToken = req.header('x-aamarva-token');
    let xHeaderToken: string | undefined;
    if (rawHeaderToken !== undefined) {
      if (rawHeaderToken.trim() === '') {
        this.sendError(res, {
          isJsonRpc,
          rpcId,
          statusCode: 400,
          errorCode: 'INVALID_REQUEST',
          message: 'x-aamarva-token header cannot be empty',
          correlationId: ctx.correlationId,
        });
        return;
      }
      xHeaderToken = rawHeaderToken.trim();
    }

    if (authBearerToken && xHeaderToken && authBearerToken !== xHeaderToken) {
      this.sendError(res, {
        isJsonRpc,
        rpcId,
        statusCode: 400,
        errorCode: 'INVALID_REQUEST',
        message: 'Conflicting tokens between Authorization and x-aamarva-token headers',
        correlationId: ctx.correlationId,
      });
      return;
    }

    const headerToken = authBearerToken ?? xHeaderToken;
    let bodyToken: string | undefined;
    if (body.token !== undefined) {
      if (typeof body.token !== 'string' || body.token.trim() === '') {
        this.sendError(res, {
          isJsonRpc,
          rpcId,
          statusCode: 400,
          errorCode: 'INVALID_REQUEST',
          message: 'token must be a non-empty string',
          correlationId: ctx.correlationId,
        });
        return;
      }
      bodyToken = body.token.trim();
    }

    if (headerToken && bodyToken && headerToken !== bodyToken) {
      this.sendError(res, {
        isJsonRpc,
        rpcId,
        statusCode: 400,
        errorCode: 'INVALID_REQUEST',
        message: 'Conflicting token values between header and body',
        correlationId: ctx.correlationId,
      });
      return;
    }
    const presentedToken = headerToken ?? bodyToken;

    // 2. Parse and validate session headers vs body
    const rawHeaderSessionId = req.header('mcp-session-id');
    let headerSessionId: string | undefined;
    if (rawHeaderSessionId !== undefined) {
      if (rawHeaderSessionId.trim() === '') {
        this.sendError(res, {
          isJsonRpc,
          rpcId,
          statusCode: 400,
          errorCode: 'INVALID_REQUEST',
          message: 'mcp-session-id header cannot be empty',
          correlationId: ctx.correlationId,
        });
        return;
      }
      headerSessionId = rawHeaderSessionId.trim();
    }

    let bodySessionId: string | undefined;
    if (body.sessionId !== undefined) {
      if (typeof body.sessionId !== 'string' || body.sessionId.trim() === '') {
        this.sendError(res, {
          isJsonRpc,
          rpcId,
          statusCode: 400,
          errorCode: 'INVALID_REQUEST',
          message: 'sessionId must be a non-empty string',
          correlationId: ctx.correlationId,
        });
        return;
      }
      bodySessionId = body.sessionId.trim();
    }

    if (headerSessionId && bodySessionId && headerSessionId !== bodySessionId) {
      this.sendError(res, {
        isJsonRpc,
        rpcId,
        statusCode: 400,
        errorCode: 'INVALID_REQUEST',
        message: 'Conflicting sessionId values between header and body',
        correlationId: ctx.correlationId,
      });
      return;
    }
    const presentedSessionId = headerSessionId ?? bodySessionId;

    // 3. Parse and validate identity binding claims from headers & body
    const parseClaimField = (
      headerName: string,
      bodyValue: unknown,
      mismatchCode: string,
      fieldName: string,
    ): { ok: true; value?: string } | { ok: false; statusCode: number; code: string; message: string } => {
      const hvRaw = req.header(headerName);
      let hv: string | undefined;
      if (hvRaw !== undefined) {
        if (hvRaw.trim() === '') {
          return { ok: false, statusCode: 400, code: 'INVALID_REQUEST', message: `${headerName} cannot be empty` };
        }
        hv = hvRaw.trim();
      }
      let bv: string | undefined;
      if (bodyValue !== undefined) {
        if (typeof bodyValue !== 'string' || bodyValue.trim() === '') {
          return { ok: false, statusCode: 400, code: 'INVALID_REQUEST', message: `${fieldName} must be a non-empty string` };
        }
        bv = bodyValue.trim();
      }
      if (hv && bv && hv !== bv) {
        return {
          ok: false,
          statusCode: 403,
          code: mismatchCode,
          message: `Conflicting ${fieldName} values between header and body`,
        };
      }
      return { ok: true, value: bv ?? hv };
    };

    const agentClaim = parseClaimField('x-aamarva-agent-id', body.agentId, 'AGENT_MISMATCH', 'agentId');
    if (!agentClaim.ok) {
      this.sendError(res, {
        isJsonRpc,
        rpcId,
        statusCode: agentClaim.statusCode,
        errorCode: agentClaim.code,
        message: agentClaim.message,
        correlationId: ctx.correlationId,
      });
      return;
    }

    const accountClaim = parseClaimField('x-aamarva-account-id', body.accountId, 'ACCOUNT_MISMATCH', 'accountId');
    if (!accountClaim.ok) {
      this.sendError(res, {
        isJsonRpc,
        rpcId,
        statusCode: accountClaim.statusCode,
        errorCode: accountClaim.code,
        message: accountClaim.message,
        correlationId: ctx.correlationId,
      });
      return;
    }

    const serverClaim = parseClaimField('x-aamarva-mcp-server-id', body.mcpServerId, 'SERVER_MISMATCH', 'mcpServerId');
    if (!serverClaim.ok) {
      this.sendError(res, {
        isJsonRpc,
        rpcId,
        statusCode: serverClaim.statusCode,
        errorCode: serverClaim.code,
        message: serverClaim.message,
        correlationId: ctx.correlationId,
      });
      return;
    }

    const rawAuthId = body.authorizationId ?? body.invocationId;
    if (rawAuthId !== undefined && (typeof rawAuthId !== 'string' || rawAuthId.trim() === '')) {
      this.sendError(res, {
        isJsonRpc,
        rpcId,
        statusCode: 400,
        errorCode: 'INVALID_REQUEST',
        message: 'authorizationId/invocationId must be a non-empty string',
        correlationId: ctx.correlationId,
      });
      return;
    }
    const expectedAuthorizationId = typeof rawAuthId === 'string' ? rawAuthId.trim() : undefined;

    // 4. Determine operation mode: MCP JSON-RPC / MCP structured op vs token-only redemption
    const explicitMethod =
      typeof body.method === 'string'
        ? body.method.trim()
        : typeof body.action === 'string'
          ? body.action.trim()
          : typeof body.toolName === 'string'
            ? 'tools/call'
            : undefined;

    if (isJsonRpc && !explicitMethod) {
      this.sendError(res, {
        isJsonRpc: true,
        rpcId,
        statusCode: 400,
        errorCode: 'INVALID_REQUEST',
        message: 'JSON-RPC 2.0 request must include a valid method',
        correlationId: ctx.correlationId,
      });
      return;
    }

    // Legacy token-only redemption flow: { token, agentId, accountId, mcpServerId, ... }
    if (!explicitMethod && !isJsonRpc) {
      const parsed = RedeemRequestBodySchema.safeParse(body);
      if (!parsed.success) {
        this.sendError(res, {
          isJsonRpc: false,
          statusCode: 400,
          errorCode: 'INVALID_REQUEST',
          message:
            'Invalid /execute request payload. Provide either an MCP JSON-RPC 2.0 request (with Authorization Bearer token or mcp-session-id) or token redemption claims.',
          correlationId: ctx.correlationId,
        });
        return;
      }

      const authRes = await this.resolveAuthorizedSession({
        presentedToken,
        presentedSessionId,
        claimedAgentId: agentClaim.value,
        claimedAccountId: accountClaim.value,
        claimedMcpServerId: serverClaim.value,
        expectedAuthorizationId,
        correlationId: ctx.correlationId,
        isInitialize: false,
      });

      if (!authRes.ok) {
        this.sendError(res, {
          isJsonRpc: false,
          statusCode: authRes.statusCode,
          errorCode: authRes.code,
          message: authRes.message,
          correlationId: ctx.correlationId,
        });
        return;
      }

      const gatewayUrlInfo = this.config
        ? resolveGatewayReachableBaseUrl(this.config, req)
        : { baseUrl: null, source: 'unconfigured' as const };

      res.setHeader('mcp-session-id', authRes.session.sessionId);
      res.status(200).json({
        redeemed: true,
        sessionId: authRes.session.sessionId,
        gatewayId: authRes.session.gatewayId,
        mcpServerId: authRes.session.mcpServerId,
        authorizationId: authRes.session.authorizationId,
        ...(parsed.data.invocationId ? { invocationId: parsed.data.invocationId } : {}),
        ...(authRes.session.scope.connectionId
          ? { connectionId: authRes.session.scope.connectionId }
          : {}),
        ...(authRes.session.scope.integrationId
          ? { integrationId: authRes.session.scope.integrationId }
          : {}),
        agentId: authRes.session.agentId,
        accountId: authRes.session.accountId,
        expiresAt: new Date(authRes.session.expiresAtMs).toISOString(),
        allowedTools: authRes.session.scope.allowedTools,
        sessionSyncStatus: authRes.sessionSyncStatus ?? 'delivered',
        ...(gatewayUrlInfo.baseUrl
          ? { gatewayPublicUrl: gatewayUrlInfo.baseUrl }
          : isExecuteEndpoint
            ? { gatewayPublicUrlConfigured: false }
            : {}),
        correlationId: ctx.correlationId,
        nextStep:
          'Session established. Send subsequent MCP requests (tools/list, tools/call) to POST /execute using the mcp-session-id header.',
      });
      return;
    }

    // 5. MCP Operation Mode (JSON-RPC 2.0 or structured Gateway MCP call)
    if (!this.executionProxy) {
      this.sendError(res, {
        isJsonRpc,
        rpcId,
        statusCode: 500,
        errorCode: 'GATEWAY_MISCONFIGURED',
        message: 'MCP execution proxy is unavailable',
        correlationId: ctx.correlationId,
      });
      return;
    }

    const method = explicitMethod!;
    const isNotification =
      method.startsWith('notifications/') || (isJsonRpc && body.id === undefined);

    // Pre-validate tools/call payload shape before consuming one-time token on bad JSON?
    // Wait: if token itself is invalid, auth check runs first; for valid tokens, validate args after/alongside.
    const authRes = await this.resolveAuthorizedSession({
      presentedToken,
      presentedSessionId,
      claimedAgentId: agentClaim.value,
      claimedAccountId: accountClaim.value,
      claimedMcpServerId: serverClaim.value,
      expectedAuthorizationId,
      correlationId: ctx.correlationId,
      isInitialize: method === 'initialize',
    });

    if (!authRes.ok) {
      this.sendError(res, {
        isJsonRpc,
        rpcId,
        statusCode: authRes.statusCode,
        errorCode: authRes.code,
        message: authRes.message,
        correlationId: ctx.correlationId,
      });
      return;
    }

    const session = authRes.session;
    res.setHeader('mcp-session-id', session.sessionId);

    if (method === 'initialize') {
      const initResult = await this.executionProxy.initializeSession({
        session,
        correlationId: ctx.correlationId,
      });
      if (initResult.statusCode !== 200) {
        this.sendError(res, {
          isJsonRpc,
          rpcId,
          statusCode: initResult.statusCode,
          errorCode: String(initResult.body.error ?? 'MCP_UPSTREAM_ERROR'),
          message: String(initResult.body.message ?? 'Upstream MCP initialization failed'),
          correlationId: ctx.correlationId,
          mcpErrorCode:
            typeof initResult.body.mcpErrorCode === 'number'
              ? initResult.body.mcpErrorCode
              : undefined,
        });
        return;
      }

      const mcpInitPayload = {
        protocolVersion: initResult.body.protocolVersion,
        capabilities: initResult.body.capabilities,
        ...(initResult.body.serverInfo ? { serverInfo: initResult.body.serverInfo } : {}),
        _meta: {
          sessionId: session.sessionId,
          gatewayId: session.gatewayId,
          mcpServerId: session.mcpServerId,
          agentId: session.agentId,
          allowedTools: session.scope.allowedTools,
          expiresAt: new Date(session.expiresAtMs).toISOString(),
        },
      };

      if (isJsonRpc) {
        res.status(200).json({
          jsonrpc: '2.0',
          id: rpcId ?? null,
          result: mcpInitPayload,
        });
      } else {
        res.status(200).json({
          sessionId: session.sessionId,
          ...mcpInitPayload,
          correlationId: ctx.correlationId,
        });
      }
      return;
    }

    if (isNotification) {
      // Standard Streamable HTTP notification acknowledgment (e.g. notifications/initialized)
      res.status(202).end();
      return;
    }

    if (method === 'ping') {
      const pingResult = await this.executionProxy.pingSession({
        session,
        correlationId: ctx.correlationId,
      });
      if (pingResult.statusCode !== 200) {
        this.sendError(res, {
          isJsonRpc,
          rpcId,
          statusCode: pingResult.statusCode,
          errorCode: String(pingResult.body.error ?? 'MCP_UPSTREAM_ERROR'),
          message: String(pingResult.body.message ?? 'Upstream MCP ping failed'),
          correlationId: ctx.correlationId,
        });
        return;
      }
      if (isJsonRpc) {
        res.status(200).json({ jsonrpc: '2.0', id: rpcId ?? null, result: {} });
      } else {
        res.status(200).json({ ok: true, sessionId: session.sessionId, correlationId: ctx.correlationId });
      }
      return;
    }

    const relayReqId = `exec_${crypto.randomBytes(8).toString('hex')}`;

    if (method === 'tools/list') {
      const listResult = await this.executionProxy.listAuthorizedTools({
        requestId: relayReqId,
        sessionId: session.sessionId,
        agentId: session.agentId,
        accountId: session.accountId,
        mcpServerId: session.mcpServerId,
        gatewayId: session.gatewayId,
        integrationId: session.scope.integrationId,
        connectionId: session.scope.connectionId,
        expectedEndpoint: session.scope.canonicalEndpoint,
      });

      if (listResult.statusCode !== 200) {
        this.sendError(res, {
          isJsonRpc,
          rpcId,
          statusCode: listResult.statusCode,
          errorCode: String(listResult.body.error ?? 'MCP_UPSTREAM_ERROR'),
          message: String(listResult.body.message ?? 'Upstream tools/list failed'),
          correlationId: String(listResult.body.correlationId ?? ctx.correlationId),
          mcpErrorCode:
            typeof listResult.body.mcpErrorCode === 'number'
              ? listResult.body.mcpErrorCode
              : undefined,
        });
        return;
      }

      if (isJsonRpc) {
        res.status(200).json({
          jsonrpc: '2.0',
          id: rpcId ?? null,
          result: {
            tools: listResult.body.tools,
          },
        });
      } else {
        res.status(200).json({
          ...listResult.body,
          sessionId: session.sessionId,
        });
      }
      return;
    }

    if (method === 'tools/call') {
      const rpcParams = isPlainRecord(body.params) ? body.params : {};
      const rawToolName = rpcParams.name ?? body.toolName;
      if (typeof rawToolName !== 'string' || rawToolName.trim() === '') {
        this.sendError(res, {
          isJsonRpc,
          rpcId,
          statusCode: 400,
          errorCode: 'INVALID_REQUEST',
          message: 'tools/call requires a non-empty tool name',
          correlationId: ctx.correlationId,
        });
        return;
      }

      const rawArgs = rpcParams.arguments ?? body.arguments;
      if (rawArgs !== undefined && !isPlainRecord(rawArgs)) {
        this.sendError(res, {
          isJsonRpc,
          rpcId,
          statusCode: 400,
          errorCode: 'INVALID_REQUEST',
          message: 'tools/call arguments must be a JSON object',
          correlationId: ctx.correlationId,
        });
        return;
      }

      const toolArgs: Record<string, unknown> = rawArgs ?? {};
      const callResult = await this.executionProxy.executeAuthorizedTool({
        requestId: relayReqId,
        sessionId: session.sessionId,
        agentId: session.agentId,
        accountId: session.accountId,
        mcpServerId: session.mcpServerId,
        gatewayId: session.gatewayId,
        integrationId: session.scope.integrationId,
        connectionId: session.scope.connectionId,
        expectedEndpoint: session.scope.canonicalEndpoint,
        toolName: rawToolName.trim(),
        arguments: toolArgs,
      });

      if (callResult.statusCode !== 200) {
        this.sendError(res, {
          isJsonRpc,
          rpcId,
          statusCode: callResult.statusCode,
          errorCode: String(callResult.body.error ?? 'MCP_UPSTREAM_ERROR'),
          message: String(callResult.body.message ?? 'Upstream tool execution failed'),
          correlationId: String(callResult.body.correlationId ?? ctx.correlationId),
          mcpErrorCode:
            typeof callResult.body.mcpErrorCode === 'number'
              ? callResult.body.mcpErrorCode
              : undefined,
        });
        return;
      }

      if (isJsonRpc) {
        res.status(200).json({
          jsonrpc: '2.0',
          id: rpcId ?? null,
          result: callResult.body.result,
        });
      } else {
        res.status(200).json({
          ...callResult.body,
          sessionId: session.sessionId,
        });
      }
      return;
    }

    // Any unsupported MCP method: fail closed without fabricating capabilities
    this.sendError(res, {
      isJsonRpc,
      rpcId,
      statusCode: 400,
      errorCode: 'METHOD_NOT_FOUND',
      message: `MCP method "${method}" is not supported by this Gateway adapter`,
      correlationId: ctx.correlationId,
    });
  }

  handleRedeem = async (req: Request, res: Response): Promise<void> => {
    await this.processRedemption(req, res, false);
  };

  handleExecute = async (req: Request, res: Response): Promise<void> => {
    await this.processRedemption(req, res, true);
  };
}
