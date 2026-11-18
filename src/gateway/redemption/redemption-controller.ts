import type { Request, Response } from 'express';
import { z } from 'zod';
import { resolveGatewayReachableBaseUrl } from '../config/gateway-url.ts';
import type { GatewayConfig } from '../config/validation.ts';
import { createExecutionContext } from '../core/execution-context.ts';
import type { RedemptionService } from './redemption-service.ts';

const RedeemRequestBodySchema = z
  .object({
    token: z.string().min(20).max(512),
    agentId: z.string().min(1).max(128),
    accountId: z.string().min(1).max(128),
    mcpServerId: z.string().min(1).max(128),
    authorizationId: z.string().min(1).max(128).optional(),
    invocationId: z.string().min(1).max(128).optional(),
  })
  .strict();

export class RedemptionController {
  private readonly service: RedemptionService;
  private readonly gatewayId: string;
  private readonly mcpServerId: string;
  private readonly config?: GatewayConfig;

  constructor(options: {
    service: RedemptionService;
    gatewayId: string;
    mcpServerId: string;
    config?: GatewayConfig;
  }) {
    this.service = options.service;
    this.gatewayId = options.gatewayId;
    this.mcpServerId = options.mcpServerId;
    this.config = options.config;
  }

  private async processRedemption(req: Request, res: Response, isExecuteEndpoint: boolean): Promise<void> {
    const parsed = RedeemRequestBodySchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        redeemed: false,
        error: 'INVALID_REQUEST',
        message:
          'Invalid token redemption payload. /execute accepts only decrypted token and binding claims (direct MCP tool calls are rejected).',
      });
      return;
    }

    const ctx = createExecutionContext({
      gatewayId: this.gatewayId,
      mcpServerId: parsed.data.mcpServerId,
      agentId: parsed.data.agentId,
      accountId: parsed.data.accountId,
    });

    const outcome = await this.service.redeemToken({
      token: parsed.data.token,
      agentId: parsed.data.agentId,
      accountId: parsed.data.accountId,
      mcpServerId: parsed.data.mcpServerId,
      expectedAuthorizationId: parsed.data.authorizationId ?? parsed.data.invocationId,
      correlationId: ctx.correlationId,
    });

    if (!outcome.ok) {
      res.status(outcome.statusCode).json({
        redeemed: false,
        error: outcome.code,
        message: outcome.message,
        correlationId: ctx.correlationId,
      });
      return;
    }

    const gatewayUrlInfo = this.config
      ? resolveGatewayReachableBaseUrl(this.config, req)
      : { baseUrl: null, source: 'unconfigured' as const };

    res.status(200).json({
      redeemed: true,
      sessionId: outcome.session.sessionId,
      gatewayId: outcome.session.gatewayId,
      mcpServerId: outcome.session.mcpServerId,
      authorizationId: outcome.session.authorizationId,
      ...(parsed.data.invocationId ? { invocationId: parsed.data.invocationId } : {}),
      ...(outcome.session.scope.connectionId
        ? { connectionId: outcome.session.scope.connectionId }
        : {}),
      ...(outcome.session.scope.integrationId
        ? { integrationId: outcome.session.scope.integrationId }
        : {}),
      agentId: outcome.session.agentId,
      accountId: outcome.session.accountId,
      expiresAt: new Date(outcome.session.expiresAtMs).toISOString(),
      allowedTools: outcome.session.scope.allowedTools,
      sessionSyncStatus: outcome.sessionSyncStatus,
      ...(gatewayUrlInfo.baseUrl
        ? { gatewayPublicUrl: gatewayUrlInfo.baseUrl }
        : isExecuteEndpoint
          ? { gatewayPublicUrlConfigured: false }
          : {}),
      correlationId: ctx.correlationId,
      nextStep:
        'Session established. Close direct connection to Gateway; send all subsequent MCP requests through AAMARVA backend mediation.',
    });
  }

  handleRedeem = async (req: Request, res: Response): Promise<void> => {
    await this.processRedemption(req, res, false);
  };

  handleExecute = async (req: Request, res: Response): Promise<void> => {
    await this.processRedemption(req, res, true);
  };
}

