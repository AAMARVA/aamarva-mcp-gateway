import { SECURITY_DEFAULTS } from '../config/security.ts';
import type {
  AuthorizationContext,
  GatewaySession,
  IssuedTokenRecord,
} from '../core/authorization-context.ts';
import { generateSessionId } from '../core/gateway-session.ts';
import { encryptTokenForAgent } from '../crypto/envelope-encryption.ts';
import type { EncryptedTokenEnvelope } from '../crypto/envelope-encryption.ts';
import type {
  GatewayIdentityKeyManager,
  GatewayPublicKeyMetadata,
} from '../crypto/gateway-keypair.ts';
import { generateShortLivedToken } from '../crypto/token-generator.ts';
import { validateAndHashToken } from '../crypto/token-validator.ts';
import type { AuditRecorder } from '../observability/audit.ts';
import type { GatewayMetrics } from '../observability/metrics.ts';
import type { RedeemFailureCode } from '../storage/interfaces.ts';
import type { RedemptionStore } from './redemption-store.ts';
import type { SessionSyncOutcome, SessionSyncOutboxProcessor } from './session-sync-outbox.ts';

export class InsufficientGrantValidityError extends Error {
  public readonly code = 'INSUFFICIENT_GRANT_VALIDITY';
  public readonly statusCode = 400;

  constructor(message = 'Authorization grant has insufficient remaining validity for short-lived token issuance') {
    super(message);
    this.name = 'InsufficientGrantValidityError';
  }
}

export interface GatewayResponseSignature {
  keyId: string;
  algorithm: 'Ed25519' | 'ECDSA-P256-SHA256';
  signature: string;
}

export interface IssueEncryptedTokenResult {
  tokenId: string;
  expiresAt: string;
  encryptedToken: EncryptedTokenEnvelope;
  gatewayPublicKey: GatewayPublicKeyMetadata;
  gatewaySignature: GatewayResponseSignature;
  unsignedResponse?: Record<string, unknown>;
}

export interface RedeemTokenInput {
  token: string;
  agentId: string;
  accountId: string;
  mcpServerId: string;
  expectedAuthorizationId?: string;
  correlationId?: string;
}

export type RedeemTokenOutcome =
  | {
      ok: true;
      session: GatewaySession;
      sessionSyncStatus: SessionSyncOutcome;
    }
  | {
      ok: false;
      code: RedeemFailureCode | 'INVALID_TOKEN_FORMAT';
      message: string;
      statusCode: number;
    };

export class RedemptionService {
  private readonly store: RedemptionStore;
  private readonly gatewayId: string;
  private readonly mcpServerId: string;
  private readonly tokenTtlSeconds: number;
  private readonly sessionTtlSeconds: number;
  private readonly gatewayIdentity: GatewayIdentityKeyManager;
  private readonly outboxProcessor?: SessionSyncOutboxProcessor;
  private readonly audit: AuditRecorder;
  private readonly metrics: GatewayMetrics;

  constructor(options: {
    store: RedemptionStore;
    gatewayId: string;
    mcpServerId: string;
    tokenTtlSeconds: number;
    sessionTtlSeconds: number;
    gatewayIdentity: GatewayIdentityKeyManager;
    outboxProcessor?: SessionSyncOutboxProcessor;
    audit: AuditRecorder;
    metrics: GatewayMetrics;
  }) {
    this.store = options.store;
    this.gatewayId = options.gatewayId;
    this.mcpServerId = options.mcpServerId;
    this.tokenTtlSeconds = options.tokenTtlSeconds;
    this.sessionTtlSeconds = options.sessionTtlSeconds;
    this.gatewayIdentity = options.gatewayIdentity;
    this.outboxProcessor = options.outboxProcessor;
    this.audit = options.audit;
    this.metrics = options.metrics;
  }

  /**
   * Phase 2-5: Generates a cryptographically random short-lived token clamped to the
   * authorization grant expiry, stores only its SHA-256 hash, encrypts the token using
   * the agent's public key, and attaches + signs with the Gateway's own public key.
   */
  async issueAndEncryptToken(params: {
    context: AuthorizationContext;
    agentPublicKeyPem: string;
    correlationId: string;
    invocationId?: string;
    redemptionEndpoint?: string;
    gatewayPublicUrl?: string | null;
    extendedSignedPayload?: boolean;
  }): Promise<IssueEncryptedTokenResult> {
    const nowMs = Date.now();
    const remainingSeconds = Math.floor((params.context.expiresAtMs - nowMs) / 1000);
    if (remainingSeconds < SECURITY_DEFAULTS.MIN_TOKEN_TTL_SECONDS) {
      throw new InsufficientGrantValidityError(
        `Remaining grant validity (${Math.max(0, remainingSeconds)}s) is below minimum ${SECURITY_DEFAULTS.MIN_TOKEN_TTL_SECONDS}s`,
      );
    }

    const effectiveTtlSeconds = Math.min(this.tokenTtlSeconds, remainingSeconds);
    const generated = generateShortLivedToken(
      effectiveTtlSeconds,
      nowMs,
      params.context.expiresAtMs,
    );

    const envelope = encryptTokenForAgent({
      plaintextToken: generated.plaintextToken,
      tokenId: generated.tokenId,
      agentId: params.context.agentId,
      accountId: params.context.accountId,
      mcpServerId: params.context.mcpServerId,
      gatewayId: params.context.gatewayId,
      expiresAtMs: generated.expiresAtMs,
      agentPublicKeyPem: params.agentPublicKeyPem,
    });

    const record: IssuedTokenRecord = {
      tokenId: generated.tokenId,
      tokenHash: generated.tokenHash,
      authorizationId: params.context.authorizationId,
      agentId: params.context.agentId,
      agentName: params.context.agentName,
      accountId: params.context.accountId,
      mcpServerId: params.context.mcpServerId,
      gatewayId: params.context.gatewayId,
      scope: params.context.scope,
      aamarvaKeyId: params.context.aamarvaKeyId,
      issuedAtMs: generated.issuedAtMs,
      expiresAtMs: generated.expiresAtMs,
      authorizationExpiresAtMs: params.context.expiresAtMs,
      redeemedAtMs: null,
      redeemedBySessionId: null,
      revokedAtMs: null,
    };

    await this.store.saveIssuedToken(record);
    this.metrics.incTokensIssued();

    const gatewayPublicKey = this.gatewayIdentity.getPublicKeyMetadata();
    const unsignedResponse = params.extendedSignedPayload
      ? {
          tokenId: generated.tokenId,
          expiresAt: envelope.expiresAt,
          gatewayId: this.gatewayId,
          mcpServerId: params.context.mcpServerId,
          agentId: params.context.agentId,
          accountId: params.context.accountId,
          authorizationId: params.context.authorizationId,
          invocationId: params.invocationId ?? params.context.authorizationId,
          ...(params.context.scope.integrationId
            ? { integrationId: params.context.scope.integrationId }
            : {}),
          ...(params.context.scope.connectionId
            ? { connectionId: params.context.scope.connectionId }
            : {}),
          redemptionEndpoint: params.redemptionEndpoint ?? '/execute',
          ...(params.gatewayPublicUrl ? { gatewayPublicUrl: params.gatewayPublicUrl } : {}),
          encryptionAlgorithm: envelope.algorithm,
          envelopeVersion: envelope.version,
          encryptedToken: envelope,
          gatewayKeyId: gatewayPublicKey.keyId,
          gatewayPublicKeyFingerprint: gatewayPublicKey.fingerprint,
          gatewayPublicKey,
          correlationId: params.correlationId,
        }
      : {
          tokenId: generated.tokenId,
          expiresAt: envelope.expiresAt,
          gatewayId: this.gatewayId,
          mcpServerId: params.context.mcpServerId,
          redemptionEndpoint: params.redemptionEndpoint ?? '/execute',
          encryptedToken: envelope,
          gatewayPublicKey,
          correlationId: params.correlationId,
        };
    const gatewaySignature = this.gatewayIdentity.signResponsePayload(unsignedResponse);

    this.audit.record({
      event: 'TOKEN_ISSUED',
      outcome: 'success',
      message: 'Short-lived token generated and encrypted with agent public key',
      correlationId: params.correlationId,
      agentId: params.context.agentId,
      accountId: params.context.accountId,
      mcpServerId: params.context.mcpServerId,
      details: {
        tokenId: generated.tokenId,
        authorizationId: params.context.authorizationId,
        algorithm: envelope.algorithm,
        gatewayKeyId: gatewayPublicKey.keyId,
        expiresAt: envelope.expiresAt,
        authorizationExpiresAt: new Date(params.context.expiresAtMs).toISOString(),
        allowedToolsCount: params.context.scope.allowedTools.length,
      },
    });

    return {
      tokenId: generated.tokenId,
      expiresAt: envelope.expiresAt,
      encryptedToken: envelope,
      gatewayPublicKey,
      gatewaySignature,
      ...(params.extendedSignedPayload ? { unsignedResponse } : {}),
    };
  }

  /**
   * Phase 6: Atomic one-time token redemption by the autonomous agent,
   * followed by durable session synchronization notification to AAMARVA backend.
   */
  async redeemToken(input: RedeemTokenInput): Promise<RedeemTokenOutcome> {
    const parsed = validateAndHashToken(input.token);
    if (!parsed) {
      this.metrics.incRedemptionsRejected();
      this.audit.record({
        event: 'TOKEN_REDEEM_FAILED',
        outcome: 'denied',
        message: 'Token redemption rejected due to invalid token format',
        correlationId: input.correlationId,
        agentId: input.agentId,
        accountId: input.accountId,
        mcpServerId: input.mcpServerId,
      });
      return {
        ok: false,
        code: 'INVALID_TOKEN_FORMAT',
        message: 'Invalid authorization token format',
        statusCode: 400,
      };
    }

    const nowMs = Date.now();
    const sessionId = generateSessionId();
    const sessionExpiresAtMs = nowMs + this.sessionTtlSeconds * 1000;
    const correlationId = input.correlationId ?? `corr_${sessionId}`;

    const result = await this.store.redeemAtomically({
      tokenHash: parsed.tokenHash,
      agentId: input.agentId,
      accountId: input.accountId,
      mcpServerId: input.mcpServerId,
      expectedAuthorizationId: input.expectedAuthorizationId,
      gatewayId: this.gatewayId,
      sessionId,
      sessionExpiresAtMs,
      correlationId,
      nowMs,
    });

    if (!result.ok) {
      this.metrics.incRedemptionsRejected();
      if (result.code === 'TOKEN_ALREADY_REDEEMED') {
        this.metrics.incReplayAttemptsBlocked();
        this.audit.record({
          event: 'TOKEN_REPLAY_BLOCKED',
          outcome: 'denied',
          message: 'Blocked attempt to replay an already-redeemed authorization token',
          correlationId: input.correlationId,
          agentId: input.agentId,
          accountId: input.accountId,
          mcpServerId: input.mcpServerId,
          details: { tokenId: parsed.tokenId, code: result.code },
        });
      } else {
        this.audit.record({
          event: 'TOKEN_REDEEM_FAILED',
          outcome: 'denied',
          message: result.message,
          correlationId: input.correlationId,
          agentId: input.agentId,
          accountId: input.accountId,
          mcpServerId: input.mcpServerId,
          details: { tokenId: parsed.tokenId, code: result.code },
        });
      }

      const statusCode =
        result.code === 'TOKEN_ALREADY_REDEEMED'
          ? 409
          : result.code === 'TOKEN_EXPIRED' ||
              result.code === 'AUTHORIZATION_EXPIRED' ||
              result.code === 'TOKEN_REVOKED'
            ? 401
            : 403;

      return {
        ok: false,
        code: result.code,
        message: result.message,
        statusCode,
      };
    }

    this.metrics.incTokensRedeemed();
    this.metrics.incSessionsCreated();

    this.audit.record({
      event: 'TOKEN_REDEEM_SUCCEEDED',
      outcome: 'success',
      message: 'One-time token redeemed and short-lived Gateway session established',
      correlationId,
      agentId: result.session.agentId,
      accountId: result.session.accountId,
      mcpServerId: result.session.mcpServerId,
      sessionId: result.session.sessionId,
      details: {
        tokenId: result.tokenRecord.tokenId,
        authorizationId: result.session.authorizationId,
        sessionExpiresAt: new Date(result.session.expiresAtMs).toISOString(),
        authorizationExpiresAt: new Date(result.session.authorizationExpiresAtMs).toISOString(),
      },
    });

    const sessionSyncStatus: SessionSyncOutcome = this.outboxProcessor
      ? await this.outboxProcessor.deliverItem(result.outboxItem, nowMs)
      : 'pending_retry';

    return { ok: true, session: result.session, sessionSyncStatus };
  }
}
