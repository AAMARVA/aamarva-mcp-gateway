import crypto from 'node:crypto';
import type { AuthorizationContext } from '../core/authorization-context.ts';
import { constantTimeEqualStrings, sha256Hex, parsePublicKeySafe } from '../config/security.ts';
import { canonicalizeMcpEndpoint } from '../crypto/credential-vault.ts';
import { SsrfBlockedError } from '../security/ssrf-guard.ts';
import type { AuditRecorder } from '../observability/audit.ts';
import type { GatewayMetrics } from '../observability/metrics.ts';
import type { GatewayStateStore } from '../storage/interfaces.ts';
import {
  AamarvaSignedAuthorizationRequestSchema,
  AamarvaSignedHandshakeRequestSchema,
  AamarvaSignedIssueTokenEndpointRequestSchema,
  AamarvaSignedRevocationRequestSchema,
  type AamarvaSignedHandshakeRequest,
} from './contracts.ts';
import type { AamarvaSignatureVerifier } from './signature-verifier.ts';

export type VerifiedAuthorizationResult =
  | {
      ok: true;
      context: AuthorizationContext;
      agentPublicKeyPem: string;
      invocationId?: string;
    }
  | { ok: false; statusCode: number; code: string; message: string };

export type VerifiedHandshakeRequestResult =
  | {
      ok: true;
      request: AamarvaSignedHandshakeRequest;
      resolvedTransport: 'stdio' | 'streamable-http';
      resolvedEndpoint: string;
      resolvedMcpServerId: string;
    }
  | { ok: false; statusCode: number; code: string; message: string };

export class AamarvaAuthorizationAdapter {
  private readonly verifier: AamarvaSignatureVerifier;
  private readonly store: GatewayStateStore;
  private readonly gatewayId: string;
  private readonly mcpServerId: string;
  private readonly requireTls: boolean;
  private readonly allowLoopbackHttp: boolean;
  private readonly mcpConfig?: {
    transport: 'stdio' | 'streamable-http';
    httpUrl?: string;
  };
  private readonly audit: AuditRecorder;
  private readonly metrics: GatewayMetrics;
  private readonly onAccountRevoked?: (accountId: string) => Promise<void>;

  constructor(options: {
    verifier: AamarvaSignatureVerifier;
    store: GatewayStateStore;
    gatewayId: string;
    mcpServerId: string;
    requireTls?: boolean;
    allowLoopbackHttp?: boolean;
    mcpConfig?: {
      transport: 'stdio' | 'streamable-http';
      httpUrl?: string;
    };
    audit: AuditRecorder;
    metrics: GatewayMetrics;
    onAccountRevoked?: (accountId: string) => Promise<void>;
  }) {
    this.verifier = options.verifier;
    this.store = options.store;
    this.gatewayId = options.gatewayId;
    this.mcpServerId = options.mcpServerId;
    this.requireTls = options.requireTls ?? false;
    this.allowLoopbackHttp = options.allowLoopbackHttp ?? false;
    this.mcpConfig = options.mcpConfig;
    this.audit = options.audit;
    this.metrics = options.metrics;
    this.onAccountRevoked = options.onAccountRevoked;
  }

  async verifyHandshakeRequest(
    rawPayload: unknown,
    correlationId: string,
  ): Promise<VerifiedHandshakeRequestResult> {
    if (rawPayload && typeof rawPayload === 'object' && !Array.isArray(rawPayload)) {
      const obj = rawPayload as Record<string, unknown>;
      const claimsObj =
        obj.claims && typeof obj.claims === 'object' && !Array.isArray(obj.claims)
          ? (obj.claims as Record<string, unknown>)
          : undefined;
      const plaintextKeys = ['authorizationHeader', 'customHeaders', 'authHeader'];
      const hasPlaintext = plaintextKeys.some(
        (k) => obj[k] !== undefined || (claimsObj !== undefined && claimsObj[k] !== undefined),
      );
      if (hasPlaintext) {
        this.metrics.incHandshakesFailed();
        this.audit.record({
          event: 'PLAINTEXT_CREDENTIALS_REJECTED',
          outcome: 'denied',
          message: 'Rejected handshake request containing plaintext external MCP credentials',
          correlationId,
        });
        return {
          ok: false,
          statusCode: 400,
          code: 'PLAINTEXT_CREDENTIALS_FORBIDDEN',
          message:
            'Plaintext credentials (authorizationHeader/customHeaders) are forbidden. Encrypt external MCP credentials using AAMARVA-GW-CRED-V1 in encryptedCredentials.',
        };
      }
    }

    const parsed = AamarvaSignedHandshakeRequestSchema.safeParse(rawPayload);
    if (!parsed.success) {
      this.metrics.incHandshakesFailed();
      this.audit.record({
        event: 'MCP_HANDSHAKE_FAILED',
        outcome: 'denied',
        message: 'Invalid or non-strict MCP verification handshake payload',
        correlationId,
      });
      return {
        ok: false,
        statusCode: 400,
        code: 'INVALID_HANDSHAKE_REQUEST',
        message: 'Malformed or disallowed fields in AAMARVA MCP handshake request',
      };
    }

    const req = parsed.data;
    const { claims, keyId, signature } = req;
    const effectiveMcpServerId = claims.mcpServerId ?? this.mcpServerId;

    if (claims.gatewayId !== this.gatewayId) {
      this.metrics.incHandshakesFailed();
      this.audit.record({
        event: 'MCP_HANDSHAKE_FAILED',
        outcome: 'denied',
        message: 'Handshake request targets a different Gateway installation ID',
        correlationId,
        accountId: claims.accountId,
        mcpServerId: effectiveMcpServerId,
      });
      return {
        ok: false,
        statusCode: 403,
        code: 'GATEWAY_MISMATCH',
        message: 'Handshake gatewayId does not match this Gateway installation',
      };
    }

    const issuedAtIso = claims.issuedAt ?? claims.timestamp ?? '';
    const sigRes = this.verifier.verifySignedGrant({
      claims,
      signature,
      keyId,
      issuedAtIso,
      expiresAtIso: claims.expiresAt,
    });

    if (!sigRes.valid) {
      this.metrics.incSignatureVerificationFailed();
      this.metrics.incHandshakesFailed();
      const isExpired = Boolean(sigRes.reason?.toLowerCase().includes('expired'));
      this.audit.record({
        event: 'MCP_HANDSHAKE_FAILED',
        outcome: 'denied',
        message: sigRes.reason ?? 'AAMARVA handshake signature verification failed',
        correlationId,
        accountId: claims.accountId,
        mcpServerId: effectiveMcpServerId,
        details: { keyId, integrationId: claims.integrationId },
      });
      return {
        ok: false,
        statusCode: 401,
        code: isExpired ? 'HANDSHAKE_CHALLENGE_EXPIRED' : 'INVALID_AAMARVA_SIGNATURE',
        message: sigRes.reason ?? 'Invalid AAMARVA handshake signature',
      };
    }

    // Resolve Subject MCP Server destination: use customer configured Subject MCP Server URL
    // when claims omit endpoint, and enforce SSRF + configured URL match when provided.
    const configuredTransport = this.mcpConfig?.transport ?? 'stdio';
    const configuredHttpUrl = this.mcpConfig?.httpUrl;
    const resolvedTransport: 'stdio' | 'streamable-http' =
      claims.transport ??
      (claims.endpoint
        ? claims.endpoint.trim().startsWith('stdio://')
          ? 'stdio'
          : 'streamable-http'
        : configuredTransport);

    let resolvedEndpoint: string;
    if (claims.endpoint) {
      resolvedEndpoint = claims.endpoint.trim();
    } else if (resolvedTransport === 'streamable-http') {
      if (!configuredHttpUrl) {
        this.metrics.incHandshakesFailed();
        return {
          ok: false,
          statusCode: 400,
          code: 'INVALID_MCP_ENDPOINT',
          message: 'No Subject MCP Server URL (MCP_HTTP_URL) is configured for streamable-http handshake',
        };
      }
      resolvedEndpoint = configuredHttpUrl;
    } else {
      resolvedEndpoint = `stdio://${effectiveMcpServerId}`;
    }

    if (resolvedTransport === 'streamable-http') {
      let canonicalTarget: string;
      try {
        canonicalTarget = canonicalizeMcpEndpoint(resolvedEndpoint, {
          allowInsecureHttp: !this.requireTls,
          allowLoopbackHttp: this.allowLoopbackHttp,
        });
      } catch (err) {
        if (err instanceof SsrfBlockedError) {
          this.metrics.incHandshakesFailed();
          this.audit.record({
            event: 'SSRF_BLOCKED',
            outcome: 'denied',
            message: err.message,
            correlationId,
            accountId: claims.accountId,
            mcpServerId: effectiveMcpServerId,
            details: { code: err.code },
          });
          return {
            ok: false,
            statusCode: err.statusCode,
            code: err.code,
            message: err.message,
          };
        }
        return {
          ok: false,
          statusCode: 400,
          code: 'INVALID_MCP_ENDPOINT',
          message: 'Invalid Subject MCP Server URL',
        };
      }

      if (configuredTransport === 'streamable-http' && configuredHttpUrl) {
        let canonicalConfigured: string;
        try {
          canonicalConfigured = canonicalizeMcpEndpoint(configuredHttpUrl, {
            allowInsecureHttp: !this.requireTls,
            allowLoopbackHttp: this.allowLoopbackHttp,
          });
        } catch (err) {
          if (err instanceof SsrfBlockedError) {
            return {
              ok: false,
              statusCode: err.statusCode,
              code: err.code,
              message: err.message,
            };
          }
          return {
            ok: false,
            statusCode: 400,
            code: 'INVALID_MCP_ENDPOINT',
            message: 'Configured Subject MCP Server URL failed validation',
          };
        }

        if (canonicalTarget !== canonicalConfigured) {
          this.metrics.incHandshakesFailed();
          this.audit.record({
            event: 'CONNECTION_SUBSTITUTION_BLOCKED',
            outcome: 'denied',
            message: 'Handshake endpoint does not match configured Subject MCP Server URL',
            correlationId,
            accountId: claims.accountId,
            mcpServerId: effectiveMcpServerId,
          });
          return {
            ok: false,
            statusCode: 403,
            code: 'ENDPOINT_MISMATCH',
            message: 'Endpoint substitution rejected: endpoint must match customer configured Subject MCP Server URL',
          };
        }
      }
      resolvedEndpoint = canonicalTarget;
    }

    if (req.expectedEndpoint) {
      let expectedNorm = req.expectedEndpoint.trim();
      let claimNorm = resolvedEndpoint.trim();
      if (resolvedTransport === 'streamable-http') {
        try {
          expectedNorm = canonicalizeMcpEndpoint(req.expectedEndpoint, {
            allowInsecureHttp: !this.requireTls,
            allowLoopbackHttp: this.allowLoopbackHttp,
          });
          claimNorm = canonicalizeMcpEndpoint(resolvedEndpoint, {
            allowInsecureHttp: !this.requireTls,
            allowLoopbackHttp: this.allowLoopbackHttp,
          });
        } catch (err) {
          if (err instanceof SsrfBlockedError) {
            this.metrics.incHandshakesFailed();
            this.audit.record({
              event: 'SSRF_BLOCKED',
              outcome: 'denied',
              message: err.message,
              correlationId,
              accountId: claims.accountId,
              mcpServerId: effectiveMcpServerId,
              details: { code: err.code },
            });
            return {
              ok: false,
              statusCode: err.statusCode,
              code: err.code,
              message: err.message,
            };
          }
          expectedNorm = '__invalid__';
        }
      }
      if (expectedNorm !== claimNorm) {
        this.metrics.incHandshakesFailed();
        this.audit.record({
          event: 'CONNECTION_SUBSTITUTION_BLOCKED',
          outcome: 'denied',
          message: 'Handshake expectedEndpoint does not match resolved Subject MCP endpoint',
          correlationId,
          accountId: claims.accountId,
          mcpServerId: effectiveMcpServerId,
        });
        return {
          ok: false,
          statusCode: 403,
          code: 'ENDPOINT_MISMATCH',
          message: 'Endpoint substitution rejected: expectedEndpoint mismatches resolved Subject MCP endpoint',
        };
      }
    }

    const nowMs = Date.now();
    const challengeTtlMs = Math.max(Date.parse(claims.expiresAt), nowMs + 24 * 3600_000);
    const claimed = await this.store.claimHandshakeChallenge(
      claims.challenge,
      challengeTtlMs,
      nowMs,
    );

    if (!claimed) {
      this.metrics.incHandshakesFailed();
      this.metrics.incReplayAttemptsBlocked();
      this.audit.record({
        event: 'HANDSHAKE_CHALLENGE_REPLAYED',
        outcome: 'denied',
        message: 'Rejected replayed MCP verification handshake challenge',
        correlationId,
        accountId: claims.accountId,
        mcpServerId: effectiveMcpServerId,
        details: { integrationId: claims.integrationId },
      });
      return {
        ok: false,
        statusCode: 409,
        code: 'HANDSHAKE_CHALLENGE_REPLAYED',
        message: 'Handshake challenge has already been used',
      };
    }

    if (claims.nonce) {
      const nonceFresh = await this.store.claimRequestId(
        `hs_nonce:${claims.nonce}`,
        challengeTtlMs,
        nowMs,
      );
      if (!nonceFresh) {
        this.metrics.incHandshakesFailed();
        this.metrics.incReplayAttemptsBlocked();
        return {
          ok: false,
          statusCode: 409,
          code: 'HANDSHAKE_NONCE_REPLAYED',
          message: 'Handshake nonce has already been used',
        };
      }
    }

    return {
      ok: true,
      request: req,
      resolvedTransport,
      resolvedEndpoint,
      resolvedMcpServerId: effectiveMcpServerId,
    };
  }

  /**
   * Phase 1: Validates and verifies AAMARVA's cryptographic signature over the
   * agent identity, public key, and tool scope before trusting any claim.
   */
  async verifyAuthorizationGrant(
    rawPayload: unknown,
    correlationId: string,
  ): Promise<VerifiedAuthorizationResult> {
    const parsed = AamarvaSignedAuthorizationRequestSchema.safeParse(rawPayload);
    if (!parsed.success) {
      this.metrics.incSignatureVerificationFailed();
      this.audit.record({
        event: 'SIGNATURE_VERIFICATION_FAILED',
        outcome: 'denied',
        message: 'Malformed AAMARVA signed authorization payload',
        correlationId,
      });
      return {
        ok: false,
        statusCode: 400,
        code: 'INVALID_AUTHORIZATION_PAYLOAD',
        message: 'Malformed AAMARVA authorization payload',
      };
    }

    const { claims, keyId, signature } = parsed.data;

    this.audit.record({
      event: 'AUTHORIZATION_RECEIVED',
      outcome: 'success',
      message: 'Received signed authorization grant from AAMARVA backend',
      correlationId,
      agentId: claims.agentId,
      accountId: claims.accountId,
      mcpServerId: claims.mcpServerId,
      details: { authorizationId: claims.authorizationId, keyId },
    });

    if (claims.gatewayId !== this.gatewayId) {
      this.audit.record({
        event: 'SIGNATURE_VERIFICATION_FAILED',
        outcome: 'denied',
        message: 'Authorization grant targets a different Gateway installation ID',
        correlationId,
        agentId: claims.agentId,
        accountId: claims.accountId,
        mcpServerId: claims.mcpServerId,
      });
      return {
        ok: false,
        statusCode: 403,
        code: 'GATEWAY_MISMATCH',
        message: 'Authorization grant gatewayId does not match this Gateway installation',
      };
    }

    const usesVerifiedConnection = Boolean(
      claims.connectionId || claims.integrationId || claims.endpoint,
    );

    if (!usesVerifiedConnection && claims.mcpServerId !== this.mcpServerId) {
      this.audit.record({
        event: 'SIGNATURE_VERIFICATION_FAILED',
        outcome: 'denied',
        message: 'Authorization grant targets a different MCP server ID',
        correlationId,
        agentId: claims.agentId,
        accountId: claims.accountId,
        mcpServerId: claims.mcpServerId,
      });
      return {
        ok: false,
        statusCode: 403,
        code: 'SERVER_MISMATCH',
        message: 'Authorization grant mcpServerId does not match configured MCP server',
      };
    }

    const verifyRes = this.verifier.verifySignedGrant({
      claims,
      signature,
      keyId,
      issuedAtIso: claims.issuedAt,
      expiresAtIso: claims.expiresAt,
    });

    if (!verifyRes.valid) {
      this.metrics.incSignatureVerificationFailed();
      this.audit.record({
        event: 'SIGNATURE_VERIFICATION_FAILED',
        outcome: 'denied',
        message: verifyRes.reason ?? 'AAMARVA signature verification failed',
        correlationId,
        agentId: claims.agentId,
        accountId: claims.accountId,
        mcpServerId: claims.mcpServerId,
        details: { keyId, authorizationId: claims.authorizationId },
      });
      return {
        ok: false,
        statusCode: 401,
        code: 'INVALID_AAMARVA_SIGNATURE',
        message: verifyRes.reason ?? 'Invalid AAMARVA signature',
      };
    }

    let boundIntegrationId: string | undefined;
    let boundConnectionId: string | undefined;
    let boundCanonicalEndpoint: string | undefined;

    if (usesVerifiedConnection) {
      let connection = claims.connectionId
        ? await this.store.getVerifiedConnection(claims.connectionId)
        : null;
      if (!connection && claims.integrationId) {
        connection = await this.store.getLatestVerifiedConnectionByIntegration(
          claims.accountId,
          claims.integrationId,
        );
      }

      if (!connection) {
        this.audit.record({
          event: 'CONNECTION_SUBSTITUTION_BLOCKED',
          outcome: 'denied',
          message: 'Authorization grant references unverified MCP connection',
          correlationId,
          agentId: claims.agentId,
          accountId: claims.accountId,
          mcpServerId: claims.mcpServerId,
        });
        return {
          ok: false,
          statusCode: 403,
          code: 'CONNECTION_NOT_VERIFIED',
          message: 'Referenced MCP connection has not completed Gateway verification handshake',
        };
      }

      if (connection.accountId !== claims.accountId) {
        this.audit.record({
          event: 'CONNECTION_SUBSTITUTION_BLOCKED',
          outcome: 'denied',
          message: 'Cross-account MCP connection reference blocked during grant verification',
          correlationId,
          agentId: claims.agentId,
          accountId: claims.accountId,
          mcpServerId: claims.mcpServerId,
        });
        return {
          ok: false,
          statusCode: 403,
          code: 'ACCOUNT_MISMATCH',
          message: 'Authorization grant accountId does not own the referenced verified MCP connection',
        };
      }

      if (claims.integrationId && connection.integrationId !== claims.integrationId) {
        return {
          ok: false,
          statusCode: 403,
          code: 'INTEGRATION_MISMATCH',
          message: 'Verified MCP connection does not match integrationId in grant',
        };
      }

      if (connection.mcpServerId !== claims.mcpServerId) {
        return {
          ok: false,
          statusCode: 403,
          code: 'SERVER_MISMATCH',
          message: 'Verified MCP connection does not match mcpServerId in grant',
        };
      }

      if (claims.endpoint) {
        let canonicalClaimEndpoint = claims.endpoint.trim();
        if (connection.transport === 'streamable-http') {
          try {
            canonicalClaimEndpoint = canonicalizeMcpEndpoint(claims.endpoint, {
              allowInsecureHttp: !this.requireTls,
              allowLoopbackHttp: this.allowLoopbackHttp,
            });
          } catch {
            canonicalClaimEndpoint = '__invalid__';
          }
        }
        if (canonicalClaimEndpoint !== connection.canonicalEndpoint) {
          this.audit.record({
            event: 'CONNECTION_SUBSTITUTION_BLOCKED',
            outcome: 'denied',
            message: 'Authorization grant endpoint substitution rejected',
            correlationId,
            agentId: claims.agentId,
            accountId: claims.accountId,
            mcpServerId: claims.mcpServerId,
          });
          return {
            ok: false,
            statusCode: 403,
            code: 'ENDPOINT_MISMATCH',
            message: 'Grant endpoint does not match verified MCP connection endpoint',
          };
        }
      }

      if (connection.status !== 'active' || Date.now() > connection.expiresAtMs) {
        return {
          ok: false,
          statusCode: 401,
          code: connection.status === 'revoked' ? 'CONNECTION_REVOKED' : 'CONNECTION_EXPIRED',
          message: 'Referenced verified MCP connection is no longer active',
        };
      }

      boundIntegrationId = connection.integrationId;
      boundConnectionId = connection.connectionId;
      boundCanonicalEndpoint = connection.canonicalEndpoint;
    }

    this.audit.record({
      event: 'SIGNATURE_VERIFICATION_SUCCEEDED',
      outcome: 'success',
      message: 'Verified AAMARVA cryptographic signature over agent authorization grant',
      correlationId,
      agentId: claims.agentId,
      accountId: claims.accountId,
      mcpServerId: claims.mcpServerId,
      details: {
        keyId,
        algorithm: verifyRes.algorithm,
        authorizationId: claims.authorizationId,
        connectionId: boundConnectionId,
      },
    });

    const context: AuthorizationContext = {
      authorizationId: claims.authorizationId,
      agentId: claims.agentId,
      agentName: claims.agentName,
      accountId: claims.accountId,
      mcpServerId: claims.mcpServerId,
      gatewayId: claims.gatewayId,
      scope: {
        allowedTools: claims.allowedTools,
        permissions: claims.permissions,
        floorApproved: claims.floorApproved,
        floorApprovalId: claims.floorApprovalId,
        integrationId: boundIntegrationId,
        connectionId: boundConnectionId,
        canonicalEndpoint: boundCanonicalEndpoint,
      },
      aamarvaKeyId: keyId,
      issuedAtMs: Date.parse(claims.issuedAt),
      expiresAtMs: Date.parse(claims.expiresAt),
    };

    return {
      ok: true,
      context,
      agentPublicKeyPem: claims.agentPublicKeyPem,
    };
  }

  /**
   * Strict verification path for POST /issuetoken:
   * Enforces AAMARVA signature, P-256 agent public key + SHA-256 fingerprint match,
   * verified integration connection ownership, invocation/authorization binding,
   * and requested tool validation against discovered tools.
   */
  async verifyIssueTokenEndpointRequest(
    rawPayload: unknown,
    correlationId: string,
  ): Promise<VerifiedAuthorizationResult> {
    if (rawPayload && typeof rawPayload === 'object' && !Array.isArray(rawPayload)) {
      const rawClaims = (rawPayload as Record<string, unknown>).claims;
      if (rawClaims && typeof rawClaims === 'object' && !Array.isArray(rawClaims)) {
        const pem = (rawClaims as Record<string, unknown>).agentPublicKeyPem;
        if (typeof pem !== 'string' || pem.trim() === '') {
          this.metrics.incSignatureVerificationFailed();
          return {
            ok: false,
            statusCode: 400,
            code: 'MISSING_AGENT_PUBLIC_KEY',
            message: 'Missing required agentPublicKeyPem in authorization claims',
          };
        }
      }
    }

    const parsed = AamarvaSignedIssueTokenEndpointRequestSchema.safeParse(rawPayload);
    if (!parsed.success) {
      this.metrics.incSignatureVerificationFailed();
      this.audit.record({
        event: 'SIGNATURE_VERIFICATION_FAILED',
        outcome: 'denied',
        message: 'Malformed AAMARVA /issuetoken authorization payload',
        correlationId,
      });
      return {
        ok: false,
        statusCode: 400,
        code: 'INVALID_AUTHORIZATION_PAYLOAD',
        message: 'Malformed AAMARVA /issuetoken authorization payload',
      };
    }

    const { claims, keyId, signature } = parsed.data;
    const authorizationId = claims.authorizationId ?? claims.invocationId!;
    const invocationId = claims.invocationId ?? authorizationId;
    const effectiveMcpServerId = claims.mcpServerId ?? this.mcpServerId;

    if (!claims.agentPublicKeyPem || claims.agentPublicKeyPem.trim() === '') {
      return {
        ok: false,
        statusCode: 400,
        code: 'MISSING_AGENT_PUBLIC_KEY',
        message: 'Missing required agentPublicKeyPem in authorization claims',
      };
    }

    if (claims.gatewayId !== this.gatewayId) {
      return {
        ok: false,
        statusCode: 403,
        code: 'GATEWAY_MISMATCH',
        message: 'Authorization grant gatewayId does not match this Gateway installation',
      };
    }

    const issuedAtIso = claims.issuedAt ?? claims.timestamp ?? '';
    const verifyRes = this.verifier.verifySignedGrant({
      claims,
      signature,
      keyId,
      issuedAtIso,
      expiresAtIso: claims.expiresAt,
    });

    if (!verifyRes.valid) {
      this.metrics.incSignatureVerificationFailed();
      const isExpired = Boolean(verifyRes.reason?.toLowerCase().includes('expired'));
      this.audit.record({
        event: 'SIGNATURE_VERIFICATION_FAILED',
        outcome: 'denied',
        message: verifyRes.reason ?? 'AAMARVA signature verification failed on /issuetoken',
        correlationId,
        agentId: claims.agentId,
        accountId: claims.accountId,
        mcpServerId: effectiveMcpServerId,
        details: { keyId, authorizationId, invocationId },
      });
      return {
        ok: false,
        statusCode: 401,
        code: isExpired ? 'INVOCATION_EXPIRED' : 'INVALID_AAMARVA_SIGNATURE',
        message: verifyRes.reason ?? 'Invalid AAMARVA signature',
      };
    }

    // Validate agent public key is strictly EC P-256 and matches registered SHA-256 SPKI fingerprint
    let agentKeyObj: crypto.KeyObject;
    try {
      agentKeyObj = parsePublicKeySafe(claims.agentPublicKeyPem);
    } catch {
      return {
        ok: false,
        statusCode: 400,
        code: 'INVALID_AGENT_PUBLIC_KEY',
        message: 'Unparseable agentPublicKeyPem; expected valid EC P-256 SPKI public key',
      };
    }

    const curve = agentKeyObj.asymmetricKeyDetails?.namedCurve;
    if (
      agentKeyObj.asymmetricKeyType !== 'ec' ||
      (curve !== 'prime256v1' && curve !== 'P-256')
    ) {
      return {
        ok: false,
        statusCode: 400,
        code: 'INVALID_AGENT_PUBLIC_KEY',
        message: 'Agent public key must be an EC P-256 (prime256v1) SPKI key',
      };
    }

    const spkiDer = agentKeyObj.export({ type: 'spki', format: 'der' }) as Buffer;
    const computedHex = sha256Hex(spkiDer).toLowerCase();
    const expectedPrefixed = `sha256:${computedHex}`;
    const providedNorm = claims.agentPublicKeyFingerprint.trim().toLowerCase();
    const providedPrefixed = providedNorm.startsWith('sha256:')
      ? providedNorm
      : `sha256:${providedNorm}`;

    if (!constantTimeEqualStrings(expectedPrefixed, providedPrefixed)) {
      this.audit.record({
        event: 'SIGNATURE_VERIFICATION_FAILED',
        outcome: 'denied',
        message: 'Agent P-256 public key fingerprint mismatch on /issuetoken',
        correlationId,
        agentId: claims.agentId,
        accountId: claims.accountId,
        mcpServerId: effectiveMcpServerId,
      });
      return {
        ok: false,
        statusCode: 400,
        code: 'AGENT_KEY_FINGERPRINT_MISMATCH',
        message: 'Agent public key SHA-256 fingerprint does not match agentPublicKeyFingerprint',
      };
    }

    // Verify integration connection established via /handshake
    let connection = claims.connectionId
      ? await this.store.getVerifiedConnection(claims.connectionId)
      : await this.store.getLatestVerifiedConnectionByIntegration(
          claims.accountId,
          claims.integrationId,
        );

    if (!connection) {
      this.audit.record({
        event: 'CONNECTION_SUBSTITUTION_BLOCKED',
        outcome: 'denied',
        message: 'Authorization request references unverified integration connection',
        correlationId,
        agentId: claims.agentId,
        accountId: claims.accountId,
        mcpServerId: effectiveMcpServerId,
      });
      return {
        ok: false,
        statusCode: 403,
        code: 'CONNECTION_NOT_VERIFIED',
        message: 'Integration has not completed Gateway verification handshake',
      };
    }

    if (connection.accountId !== claims.accountId) {
      return {
        ok: false,
        statusCode: 403,
        code: 'ACCOUNT_MISMATCH',
        message: 'Authorization accountId does not own the verified MCP connection',
      };
    }

    if (connection.integrationId !== claims.integrationId) {
      return {
        ok: false,
        statusCode: 403,
        code: 'INTEGRATION_MISMATCH',
        message: 'Verified MCP connection does not match integrationId',
      };
    }

    if (connection.mcpServerId !== effectiveMcpServerId) {
      return {
        ok: false,
        statusCode: 403,
        code: 'SERVER_MISMATCH',
        message: 'Verified MCP connection does not match mcpServerId',
      };
    }

    if (claims.endpoint) {
      let canonicalClaimEndpoint = claims.endpoint.trim();
      if (connection.transport === 'streamable-http') {
        try {
          canonicalClaimEndpoint = canonicalizeMcpEndpoint(claims.endpoint, {
            allowInsecureHttp: !this.requireTls,
            allowLoopbackHttp: this.allowLoopbackHttp,
          });
        } catch {
          canonicalClaimEndpoint = '__invalid__';
        }
      }
      if (canonicalClaimEndpoint !== connection.canonicalEndpoint) {
        return {
          ok: false,
          statusCode: 403,
          code: 'ENDPOINT_MISMATCH',
          message: 'Authorization endpoint does not match verified Subject MCP Server URL',
        };
      }
    }

    if (connection.status !== 'active' || Date.now() > connection.expiresAtMs) {
      return {
        ok: false,
        statusCode: 401,
        code: connection.status === 'revoked' ? 'CONNECTION_REVOKED' : 'CONNECTION_EXPIRED',
        message: 'Verified MCP connection is no longer active',
      };
    }

    // Validate all requested tools were discovered and exist on the verified integration
    const discoveredSet = new Set(connection.toolNames);
    const unauthorizedTools = claims.allowedTools.filter((t) => !discoveredSet.has(t));
    if (unauthorizedTools.length > 0) {
      this.audit.record({
        event: 'MCP_TOOL_DENIED',
        outcome: 'denied',
        message: `Rejected token issuance for unrecognized/unauthorized tool(s): ${unauthorizedTools.join(', ')}`,
        correlationId,
        agentId: claims.agentId,
        accountId: claims.accountId,
        mcpServerId: effectiveMcpServerId,
        details: { unauthorizedTools },
      });
      return {
        ok: false,
        statusCode: 403,
        code: 'TOOL_NOT_AUTHORIZED',
        message: `Requested tool(s) not authorized on verified integration: ${unauthorizedTools.join(', ')}`,
      };
    }

    const context: AuthorizationContext = {
      authorizationId,
      agentId: claims.agentId,
      agentName: claims.agentName ?? claims.agentId,
      accountId: claims.accountId,
      mcpServerId: effectiveMcpServerId,
      gatewayId: claims.gatewayId,
      scope: {
        allowedTools: claims.allowedTools,
        permissions: claims.permissions,
        floorApproved: claims.floorApproved,
        floorApprovalId: claims.floorApprovalId,
        integrationId: connection.integrationId,
        connectionId: connection.connectionId,
        canonicalEndpoint: connection.canonicalEndpoint,
      },
      aamarvaKeyId: keyId,
      issuedAtMs: Date.parse(issuedAtIso),
      expiresAtMs: Date.parse(claims.expiresAt),
    };

    return {
      ok: true,
      context,
      agentPublicKeyPem: claims.agentPublicKeyPem,
      invocationId,
    };
  }

  async processRevocation(
    rawPayload: unknown,
    correlationId: string,
  ): Promise<{
    ok: boolean;
    statusCode: number;
    revokedCount: number;
    duplicate?: boolean;
    message: string;
  }> {
    const parsed = AamarvaSignedRevocationRequestSchema.safeParse(rawPayload);
    if (!parsed.success) {
      return {
        ok: false,
        statusCode: 400,
        revokedCount: 0,
        message: 'Invalid AAMARVA revocation payload',
      };
    }

    const { claims, keyId, signature } = parsed.data;
    const sigRes = this.verifier.verifySignedGrant({
      claims,
      signature,
      keyId,
      issuedAtIso: claims.revokedAt,
      expiresAtIso: new Date(Date.parse(claims.revokedAt) + 300_000).toISOString(),
    });

    if (!sigRes.valid) {
      this.metrics.incSignatureVerificationFailed();
      return {
        ok: false,
        statusCode: 401,
        revokedCount: 0,
        message: sigRes.reason ?? 'Invalid revocation signature',
      };
    }

    const nowMs = Date.now();
    const claimed = await this.store.claimRevocationId(
      claims.revocationId,
      nowMs + 7 * 86_400_000,
      nowMs,
    );

    if (!claimed) {
      return {
        ok: true,
        statusCode: 200,
        revokedCount: 0,
        duplicate: true,
        message: 'Duplicate revocation ignored idempotently',
      };
    }

    let revokedCount = 0;

    if (claims.sessionId) {
      const ok = await this.store.revokeSession(
        claims.sessionId,
        claims.reason,
        claims.revokedBy,
        nowMs,
      );
      if (ok) revokedCount += 1;
    } else if (claims.authorizationId) {
      revokedCount = await this.store.revokeByAuthorization(
        claims.authorizationId,
        claims.reason,
        claims.revokedBy,
        nowMs,
      );
    } else if (claims.agentId && claims.accountId) {
      revokedCount = await this.store.revokeByAgent(
        claims.agentId,
        claims.accountId,
        claims.reason,
        claims.revokedBy,
        nowMs,
      );
    } else if (claims.accountId) {
      revokedCount = await this.store.revokeByAccount(
        claims.accountId,
        claims.reason,
        claims.revokedBy,
        nowMs,
      );
      await this.onAccountRevoked?.(claims.accountId);
    } else {
      return {
        ok: false,
        statusCode: 400,
        revokedCount: 0,
        message:
          'Revocation must specify sessionId, authorizationId, (agentId + accountId), or accountId',
      };
    }

    if (revokedCount > 0) {
      this.metrics.incSessionsRevoked(revokedCount);
    }

    this.audit.record({
      event: 'SESSION_REVOKED',
      outcome: 'success',
      message: `Processed AAMARVA revocation (${revokedCount} session(s) revoked)`,
      correlationId,
      agentId: claims.agentId,
      accountId: claims.accountId,
      sessionId: claims.sessionId,
      details: {
        revocationId: claims.revocationId,
        authorizationId: claims.authorizationId,
        reason: claims.reason,
        revokedBy: claims.revokedBy,
        revokedCount,
      },
    });

    return {
      ok: true,
      statusCode: 200,
      revokedCount,
      duplicate: false,
      message: 'Revocation applied',
    };
  }
}
