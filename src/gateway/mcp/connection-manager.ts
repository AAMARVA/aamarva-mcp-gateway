import crypto from 'node:crypto';
import { canonicalizeJson, sha256Hex } from '../config/security.ts';
import type {
  GatewayHandshakeResponse,
  GatewayVerificationAttestation,
  VerifiedMcpConnectionRecord,
} from '../core/authorization-context.ts';
import {
  decryptHandshakeCredentialEnvelope,
  decryptStoredMcpCredentials,
  encryptStoredMcpCredentials,
  type EncryptedCredentialEnvelope,
  type ExternalMcpCredentials,
} from '../crypto/credential-vault.ts';
import type { GatewayIdentityKeyManager } from '../crypto/gateway-keypair.ts';
import type { AuditRecorder } from '../observability/audit.ts';
import type { GatewayMetrics } from '../observability/metrics.ts';
import {
  canonicalizeEndpointForPoolCheck,
  normalizeAndCheckDestination,
} from './connection-manager-helpers.ts';
import {
  resolveAndValidateMcpDestination,
  SsrfBlockedError,
  type DnsLookupFn,
} from '../security/ssrf-guard.ts';
import type { GatewayStateStore } from '../storage/interfaces.ts';
import type { McpToolDefinition, McpUpstreamAdapter } from './mcp-transport.ts';
import { StreamableHttpMcpTransportAdapter } from './streamable-http-adapter.ts';

export class HandshakeVerificationError extends Error {
  readonly statusCode: number;
  readonly code: string;

  constructor(statusCode: number, code: string, message: string) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

export interface PerformHandshakeParams {
  accountId: string;
  integrationId: string;
  mcpServerId: string;
  challenge: string;
  transport: 'stdio' | 'streamable-http';
  endpoint: string;
  encryptedCredentials?: EncryptedCredentialEnvelope;
  attestationTtlSeconds?: number;
  correlationId: string;
}

export type ResolveAdapterResult =
  | {
      ok: true;
      adapter: McpUpstreamAdapter;
      connection: VerifiedMcpConnectionRecord;
    }
  | {
      ok: false;
      statusCode: number;
      code: string;
      message: string;
    };

interface PooledMcpConnection {
  accountId: string;
  canonicalEndpoint: string;
  validatedIpsKey: string;
  adapter: McpUpstreamAdapter;
  ownsLifecycle: boolean;
}

/**
 * Manages outbound MCP verification handshakes, cryptographic attestations,
 * SSRF + DNS-rebinding destination pinning, encrypted external credentials at rest,
 * and pooled authenticated connections strictly partitioned by
 * (accountId, integrationId, connectionId, canonicalEndpoint).
 */
export class McpConnectionManager {
  private readonly gatewayId: string;
  private readonly defaultMcpServerId: string;
  private readonly defaultMcpAdapter: McpUpstreamAdapter;
  private readonly store: GatewayStateStore;
  private readonly gatewayIdentity: GatewayIdentityKeyManager;
  private readonly backendAuthSecret: string;
  private readonly vaultSecret: string;
  private readonly requireTls: boolean;
  private readonly allowLoopbackHttp: boolean;
  private readonly configuredSubjectAuthHeader?: {
    httpUrl: string;
    authorizationHeader: string;
  };
  private readonly dnsLookup?: DnsLookupFn;
  private readonly fetchOverride?: (input: string | URL, init?: RequestInit) => Promise<Response>;
  private readonly defaultTimeoutMs: number;
  private readonly audit: AuditRecorder;
  private readonly metrics: GatewayMetrics;
  private readonly pool = new Map<string, PooledMcpConnection>();

  constructor(options: {
    gatewayId: string;
    defaultMcpServerId: string;
    defaultMcpAdapter: McpUpstreamAdapter;
    store: GatewayStateStore;
    gatewayIdentity: GatewayIdentityKeyManager;
    backendAuthSecret: string;
    requireTls: boolean;
    allowLoopbackHttp?: boolean;
    configuredSubjectAuthHeader?: {
      httpUrl: string;
      authorizationHeader: string;
    };
    dnsLookup?: DnsLookupFn;
    fetchOverride?: (input: string | URL, init?: RequestInit) => Promise<Response>;
    defaultTimeoutMs: number;
    audit: AuditRecorder;
    metrics: GatewayMetrics;
  }) {
    this.gatewayId = options.gatewayId;
    this.defaultMcpServerId = options.defaultMcpServerId;
    this.defaultMcpAdapter = options.defaultMcpAdapter;
    this.store = options.store;
    this.gatewayIdentity = options.gatewayIdentity;
    this.backendAuthSecret = options.backendAuthSecret;
    this.vaultSecret = `${options.backendAuthSecret}:${options.gatewayIdentity.getPublicKeyMetadata().fingerprint}`;
    this.requireTls = options.requireTls;
    this.allowLoopbackHttp = options.allowLoopbackHttp ?? false;
    this.configuredSubjectAuthHeader = options.configuredSubjectAuthHeader;
    this.dnsLookup = options.dnsLookup;
    this.fetchOverride = options.fetchOverride;
    this.defaultTimeoutMs = options.defaultTimeoutMs;
    this.audit = options.audit;
    this.metrics = options.metrics;
  }

  async performHandshakeAndAttest(params: PerformHandshakeParams): Promise<GatewayHandshakeResponse> {
    let canonicalEndpoint: string;
    let validatedIpsKey = 'stdio';

    if (params.transport === 'stdio') {
      if (params.mcpServerId !== this.defaultMcpServerId) {
        throw new HandshakeVerificationError(
          403,
          'SERVER_MISMATCH',
          'STDIO handshake mcpServerId must match this Gateway configured MCP server',
        );
      }
      canonicalEndpoint = `stdio://${this.defaultMcpServerId}`;
      if (params.endpoint.trim() !== canonicalEndpoint && params.endpoint.trim() !== 'stdio://configured') {
        throw new HandshakeVerificationError(
          403,
          'ENDPOINT_MISMATCH',
          'STDIO handshake endpoint does not match configured Gateway STDIO server binding',
        );
      }
    } else {
      const validatedDest = await normalizeAndCheckDestination(
        params.endpoint,
        {
          allowInsecureHttp: !this.requireTls,
          allowLoopbackHttp: this.allowLoopbackHttp,
          dnsLookup: this.dnsLookup,
        },
        this.audit,
        this.metrics,
        params.correlationId,
        params.accountId,
        params.mcpServerId,
      );
      canonicalEndpoint = validatedDest.canonicalEndpoint;
      validatedIpsKey = validatedDest.validatedIpsKey;
    }

    // Decrypt mandatory encrypted credential envelope if authentication credentials are supplied.
    // Unauthenticated MCP servers proceed cleanly with no credentials; plaintext fields are never permitted.
    let resolvedCredentials: ExternalMcpCredentials | null = null;
    if (params.encryptedCredentials) {
      try {
        resolvedCredentials = decryptHandshakeCredentialEnvelope({
          envelope: params.encryptedCredentials,
          backendAuthSecret: this.backendAuthSecret,
          gatewayId: this.gatewayId,
          accountId: params.accountId,
          integrationId: params.integrationId,
          challenge: params.challenge,
        });
      } catch {
        this.metrics.incHandshakesFailed();
        throw new HandshakeVerificationError(
          400,
          'CREDENTIAL_DECRYPTION_FAILED',
          'Failed to decrypt external MCP credentials envelope',
        );
      }
    } else if (
      params.transport === 'streamable-http' &&
      this.configuredSubjectAuthHeader &&
      this.configuredSubjectAuthHeader.authorizationHeader
    ) {
      try {
        const configuredCanonical = canonicalizeEndpointForPoolCheck(
          'streamable-http',
          this.configuredSubjectAuthHeader.httpUrl,
          canonicalEndpoint,
          { allowInsecureHttp: !this.requireTls, allowLoopbackHttp: this.allowLoopbackHttp },
        );
        if (configuredCanonical.ok) {
          resolvedCredentials = {
            authorizationHeader: this.configuredSubjectAuthHeader.authorizationHeader,
          };
        }
      } catch {
        // Ignore if configured URL check does not apply
      }
    }

    let adapter: McpUpstreamAdapter;
    let ownsLifecycle = false;

    if (params.transport === 'stdio') {
      adapter = this.defaultMcpAdapter;
    } else {
      adapter = new StreamableHttpMcpTransportAdapter({
        endpointUrl: canonicalEndpoint,
        upstreamAuthHeader: resolvedCredentials?.authorizationHeader,
        customHeaders: resolvedCredentials?.customHeaders,
        defaultTimeoutMs: this.defaultTimeoutMs,
        audit: this.audit,
        allowInsecureHttp: !this.requireTls,
        allowLoopbackHttp: this.allowLoopbackHttp,
        dnsLookup: this.dnsLookup,
        fetchOverride: this.fetchOverride,
      });
      ownsLifecycle = true;
    }

    let discoveredTools: McpToolDefinition[];
    try {
      await adapter.connect();
      if (adapter.ping) {
        await adapter.ping({ timeoutMs: this.defaultTimeoutMs });
      }
      const status = adapter.getStatus();

      if (!adapter.isConnected() || !status.connected) {
        throw new Error('MCP initialize did not result in a connected session');
      }
      if (!status.negotiatedProtocolVersion || status.negotiatedProtocolVersion.trim() === '') {
        throw new Error('External MCP server failed to negotiate a valid protocolVersion');
      }

      discoveredTools = await adapter.listTools({ timeoutMs: this.defaultTimeoutMs });
      if (!Array.isArray(discoveredTools)) {
        throw new Error('External MCP server returned invalid tools/list response');
      }
      for (const tool of discoveredTools) {
        if (
          !tool ||
          typeof tool.name !== 'string' ||
          tool.name.trim() === '' ||
          typeof tool.inputSchema !== 'object' ||
          tool.inputSchema === null
        ) {
          throw new Error('External MCP server returned malformed tool definition');
        }
      }

      const nowMs = Date.now();
      const ttlSeconds = Math.min(Math.max(params.attestationTtlSeconds ?? 3600, 60), 86400);
      const expiresAtMs = nowMs + ttlSeconds * 1000;
      const connectionId = `mcpc_${crypto.randomBytes(12).toString('hex')}`;
      const attestationId = `att_${crypto.randomBytes(12).toString('hex')}`;

      const normalizedTools = [...discoveredTools]
        .map((t) => ({
          name: t.name,
          title: t.title,
          description: t.description,
          inputSchema: t.inputSchema,
        }))
        .sort((a, b) => a.name.localeCompare(b.name));
      const toolsListHash = `sha256:${sha256Hex(canonicalizeJson(normalizedTools))}`;

      const encryptedCredentialsJson =
        resolvedCredentials &&
        (resolvedCredentials.authorizationHeader || resolvedCredentials.customHeaders)
          ? encryptStoredMcpCredentials({
              credentials: resolvedCredentials,
              vaultSecret: this.vaultSecret,
              gatewayId: this.gatewayId,
              accountId: params.accountId,
              integrationId: params.integrationId,
              mcpServerId: params.mcpServerId,
              canonicalEndpoint,
            })
          : null;

      const serverCapabilities = status.serverCapabilities ?? {};
      const record: VerifiedMcpConnectionRecord = {
        connectionId,
        attestationId,
        accountId: params.accountId,
        integrationId: params.integrationId,
        mcpServerId: params.mcpServerId,
        gatewayId: this.gatewayId,
        transport: params.transport,
        canonicalEndpoint,
        negotiatedProtocolVersion: status.negotiatedProtocolVersion,
        serverInfo: status.serverInfo,
        serverCapabilities,
        toolsListHash,
        toolNames: normalizedTools.map((t) => t.name),
        encryptedCredentialsJson,
        status: 'active',
        verifiedAtMs: nowMs,
        expiresAtMs,
        revokedAtMs: null,
        revocationReason: null,
      };

      await this.store.saveVerifiedConnection(record);
      this.pool.set(connectionId, {
        accountId: params.accountId,
        canonicalEndpoint,
        validatedIpsKey,
        adapter,
        ownsLifecycle,
      });

      const gatewayPublicKey = this.gatewayIdentity.getPublicKeyMetadata();
      const attestation: GatewayVerificationAttestation = {
        version: 'AAMARVA-GW-ATTEST-V1',
        attestationId,
        connectionId,
        gatewayId: this.gatewayId,
        gatewayKeyId: gatewayPublicKey.keyId,
        gatewayPublicKeyFingerprint: gatewayPublicKey.fingerprint,
        challenge: params.challenge,
        accountId: params.accountId,
        integrationId: params.integrationId,
        mcpServerId: params.mcpServerId,
        canonicalEndpoint,
        transport: params.transport,
        mcpInitialized: true,
        negotiatedProtocolVersion: status.negotiatedProtocolVersion,
        ...(status.serverInfo ? { serverInfo: status.serverInfo } : {}),
        serverCapabilities,
        toolsDiscoverySuccess: true,
        toolCount: normalizedTools.length,
        toolsListHash,
        handshakeTimestamp: new Date(nowMs).toISOString(),
        expiresAt: new Date(expiresAtMs).toISOString(),
      };

      const sig = this.gatewayIdentity.signResponsePayload(attestation);

      this.metrics.incHandshakesSucceeded();
      this.audit.record({
        event: 'MCP_HANDSHAKE_SUCCEEDED',
        outcome: 'success',
        message: 'Verified outbound MCP server connection and issued cryptographic attestation',
        correlationId: params.correlationId,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
        details: {
          connectionId,
          attestationId,
          integrationId: params.integrationId,
          transport: params.transport,
          canonicalEndpoint,
          negotiatedProtocolVersion: status.negotiatedProtocolVersion,
          toolCount: normalizedTools.length,
          toolsListHash,
        },
      });

      return {
        verified: true,
        protocolVersion: status.negotiatedProtocolVersion,
        ...(status.serverInfo ? { serverInfo: status.serverInfo } : {}),
        capabilities: serverCapabilities,
        serverCapabilities,
        mcpInitialize: {
          protocolVersion: status.negotiatedProtocolVersion,
          ...(status.serverInfo ? { serverInfo: status.serverInfo } : {}),
          capabilities: serverCapabilities,
        },
        attestation,
        gatewayPublicKey,
        gatewaySignature: sig.signature,
        tools: normalizedTools,
        correlationId: params.correlationId,
      };
    } catch (err) {
      if (ownsLifecycle) {
        await adapter.disconnect().catch(() => undefined);
      }
      this.metrics.incHandshakesFailed();

      const ssrfErr = err instanceof SsrfBlockedError
        ? err
        : err instanceof Error && 'cause' in err && (err as { cause?: unknown }).cause instanceof SsrfBlockedError
          ? ((err as { cause: SsrfBlockedError }).cause)
          : null;

      if (ssrfErr) {
        this.audit.record({
          event: 'SSRF_BLOCKED',
          outcome: 'denied',
          message: ssrfErr.message,
          correlationId: params.correlationId,
          accountId: params.accountId,
          mcpServerId: params.mcpServerId,
          details: { code: ssrfErr.code, integrationId: params.integrationId },
        });
        throw ssrfErr;
      }

      const message = err instanceof Error ? err.message : 'External MCP handshake failed';
      const isAuthFailure = message.includes('401') || message.includes('403') || /unauthorized/i.test(message);

      this.audit.record({
        event: 'MCP_HANDSHAKE_FAILED',
        outcome: 'failure',
        message: `External MCP handshake verification failed: ${message}`,
        correlationId: params.correlationId,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
        details: {
          integrationId: params.integrationId,
          transport: params.transport,
          canonicalEndpoint,
          isAuthFailure,
        },
      });

      if (err instanceof HandshakeVerificationError) {
        throw err;
      }

      throw new HandshakeVerificationError(
        502,
        isAuthFailure ? 'MCP_UPSTREAM_AUTH_FAILED' : 'MCP_HANDSHAKE_FAILED',
        isAuthFailure
          ? 'Upstream MCP server rejected Gateway authentication credentials'
          : 'External MCP handshake verification failed',
      );
    }
  }

  async resolveConnectionForAccount(params: {
    connectionId?: string;
    integrationId?: string;
    accountId: string;
    mcpServerId: string;
    expectedEndpoint?: string;
  }): Promise<ResolveAdapterResult> {
    let record: VerifiedMcpConnectionRecord | null = null;
    if (params.connectionId) {
      record = await this.store.getVerifiedConnection(params.connectionId);
    } else if (params.integrationId) {
      record = await this.store.getLatestVerifiedConnectionByIntegration(
        params.accountId,
        params.integrationId,
      );
    }

    if (!record) {
      return {
        ok: false,
        statusCode: 403,
        code: 'CONNECTION_NOT_VERIFIED',
        message: 'No verified MCP connection exists for this integration/connectionId',
      };
    }

    if (record.accountId !== params.accountId) {
      return {
        ok: false,
        statusCode: 403,
        code: 'ACCOUNT_MISMATCH',
        message: 'Verified MCP connection belongs to a different account',
      };
    }

    if (params.integrationId && record.integrationId !== params.integrationId) {
      return {
        ok: false,
        statusCode: 403,
        code: 'INTEGRATION_MISMATCH',
        message: 'Verified MCP connection does not match the requested integrationId',
      };
    }

    if (record.mcpServerId !== params.mcpServerId) {
      return {
        ok: false,
        statusCode: 403,
        code: 'SERVER_MISMATCH',
        message: 'Verified MCP connection does not match the requested mcpServerId',
      };
    }

    if (params.expectedEndpoint) {
      const matchRes = canonicalizeEndpointForPoolCheck(
        record.transport,
        params.expectedEndpoint,
        record.canonicalEndpoint,
        { allowInsecureHttp: !this.requireTls, allowLoopbackHttp: this.allowLoopbackHttp },
      );
      if (!matchRes.ok) {
        return {
          ok: false,
          statusCode: 403,
          code: 'ENDPOINT_MISMATCH',
          message: matchRes.message,
        };
      }
    }

    if (record.status === 'revoked' || record.revokedAtMs !== null) {
      return {
        ok: false,
        statusCode: 401,
        code: 'CONNECTION_REVOKED',
        message: 'Verified MCP connection has been revoked',
      };
    }

    if (record.status === 'expired' || Date.now() > record.expiresAtMs) {
      return {
        ok: false,
        statusCode: 401,
        code: 'CONNECTION_EXPIRED',
        message: 'Verified MCP attestation has expired; re-run handshake verification',
      };
    }

    if (record.transport === 'stdio') {
      const pooled = this.pool.get(record.connectionId);
      if (pooled && pooled.accountId === params.accountId) {
        return { ok: true, adapter: pooled.adapter, connection: record };
      }
      this.pool.set(record.connectionId, {
        accountId: record.accountId,
        canonicalEndpoint: record.canonicalEndpoint,
        validatedIpsKey: 'stdio',
        adapter: this.defaultMcpAdapter,
        ownsLifecycle: false,
      });
      return { ok: true, adapter: this.defaultMcpAdapter, connection: record };
    }

    // Revalidate DNS / SSRF destination on EVERY reuse or reconnect to block DNS rebinding
    let validatedDest;
    try {
      validatedDest = await resolveAndValidateMcpDestination(record.canonicalEndpoint, {
        allowInsecureHttp: !this.requireTls,
        allowLoopbackHttp: this.allowLoopbackHttp,
        dnsLookup: this.dnsLookup,
      });
    } catch (err) {
      const existing = this.pool.get(record.connectionId);
      if (existing) {
        if (existing.ownsLifecycle) {
          await existing.adapter.disconnect().catch(() => undefined);
        }
        this.pool.delete(record.connectionId);
      }
      const msg = err instanceof Error ? err.message : 'Destination failed SSRF revalidation';
      this.audit.record({
        event: 'SSRF_BLOCKED',
        outcome: 'denied',
        message: msg,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
        details: { connectionId: record.connectionId },
      });
      return {
        ok: false,
        statusCode: err instanceof SsrfBlockedError ? err.statusCode : 403,
        code: err instanceof SsrfBlockedError ? err.code : 'SSRF_BLOCKED_DESTINATION',
        message: 'Upstream MCP destination blocked by SSRF security policy',
      };
    }

    const currentIpsKey = validatedDest.allValidatedAddresses
      .map((a) => `${a.family}:${a.address}`)
      .sort()
      .join(',');

    const pooled = this.pool.get(record.connectionId);
    if (pooled) {
      if (
        pooled.accountId !== params.accountId ||
        pooled.canonicalEndpoint !== validatedDest.canonicalEndpoint ||
        pooled.validatedIpsKey !== currentIpsKey
      ) {
        if (pooled.ownsLifecycle) {
          await pooled.adapter.disconnect().catch(() => undefined);
        }
        this.pool.delete(record.connectionId);
        return {
          ok: false,
          statusCode: 403,
          code: 'SSRF_DESTINATION_CHANGED',
          message:
            'Pooled connection invalidated because validated destination binding changed',
        };
      }
      return { ok: true, adapter: pooled.adapter, connection: record };
    }

    // Reconnect transparently using AES-256-GCM decrypted credentials bound to this account & endpoint
    let creds: ExternalMcpCredentials = {};
    if (record.encryptedCredentialsJson) {
      creds = decryptStoredMcpCredentials({
        encryptedJson: record.encryptedCredentialsJson,
        vaultSecret: this.vaultSecret,
        gatewayId: this.gatewayId,
        accountId: record.accountId,
        integrationId: record.integrationId,
        mcpServerId: record.mcpServerId,
        canonicalEndpoint: record.canonicalEndpoint,
      });
    }

    const reconnectedAdapter = new StreamableHttpMcpTransportAdapter({
      endpointUrl: record.canonicalEndpoint,
      upstreamAuthHeader: creds.authorizationHeader,
      customHeaders: creds.customHeaders,
      defaultTimeoutMs: this.defaultTimeoutMs,
      audit: this.audit,
      allowInsecureHttp: !this.requireTls,
      allowLoopbackHttp: this.allowLoopbackHttp,
      dnsLookup: this.dnsLookup,
      fetchOverride: this.fetchOverride,
    });
    try {
      await reconnectedAdapter.connect();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Upstream MCP reconnection failed';
      this.audit.record({
        event: 'MCP_HANDSHAKE_FAILED',
        outcome: 'failure',
        message: `Upstream MCP reconnection failed: ${msg}`,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
        details: { connectionId: record.connectionId },
      });
      return {
        ok: false,
        statusCode: 502,
        code: 'MCP_UPSTREAM_ERROR',
        message: 'Upstream MCP connection failed',
      };
    }
    this.pool.set(record.connectionId, {
      accountId: record.accountId,
      canonicalEndpoint: validatedDest.canonicalEndpoint,
      validatedIpsKey: currentIpsKey,
      adapter: reconnectedAdapter,
      ownsLifecycle: true,
    });
    return { ok: true, adapter: reconnectedAdapter, connection: record };
  }

  async disconnectAccount(accountId: string): Promise<void> {
    for (const [connectionId, entry] of this.pool.entries()) {
      if (entry.accountId === accountId) {
        if (entry.ownsLifecycle) {
          await entry.adapter.disconnect().catch(() => undefined);
        }
        this.pool.delete(connectionId);
      }
    }
  }

  async disconnectAll(): Promise<void> {
    for (const [connectionId, entry] of this.pool.entries()) {
      if (entry.ownsLifecycle) {
        await entry.adapter.disconnect().catch(() => undefined);
      }
      this.pool.delete(connectionId);
    }
  }
}
