import crypto from 'node:crypto';
import { createSsrfSafeFetch, type DnsLookupFn } from '../security/ssrf-guard.ts';
import type { AamarvaSessionEstablishedNotification } from './contracts.ts';
import type { AamarvaSignatureVerifier } from './signature-verifier.ts';

export interface OnlineRevocationCheckResult {
  active: boolean;
  reason?: string;
}

export interface SessionSyncResult {
  ok: boolean;
  statusCode?: number;
  error?: string;
}

export interface AamarvaBackendClient {
  notifySessionEstablished(
    notification: AamarvaSessionEstablishedNotification,
  ): Promise<SessionSyncResult>;

  checkAuthorizationStatus(params: {
    authorizationId: string;
    sessionId: string;
    agentId: string;
    accountId: string;
  }): Promise<OnlineRevocationCheckResult>;

  reportExecutionEvent(event: {
    eventType: string;
    gatewayId: string;
    mcpServerId: string;
    sessionId: string;
    agentId: string;
    accountId: string;
    requestId: string;
    toolName?: string;
    outcome: 'success' | 'failure' | 'denied';
    timestamp: string;
  }): Promise<void>;
}

/**
 * Outbound HTTP client for communicating with AAMARVA Core backend endpoints.
 * All outbound requests pass through the Gateway SSRF guard (DNS resolution + IP blocklist + redirect block).
 */
export class HttpAamarvaBackendClient implements AamarvaBackendClient {
  private readonly baseUrl: string;
  private readonly gatewayId: string;
  private readonly verifier: AamarvaSignatureVerifier;
  private readonly timeoutMs: number;
  private readonly fetchFn: (input: string | URL, init?: RequestInit) => Promise<Response>;

  constructor(options: {
    baseUrl: string;
    gatewayId: string;
    verifier: AamarvaSignatureVerifier;
    timeoutMs?: number;
    allowInsecureHttp?: boolean;
    allowLoopbackHttp?: boolean;
    dnsLookup?: DnsLookupFn;
    fetchOverride?: (input: string | URL, init?: RequestInit) => Promise<Response>;
  }) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.gatewayId = options.gatewayId;
    this.verifier = options.verifier;
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.fetchFn =
      options.fetchOverride ??
      createSsrfSafeFetch({
        allowInsecureHttp: options.allowInsecureHttp ?? false,
        allowLoopbackHttp: options.allowLoopbackHttp ?? false,
        dnsLookup: options.dnsLookup,
      });
  }

  async notifySessionEstablished(
    notification: AamarvaSessionEstablishedNotification,
  ): Promise<SessionSyncResult> {
    const path = '/v1/gateway/sessions/established';
    const body = JSON.stringify(notification);
    const timestamp = String(Date.now());
    const requestId = `sync_${crypto.randomBytes(8).toString('hex')}`;
    const signature = this.verifier.computeBackendRequestHmac({
      method: 'POST',
      path,
      timestamp,
      requestId,
      rawBody: body,
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const resp = await this.fetchFn(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-aamarva-gateway-id': this.gatewayId,
          'x-aamarva-timestamp': timestamp,
          'x-aamarva-request-id': requestId,
          'x-aamarva-hmac-sha256': signature,
          'x-aamarva-idempotency-key': notification.idempotencyKey,
        },
        body,
        signal: controller.signal,
      });

      if (!resp.ok) {
        return {
          ok: false,
          statusCode: resp.status,
          error: `AAMARVA session sync returned HTTP ${resp.status}`,
        };
      }
      return { ok: true, statusCode: resp.status };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : 'Session sync network failure',
      };
    } finally {
      clearTimeout(timer);
    }
  }

  async checkAuthorizationStatus(params: {
    authorizationId: string;
    sessionId: string;
    agentId: string;
    accountId: string;
  }): Promise<OnlineRevocationCheckResult> {
    const path = '/v1/gateway/authorizations/status';
    const body = JSON.stringify({ gatewayId: this.gatewayId, ...params });
    const timestamp = String(Date.now());
    const requestId = `chk_${crypto.randomBytes(8).toString('hex')}`;
    const signature = this.verifier.computeBackendRequestHmac({
      method: 'POST',
      path,
      timestamp,
      requestId,
      rawBody: body,
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const resp = await this.fetchFn(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-aamarva-gateway-id': this.gatewayId,
          'x-aamarva-timestamp': timestamp,
          'x-aamarva-request-id': requestId,
          'x-aamarva-hmac-sha256': signature,
        },
        body,
        signal: controller.signal,
      });

      if (!resp.ok) {
        return { active: false, reason: `AAMARVA status check returned HTTP ${resp.status} (fail-closed)` };
      }
      const data = (await resp.json()) as { active?: boolean; reason?: string };
      return {
        active: data.active === true,
        reason: data.reason,
      };
    } catch (err) {
      return {
        active: false,
        reason: `AAMARVA backend unavailable for revocation verification: ${err instanceof Error ? err.message : 'network error'}`,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  async reportExecutionEvent(event: {
    eventType: string;
    gatewayId: string;
    mcpServerId: string;
    sessionId: string;
    agentId: string;
    accountId: string;
    requestId: string;
    toolName?: string;
    outcome: 'success' | 'failure' | 'denied';
    timestamp: string;
  }): Promise<void> {
    const path = '/v1/gateway/events';
    const body = JSON.stringify(event);
    const timestamp = String(Date.now());
    const requestId = `evt_${crypto.randomBytes(8).toString('hex')}`;
    const signature = this.verifier.computeBackendRequestHmac({
      method: 'POST',
      path,
      timestamp,
      requestId,
      rawBody: body,
    });

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      await this.fetchFn(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-aamarva-gateway-id': this.gatewayId,
          'x-aamarva-timestamp': timestamp,
          'x-aamarva-request-id': requestId,
          'x-aamarva-hmac-sha256': signature,
        },
        body,
        signal: controller.signal,
      });
    } catch {
      // Operational telemetry reporting must never crash execution path; logged separately
    } finally {
      clearTimeout(timer);
    }
  }
}

export class LocalTestAamarvaBackendClient implements AamarvaBackendClient {
  private readonly revokedAuthorizations = new Set<string>();
  public readonly reportedEvents: Array<Record<string, unknown>> = [];
  public readonly syncedSessions = new Map<string, AamarvaSessionEstablishedNotification>();
  public readonly sessionSyncAttempts: Array<{
    idempotencyKey: string;
    sessionId: string;
    ok: boolean;
  }> = [];
  private remainingSyncFailures = 0;
  private alwaysFailSync = false;

  setFailNextSessionSyncs(count: number): void {
    this.remainingSyncFailures = count;
  }

  setAlwaysFailSessionSync(fail: boolean): void {
    this.alwaysFailSync = fail;
  }

  markRevoked(authorizationId: string): void {
    this.revokedAuthorizations.add(authorizationId);
  }

  async notifySessionEstablished(
    notification: AamarvaSessionEstablishedNotification,
  ): Promise<SessionSyncResult> {
    if (this.alwaysFailSync || this.remainingSyncFailures > 0) {
      if (this.remainingSyncFailures > 0) {
        this.remainingSyncFailures -= 1;
      }
      this.sessionSyncAttempts.push({
        idempotencyKey: notification.idempotencyKey,
        sessionId: notification.sessionId,
        ok: false,
      });
      return {
        ok: false,
        statusCode: 503,
        error: 'Simulated AAMARVA backend outage during session sync',
      };
    }

    this.sessionSyncAttempts.push({
      idempotencyKey: notification.idempotencyKey,
      sessionId: notification.sessionId,
      ok: true,
    });
    if (!this.syncedSessions.has(notification.idempotencyKey)) {
      this.syncedSessions.set(notification.idempotencyKey, notification);
    }
    return { ok: true, statusCode: 200 };
  }

  async checkAuthorizationStatus(params: {
    authorizationId: string;
  }): Promise<OnlineRevocationCheckResult> {
    if (this.revokedAuthorizations.has(params.authorizationId)) {
      return { active: false, reason: 'Revoked in AAMARVA Core' };
    }
    return { active: true };
  }

  async reportExecutionEvent(event: Record<string, unknown>): Promise<void> {
    this.reportedEvents.push(event);
  }
}
