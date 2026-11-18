import type { AamarvaBackendClient } from '../aamarva/aamarva-client.ts';
import type { SessionSyncOutboxItem } from '../core/authorization-context.ts';
import type { AuditRecorder } from '../observability/audit.ts';
import type { GatewayMetrics } from '../observability/metrics.ts';
import type { GatewayStateStore } from '../storage/interfaces.ts';

export type SessionSyncOutcome = 'delivered' | 'pending_retry' | 'failed';

export class SessionSyncOutboxProcessor {
  private readonly store: GatewayStateStore;
  private readonly aamarvaClient: AamarvaBackendClient;
  private readonly audit: AuditRecorder;
  private readonly metrics: GatewayMetrics;
  private readonly maxAttempts: number;
  private readonly baseRetryDelayMs: number;
  private readonly pollIntervalMs: number;
  private timer: NodeJS.Timeout | null = null;
  private flushing = false;

  constructor(options: {
    store: GatewayStateStore;
    aamarvaClient: AamarvaBackendClient;
    audit: AuditRecorder;
    metrics: GatewayMetrics;
    maxAttempts?: number;
    baseRetryDelayMs?: number;
    pollIntervalMs?: number;
  }) {
    this.store = options.store;
    this.aamarvaClient = options.aamarvaClient;
    this.audit = options.audit;
    this.metrics = options.metrics;
    this.maxAttempts = options.maxAttempts ?? 5;
    this.baseRetryDelayMs = options.baseRetryDelayMs ?? 1000;
    this.pollIntervalMs = options.pollIntervalMs ?? 5000;
  }

  start(): void {
    if (this.timer) return;
    // Trigger immediate recovery flush on startup for items left pending before crash/restart
    void this.flushPending();
    this.timer = setInterval(() => {
      void this.flushPending();
    }, this.pollIntervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  async deliverItem(
    item: SessionSyncOutboxItem,
    nowMs = Date.now(),
  ): Promise<SessionSyncOutcome> {
    if (item.status === 'delivered') {
      return 'delivered';
    }

    const result = await this.aamarvaClient.notifySessionEstablished({
      outboxId: item.outboxId,
      idempotencyKey: item.idempotencyKey,
      sessionId: item.sessionId,
      tokenId: item.tokenId,
      authorizationId: item.authorizationId,
      agentId: item.agentId,
      accountId: item.accountId,
      gatewayId: item.gatewayId,
      mcpServerId: item.mcpServerId,
      sessionExpiresAt: new Date(item.sessionExpiresAtMs).toISOString(),
      authorizationExpiresAt: new Date(item.authorizationExpiresAtMs).toISOString(),
      allowedTools: item.scope.allowedTools,
      floorApproved: item.scope.floorApproved,
      correlationId: item.correlationId,
      establishedAt: new Date(item.createdAtMs).toISOString(),
    });

    if (result.ok) {
      await this.store.markOutboxDelivered(item.outboxId, nowMs);
      this.metrics.incSessionSyncDelivered();
      this.audit.record({
        event: 'SESSION_SYNC_DELIVERED',
        outcome: 'success',
        message: 'Session establishment synchronized to AAMARVA backend',
        correlationId: item.correlationId,
        agentId: item.agentId,
        accountId: item.accountId,
        mcpServerId: item.mcpServerId,
        sessionId: item.sessionId,
        details: {
          outboxId: item.outboxId,
          idempotencyKey: item.idempotencyKey,
          attempt: item.attempts + 1,
        },
      });
      return 'delivered';
    }

    const nextAttempts = item.attempts + 1;
    const errorMessage = result.error ?? `HTTP ${result.statusCode ?? 'error'}`;
    const terminalFail = nextAttempts >= this.maxAttempts;

    if (terminalFail) {
      await this.store.markOutboxRetry(item.outboxId, nowMs, nextAttempts, errorMessage, true);
      this.metrics.incSessionSyncFailed();
      this.audit.record({
        event: 'SESSION_SYNC_FAILED',
        outcome: 'failure',
        message: `Session synchronization permanently failed after ${nextAttempts} attempt(s)`,
        correlationId: item.correlationId,
        agentId: item.agentId,
        accountId: item.accountId,
        mcpServerId: item.mcpServerId,
        sessionId: item.sessionId,
        details: {
          outboxId: item.outboxId,
          idempotencyKey: item.idempotencyKey,
          attempts: nextAttempts,
          lastError: errorMessage,
        },
      });
      return 'failed';
    }

    const backoffMs = this.baseRetryDelayMs * Math.pow(2, nextAttempts - 1);
    const nextAttemptAtMs = nowMs + backoffMs;
    await this.store.markOutboxRetry(
      item.outboxId,
      nextAttemptAtMs,
      nextAttempts,
      errorMessage,
      false,
    );
    this.audit.record({
      event: 'SESSION_SYNC_RETRY_SCHEDULED',
      outcome: 'failure',
      message: `Session synchronization attempt ${nextAttempts} failed; retry scheduled`,
      correlationId: item.correlationId,
      agentId: item.agentId,
      accountId: item.accountId,
      mcpServerId: item.mcpServerId,
      sessionId: item.sessionId,
      details: {
        outboxId: item.outboxId,
        idempotencyKey: item.idempotencyKey,
        attempts: nextAttempts,
        nextAttemptAt: new Date(nextAttemptAtMs).toISOString(),
        lastError: errorMessage,
      },
    });
    return 'pending_retry';
  }

  async flushPending(nowMs = Date.now()): Promise<number> {
    if (this.flushing) return 0;
    this.flushing = true;
    try {
      const items = await this.store.getPendingOutboxItems(nowMs, 25);
      let processed = 0;
      for (const item of items) {
        await this.deliverItem(item, nowMs);
        processed += 1;
      }
      return processed;
    } finally {
      this.flushing = false;
    }
  }
}
