import type { GatewayStateStore } from '../storage/interfaces.ts';

export class ReplayProtection {
  private readonly store: GatewayStateStore;
  private readonly maxClockSkewMs: number;

  constructor(options: { store: GatewayStateStore; maxClockSkewSeconds: number }) {
    this.store = options.store;
    this.maxClockSkewMs = options.maxClockSkewSeconds * 1000;
  }

  /**
   * Claims a unique requestId from the AAMARVA backend relay within the skew window.
   * Returns false if the requestId was already seen or timestamp is outside allowed clock skew.
   */
  async verifyAndClaimRequest(params: {
    requestId: string;
    timestampMs: number;
    nowMs?: number;
  }): Promise<{ ok: boolean; reason?: string }> {
    const nowMs = params.nowMs ?? Date.now();
    if (Math.abs(nowMs - params.timestampMs) > this.maxClockSkewMs) {
      return { ok: false, reason: 'Request timestamp outside allowed clock skew window' };
    }

    const expiresAtMs = nowMs + this.maxClockSkewMs * 2;
    const claimed = await this.store.claimRequestId(params.requestId, expiresAtMs, nowMs);
    if (!claimed) {
      return { ok: false, reason: 'Duplicate requestId detected (replay blocked)' };
    }
    return { ok: true };
  }
}
