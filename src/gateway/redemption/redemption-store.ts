import type { IssuedTokenRecord } from '../core/authorization-context.ts';
import type { AtomicRedeemParams, AtomicRedeemResult, GatewayStateStore } from '../storage/interfaces.ts';

export class RedemptionStore {
  private readonly store: GatewayStateStore;

  constructor(store: GatewayStateStore) {
    this.store = store;
  }

  async saveIssuedToken(record: IssuedTokenRecord): Promise<void> {
    await this.store.saveIssuedToken(record);
  }

  async redeemAtomically(params: AtomicRedeemParams): Promise<AtomicRedeemResult> {
    return this.store.redeemTokenAtomically(params);
  }
}
