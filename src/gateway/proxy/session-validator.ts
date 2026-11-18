import type { AamarvaBackendClient } from '../aamarva/aamarva-client.ts';
import type { GatewaySessionManager, SessionValidationResult } from '../core/gateway-session.ts';

export class SessionValidator {
  private readonly sessionManager: GatewaySessionManager;
  private readonly onlineRevocationCheck: boolean;
  private readonly aamarvaClient?: AamarvaBackendClient;

  constructor(options: {
    sessionManager: GatewaySessionManager;
    onlineRevocationCheck: boolean;
    aamarvaClient?: AamarvaBackendClient;
  }) {
    this.sessionManager = options.sessionManager;
    this.onlineRevocationCheck = options.onlineRevocationCheck;
    this.aamarvaClient = options.aamarvaClient;
  }

  async validate(params: {
    sessionId: string;
    agentId: string;
    accountId: string;
    mcpServerId: string;
    gatewayId: string;
    toolName?: string;
  }): Promise<SessionValidationResult> {
    const localResult = await this.sessionManager.validateActiveSession(params);
    if (!localResult.valid || !localResult.session) {
      return localResult;
    }

    if (this.onlineRevocationCheck && this.aamarvaClient) {
      const online = await this.aamarvaClient.checkAuthorizationStatus({
        authorizationId: localResult.session.authorizationId,
        sessionId: localResult.session.sessionId,
        agentId: localResult.session.agentId,
        accountId: localResult.session.accountId,
      });

      if (!online.active) {
        await this.sessionManager.revokeSession(
          localResult.session.sessionId,
          online.reason ?? 'Revoked by AAMARVA online status check',
          'aamarva-online-check',
        );
        return {
          valid: false,
          session: localResult.session,
          code: 'SESSION_REVOKED',
          reason: online.reason ?? 'Authorization revoked in AAMARVA',
        };
      }
    }

    return localResult;
  }
}
