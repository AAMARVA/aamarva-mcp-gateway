export interface GatewayMetricsSnapshot {
  startedAt: string;
  tokensIssued: number;
  tokensRedeemed: number;
  redemptionsRejected: number;
  replayAttemptsBlocked: number;
  sessionsCreated: number;
  sessionsRevoked: number;
  handshakesSucceeded: number;
  handshakesFailed: number;
  mcpToolsListed: number;
  mcpExecutionsAllowed: number;
  mcpExecutionsDenied: number;
  mcpExecutionsFailed: number;
  signatureVerificationFailed: number;
  sessionSyncDelivered: number;
  sessionSyncFailed: number;
}

export class GatewayMetrics {
  private readonly startedAt = new Date().toISOString();
  private tokensIssued = 0;
  private tokensRedeemed = 0;
  private redemptionsRejected = 0;
  private replayAttemptsBlocked = 0;
  private sessionsCreated = 0;
  private sessionsRevoked = 0;
  private handshakesSucceeded = 0;
  private handshakesFailed = 0;
  private mcpToolsListed = 0;
  private mcpExecutionsAllowed = 0;
  private mcpExecutionsDenied = 0;
  private mcpExecutionsFailed = 0;
  private signatureVerificationFailed = 0;
  private sessionSyncDelivered = 0;
  private sessionSyncFailed = 0;

  incTokensIssued(): void { this.tokensIssued += 1; }
  incTokensRedeemed(): void { this.tokensRedeemed += 1; }
  incRedemptionsRejected(): void { this.redemptionsRejected += 1; }
  incReplayAttemptsBlocked(): void { this.replayAttemptsBlocked += 1; }
  incSessionsCreated(): void { this.sessionsCreated += 1; }
  incSessionsRevoked(count = 1): void { this.sessionsRevoked += count; }
  incHandshakesSucceeded(): void { this.handshakesSucceeded += 1; }
  incHandshakesFailed(): void { this.handshakesFailed += 1; }
  incMcpToolsListed(): void { this.mcpToolsListed += 1; }
  incMcpExecutionsAllowed(): void { this.mcpExecutionsAllowed += 1; }
  incMcpExecutionsDenied(): void { this.mcpExecutionsDenied += 1; }
  incMcpExecutionsFailed(): void { this.mcpExecutionsFailed += 1; }
  incSignatureVerificationFailed(): void { this.signatureVerificationFailed += 1; }
  incSessionSyncDelivered(): void { this.sessionSyncDelivered += 1; }
  incSessionSyncFailed(): void { this.sessionSyncFailed += 1; }

  snapshot(): GatewayMetricsSnapshot {
    return {
      startedAt: this.startedAt,
      tokensIssued: this.tokensIssued,
      tokensRedeemed: this.tokensRedeemed,
      redemptionsRejected: this.redemptionsRejected,
      replayAttemptsBlocked: this.replayAttemptsBlocked,
      sessionsCreated: this.sessionsCreated,
      sessionsRevoked: this.sessionsRevoked,
      handshakesSucceeded: this.handshakesSucceeded,
      handshakesFailed: this.handshakesFailed,
      mcpToolsListed: this.mcpToolsListed,
      mcpExecutionsAllowed: this.mcpExecutionsAllowed,
      mcpExecutionsDenied: this.mcpExecutionsDenied,
      mcpExecutionsFailed: this.mcpExecutionsFailed,
      signatureVerificationFailed: this.signatureVerificationFailed,
      sessionSyncDelivered: this.sessionSyncDelivered,
      sessionSyncFailed: this.sessionSyncFailed,
    };
  }
}
