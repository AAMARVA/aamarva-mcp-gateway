import type { GatewayPublicKeyMetadata } from '../crypto/gateway-keypair.ts';

export type SessionStatus = 'active' | 'expired' | 'revoked';

export interface AuthorizationScope {
  /** Explicit allow-list of MCP tool names granted by AAMARVA for this session. */
  allowedTools: string[];
  /** Optional resource or action restrictions enforced by AAMARVA policy. */
  permissions?: string[];
  /** Whether human FLOOR approval was completed in AAMARVA. */
  floorApproved?: boolean;
  floorApprovalId?: string;
  /** Optional binding to a Gateway-verified external MCP integration connection. */
  integrationId?: string;
  connectionId?: string;
  canonicalEndpoint?: string;
}

export interface AuthorizationContext {
  authorizationId: string;
  agentId: string;
  agentName: string;
  accountId: string;
  mcpServerId: string;
  gatewayId: string;
  scope: AuthorizationScope;
  aamarvaKeyId: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

export interface IssuedTokenRecord {
  tokenId: string;
  /** SHA-256 hex digest of the plaintext token; plaintext is never persisted. */
  tokenHash: string;
  authorizationId: string;
  agentId: string;
  agentName: string;
  accountId: string;
  mcpServerId: string;
  gatewayId: string;
  scope: AuthorizationScope;
  aamarvaKeyId: string;
  issuedAtMs: number;
  expiresAtMs: number;
  authorizationExpiresAtMs: number;
  redeemedAtMs: number | null;
  redeemedBySessionId: string | null;
  revokedAtMs: number | null;
}

export interface GatewaySession {
  sessionId: string;
  tokenId: string;
  authorizationId: string;
  agentId: string;
  agentName: string;
  accountId: string;
  mcpServerId: string;
  gatewayId: string;
  scope: AuthorizationScope;
  status: SessionStatus;
  createdAtMs: number;
  expiresAtMs: number;
  authorizationExpiresAtMs: number;
  revokedAtMs: number | null;
  revocationReason: string | null;
  revokedBy: string | null;
  lastUsedAtMs: number | null;
}

export type OutboxDeliveryStatus = 'pending' | 'delivered' | 'failed';

export interface SessionSyncOutboxItem {
  outboxId: string;
  idempotencyKey: string;
  sessionId: string;
  tokenId: string;
  authorizationId: string;
  agentId: string;
  accountId: string;
  gatewayId: string;
  mcpServerId: string;
  sessionExpiresAtMs: number;
  authorizationExpiresAtMs: number;
  scope: AuthorizationScope;
  correlationId: string;
  status: OutboxDeliveryStatus;
  attempts: number;
  nextAttemptAtMs: number;
  createdAtMs: number;
  deliveredAtMs: number | null;
  lastError: string | null;
}

export interface VerifiedMcpConnectionRecord {
  connectionId: string;
  attestationId: string;
  accountId: string;
  integrationId: string;
  mcpServerId: string;
  gatewayId: string;
  transport: 'stdio' | 'streamable-http';
  canonicalEndpoint: string;
  negotiatedProtocolVersion: string;
  serverInfo?: { name: string; version: string };
  serverCapabilities?: Record<string, unknown>;
  toolsListHash: string;
  toolNames: string[];
  /** AES-256-GCM encrypted upstream credentials JSON; plaintext is never persisted or returned. */
  encryptedCredentialsJson: string | null;
  status: SessionStatus;
  verifiedAtMs: number;
  expiresAtMs: number;
  revokedAtMs: number | null;
  revocationReason: string | null;
}

export interface GatewayVerificationAttestation {
  version: 'AAMARVA-GW-ATTEST-V1';
  attestationId: string;
  connectionId: string;
  gatewayId: string;
  gatewayKeyId: string;
  gatewayPublicKeyFingerprint: string;
  challenge: string;
  accountId: string;
  integrationId: string;
  mcpServerId: string;
  canonicalEndpoint: string;
  transport: 'stdio' | 'streamable-http';
  mcpInitialized: true;
  negotiatedProtocolVersion: string;
  serverInfo?: { name: string; version: string };
  serverCapabilities?: Record<string, unknown>;
  toolsDiscoverySuccess: true;
  toolCount: number;
  toolsListHash: string;
  handshakeTimestamp: string;
  expiresAt: string;
}

export interface GatewayHandshakeResponse {
  verified: true;
  protocolVersion: string;
  serverInfo?: { name: string; version: string };
  capabilities: Record<string, unknown>;
  serverCapabilities: Record<string, unknown>;
  mcpInitialize: {
    protocolVersion: string;
    serverInfo?: { name: string; version: string };
    capabilities: Record<string, unknown>;
  };
  attestation: GatewayVerificationAttestation;
  gatewayPublicKey: GatewayPublicKeyMetadata;
  gatewaySignature: string;
  tools: Array<{
    name: string;
    title?: string;
    description?: string;
    inputSchema: Record<string, unknown>;
  }>;
  correlationId: string;
}
