import { z } from 'zod';

/**
 * STAGE 1 CONTRACT AUDIT STATUS:
 * No external AAMARVA Core repository or ADK OpenAPI specification was provided
 * in this greenfield workspace. Therefore, all AAMARVA <-> Gateway wire contracts
 * below represent the minimal explicit integration contract defined by the Gateway
 * specification and tested via a dedicated Contract Test Harness.
 * See docs/AAMARVA_INTEGRATION.md for the complete contract audit matrix.
 */
export const CONTRACT_AUDIT_MATRIX = [
  {
    integration: 'AAMARVA -> Gateway initial MCP verification handshake',
    actualContract:
      'POST /api/v1/aamarva/mcp/handshake (Ed25519/P-256 signed challenge + HMAC headers -> outbound MCP initialize + tools/list -> signed attestation)',
    source: 'Gateway specification (AAMARVA Core spec unavailable in workspace)',
    status: 'UNAVAILABLE_EXTERNALLY_DEFINED_CONTRACT',
  },
  {
    integration: 'AAMARVA -> Gateway authorization grant',
    actualContract: 'POST /api/v1/aamarva/authorizations/issue-token (Ed25519/P-256 signed payload)',
    source: 'Gateway specification (AAMARVA Core spec unavailable in workspace)',
    status: 'UNAVAILABLE_EXTERNALLY_DEFINED_CONTRACT',
  },
  {
    integration: 'Gateway -> AAMARVA encrypted token delivery',
    actualContract:
      'Synchronous HTTP 201 response envelope (AAMARVA-GW-ENV-V1) containing encryptedToken, gatewayPublicKey, and gatewaySignature',
    source: 'Gateway specification (AAMARVA Core relay spec unavailable in workspace)',
    status: 'UNAVAILABLE_EXTERNALLY_DEFINED_CONTRACT',
  },
  {
    integration: 'AAMARVA -> Agent encrypted token relay',
    actualContract: 'Existing AAMARVA Core / ADK encrypted payload relay (with gatewayPublicKey)',
    source: 'AAMARVA Core / ADK (external)',
    status: 'EXTERNAL_AAMARVA_OWNED',
  },
  {
    integration: 'Agent -> Gateway one-time token redemption',
    actualContract: 'POST /api/v1/redeem (TLS, atomic single-use)',
    source: 'Gateway specification',
    status: 'IMPLEMENTED_IN_GATEWAY',
  },
  {
    integration: 'Gateway -> AAMARVA session establishment sync',
    actualContract:
      'POST /v1/gateway/sessions/established (HMAC-SHA256 + x-aamarva-idempotency-key via durable outbox)',
    source: 'Gateway specification (AAMARVA Core receiver spec unavailable in workspace)',
    status: 'UNAVAILABLE_EXTERNALLY_DEFINED_CONTRACT',
  },
  {
    integration: 'Agent -> AAMARVA subsequent MCP request',
    actualContract: 'Existing AAMARVA ADK -> AAMARVA Backend pathway',
    source: 'AAMARVA ADK / Core (external)',
    status: 'EXTERNAL_AAMARVA_OWNED',
  },
  {
    integration: 'AAMARVA -> Gateway MCP execution relay',
    actualContract: 'POST /api/v1/aamarva/mcp/tools/list & POST /api/v1/aamarva/mcp/tools/call',
    source: 'Gateway specification (AAMARVA Core relay caller spec unavailable in workspace)',
    status: 'UNAVAILABLE_EXTERNALLY_DEFINED_CONTRACT',
  },
  {
    integration: 'Gateway -> Upstream MCP server',
    actualContract: 'MCP JSON-RPC over STDIO or Streamable HTTP (@modelcontextprotocol/sdk)',
    source: 'Model Context Protocol specification',
    status: 'IMPLEMENTED_IN_GATEWAY',
  },
] as const;

export const GatewayPublicKeyMetadataSchema = z.object({
  keyId: z.string().min(1).max(128),
  algorithm: z.enum(['Ed25519', 'ECDSA-P256-SHA256']),
  purpose: z.literal('gateway-response-signing'),
  encoding: z.literal('PEM-SPKI'),
  publicKey: z.string().min(32).max(8192),
  fingerprint: z.string().regex(/^sha256:[a-f0-9]{64}$/),
});

export type GatewayPublicKeyMetadataContract = z.infer<typeof GatewayPublicKeyMetadataSchema>;

export const AamarvaSessionEstablishedNotificationSchema = z.object({
  outboxId: z.string().min(4).max(128),
  idempotencyKey: z.string().min(4).max(128),
  sessionId: z.string().min(6).max(128),
  tokenId: z.string().min(4).max(128),
  authorizationId: z.string().min(3).max(128),
  agentId: z.string().min(1).max(128),
  accountId: z.string().min(1).max(128),
  gatewayId: z.string().min(1).max(128),
  mcpServerId: z.string().min(1).max(128),
  sessionExpiresAt: z.string().datetime(),
  authorizationExpiresAt: z.string().datetime(),
  allowedTools: z.array(z.string().min(1)),
  floorApproved: z.boolean().optional(),
  correlationId: z.string().min(1).max(128),
  establishedAt: z.string().datetime(),
});

export type AamarvaSessionEstablishedNotification = z.infer<
  typeof AamarvaSessionEstablishedNotificationSchema
>;

export const EncryptedHandshakeCredentialsSchema = z
  .object({
    version: z.literal('AAMARVA-GW-CRED-V1'),
    salt: z.string().min(16),
    iv: z.string().min(12),
    ciphertext: z.string().min(8),
    tag: z.string().min(16),
  })
  .strict();

export const AamarvaHandshakeClaimsSchema = z
  .object({
    challenge: z
      .string()
      .min(16)
      .max(256)
      .regex(/^\S+$/, 'Challenge must not contain whitespace'),
    nonce: z
      .string()
      .min(8)
      .max(256)
      .regex(/^\S+$/, 'Nonce must not contain whitespace')
      .optional(),
    accountId: z.string().min(1).max(128),
    integrationId: z.string().min(1).max(128),
    mcpServerId: z.string().min(1).max(128).optional(),
    gatewayId: z.string().min(1).max(128),
    transport: z.enum(['streamable-http', 'stdio']).optional(),
    endpoint: z.string().min(5).max(2048).optional(),
    attestationTtlSeconds: z.number().int().min(60).max(86400).optional(),
    issuedAt: z.string().datetime().optional(),
    timestamp: z.string().datetime().optional(),
    expiresAt: z.string().datetime(),
  })
  .strict()
  .refine((c) => Boolean(c.issuedAt || c.timestamp), {
    message: 'Handshake claims must include issuedAt or timestamp',
  });

export type AamarvaHandshakeClaims = z.infer<typeof AamarvaHandshakeClaimsSchema>;

export const AamarvaSignedHandshakeRequestSchema = z
  .object({
    claims: AamarvaHandshakeClaimsSchema,
    keyId: z.string().min(1).max(128),
    signature: z.string().min(16).max(2048),
    expectedEndpoint: z.string().min(5).max(2048).optional(),
    encryptedCredentials: EncryptedHandshakeCredentialsSchema.optional(),
  })
  .strict();

export type AamarvaSignedHandshakeRequest = z.infer<typeof AamarvaSignedHandshakeRequestSchema>;

export const PositiveIntegerMinutesSchema = z
  .number()
  .int()
  .positive()
  .refine(
    (val) =>
      Number.isSafeInteger(val) &&
      Number.isSafeInteger(val * 60_000) &&
      !Number.isNaN(new Date(Date.now() + val * 60_000).getTime()),
    'expires_in_minutes must be a positive safe integer within valid timestamp range',
  );

export const AamarvaIssueTokenEndpointClaimsSchema = z
  .object({
    authorizationId: z.string().min(3).max(128).optional(),
    invocationId: z.string().min(3).max(128).optional(),
    agentId: z.string().min(1).max(128).refine((v) => v.trim().length > 0, 'agentId must not be blank'),
    agentName: z.string().min(1).max(256).refine((v) => v.trim().length > 0, 'agentName must not be blank'),
    accountId: z.string().min(1).max(128),
    integrationId: z.string().min(1).max(128),
    connectionId: z.string().min(4).max(128).optional(),
    mcpServerId: z.string().min(1).max(128).optional(),
    gatewayId: z.string().min(1).max(128),
    endpoint: z.string().min(5).max(2048).optional(),
    agentPublicKeyPem: z.string().min(32).max(8192).refine((v) => v.trim().length >= 32, 'agentPublicKeyPem must not be blank'),
    agentPublicKeyFingerprint: z.string().min(16).max(128),
    allowedTools: z.array(z.string().min(1).max(128)).min(1),
    permissions: z.array(z.string().min(1).max(256)).optional(),
    floorApproved: z.boolean().optional(),
    floorApprovalId: z.string().optional(),
    issuedAt: z.string().datetime().optional(),
    timestamp: z.string().datetime().optional(),
    expiresAt: z.string().datetime(),
    expires_in_minutes: PositiveIntegerMinutesSchema.optional(),
  })
  .strict()
  .refine((c) => Boolean(c.authorizationId || c.invocationId), {
    message: 'Authorization request must specify authorizationId or invocationId',
  })
  .refine((c) => Boolean(c.issuedAt || c.timestamp), {
    message: 'Authorization request must include issuedAt or timestamp',
  });

export const AamarvaSignedIssueTokenEndpointRequestSchema = z
  .object({
    claims: AamarvaIssueTokenEndpointClaimsSchema,
    keyId: z.string().min(1).max(128),
    signature: z.string().min(16).max(2048),
    expires_in_minutes: PositiveIntegerMinutesSchema,
  })
  .strict()
  .refine(
    (req) =>
      req.claims.expires_in_minutes === undefined ||
      req.expires_in_minutes === req.claims.expires_in_minutes,
    {
      message: 'Conflicting expires_in_minutes values between request body and claims',
    },
  );

export type AamarvaSignedIssueTokenEndpointRequest = z.infer<
  typeof AamarvaSignedIssueTokenEndpointRequestSchema
>;

export const AamarvaAuthorizationGrantClaimsSchema = z.object({
  authorizationId: z.string().min(3).max(128),
  agentId: z.string().min(1).max(128),
  agentName: z.string().min(1).max(256),
  accountId: z.string().min(1).max(128),
  agentPublicKeyPem: z.string().min(32).max(8192),
  mcpServerId: z.string().min(1).max(128),
  gatewayId: z.string().min(1).max(128),
  integrationId: z.string().min(1).max(128).optional(),
  connectionId: z.string().min(4).max(128).optional(),
  endpoint: z.string().min(5).max(2048).optional(),
  allowedTools: z.array(z.string().min(1).max(128)).min(1),
  permissions: z.array(z.string()).optional(),
  floorApproved: z.boolean().optional(),
  floorApprovalId: z.string().optional(),
  issuedAt: z.string().datetime(),
  expiresAt: z.string().datetime(),
});

export type AamarvaAuthorizationGrantClaims = z.infer<
  typeof AamarvaAuthorizationGrantClaimsSchema
>;

export const AamarvaSignedAuthorizationRequestSchema = z.object({
  claims: AamarvaAuthorizationGrantClaimsSchema,
  keyId: z.string().min(1).max(128),
  signature: z.string().min(16).max(2048),
});

export type AamarvaSignedAuthorizationRequest = z.infer<
  typeof AamarvaSignedAuthorizationRequestSchema
>;

export const AamarvaRevocationClaimsSchema = z
  .object({
    revocationId: z.string().min(3).max(128),
    authorizationId: z.string().min(1).optional(),
    sessionId: z.string().min(1).optional(),
    agentId: z.string().min(1).optional(),
    accountId: z.string().min(1).optional(),
    mcpServerId: z.string().min(1).optional(),
    reason: z.string().min(1).max(512),
    revokedBy: z.string().min(1).max(128),
    revokedAt: z.string().datetime(),
  })
  .refine(
    (c) => Boolean(c.sessionId || c.authorizationId || c.accountId),
    {
      message:
        'Revocation claims must specify sessionId, authorizationId, (agentId + accountId), or accountId',
    },
  );

export const AamarvaSignedRevocationRequestSchema = z.object({
  claims: AamarvaRevocationClaimsSchema,
  keyId: z.string().min(1).max(128),
  signature: z.string().min(16).max(2048),
});

export const AamarvaMcpToolsListRelaySchema = z.object({
  requestId: z.string().min(6).max(128),
  sessionId: z.string().min(6).max(128),
  agentId: z.string().min(1).max(128),
  accountId: z.string().min(1).max(128),
  mcpServerId: z.string().min(1).max(128),
  gatewayId: z.string().min(1).max(128),
  integrationId: z.string().min(1).max(128).optional(),
  connectionId: z.string().min(4).max(128).optional(),
  expectedEndpoint: z.string().min(5).max(2048).optional(),
  timestamp: z.string().datetime(),
});

export const AamarvaMcpToolCallRelaySchema = z.object({
  requestId: z.string().min(6).max(128),
  sessionId: z.string().min(6).max(128),
  agentId: z.string().min(1).max(128),
  accountId: z.string().min(1).max(128),
  mcpServerId: z.string().min(1).max(128),
  gatewayId: z.string().min(1).max(128),
  integrationId: z.string().min(1).max(128).optional(),
  connectionId: z.string().min(4).max(128).optional(),
  expectedEndpoint: z.string().min(5).max(2048).optional(),
  toolName: z.string().min(1).max(128),
  arguments: z.record(z.string(), z.unknown()).default({}),
  timestamp: z.string().datetime(),
});

export type AamarvaMcpToolsListRelay = z.infer<typeof AamarvaMcpToolsListRelaySchema>;
export type AamarvaMcpToolCallRelay = z.infer<typeof AamarvaMcpToolCallRelaySchema>;
