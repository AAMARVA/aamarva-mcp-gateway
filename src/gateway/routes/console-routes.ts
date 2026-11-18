import crypto from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import {
  decryptTokenAsAgent,
  signPayloadAsMockAamarva,
} from '../../../tests/fixtures/agent-decryption-harness.ts';
import { CONTRACT_AUDIT_MATRIX } from '../aamarva/contracts.ts';
import { getOrCreateEphemeralDevKeys } from '../config/environment.ts';
import { constantTimeEqualStrings } from '../config/security.ts';
import type { AamarvaMcpGateway } from '../core/gateway.ts';
import { createSsrfSafeFetch } from '../security/ssrf-guard.ts';

interface SandboxAgentProfile {
  agentId: string;
  agentName: string;
  accountId: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

const sandboxAgents = new Map<string, SandboxAgentProfile>();

function getOrCreateSandboxAgent(agentId: string, agentName: string, accountId: string): SandboxAgentProfile {
  const key = `${agentId}:${accountId}`;
  const existing = sandboxAgents.get(key);
  if (existing) return existing;

  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const profile: SandboxAgentProfile = {
    agentId,
    agentName,
    accountId,
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
  };
  sandboxAgents.set(key, profile);
  return profile;
}

export function createOperatorConsoleRouter(gateway: AamarvaMcpGateway): Router {
  const router = Router();

  router.use((req, res, next) => {
    const configuredToken = gateway.config.features.operatorAuthToken;
    const isProd = gateway.config.nodeEnv === 'production';

    if (!configuredToken && !isProd) {
      next();
      return;
    }

    if (!configuredToken) {
      gateway.audit.record({
        event: 'OPERATOR_AUTH_FAILED',
        outcome: 'denied',
        message: 'Operator Console rejected request because OPERATOR_CONSOLE_AUTH_TOKEN is missing',
        details: { path: req.path, method: req.method },
      });
      res.status(401).json({
        error: 'UNAUTHORIZED_OPERATOR',
        message: 'Operator authentication token is not configured',
      });
      return;
    }

    const authHeader = req.header('authorization') ?? '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

    if (!token || !constantTimeEqualStrings(token, configuredToken)) {
      gateway.audit.record({
        event: 'OPERATOR_AUTH_FAILED',
        outcome: 'denied',
        message: 'Rejected unauthenticated or invalid Operator Console access attempt',
        details: { path: req.path, method: req.method },
      });
      res.status(401).json({
        error: 'UNAUTHORIZED_OPERATOR',
        message: 'Valid Bearer operator authentication token is required',
      });
      return;
    }

    gateway.audit.record({
      event: 'OPERATOR_AUTH_SUCCEEDED',
      outcome: 'success',
      message: 'Authenticated Operator Console request',
      details: { path: req.path, method: req.method },
    });
    next();
  });

  router.get('/status', async (_req, res) => {
    const storeOk = await gateway.store.ping();
    const mcpStatus = gateway.mcpAdapter.getStatus();
    let upstreamTools: Array<{ name: string; title?: string; description?: string; inputSchema: Record<string, unknown> }> = [];
    try {
      if (mcpStatus.connected) {
        upstreamTools = await gateway.toolDiscovery.listAllUpstreamTools({ timeoutMs: 4000 });
      }
    } catch {
      upstreamTools = [];
    }

    const sessions = await gateway.sessionManager.listSessions(50);

    res.json({
      gateway: {
        gatewayId: gateway.config.gatewayId,
        mcpServerId: gateway.config.mcpServerId,
        nodeEnv: gateway.config.nodeEnv,
        requireTls: gateway.config.security.requireTls,
        trustedProxies: gateway.config.security.trustedProxies,
        onlineRevocationCheck: gateway.config.aamarva.onlineRevocationCheck,
        tokenTtlSeconds: gateway.config.security.tokenTtlSeconds,
        sessionTtlSeconds: gateway.config.security.sessionTtlSeconds,
        storageDriver: gateway.store.driverName,
        storeHealthy: storeOk,
        trustedKeyIds: gateway.signatureVerifier.listTrustedKeyIds(),
        gatewayPublicKey: gateway.gatewayIdentity.getPublicKeyMetadata(),
        sandboxEnabled: gateway.config.features.enableSandbox,
      },
      mcpUpstream: mcpStatus,
      upstreamTools,
      metrics: gateway.metrics.snapshot(),
      sessions: sessions.map((s) => ({
        sessionId: s.sessionId,
        tokenId: s.tokenId,
        authorizationId: s.authorizationId,
        agentId: s.agentId,
        agentName: s.agentName,
        accountId: s.accountId,
        allowedTools: s.scope.allowedTools,
        floorApproved: s.scope.floorApproved ?? false,
        status: s.status,
        createdAt: new Date(s.createdAtMs).toISOString(),
        expiresAt: new Date(s.expiresAtMs).toISOString(),
        authorizationExpiresAt: new Date(s.authorizationExpiresAtMs).toISOString(),
        revokedAt: s.revokedAtMs ? new Date(s.revokedAtMs).toISOString() : null,
        revocationReason: s.revocationReason,
        lastUsedAt: s.lastUsedAtMs ? new Date(s.lastUsedAtMs).toISOString() : null,
      })),
      auditLogs: gateway.logger.getRecentEntries(100),
      contractMatrix: CONTRACT_AUDIT_MATRIX,
    });
  });

  router.post('/sessions/:sessionId/revoke', async (req, res) => {
    const sessionId = req.params.sessionId;
    const reason = typeof req.body?.reason === 'string' && req.body.reason.trim()
      ? req.body.reason.trim()
      : 'Operator manual revocation';

    const revoked = await gateway.sessionManager.revokeSession(sessionId, reason, 'gateway-operator');
    if (!revoked) {
      res.status(404).json({ error: 'SESSION_NOT_FOUND_OR_ALREADY_REVOKED' });
      return;
    }

    gateway.metrics.incSessionsRevoked(1);
    gateway.audit.record({
      event: 'SESSION_REVOKED',
      outcome: 'success',
      message: 'Session revoked via Gateway Operator Console',
      sessionId,
      details: { reason, revokedBy: 'gateway-operator' },
    });

    res.json({ revoked: true, sessionId });
  });

  if (gateway.config.features.enableSandbox) {
    const baseLocalUrl = `http://127.0.0.1:${gateway.config.port}`;
    const localSandboxFetch = createSsrfSafeFetch({
      allowInsecureHttp: true,
      allowLoopbackHttp: gateway.config.nodeEnv !== 'production',
    });

    async function callGatewayAsMockAamarva(path: string, bodyObj: unknown) {
      const rawBody = JSON.stringify(bodyObj);
      const timestamp = String(Date.now());
      const requestId = `mock_req_${crypto.randomBytes(8).toString('hex')}`;
      const hmac = gateway.signatureVerifier.computeBackendRequestHmac({
        method: 'POST',
        path,
        timestamp,
        requestId,
        rawBody,
      });

      const resp = await localSandboxFetch(`${baseLocalUrl}${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-forwarded-proto': 'https',
          'x-aamarva-gateway-id': gateway.config.gatewayId,
          'x-aamarva-timestamp': timestamp,
          'x-aamarva-request-id': requestId,
          'x-aamarva-hmac-sha256': hmac,
        },
        body: rawBody,
      });
      const json = await resp.json();
      return { status: resp.status, json };
    }

    const IssueSchema = z.object({
      agentId: z.string().min(1).default('agent_procurement_01'),
      agentName: z.string().min(1).default('Procurement Planner Agent'),
      accountId: z.string().min(1).default('acct_enterprise_409'),
      allowedTools: z.array(z.string().min(1)).min(1).default(['inventory_lookup', 'calculate_quote']),
      floorApproved: z.boolean().default(true),
    });

    // Sandbox Step 1-4: Mock AAMARVA signs grant -> calls Gateway /issue-token -> returns encrypted envelope
    router.post('/sandbox/issue-token', async (req, res) => {
      const parsed = IssueSchema.safeParse(req.body ?? {});
      if (!parsed.success) {
        res.status(400).json({ error: 'INVALID_SANDBOX_PARAMS' });
        return;
      }

      const { agentId, agentName, accountId, allowedTools, floorApproved } = parsed.data;
      const devKeys = getOrCreateEphemeralDevKeys();
      const agent = getOrCreateSandboxAgent(agentId, agentName, accountId);

      const now = Date.now();
      const claims = {
        authorizationId: `auth_${crypto.randomBytes(6).toString('hex')}`,
        agentId: agent.agentId,
        agentName: agent.agentName,
        accountId: agent.accountId,
        agentPublicKeyPem: agent.publicKeyPem,
        mcpServerId: gateway.config.mcpServerId,
        gatewayId: gateway.config.gatewayId,
        allowedTools,
        floorApproved,
        floorApprovalId: floorApproved ? `floor_${crypto.randomBytes(4).toString('hex')}` : undefined,
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + 600_000).toISOString(),
      };

      const signature = signPayloadAsMockAamarva(claims, devKeys.signingPrivateKeyPem);
      const gatewayResp = await callGatewayAsMockAamarva('/issuetoken', {
        claims,
        keyId: devKeys.signingKeyId,
        signature,
      });

      res.status(gatewayResp.status).json({
        mode: 'MOCK_AAMARVA_TEST_HARNESS',
        signedGrant: { claims, keyId: devKeys.signingKeyId, signature },
        gatewayResponse: gatewayResp.json,
      });
    });

    // Sandbox Step 5-6: Simulated Agent ADK decrypts envelope with its X25519 private key & calls POST /execute
    router.post('/sandbox/agent-decrypt-and-redeem', async (req, res) => {
      const { encryptedToken, agentId, accountId } = req.body ?? {};
      const profile = sandboxAgents.get(`${agentId}:${accountId}`);
      if (!profile) {
        res.status(404).json({ error: 'SANDBOX_AGENT_NOT_FOUND' });
        return;
      }

      try {
        const decrypted = decryptTokenAsAgent(encryptedToken, profile.privateKeyPem);
        const redeemResp = await localSandboxFetch(`${baseLocalUrl}/execute`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-forwarded-proto': 'https',
          },
          body: JSON.stringify({
            token: decrypted.token,
            agentId: profile.agentId,
            accountId: profile.accountId,
            mcpServerId: decrypted.mcpServerId,
          }),
        });
        const redeemJson = await redeemResp.json();
        res.status(redeemResp.status).json({
          mode: 'SIMULATED_AGENT_ADK_HARNESS',
          decryptedTokenId: decrypted.tokenId,
          // Exposed only inside non-production sandbox response to allow user to test replay attack
          plaintextTokenForReplayTest: decrypted.token,
          redemptionResponse: redeemJson,
        });
      } catch (err) {
        res.status(400).json({
          error: 'DECRYPTION_OR_REDEEM_FAILED',
          message: err instanceof Error ? err.message : 'error',
        });
      }
    });

    // Sandbox Replay Attack Test: Re-submits an already-redeemed plaintext token directly to /execute
    router.post('/sandbox/replay-token', async (req, res) => {
      const { token, agentId, accountId, mcpServerId } = req.body ?? {};
      const redeemResp = await localSandboxFetch(`${baseLocalUrl}/execute`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-forwarded-proto': 'https',
        },
        body: JSON.stringify({ token, agentId, accountId, mcpServerId }),
      });
      const redeemJson = await redeemResp.json();
      res.status(redeemResp.status).json(redeemJson);
    });

    // Sandbox Step 7: Internal Gateway MCP tools/list or tools/call via ExecutionProxy
    router.post('/sandbox/aamarva-relay-tools-list', async (req, res) => {
      const { sessionId, agentId, accountId } = req.body ?? {};
      const result = await gateway.executionProxy.listAuthorizedTools({
        requestId: `relay_${crypto.randomBytes(6).toString('hex')}`,
        sessionId,
        agentId,
        accountId,
        mcpServerId: gateway.config.mcpServerId,
        gatewayId: gateway.config.gatewayId,
      });
      res.status(result.statusCode).json(result.body);
    });

    router.post('/sandbox/aamarva-relay-tool-call', async (req, res) => {
      const { sessionId, agentId, accountId, toolName, arguments: toolArgs } = req.body ?? {};
      const result = await gateway.executionProxy.executeAuthorizedTool({
        requestId: `relay_${crypto.randomBytes(6).toString('hex')}`,
        sessionId,
        agentId,
        accountId,
        mcpServerId: gateway.config.mcpServerId,
        gatewayId: gateway.config.gatewayId,
        toolName,
        arguments: toolArgs ?? {},
      });
      res.status(result.statusCode).json(result.body);
    });
  }

  return router;
}
