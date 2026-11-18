import { Router } from 'express';
import type { AamarvaBackendRelay } from '../aamarva/backend-relay.ts';

/**
 * Exposes backend-to-Gateway routes strictly for the authenticated AAMARVA Core backend.
 * Every route requires HMAC-SHA256 authentication + timestamp freshness + replay check.
 */
export function createAamarvaRouter(options: {
  relay: AamarvaBackendRelay;
  tlsMiddleware: ReturnType<typeof import('../middleware/request-validation.ts').createTlsEnforcementMiddleware>;
  rateLimitMiddleware: ReturnType<typeof import('../middleware/rate-limit.ts').createRateLimitMiddleware>;
  jsonTypeMiddleware: ReturnType<typeof import('../middleware/request-validation.ts').createJsonContentTypeMiddleware>;
  backendAuthMiddleware: ReturnType<typeof import('../middleware/authentication.ts').createAamarvaBackendAuthMiddleware>;
}): Router {
  const router = Router();

  router.use(
    options.tlsMiddleware,
    options.rateLimitMiddleware,
    options.jsonTypeMiddleware,
    options.backendAuthMiddleware,
  );

  router.post('/mcp/handshake', options.relay.handleMcpHandshake);
  router.post('/authorizations/issue-token', options.relay.handleIssueEncryptedToken);
  router.post('/authorizations/revoke', options.relay.handleRevocation);
  router.post('/mcp/tools/list', options.relay.handleToolsList);
  router.post('/mcp/tools/call', options.relay.handleToolCall);

  return router;
}
