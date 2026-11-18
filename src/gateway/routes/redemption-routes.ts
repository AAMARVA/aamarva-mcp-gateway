import { Router } from 'express';
import type { RedemptionController } from '../redemption/redemption-controller.ts';

/**
 * Exposes the ONLY direct agent-to-Gateway operation:
 * POST /api/v1/redeem — one-time submission of decrypted short-lived token.
 * No other agent-facing endpoints are permitted by the AAMARVA Gateway architecture.
 */
export function createRedemptionRouter(options: {
  controller: RedemptionController;
  tlsMiddleware: ReturnType<typeof import('../middleware/request-validation.ts').createTlsEnforcementMiddleware>;
  rateLimitMiddleware: ReturnType<typeof import('../middleware/rate-limit.ts').createRateLimitMiddleware>;
  jsonTypeMiddleware: ReturnType<typeof import('../middleware/request-validation.ts').createJsonContentTypeMiddleware>;
}): Router {
  const router = Router();
  router.post(
    '/redeem',
    options.tlsMiddleware,
    options.rateLimitMiddleware,
    options.jsonTypeMiddleware,
    options.controller.handleRedeem,
  );
  return router;
}
