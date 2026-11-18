import type { NextFunction, Request, Response } from 'express';
import type { AamarvaSignatureVerifier } from '../aamarva/signature-verifier.ts';
import type { AuditRecorder } from '../observability/audit.ts';
import type { ReplayProtection } from '../redemption/replay-protection.ts';

export interface RequestWithRawBody extends Request {
  rawBody?: Buffer;
}

/**
 * Authenticates requests arriving at /api/v1/aamarva/* so ONLY the AAMARVA Core
 * backend (possessing AAMARVA_BACKEND_AUTH_SECRET) can invoke issuance, revocation,
 * or MCP execution relay endpoints. Agents cannot call these directly.
 */
export function createAamarvaBackendAuthMiddleware(options: {
  verifier: AamarvaSignatureVerifier;
  replayProtection: ReplayProtection;
  gatewayId: string;
  audit: AuditRecorder;
}) {
  return async (req: RequestWithRawBody, res: Response, next: NextFunction): Promise<void> => {
    const gatewayHeader = req.header('x-aamarva-gateway-id');
    const timestamp = req.header('x-aamarva-timestamp');
    const requestId = req.header('x-aamarva-request-id');
    const providedSig = req.header('x-aamarva-hmac-sha256');

    if (!gatewayHeader || !timestamp || !requestId || !providedSig) {
      options.audit.record({
        event: 'BACKEND_AUTH_FAILED',
        outcome: 'denied',
        message: 'Missing required AAMARVA backend authentication headers',
        details: { path: req.originalUrl },
      });
      res.status(401).json({
        error: 'BACKEND_AUTH_REQUIRED',
        message: 'Missing AAMARVA backend authentication headers',
      });
      return;
    }

    if (gatewayHeader !== options.gatewayId) {
      options.audit.record({
        event: 'BACKEND_AUTH_FAILED',
        outcome: 'denied',
        message: 'Gateway ID header mismatch on backend request',
        details: { providedGatewayId: gatewayHeader },
      });
      res.status(403).json({
        error: 'GATEWAY_MISMATCH',
        message: 'x-aamarva-gateway-id does not match this Gateway installation',
      });
      return;
    }

    const rawBody = req.rawBody ?? Buffer.from(JSON.stringify(req.body ?? {}), 'utf8');
    const pathOnly = req.originalUrl.split('?')[0];

    const sigCheck = options.verifier.verifyBackendRequestHmac({
      method: req.method,
      path: pathOnly,
      timestamp,
      requestId,
      rawBody,
      providedSignatureHex: providedSig,
    });

    if (!sigCheck.valid) {
      options.audit.record({
        event: 'BACKEND_AUTH_FAILED',
        outcome: 'denied',
        message: sigCheck.reason ?? 'AAMARVA backend HMAC verification failed',
        requestId,
        details: { path: pathOnly },
      });
      res.status(401).json({
        error: 'INVALID_BACKEND_SIGNATURE',
        message: sigCheck.reason ?? 'Invalid AAMARVA backend authentication',
      });
      return;
    }

    const headerReplay = await options.replayProtection.verifyAndClaimRequest({
      requestId: `hdr:${requestId}`,
      timestampMs: Number.parseInt(timestamp, 10),
    });

    if (!headerReplay.ok) {
      options.audit.record({
        event: 'BACKEND_AUTH_FAILED',
        outcome: 'denied',
        message: headerReplay.reason ?? 'Backend request header replay blocked',
        requestId,
        details: { path: pathOnly },
      });
      res.status(409).json({
        error: 'REPLAY_DETECTED',
        message: headerReplay.reason,
      });
      return;
    }

    next();
  };
}
