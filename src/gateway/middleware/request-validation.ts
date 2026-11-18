import type { Express, NextFunction, Request, Response } from 'express';

const STRICT_ALLOWED_ADAPTER_PATHS = new Set<string>([
  '/handshake',
  '/issuetoken',
  '/execute',
]);

const ATTACHED_INGRESS_APPS = new WeakSet<object>();

/**
 * Extracts the exact raw request pathname before Express path decoding,
 * dot-segment normalization, or trailing-slash relaxation.
 */
export function extractRawRequestPathname(req: Pick<Request, 'originalUrl' | 'url'>): string {
  const rawUrl = req.originalUrl ?? req.url ?? '';
  const queryIndex = rawUrl.indexOf('?');
  return queryIndex === -1 ? rawUrl : rawUrl.slice(0, queryIndex);
}

/**
 * Central early-ingress allowlist enforced whenever the AAMARVA Gateway adapter is enabled.
 * Permits ONLY exact POST /handshake, POST /issuetoken, and POST /execute.
 * Rejects everything else (including /, /healthz, /readyz, /api/console/*, static/SPA,
 * trailing slashes, encoded path variations, and unsupported methods) with 404 or 405.
 */
export function createStrictAamarvaIngressMiddleware() {
  return (req: Request, res: Response, next: NextFunction): void => {
    const rawPath = extractRawRequestPathname(req);

    if (!STRICT_ALLOWED_ADAPTER_PATHS.has(rawPath)) {
      res.status(404).json({
        error: 'NOT_FOUND',
        message: 'Endpoint not found',
      });
      return;
    }

    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      res.status(405).json({
        error: 'METHOD_NOT_ALLOWED',
        message: 'Only POST is supported on this Gateway endpoint',
      });
      return;
    }

    next();
  };
}

export function attachStrictAamarvaIngressGuard(app: Express): void {
  if (ATTACHED_INGRESS_APPS.has(app)) {
    return;
  }
  ATTACHED_INGRESS_APPS.add(app);
  app.use(createStrictAamarvaIngressMiddleware());
}

export interface TlsEnforcementOptions {
  requireTls: boolean;
  trustedProxies?: string[];
}

function normalizeIp(ip: string | undefined): string {
  if (!ip) return '';
  const trimmed = ip.trim();
  return trimmed.startsWith('::ffff:') ? trimmed.slice(7) : trimmed;
}

export function createTlsEnforcementMiddleware(options: boolean | TlsEnforcementOptions) {
  const requireTls = typeof options === 'boolean' ? options : options.requireTls;
  const trustedProxySet = new Set(
    (typeof options === 'boolean' ? [] : (options.trustedProxies ?? [])).map(normalizeIp).filter(Boolean),
  );

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!requireTls) {
      next();
      return;
    }

    const socketEncrypted = Boolean((req.socket as { encrypted?: boolean } | undefined)?.encrypted);
    if (socketEncrypted) {
      next();
      return;
    }

    const peerIp = normalizeIp(req.socket?.remoteAddress);
    const forwardedProto = req.header('x-forwarded-proto')?.split(',')[0]?.trim().toLowerCase();
    const fromTrustedProxy = peerIp.length > 0 && trustedProxySet.has(peerIp);

    if (fromTrustedProxy && forwardedProto === 'https') {
      next();
      return;
    }

    res.status(403).json({
      error: 'TLS_REQUIRED',
      message: 'Plaintext HTTP is rejected; HTTPS/TLS is mandatory for Gateway security endpoints',
    });
  };
}

export function createJsonContentTypeMiddleware() {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
      const ct = req.header('content-type') ?? '';
      if (!ct.toLowerCase().includes('application/json')) {
        res.status(415).json({
          error: 'UNSUPPORTED_MEDIA_TYPE',
          message: 'Content-Type must be application/json',
        });
        return;
      }
    }
    next();
  };
}
