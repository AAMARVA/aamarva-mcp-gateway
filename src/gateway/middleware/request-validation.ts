import type { NextFunction, Request, Response } from 'express';

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
