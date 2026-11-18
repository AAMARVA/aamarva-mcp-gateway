import type { NextFunction, Request, Response } from 'express';

interface Bucket {
  count: number;
  resetAtMs: number;
}

export function createRateLimitMiddleware(options: {
  maxRequests: number;
  windowMs: number;
  keyPrefix: string;
}) {
  const buckets = new Map<string, Bucket>();

  return (req: Request, res: Response, next: NextFunction): void => {
    const now = Date.now();
    const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
    const key = `${options.keyPrefix}:${clientIp}`;

    let bucket = buckets.get(key);
    if (!bucket || now > bucket.resetAtMs) {
      bucket = { count: 0, resetAtMs: now + options.windowMs };
      buckets.set(key, bucket);
    }

    bucket.count += 1;
    res.setHeader('X-RateLimit-Limit', String(options.maxRequests));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, options.maxRequests - bucket.count)));

    if (bucket.count > options.maxRequests) {
      const retryAfter = Math.ceil((bucket.resetAtMs - now) / 1000);
      res.setHeader('Retry-After', String(Math.max(1, retryAfter)));
      res.status(429).json({
        error: 'RATE_LIMIT_EXCEEDED',
        message: 'Too many requests; retry later',
      });
      return;
    }

    // Periodic pruning to avoid unbounded memory growth
    if (buckets.size > 10_000) {
      for (const [k, b] of buckets.entries()) {
        if (now > b.resetAtMs) buckets.delete(k);
      }
    }

    next();
  };
}
