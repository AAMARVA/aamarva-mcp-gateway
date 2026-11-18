import type { NextFunction, Request, Response } from 'express';
import type { GatewayLogger } from '../observability/logger.ts';

export function createErrorHandlerMiddleware(logger: GatewayLogger) {
  return (err: unknown, req: Request, res: Response, _next: NextFunction): void => {
    const status =
      typeof err === 'object' &&
      err !== null &&
      'status' in err &&
      typeof (err as { status: unknown }).status === 'number'
        ? (err as { status: number }).status
        : 500;

    const isPayloadTooLarge =
      typeof err === 'object' &&
      err !== null &&
      'type' in err &&
      (err as { type: unknown }).type === 'entity.too.large';

    if (isPayloadTooLarge) {
      res.status(413).json({
        error: 'PAYLOAD_TOO_LARGE',
        message: 'Request body exceeds configured size limit',
      });
      return;
    }

    const isSyntaxError = err instanceof SyntaxError && 'body' in err;
    if (isSyntaxError) {
      res.status(400).json({
        error: 'MALFORMED_JSON',
        message: 'Request body is not valid JSON',
      });
      return;
    }

    logger.error({
      event: 'UNHANDLED_HTTP_ERROR',
      outcome: 'failure',
      message: err instanceof Error ? err.message : 'Unhandled error',
      details: { path: req.originalUrl, method: req.method, status },
    });

    res.status(status >= 400 && status < 600 ? status : 500).json({
      error: 'GATEWAY_ERROR',
      message: status < 500 && err instanceof Error ? err.message : 'Internal Gateway error',
    });
  };
}
