import crypto from 'node:crypto';
import { SECURITY_DEFAULTS, sha256Hex } from '../config/security.ts';

export interface GeneratedToken {
  tokenId: string;
  plaintextToken: string;
  tokenHash: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

/**
 * Generates a high-entropy, unpredictable short-lived token.
 * Format: agw1.<tokenId>.<256-bit base64url CSPRNG secret>
 * Contains no PII, account IDs, or predictable timestamps.
 */
export function generateShortLivedToken(
  ttlSeconds: number,
  nowMs = Date.now(),
  maxExpiresAtMs?: number,
  options?: { allowExtendedTtl?: boolean },
): GeneratedToken {
  const maxTtlSeconds = options?.allowExtendedTtl
    ? Number.MAX_SAFE_INTEGER
    : SECURITY_DEFAULTS.MAX_TOKEN_TTL_SECONDS;
  if (
    !Number.isFinite(ttlSeconds) ||
    ttlSeconds < SECURITY_DEFAULTS.MIN_TOKEN_TTL_SECONDS ||
    ttlSeconds > maxTtlSeconds
  ) {
    throw new Error(
      `Token TTL ${ttlSeconds}s outside allowed range [${SECURITY_DEFAULTS.MIN_TOKEN_TTL_SECONDS}, ${maxTtlSeconds}]`,
    );
  }

  const requestedExpiresAtMs = nowMs + ttlSeconds * 1000;
  const expiresAtMs =
    maxExpiresAtMs !== undefined ? Math.min(requestedExpiresAtMs, maxExpiresAtMs) : requestedExpiresAtMs;

  if (expiresAtMs - nowMs < SECURITY_DEFAULTS.MIN_TOKEN_TTL_SECONDS * 1000) {
    throw new Error('Insufficient remaining authorization validity for short-lived token');
  }

  const tokenId = `tok_${crypto.randomBytes(SECURITY_DEFAULTS.TOKEN_ID_BYTE_LENGTH).toString('hex')}`;
  const secretPart = crypto.randomBytes(SECURITY_DEFAULTS.TOKEN_BYTE_LENGTH).toString('base64url');
  const plaintextToken = `agw1.${tokenId}.${secretPart}`;
  const tokenHash = sha256Hex(plaintextToken);

  return {
    tokenId,
    plaintextToken,
    tokenHash,
    issuedAtMs: nowMs,
    expiresAtMs,
  };
}
