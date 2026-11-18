import crypto from 'node:crypto';

export const SECURITY_DEFAULTS = {
  MIN_TOKEN_TTL_SECONDS: 15,
  MAX_TOKEN_TTL_SECONDS: 600,
  MIN_SESSION_TTL_SECONDS: 60,
  MAX_SESSION_TTL_SECONDS: 86400,
  TOKEN_BYTE_LENGTH: 32,
  TOKEN_ID_BYTE_LENGTH: 16,
  SESSION_ID_BYTE_LENGTH: 16,
  ENVELOPE_VERSION: 'AAMARVA-GW-ENV-V1',
  HKDF_INFO_PREFIX: 'aamarva-mcp-gateway:token-envelope:v1',
} as const;

const SENSITIVE_KEY_PATTERN =
  /^(token|plaintexttoken|rawtoken|privatekey|secret|password|authorization|authorizationheader|apikey|mcpcredentials|encryptedtoken|encryptedcredentials|encryptedcredentialsjson|ciphertext|authheader|customheaders|credential|credentials|bearer)$/i;

/**
 * Recursively redacts sensitive fields before logging or returning diagnostics.
 */
export function redactSensitiveData(value: unknown, depth = 0): unknown {
  if (depth > 8 || value === null || value === undefined) {
    return value;
  }

  if (typeof value === 'string') {
    if (value.startsWith('-----BEGIN') && value.includes('PRIVATE KEY')) {
      return '[REDACTED_PRIVATE_KEY]';
    }
    if (value.startsWith('Bearer ')) {
      return 'Bearer [REDACTED]';
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveData(item, depth + 1));
  }

  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SENSITIVE_KEY_PATTERN.test(k.replace(/[_-]/g, ''))) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = redactSensitiveData(v, depth + 1);
      }
    }
    return out;
  }

  return value;
}

/**
 * Produces deterministic canonical JSON (sorted object keys recursively)
 * so cryptographic signatures are invariant to JSON property order.
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(',')}]`;
  }
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  const entries = sortedKeys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`);
  return `{${entries.join(',')}}`;
}

export function sha256Hex(input: string | Buffer): string {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export function constantTimeEqualStrings(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}
