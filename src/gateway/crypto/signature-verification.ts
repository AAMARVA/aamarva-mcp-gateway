import crypto from 'node:crypto';
import { canonicalizeJson } from '../config/security.ts';

export interface SignatureVerificationResult {
  valid: boolean;
  reason?: string;
  algorithm?: 'ed25519' | 'ecdsa-p256-sha256';
}

export class SignatureVerifier {
  private readonly trustedKeys: Map<string, crypto.KeyObject>;

  constructor(trustedSigningKeysPem: Record<string, string>) {
    this.trustedKeys = new Map();
    for (const [keyId, pem] of Object.entries(trustedSigningKeysPem)) {
      const normalizedPem = pem.replace(/\\n/g, '\n').trim();
      const keyObject = crypto.createPublicKey(normalizedPem);
      this.trustedKeys.set(keyId, keyObject);
    }
  }

  hasKey(keyId: string): boolean {
    return this.trustedKeys.has(keyId);
  }

  listKeyIds(): string[] {
    return Array.from(this.trustedKeys.keys());
  }

  verifySignedPayload(params: {
    payload: unknown;
    signatureBase64: string;
    keyId: string;
  }): SignatureVerificationResult {
    const publicKey = this.trustedKeys.get(params.keyId);
    if (!publicKey) {
      return { valid: false, reason: `Untrusted or unknown AAMARVA signing keyId: ${params.keyId}` };
    }

    if (!params.signatureBase64 || typeof params.signatureBase64 !== 'string') {
      return { valid: false, reason: 'Missing cryptographic signature' };
    }

    let signatureBuffer: Buffer;
    try {
      signatureBuffer = Buffer.from(params.signatureBase64, 'base64');
      if (signatureBuffer.length === 0) {
        return { valid: false, reason: 'Empty signature buffer' };
      }
    } catch {
      return { valid: false, reason: 'Malformed base64 signature' };
    }

    const canonicalPayload = Buffer.from(canonicalizeJson(params.payload), 'utf8');
    const keyType = publicKey.asymmetricKeyType;

    try {
      if (keyType === 'ed25519') {
        const ok = crypto.verify(null, canonicalPayload, publicKey, signatureBuffer);
        return ok
          ? { valid: true, algorithm: 'ed25519' }
          : { valid: false, reason: 'Ed25519 signature verification failed' };
      }

      if (keyType === 'ec') {
        const curve = publicKey.asymmetricKeyDetails?.namedCurve;
        if (curve !== 'prime256v1' && curve !== 'P-256') {
          return { valid: false, reason: `Unsupported EC curve for signature verification: ${String(curve)}` };
        }
        const ok = crypto.verify('sha256', canonicalPayload, publicKey, signatureBuffer);
        return ok
          ? { valid: true, algorithm: 'ecdsa-p256-sha256' }
          : { valid: false, reason: 'ECDSA P-256 signature verification failed' };
      }

      return { valid: false, reason: `Unsupported AAMARVA signing key type: ${String(keyType)}` };
    } catch (err) {
      return {
        valid: false,
        reason: `Signature verification threw error: ${err instanceof Error ? err.message : 'unknown error'}`,
      };
    }
  }
}
