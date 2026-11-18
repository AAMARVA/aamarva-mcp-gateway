import crypto from 'node:crypto';
import { constantTimeEqualStrings, sha256Hex } from '../config/security.ts';
import { SignatureVerifier } from '../crypto/signature-verification.ts';
import type { SignatureVerificationResult } from '../crypto/signature-verification.ts';

export class AamarvaSignatureVerifier {
  private readonly verifier: SignatureVerifier;
  private readonly backendAuthSecret: string;
  private readonly maxClockSkewMs: number;

  constructor(options: {
    trustedSigningKeys: Record<string, string>;
    backendAuthSecret: string;
    maxClockSkewSeconds: number;
  }) {
    this.verifier = new SignatureVerifier(options.trustedSigningKeys);
    this.backendAuthSecret = options.backendAuthSecret;
    this.maxClockSkewMs = options.maxClockSkewSeconds * 1000;
  }

  listTrustedKeyIds(): string[] {
    return this.verifier.listKeyIds();
  }

  verifySignedGrant(params: {
    claims: unknown;
    signature: string;
    keyId: string;
    issuedAtIso: string;
    expiresAtIso: string;
  }): SignatureVerificationResult {
    const sigResult = this.verifier.verifySignedPayload({
      payload: params.claims,
      signatureBase64: params.signature,
      keyId: params.keyId,
    });

    if (!sigResult.valid) {
      return sigResult;
    }

    const nowMs = Date.now();
    const issuedAtMs = Date.parse(params.issuedAtIso);
    const expiresAtMs = Date.parse(params.expiresAtIso);

    if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)) {
      return { valid: false, reason: 'Invalid issuedAt or expiresAt timestamp' };
    }

    if (issuedAtMs - nowMs > this.maxClockSkewMs) {
      return { valid: false, reason: 'Authorization grant issuedAt is too far in the future' };
    }

    if (nowMs > expiresAtMs) {
      return { valid: false, reason: 'Authorization grant has already expired' };
    }

    if (expiresAtMs <= issuedAtMs) {
      return { valid: false, reason: 'Authorization grant expiresAt must be after issuedAt' };
    }

    return sigResult;
  }

  /**
   * Computes canonical HMAC-SHA256 authentication tag for AAMARVA <-> Gateway backend HTTP calls.
   */
  computeBackendRequestHmac(params: {
    method: string;
    path: string;
    timestamp: string;
    requestId: string;
    rawBody: string | Buffer;
  }): string {
    const bodyHash = sha256Hex(params.rawBody);
    const canonical = `${params.method.toUpperCase()}\n${params.path}\n${params.timestamp}\n${params.requestId}\n${bodyHash}`;
    return crypto
      .createHmac('sha256', this.backendAuthSecret)
      .update(canonical, 'utf8')
      .digest('hex');
  }

  verifyBackendRequestHmac(params: {
    method: string;
    path: string;
    timestamp: string;
    requestId: string;
    rawBody: string | Buffer;
    providedSignatureHex: string;
  }): { valid: boolean; reason?: string } {
    const tsMs = Number.parseInt(params.timestamp, 10);
    if (!Number.isFinite(tsMs)) {
      return { valid: false, reason: 'Invalid X-Aamarva-Timestamp header' };
    }
    if (Math.abs(Date.now() - tsMs) > this.maxClockSkewMs) {
      return { valid: false, reason: 'Backend request timestamp outside allowed clock skew' };
    }
    const expected = this.computeBackendRequestHmac({
      method: params.method,
      path: params.path,
      timestamp: params.timestamp,
      requestId: params.requestId,
      rawBody: params.rawBody,
    });
    if (!constantTimeEqualStrings(expected, params.providedSignatureHex)) {
      return { valid: false, reason: 'Invalid AAMARVA backend HMAC signature' };
    }
    return { valid: true };
  }
}
