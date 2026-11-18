import crypto from 'node:crypto';
import { canonicalizeJson, sha256Hex, parsePrivateKeySafe, parsePublicKeySafe } from '../config/security.ts';

export interface GatewaySigningKeyPairConfig {
  keyId: string;
  privateKeyPem: string;
  publicKeyPem?: string;
}

export interface GatewayPublicKeyMetadata {
  keyId: string;
  algorithm: 'Ed25519' | 'ECDSA-P256-SHA256';
  purpose: 'gateway-response-signing';
  encoding: 'PEM-SPKI';
  publicKey: string;
  fingerprint: string;
}

interface LoadedGatewaySigningKey {
  keyId: string;
  algorithm: 'Ed25519' | 'ECDSA-P256-SHA256';
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  publicKeyPem: string;
  fingerprint: string;
}

/**
 * Manages the Gateway installation's own cryptographic signing identity.
 * Strictly separate from agent encryption public keys.
 * Never exposes private keys through any API.
 */
export class GatewayIdentityKeyManager {
  private readonly keys = new Map<string, LoadedGatewaySigningKey>();
  private activeKeyId: string;

  constructor(options: {
    activeKeyId: string;
    signingKeys: Record<string, { privateKeyPem: string; publicKeyPem?: string }>;
  }) {
    if (!options.signingKeys || Object.keys(options.signingKeys).length === 0) {
      throw new Error('At least one Gateway signing keypair must be configured');
    }

    for (const [keyId, entry] of Object.entries(options.signingKeys)) {
      const privateKey = parsePrivateKeySafe(entry.privateKeyPem);
      const publicKey = entry.publicKeyPem
        ? parsePublicKeySafe(entry.publicKeyPem)
        : crypto.createPublicKey(privateKey);

      const keyType = privateKey.asymmetricKeyType;
      let algorithm: 'Ed25519' | 'ECDSA-P256-SHA256';
      if (keyType === 'ed25519') {
        algorithm = 'Ed25519';
      } else if (
        keyType === 'ec' &&
        (privateKey.asymmetricKeyDetails?.namedCurve === 'prime256v1' ||
          privateKey.asymmetricKeyDetails?.namedCurve === 'P-256')
      ) {
        algorithm = 'ECDSA-P256-SHA256';
      } else {
        throw new Error(`Unsupported Gateway signing key type: ${String(keyType)}`);
      }

      const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
      const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
      const fingerprint = `sha256:${sha256Hex(spkiDer)}`;

      this.keys.set(keyId, {
        keyId,
        algorithm,
        privateKey,
        publicKey,
        publicKeyPem,
        fingerprint,
      });
    }

    if (!this.keys.has(options.activeKeyId)) {
      throw new Error(`Active Gateway signing keyId "${options.activeKeyId}" not found in configured keys`);
    }
    this.activeKeyId = options.activeKeyId;
  }

  getActiveKeyId(): string {
    return this.activeKeyId;
  }

  listKeyIds(): string[] {
    return Array.from(this.keys.keys());
  }

  /**
   * Rotates the active Gateway signing key while retaining older keys for verification
   * during active session lifetimes.
   */
  rotateActiveKey(newKeyId: string, newKey?: { privateKeyPem: string; publicKeyPem?: string }): void {
    if (newKey) {
      const temp = new GatewayIdentityKeyManager({
        activeKeyId: newKeyId,
        signingKeys: { [newKeyId]: newKey },
      });
      const loaded = temp.keys.get(newKeyId);
      if (loaded) {
        this.keys.set(newKeyId, loaded);
      }
    }
    if (!this.keys.has(newKeyId)) {
      throw new Error(`Cannot rotate to unknown Gateway keyId: ${newKeyId}`);
    }
    this.activeKeyId = newKeyId;
  }

  getPublicKeyMetadata(keyId = this.activeKeyId): GatewayPublicKeyMetadata {
    const entry = this.keys.get(keyId);
    if (!entry) {
      throw new Error(`Unknown Gateway signing keyId: ${keyId}`);
    }
    return {
      keyId: entry.keyId,
      algorithm: entry.algorithm,
      purpose: 'gateway-response-signing',
      encoding: 'PEM-SPKI',
      publicKey: entry.publicKeyPem,
      fingerprint: entry.fingerprint,
    };
  }

  signResponsePayload(payload: unknown): {
    keyId: string;
    algorithm: 'Ed25519' | 'ECDSA-P256-SHA256';
    signature: string;
  } {
    const entry = this.keys.get(this.activeKeyId);
    if (!entry) {
      throw new Error(`Active Gateway signing key missing: ${this.activeKeyId}`);
    }
    const canonical = Buffer.from(canonicalizeJson(payload), 'utf8');
    const sig =
      entry.algorithm === 'Ed25519'
        ? crypto.sign(null, canonical, entry.privateKey)
        : crypto.sign('sha256', canonical, entry.privateKey);

    return {
      keyId: entry.keyId,
      algorithm: entry.algorithm,
      signature: sig.toString('base64'),
    };
  }
}

export function verifyGatewayResponseSignature(params: {
  payload: unknown;
  signatureBase64: string;
  gatewayPublicKey: GatewayPublicKeyMetadata;
}): boolean {
  const pubKey = parsePublicKeySafe(params.gatewayPublicKey.publicKey);
  const spkiDer = pubKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const expectedFingerprint = `sha256:${sha256Hex(spkiDer)}`;
  if (expectedFingerprint !== params.gatewayPublicKey.fingerprint) {
    return false;
  }

  const canonical = Buffer.from(canonicalizeJson(params.payload), 'utf8');
  const sigBuf = Buffer.from(params.signatureBase64, 'base64');

  if (params.gatewayPublicKey.algorithm === 'Ed25519') {
    return crypto.verify(null, canonical, pubKey, sigBuf);
  }
  return crypto.verify('sha256', canonical, pubKey, sigBuf);
}

export interface AttestationVerificationParams {
  attestation: {
    version: string;
    gatewayId: string;
    gatewayKeyId: string;
    gatewayPublicKeyFingerprint: string;
    challenge: string;
    accountId: string;
    integrationId: string;
    mcpServerId: string;
    canonicalEndpoint: string;
    mcpInitialized: boolean;
    toolsDiscoverySuccess: boolean;
    handshakeTimestamp: string;
    expiresAt: string;
  };
  signatureBase64: string;
  /**
   * Pre-configured trusted Gateway public keys owned by AAMARVA Core.
   * Never automatically trust an untrusted key bundled alongside the response.
   */
  trustedGatewayKeys: Record<string, GatewayPublicKeyMetadata>;
  expectedChallenge: string;
  expectedAccountId: string;
  expectedIntegrationId: string;
  expectedGatewayId: string;
  expectedCanonicalEndpoint?: string;
  nowMs?: number;
}

export function verifyGatewayAttestation(params: AttestationVerificationParams): {
  valid: boolean;
  reason?: string;
} {
  const { attestation } = params;
  const nowMs = params.nowMs ?? Date.now();

  if (attestation.version !== 'AAMARVA-GW-ATTEST-V1') {
    return { valid: false, reason: 'Unsupported attestation version' };
  }

  const trustedKey = params.trustedGatewayKeys[attestation.gatewayKeyId];
  if (!trustedKey) {
    return { valid: false, reason: `Untrusted Gateway signing keyId: ${attestation.gatewayKeyId}` };
  }

  if (trustedKey.fingerprint !== attestation.gatewayPublicKeyFingerprint) {
    return { valid: false, reason: 'Attestation public key fingerprint does not match trusted Gateway key' };
  }

  const sigValid = verifyGatewayResponseSignature({
    payload: attestation,
    signatureBase64: params.signatureBase64,
    gatewayPublicKey: trustedKey,
  });
  if (!sigValid) {
    return { valid: false, reason: 'Cryptographic signature verification failed over attestation payload' };
  }

  const expiresAtMs = Date.parse(attestation.expiresAt);
  if (!Number.isFinite(expiresAtMs) || nowMs > expiresAtMs) {
    return { valid: false, reason: 'Attestation has expired' };
  }

  if (!attestation.mcpInitialized || !attestation.toolsDiscoverySuccess) {
    return { valid: false, reason: 'Attestation does not prove both MCP initialize and tools/list success' };
  }

  if (attestation.challenge !== params.expectedChallenge) {
    return { valid: false, reason: 'Attestation challenge mismatch' };
  }
  if (attestation.accountId !== params.expectedAccountId) {
    return { valid: false, reason: 'Attestation accountId mismatch' };
  }
  if (attestation.integrationId !== params.expectedIntegrationId) {
    return { valid: false, reason: 'Attestation integrationId mismatch' };
  }
  if (attestation.gatewayId !== params.expectedGatewayId) {
    return { valid: false, reason: 'Attestation gatewayId mismatch' };
  }
  if (
    params.expectedCanonicalEndpoint &&
    attestation.canonicalEndpoint !== params.expectedCanonicalEndpoint
  ) {
    return { valid: false, reason: 'Attestation endpoint mismatch' };
  }

  return { valid: true };
}
