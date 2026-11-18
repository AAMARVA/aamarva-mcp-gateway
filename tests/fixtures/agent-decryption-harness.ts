import crypto from 'node:crypto';
import { SECURITY_DEFAULTS, canonicalizeJson } from '../../src/gateway/config/security.ts';
import type { EncryptedTokenEnvelope } from '../../src/gateway/crypto/envelope-encryption.ts';
import { buildEnvelopeAad } from '../../src/gateway/crypto/envelope-encryption.ts';

export interface DecryptedTokenPayload {
  v: number;
  tokenId: string;
  token: string;
  gatewayId: string;
  mcpServerId: string;
  expiresAt: string;
}

/**
 * TEST HARNESS / SIMULATED AGENT ADK ONLY.
 * Never imported by Gateway runtime code (Phase 5 is strictly agent-side).
 */
export function decryptTokenAsAgent(
  envelope: EncryptedTokenEnvelope,
  agentPrivateKeyPem: string,
): DecryptedTokenPayload {
  if (envelope.version !== SECURITY_DEFAULTS.ENVELOPE_VERSION) {
    throw new Error(`Unsupported envelope version: ${envelope.version}`);
  }

  const privateKey = crypto.createPrivateKey(agentPrivateKeyPem);
  const aad = buildEnvelopeAad({
    version: envelope.version,
    algorithm: envelope.algorithm,
    tokenId: envelope.tokenId,
    agentId: envelope.agentId,
    accountId: envelope.accountId,
    mcpServerId: envelope.mcpServerId,
    gatewayId: envelope.gatewayId,
    expiresAt: envelope.expiresAt,
  });

  let cek: Buffer;

  if (
    envelope.algorithm === 'X25519-HKDF-SHA256-AES-256-GCM' ||
    envelope.algorithm === 'P256-HKDF-SHA256-AES-256-GCM'
  ) {
    if (!envelope.ephemeralPublicKeyPem || !envelope.saltBase64) {
      throw new Error('Missing ECDH parameters in encrypted envelope');
    }
    const ephPub = crypto.createPublicKey(envelope.ephemeralPublicKeyPem);
    const sharedSecret = crypto.diffieHellman({
      privateKey,
      publicKey: ephPub,
    });
    const salt = Buffer.from(envelope.saltBase64, 'base64');
    const info = Buffer.from(
      `${SECURITY_DEFAULTS.HKDF_INFO_PREFIX}:${envelope.agentId}:${envelope.tokenId}`,
      'utf8',
    );
    cek = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, salt, info, 32));
  } else if (envelope.algorithm === 'RSA-OAEP-256-AES-256-GCM') {
    if (!envelope.wrappedKeyBase64) {
      throw new Error('Missing wrapped RSA key in encrypted envelope');
    }
    cek = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(envelope.wrappedKeyBase64, 'base64'),
    );
  } else {
    throw new Error(`Unsupported envelope algorithm: ${String(envelope.algorithm)}`);
  }

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    cek,
    Buffer.from(envelope.ivBase64, 'base64'),
  );
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(envelope.authTagBase64, 'base64'));

  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertextBase64, 'base64')),
    decipher.final(),
  ]).toString('utf8');

  return JSON.parse(plaintext) as DecryptedTokenPayload;
}

/**
 * TEST HARNESS / MOCK AAMARVA SIGNER ONLY.
 * Signs canonical authorization or revocation payloads with a test Ed25519/ECDSA key.
 */
export function signPayloadAsMockAamarva(
  claims: Record<string, unknown>,
  aamarvaPrivateKeyPem: string,
): string {
  const privateKey = crypto.createPrivateKey(aamarvaPrivateKeyPem);
  const canonical = Buffer.from(canonicalizeJson(claims), 'utf8');
  if (privateKey.asymmetricKeyType === 'ed25519') {
    return crypto.sign(null, canonical, privateKey).toString('base64');
  }
  return crypto.sign('sha256', canonical, privateKey).toString('base64');
}
