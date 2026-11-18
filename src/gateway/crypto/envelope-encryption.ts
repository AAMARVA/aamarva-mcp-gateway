import crypto from 'node:crypto';
import { SECURITY_DEFAULTS, canonicalizeJson, parsePublicKeySafe } from '../config/security.ts';

export type EnvelopeAlgorithm =
  | 'X25519-HKDF-SHA256-AES-256-GCM'
  | 'P256-HKDF-SHA256-AES-256-GCM'
  | 'RSA-OAEP-256-AES-256-GCM';

export interface EncryptedTokenEnvelope {
  version: typeof SECURITY_DEFAULTS.ENVELOPE_VERSION;
  algorithm: EnvelopeAlgorithm;
  tokenId: string;
  gatewayId: string;
  mcpServerId: string;
  agentId: string;
  accountId: string;
  expiresAt: string;
  /** Ephemeral public key SPKI PEM (present for ECDH algorithms) */
  ephemeralPublicKeyPem?: string;
  /** HKDF salt base64 (present for ECDH algorithms) */
  saltBase64?: string;
  /** RSA-OAEP-256 wrapped CEK base64 (present for RSA-OAEP-256) */
  wrappedKeyBase64?: string;
  ivBase64: string;
  authTagBase64: string;
  ciphertextBase64: string;
}

export interface TokenEnvelopeInput {
  plaintextToken: string;
  tokenId: string;
  agentId: string;
  accountId: string;
  mcpServerId: string;
  gatewayId: string;
  expiresAtMs: number;
  agentPublicKeyPem: string;
}

export function buildEnvelopeAad(params: {
  version: string;
  algorithm: EnvelopeAlgorithm;
  tokenId: string;
  agentId: string;
  accountId: string;
  mcpServerId: string;
  gatewayId: string;
  expiresAt: string;
}): Buffer {
  return Buffer.from(
    canonicalizeJson({
      version: params.version,
      algorithm: params.algorithm,
      tokenId: params.tokenId,
      agentId: params.agentId,
      accountId: params.accountId,
      mcpServerId: params.mcpServerId,
      gatewayId: params.gatewayId,
      expiresAt: params.expiresAt,
    }),
    'utf8',
  );
}

/**
 * Encrypts the short-lived plaintext token to the agent's public key so that
 * AAMARVA cannot inspect the plaintext token while relaying it to the agent.
 */
export function encryptTokenForAgent(input: TokenEnvelopeInput): EncryptedTokenEnvelope {
  let agentPubKey: crypto.KeyObject;
  try {
    agentPubKey = parsePublicKeySafe(input.agentPublicKeyPem);
  } catch (err) {
    throw new Error(
      `Invalid agent public key: ${err instanceof Error ? err.message : 'unparseable key'}`,
    );
  }

  const expiresAt = new Date(input.expiresAtMs).toISOString();
  const payloadBuffer = Buffer.from(
    JSON.stringify({
      v: 1,
      tokenId: input.tokenId,
      token: input.plaintextToken,
      gatewayId: input.gatewayId,
      mcpServerId: input.mcpServerId,
      expiresAt,
    }),
    'utf8',
  );

  const keyType = agentPubKey.asymmetricKeyType;

  if (keyType === 'x25519') {
    const algorithm: EnvelopeAlgorithm = 'X25519-HKDF-SHA256-AES-256-GCM';
    const ephemeral = crypto.generateKeyPairSync('x25519');
    const sharedSecret = crypto.diffieHellman({
      privateKey: ephemeral.privateKey,
      publicKey: agentPubKey,
    });
    const salt = crypto.randomBytes(32);
    const info = Buffer.from(
      `${SECURITY_DEFAULTS.HKDF_INFO_PREFIX}:${input.agentId}:${input.tokenId}`,
      'utf8',
    );
    const cek = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, salt, info, 32));
    const iv = crypto.randomBytes(12);
    const aad = buildEnvelopeAad({
      version: SECURITY_DEFAULTS.ENVELOPE_VERSION,
      algorithm,
      tokenId: input.tokenId,
      agentId: input.agentId,
      accountId: input.accountId,
      mcpServerId: input.mcpServerId,
      gatewayId: input.gatewayId,
      expiresAt,
    });

    const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(payloadBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      version: SECURITY_DEFAULTS.ENVELOPE_VERSION,
      algorithm,
      tokenId: input.tokenId,
      gatewayId: input.gatewayId,
      mcpServerId: input.mcpServerId,
      agentId: input.agentId,
      accountId: input.accountId,
      expiresAt,
      ephemeralPublicKeyPem: ephemeral.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      saltBase64: salt.toString('base64'),
      ivBase64: iv.toString('base64'),
      authTagBase64: authTag.toString('base64'),
      ciphertextBase64: ciphertext.toString('base64'),
    };
  }

  if (keyType === 'ec') {
    const curve = agentPubKey.asymmetricKeyDetails?.namedCurve;
    if (curve !== 'prime256v1' && curve !== 'P-256') {
      throw new Error(`Unsupported EC curve for agent public key: ${String(curve)}. Expected P-256 or X25519.`);
    }
    const algorithm: EnvelopeAlgorithm = 'P256-HKDF-SHA256-AES-256-GCM';
    const ephemeral = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const sharedSecret = crypto.diffieHellman({
      privateKey: ephemeral.privateKey,
      publicKey: agentPubKey,
    });
    const salt = crypto.randomBytes(32);
    const info = Buffer.from(
      `${SECURITY_DEFAULTS.HKDF_INFO_PREFIX}:${input.agentId}:${input.tokenId}`,
      'utf8',
    );
    const cek = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, salt, info, 32));
    const iv = crypto.randomBytes(12);
    const aad = buildEnvelopeAad({
      version: SECURITY_DEFAULTS.ENVELOPE_VERSION,
      algorithm,
      tokenId: input.tokenId,
      agentId: input.agentId,
      accountId: input.accountId,
      mcpServerId: input.mcpServerId,
      gatewayId: input.gatewayId,
      expiresAt,
    });

    const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(payloadBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      version: SECURITY_DEFAULTS.ENVELOPE_VERSION,
      algorithm,
      tokenId: input.tokenId,
      gatewayId: input.gatewayId,
      mcpServerId: input.mcpServerId,
      agentId: input.agentId,
      accountId: input.accountId,
      expiresAt,
      ephemeralPublicKeyPem: ephemeral.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      saltBase64: salt.toString('base64'),
      ivBase64: iv.toString('base64'),
      authTagBase64: authTag.toString('base64'),
      ciphertextBase64: ciphertext.toString('base64'),
    };
  }

  if (keyType === 'rsa') {
    const modulusLength = agentPubKey.asymmetricKeyDetails?.modulusLength ?? 0;
    if (modulusLength < 2048) {
      throw new Error(`Insecure RSA key size (${modulusLength} bits). Minimum 2048 bits required.`);
    }
    const algorithm: EnvelopeAlgorithm = 'RSA-OAEP-256-AES-256-GCM';
    const cek = crypto.randomBytes(32);
    const wrappedKey = crypto.publicEncrypt(
      {
        key: agentPubKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      cek,
    );
    const iv = crypto.randomBytes(12);
    const aad = buildEnvelopeAad({
      version: SECURITY_DEFAULTS.ENVELOPE_VERSION,
      algorithm,
      tokenId: input.tokenId,
      agentId: input.agentId,
      accountId: input.accountId,
      mcpServerId: input.mcpServerId,
      gatewayId: input.gatewayId,
      expiresAt,
    });

    const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(payloadBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      version: SECURITY_DEFAULTS.ENVELOPE_VERSION,
      algorithm,
      tokenId: input.tokenId,
      gatewayId: input.gatewayId,
      mcpServerId: input.mcpServerId,
      agentId: input.agentId,
      accountId: input.accountId,
      expiresAt,
      wrappedKeyBase64: wrappedKey.toString('base64'),
      ivBase64: iv.toString('base64'),
      authTagBase64: authTag.toString('base64'),
      ciphertextBase64: ciphertext.toString('base64'),
    };
  }

  throw new Error(`Unsupported agent public key algorithm: ${String(keyType)}`);
}
