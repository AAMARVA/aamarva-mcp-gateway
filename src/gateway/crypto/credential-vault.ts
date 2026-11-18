import crypto from 'node:crypto';
import { canonicalizeJson } from '../config/security.ts';
import { validateAndCanonicalizeMcpUrl } from '../security/ssrf-guard.ts';

export interface ExternalMcpCredentials {
  authorizationHeader?: string;
  customHeaders?: Record<string, string>;
}

export interface EncryptedCredentialEnvelope {
  version: 'AAMARVA-GW-CRED-V1';
  salt: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

export interface StoredEncryptedCredentials {
  version: 'AAMARVA-GW-STORED-CRED-V1';
  salt: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

export function canonicalizeMcpEndpoint(
  rawEndpoint: string,
  options: { allowInsecureHttp: boolean; allowLoopbackHttp?: boolean },
): string {
  return validateAndCanonicalizeMcpUrl(rawEndpoint, options).toString();
}

function deriveAesKey(secret: string, salt: Buffer, info: string): Buffer {
  return Buffer.from(crypto.hkdfSync('sha256', Buffer.from(secret, 'utf8'), salt, Buffer.from(info, 'utf8'), 32));
}

/**
 * Encrypts external MCP credentials in-transit from AAMARVA Core -> Gateway
 * bound cryptographically to (gatewayId, accountId, integrationId, challenge).
 */
export function encryptHandshakeCredentialEnvelope(params: {
  credentials: ExternalMcpCredentials;
  backendAuthSecret: string;
  gatewayId: string;
  accountId: string;
  integrationId: string;
  challenge: string;
}): EncryptedCredentialEnvelope {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveAesKey(
    params.backendAuthSecret,
    salt,
    'aamarva-mcp-gateway:handshake-credentials:v1',
  );
  const aad = Buffer.from(
    canonicalizeJson({
      version: 'AAMARVA-GW-CRED-V1',
      gatewayId: params.gatewayId,
      accountId: params.accountId,
      integrationId: params.integrationId,
      challenge: params.challenge,
    }),
    'utf8',
  );

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const plaintext = Buffer.from(JSON.stringify(params.credentials), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    version: 'AAMARVA-GW-CRED-V1',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: tag.toString('base64'),
  };
}

export function decryptHandshakeCredentialEnvelope(params: {
  envelope: EncryptedCredentialEnvelope;
  backendAuthSecret: string;
  gatewayId: string;
  accountId: string;
  integrationId: string;
  challenge: string;
}): ExternalMcpCredentials {
  if (params.envelope.version !== 'AAMARVA-GW-CRED-V1') {
    throw new Error('Unsupported credential envelope version');
  }

  const salt = Buffer.from(params.envelope.salt, 'base64');
  const iv = Buffer.from(params.envelope.iv, 'base64');
  const ciphertext = Buffer.from(params.envelope.ciphertext, 'base64');
  const tag = Buffer.from(params.envelope.tag, 'base64');

  const key = deriveAesKey(
    params.backendAuthSecret,
    salt,
    'aamarva-mcp-gateway:handshake-credentials:v1',
  );
  const aad = Buffer.from(
    canonicalizeJson({
      version: 'AAMARVA-GW-CRED-V1',
      gatewayId: params.gatewayId,
      accountId: params.accountId,
      integrationId: params.integrationId,
      challenge: params.challenge,
    }),
    'utf8',
  );

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  const parsed = JSON.parse(plaintext) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Decrypted credential envelope must be a JSON object');
  }
  const obj = parsed as ExternalMcpCredentials;
  if (obj.authorizationHeader !== undefined && typeof obj.authorizationHeader !== 'string') {
    throw new Error('Invalid authorizationHeader inside decrypted envelope');
  }
  if (
    obj.customHeaders !== undefined &&
    (!obj.customHeaders || typeof obj.customHeaders !== 'object' || Array.isArray(obj.customHeaders))
  ) {
    throw new Error('Invalid customHeaders inside decrypted envelope');
  }
  if (!obj.authorizationHeader && (!obj.customHeaders || Object.keys(obj.customHeaders).length === 0)) {
    throw new Error('Encrypted credential envelope contains no credentials');
  }
  return {
    authorizationHeader: obj.authorizationHeader,
    customHeaders: obj.customHeaders,
  };
}

/**
 * Encrypts external MCP credentials for storage at rest with strict AAD binding
 * to (gatewayId, accountId, integrationId, mcpServerId, canonicalEndpoint).
 */
export function encryptStoredMcpCredentials(params: {
  credentials: ExternalMcpCredentials;
  vaultSecret: string;
  gatewayId: string;
  accountId: string;
  integrationId: string;
  mcpServerId: string;
  canonicalEndpoint: string;
}): string {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveAesKey(params.vaultSecret, salt, 'aamarva-mcp-gateway:stored-credentials:v1');
  const aad = Buffer.from(
    canonicalizeJson({
      version: 'AAMARVA-GW-STORED-CRED-V1',
      gatewayId: params.gatewayId,
      accountId: params.accountId,
      integrationId: params.integrationId,
      mcpServerId: params.mcpServerId,
      canonicalEndpoint: params.canonicalEndpoint,
    }),
    'utf8',
  );

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const plaintext = Buffer.from(JSON.stringify(params.credentials), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const stored: StoredEncryptedCredentials = {
    version: 'AAMARVA-GW-STORED-CRED-V1',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: tag.toString('base64'),
  };
  return JSON.stringify(stored);
}

export function decryptStoredMcpCredentials(params: {
  encryptedJson: string;
  vaultSecret: string;
  gatewayId: string;
  accountId: string;
  integrationId: string;
  mcpServerId: string;
  canonicalEndpoint: string;
}): ExternalMcpCredentials {
  const stored = JSON.parse(params.encryptedJson) as StoredEncryptedCredentials;
  if (stored.version !== 'AAMARVA-GW-STORED-CRED-V1') {
    throw new Error('Unsupported stored credential envelope version');
  }

  const salt = Buffer.from(stored.salt, 'base64');
  const iv = Buffer.from(stored.iv, 'base64');
  const ciphertext = Buffer.from(stored.ciphertext, 'base64');
  const tag = Buffer.from(stored.tag, 'base64');
  const key = deriveAesKey(params.vaultSecret, salt, 'aamarva-mcp-gateway:stored-credentials:v1');
  const aad = Buffer.from(
    canonicalizeJson({
      version: 'AAMARVA-GW-STORED-CRED-V1',
      gatewayId: params.gatewayId,
      accountId: params.accountId,
      integrationId: params.integrationId,
      mcpServerId: params.mcpServerId,
      canonicalEndpoint: params.canonicalEndpoint,
    }),
    'utf8',
  );

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  return JSON.parse(plaintext) as ExternalMcpCredentials;
}
