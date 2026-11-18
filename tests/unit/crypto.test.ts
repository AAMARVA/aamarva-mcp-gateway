import crypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { AamarvaSignatureVerifier } from '../../src/gateway/aamarva/signature-verifier.ts';
import { redactSensitiveData } from '../../src/gateway/config/security.ts';
import { encryptTokenForAgent } from '../../src/gateway/crypto/envelope-encryption.ts';
import { generateShortLivedToken } from '../../src/gateway/crypto/token-generator.ts';
import { validateAndHashToken } from '../../src/gateway/crypto/token-validator.ts';
import {
  decryptTokenAsAgent,
  signPayloadAsMockAamarva,
} from '../fixtures/agent-decryption-harness.ts';

describe('Cryptographic Verification & Envelope Encryption', () => {
  it('verifies valid Ed25519 AAMARVA signatures and supports key rotation', () => {
    const k1 = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const k2 = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const verifier = new AamarvaSignatureVerifier({
      trustedSigningKeys: {
        'key-2026-01': k1.publicKey,
        'key-2026-02': k2.publicKey,
      },
      backendAuthSecret: 'test-backend-secret-32-bytes-minimum',
      maxClockSkewSeconds: 60,
    });

    const now = Date.now();
    const claims = {
      authorizationId: 'auth_123',
      agentId: 'agent_1',
      agentName: 'Planner',
      accountId: 'acct_1',
      allowedTools: ['inventory_lookup'],
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 120_000).toISOString(),
    };

    const sig1 = signPayloadAsMockAamarva(claims, k1.privateKey);
    const sig2 = signPayloadAsMockAamarva(claims, k2.privateKey);

    expect(
      verifier.verifySignedGrant({
        claims,
        signature: sig1,
        keyId: 'key-2026-01',
        issuedAtIso: claims.issuedAt,
        expiresAtIso: claims.expiresAt,
      }),
    ).toEqual({ valid: true, algorithm: 'ed25519' });

    expect(
      verifier.verifySignedGrant({
        claims,
        signature: sig2,
        keyId: 'key-2026-02',
        issuedAtIso: claims.issuedAt,
        expiresAtIso: claims.expiresAt,
      }),
    ).toEqual({ valid: true, algorithm: 'ed25519' });

    // Tampered payload must fail
    const tampered = { ...claims, allowedTools: ['inventory_lookup', 'ledger_export'] };
    expect(
      verifier.verifySignedGrant({
        claims: tampered,
        signature: sig1,
        keyId: 'key-2026-01',
        issuedAtIso: claims.issuedAt,
        expiresAtIso: claims.expiresAt,
      }).valid,
    ).toBe(false);

    // Unknown keyId must fail
    expect(
      verifier.verifySignedGrant({
        claims,
        signature: sig1,
        keyId: 'unknown-key',
        issuedAtIso: claims.issuedAt,
        expiresAtIso: claims.expiresAt,
      }).valid,
    ).toBe(false);

    // Invalid signature must fail
    expect(
      verifier.verifySignedGrant({
        claims,
        signature: Buffer.from('not-a-valid-signature').toString('base64'),
        keyId: 'key-2026-01',
        issuedAtIso: claims.issuedAt,
        expiresAtIso: claims.expiresAt,
      }).valid,
    ).toBe(false);
  });

  it('verifies ECDSA P-256 signatures', () => {
    const ec = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const verifier = new AamarvaSignatureVerifier({
      trustedSigningKeys: { 'ec-key-1': ec.publicKey },
      backendAuthSecret: 'test-backend-secret-32-bytes-minimum',
      maxClockSkewSeconds: 60,
    });

    const now = Date.now();
    const claims = {
      authorizationId: 'auth_ec',
      agentId: 'agent_ec',
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
    };

    const sig = signPayloadAsMockAamarva(claims, ec.privateKey);
    const res = verifier.verifySignedGrant({
      claims,
      signature: sig,
      keyId: 'ec-key-1',
      issuedAtIso: claims.issuedAt,
      expiresAtIso: claims.expiresAt,
    });
    expect(res).toEqual({ valid: true, algorithm: 'ecdsa-p256-sha256' });
  });

  it('generates unpredictable tokens without PII and validates hashes', () => {
    const t1 = generateShortLivedToken(120);
    const t2 = generateShortLivedToken(120);
    expect(t1.plaintextToken).not.toBe(t2.plaintextToken);
    expect(t1.tokenId).not.toBe(t2.tokenId);
    expect(t1.plaintextToken.startsWith('agw1.tok_')).toBe(true);

    const parsed = validateAndHashToken(t1.plaintextToken);
    expect(parsed).not.toBeNull();
    expect(parsed?.tokenHash).toBe(t1.tokenHash);
    expect(validateAndHashToken('bad-token')).toBeNull();
  });

  it('encrypts with X25519 ECDH+HKDF+AES-256-GCM and decrypts only with matching agent private key', () => {
    const agent = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const wrongAgent = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const gen = generateShortLivedToken(120);
    const envelope = encryptTokenForAgent({
      plaintextToken: gen.plaintextToken,
      tokenId: gen.tokenId,
      agentId: 'agent_x',
      accountId: 'acct_x',
      mcpServerId: 'mcp_1',
      gatewayId: 'gw_1',
      expiresAtMs: gen.expiresAtMs,
      agentPublicKeyPem: agent.publicKey,
    });

    expect(envelope.algorithm).toBe('X25519-HKDF-SHA256-AES-256-GCM');
    expect(JSON.stringify(envelope)).not.toContain(gen.plaintextToken);

    const decrypted = decryptTokenAsAgent(envelope, agent.privateKey);
    expect(decrypted.token).toBe(gen.plaintextToken);
    expect(decrypted.tokenId).toBe(gen.tokenId);

    // Wrong private key must fail GCM auth
    expect(() => decryptTokenAsAgent(envelope, wrongAgent.privateKey)).toThrow();

    // Tampered envelope AAD metadata must fail GCM auth
    const tamperedEnvelope = { ...envelope, agentId: 'attacker_agent' };
    expect(() => decryptTokenAsAgent(tamperedEnvelope, agent.privateKey)).toThrow();

    // Tampered ciphertext must fail GCM auth
    const origBytes = Buffer.from(envelope.ciphertextBase64, 'base64');
    origBytes[0] = origBytes[0] ^ 0xff;
    const tamperedCipher = { ...envelope, ciphertextBase64: origBytes.toString('base64') };
    expect(() => decryptTokenAsAgent(tamperedCipher, agent.privateKey)).toThrow();
  });

  it('encrypts with P-256 ECDH and RSA-OAEP-256 and rejects weak/invalid keys', () => {
    const p256 = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const gen = generateShortLivedToken(120);
    const envP256 = encryptTokenForAgent({
      plaintextToken: gen.plaintextToken,
      tokenId: gen.tokenId,
      agentId: 'agent_p256',
      accountId: 'acct_1',
      mcpServerId: 'mcp_1',
      gatewayId: 'gw_1',
      expiresAtMs: gen.expiresAtMs,
      agentPublicKeyPem: p256.publicKey,
    });
    expect(envP256.algorithm).toBe('P256-HKDF-SHA256-AES-256-GCM');
    expect(decryptTokenAsAgent(envP256, p256.privateKey).token).toBe(gen.plaintextToken);

    const rsa2048 = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    const envRsa = encryptTokenForAgent({
      plaintextToken: gen.plaintextToken,
      tokenId: gen.tokenId,
      agentId: 'agent_rsa',
      accountId: 'acct_1',
      mcpServerId: 'mcp_1',
      gatewayId: 'gw_1',
      expiresAtMs: gen.expiresAtMs,
      agentPublicKeyPem: rsa2048.publicKey,
    });
    expect(envRsa.algorithm).toBe('RSA-OAEP-256-AES-256-GCM');
    expect(decryptTokenAsAgent(envRsa, rsa2048.privateKey).token).toBe(gen.plaintextToken);

    expect(() =>
      encryptTokenForAgent({
        plaintextToken: gen.plaintextToken,
        tokenId: gen.tokenId,
        agentId: 'agent_bad',
        accountId: 'acct_1',
        mcpServerId: 'mcp_1',
        gatewayId: 'gw_1',
        expiresAtMs: gen.expiresAtMs,
        agentPublicKeyPem: 'not-a-pem-key',
      }),
    ).toThrow();
  });

  it('redacts sensitive secrets from logs', () => {
    const redacted = redactSensitiveData({
      token: 'agw1.tok_123.secret',
      privateKey: '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----',
      mcpCredentials: 'Bearer owner-secret',
      nested: { authorization: 'Bearer xyz', safeField: 'agent_1' },
    }) as Record<string, unknown>;

    expect(redacted.token).toBe('[REDACTED]');
    expect(redacted.privateKey).toBe('[REDACTED]');
    expect(redacted.mcpCredentials).toBe('[REDACTED]');
    expect((redacted.nested as Record<string, unknown>).authorization).toBe('[REDACTED]');
    expect((redacted.nested as Record<string, unknown>).safeField).toBe('agent_1');
  });
});
