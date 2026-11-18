import { canonicalizeMcpEndpoint } from '../crypto/credential-vault.ts';
import type { AuditRecorder } from '../observability/audit.ts';
import type { GatewayMetrics } from '../observability/metrics.ts';
import {
  resolveAndValidateMcpDestination,
  SsrfBlockedError,
  type SsrfPolicyOptions,
} from '../security/ssrf-guard.ts';

export async function normalizeAndCheckDestination(
  rawEndpoint: string,
  policy: SsrfPolicyOptions,
  audit: AuditRecorder,
  metrics: GatewayMetrics,
  correlationId: string,
  accountId: string,
  mcpServerId: string,
): Promise<{ canonicalEndpoint: string; validatedIpsKey: string }> {
  try {
    const dest = await resolveAndValidateMcpDestination(rawEndpoint, policy);
    const validatedIpsKey = dest.allValidatedAddresses
      .map((a) => `${a.family}:${a.address}`)
      .sort()
      .join(',');
    return {
      canonicalEndpoint: dest.canonicalEndpoint,
      validatedIpsKey,
    };
  } catch (err) {
    metrics.incHandshakesFailed();
    if (err instanceof SsrfBlockedError) {
      audit.record({
        event: 'SSRF_BLOCKED',
        outcome: 'denied',
        message: err.message,
        correlationId,
        accountId,
        mcpServerId,
        details: { code: err.code },
      });
      throw err;
    }
    throw new SsrfBlockedError(
      'INVALID_MCP_ENDPOINT',
      'Invalid external MCP endpoint URL',
      400,
    );
  }
}

export function canonicalizeEndpointForPoolCheck(
  transport: 'stdio' | 'streamable-http',
  expectedEndpoint: string,
  recordCanonicalEndpoint: string,
  policy: { allowInsecureHttp: boolean; allowLoopbackHttp: boolean },
): { ok: true } | { ok: false; message: string } {
  let canonicalExpected: string;
  if (transport === 'stdio') {
    canonicalExpected = expectedEndpoint.trim();
  } else {
    try {
      canonicalExpected = canonicalizeMcpEndpoint(expectedEndpoint, policy);
    } catch {
      return { ok: false, message: 'Invalid expected endpoint binding' };
    }
  }
  if (canonicalExpected !== recordCanonicalEndpoint) {
    return {
      ok: false,
      message: 'Endpoint substitution rejected: endpoint does not match verified attestation',
    };
  }
  return { ok: true };
}
