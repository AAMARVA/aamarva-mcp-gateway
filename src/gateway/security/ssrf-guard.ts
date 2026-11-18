import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { Readable } from 'node:stream';

export interface DnsResolvedAddress {
  address: string;
  family: 4 | 6;
}

export type DnsLookupFn = (hostname: string) => Promise<DnsResolvedAddress[]>;

export interface SsrfPolicyOptions {
  /** Allow plaintext http:// (must be false when REQUIRE_TLS=true). */
  allowInsecureHttp: boolean;
  /**
   * Explicitly development/test-only exception limited strictly to loopback addresses.
   * Prohibited in production by config validation. Never permits RFC1918, link-local, or metadata.
   */
  allowLoopbackHttp?: boolean;
  /** Optional injectable DNS resolver for deterministic testing. */
  dnsLookup?: DnsLookupFn;
}

export class SsrfBlockedError extends Error {
  readonly code: string;
  readonly statusCode: number;

  constructor(code: string, message: string, statusCode = 403) {
    super(message);
    this.name = 'SsrfBlockedError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

interface CidrV4 {
  base: number;
  mask: number;
  label: string;
}

interface CidrV6 {
  base: bigint;
  mask: bigint;
  label: string;
}

function parseIpv4ToUint32(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    if (part.length > 1 && part.startsWith('0')) return null;
    const octet = Number.parseInt(part, 10);
    if (octet < 0 || octet > 255) return null;
    value = ((value << 8) | octet) >>> 0;
  }
  return value;
}

function makeCidrV4(cidr: string, label: string): CidrV4 {
  const [ipStr, prefixStr] = cidr.split('/');
  const base = parseIpv4ToUint32(ipStr);
  if (base === null) throw new Error(`Invalid CIDR base IPv4: ${cidr}`);
  const prefix = Number.parseInt(prefixStr, 10);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { base: (base & mask) >>> 0, mask, label };
}

const BLOCKED_IPV4_CIDRS: CidrV4[] = [
  makeCidrV4('0.0.0.0/8', 'IPv4 unspecified / this-network'),
  makeCidrV4('10.0.0.0/8', 'RFC1918 private network'),
  makeCidrV4('100.64.0.0/10', 'CGNAT / shared address space'),
  makeCidrV4('127.0.0.0/8', 'IPv4 loopback'),
  makeCidrV4('169.254.0.0/16', 'IPv4 link-local / cloud metadata'),
  makeCidrV4('172.16.0.0/12', 'RFC1918 private network'),
  makeCidrV4('192.0.0.0/24', 'IETF protocol assignments'),
  makeCidrV4('192.0.2.0/24', 'TEST-NET-1 reserved documentation'),
  makeCidrV4('192.88.99.0/24', 'Deprecated 6to4 relay anycast'),
  makeCidrV4('192.168.0.0/16', 'RFC1918 private network'),
  makeCidrV4('198.18.0.0/15', 'Benchmarking reserved range'),
  makeCidrV4('198.51.100.0/24', 'TEST-NET-2 reserved documentation'),
  makeCidrV4('203.0.113.0/24', 'TEST-NET-3 reserved documentation'),
  makeCidrV4('224.0.0.0/4', 'IPv4 multicast'),
  makeCidrV4('240.0.0.0/4', 'IPv4 reserved / broadcast'),
];

const IPV4_LOOPBACK_CIDR = makeCidrV4('127.0.0.0/8', 'IPv4 loopback');

function parseIpv6ToBigInt(rawIp: string): bigint | null {
  const cleaned = rawIp.trim().replace(/^\[/, '').replace(/\]$/, '');
  if (!cleaned || cleaned.includes('%')) return null;
  if (!net.isIPv6(cleaned)) return null;

  const doubleColonParts = cleaned.split('::');
  if (doubleColonParts.length > 2) return null;

  const parseSide = (side: string): number[] | null => {
    if (!side) return [];
    const tokens = side.split(':');
    const out: number[] = [];
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (token.includes('.')) {
        // Dotted IPv4 tail valid only at end
        if (i !== tokens.length - 1) return null;
        const v4 = parseIpv4ToUint32(token);
        if (v4 === null) return null;
        out.push((v4 >>> 16) & 0xffff, v4 & 0xffff);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(token)) return null;
        out.push(Number.parseInt(token, 16));
      }
    }
    return out;
  };

  let hextets: number[];
  if (doubleColonParts.length === 2) {
    const left = parseSide(doubleColonParts[0]);
    const right = parseSide(doubleColonParts[1]);
    if (!left || !right) return null;
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    hextets = [...left, ...new Array<number>(missing).fill(0), ...right];
  } else {
    const full = parseSide(cleaned);
    if (!full || full.length !== 8) return null;
    hextets = full;
  }

  let result = 0n;
  for (const h of hextets) {
    result = (result << 16n) | BigInt(h);
  }
  return result;
}

function makeCidrV6(prefixIp: string, prefixLen: number, label: string): CidrV6 {
  const base = parseIpv6ToBigInt(prefixIp);
  if (base === null) throw new Error(`Invalid CIDR base IPv6: ${prefixIp}`);
  const allOnes = (1n << 128n) - 1n;
  const mask = prefixLen === 0 ? 0n : (allOnes << BigInt(128 - prefixLen)) & allOnes;
  return { base: base & mask, mask, label };
}

const BLOCKED_IPV6_CIDRS: CidrV6[] = [
  makeCidrV6('::', 128, 'IPv6 unspecified'),
  makeCidrV6('::1', 128, 'IPv6 loopback'),
  makeCidrV6('100::', 64, 'IPv6 discard-only'),
  makeCidrV6('2001::', 32, 'Teredo tunneling'),
  makeCidrV6('2001:2::', 48, 'IPv6 benchmarking'),
  makeCidrV6('2001:db8::', 32, 'IPv6 documentation'),
  makeCidrV6('2002::', 16, '6to4 transitioning'),
  makeCidrV6('64:ff9b::', 96, 'NAT64'),
  makeCidrV6('64:ff9b:1::', 48, 'Local-use NAT64'),
  makeCidrV6('fc00::', 7, 'IPv6 Unique Local Address (ULA)'),
  makeCidrV6('fe80::', 10, 'IPv6 link-local'),
  makeCidrV6('fec0::', 10, 'Deprecated IPv6 site-local'),
  makeCidrV6('ff00::', 8, 'IPv6 multicast'),
];

function checkBlockedIpv4Uint32(
  v4: number,
  options: { allowLoopback?: boolean },
): string | null {
  if (options.allowLoopback && (v4 & IPV4_LOOPBACK_CIDR.mask) >>> 0 === IPV4_LOOPBACK_CIDR.base) {
    return null;
  }
  for (const cidr of BLOCKED_IPV4_CIDRS) {
    if (((v4 & cidr.mask) >>> 0) === cidr.base) {
      return `Blocked IPv4 destination (${cidr.label})`;
    }
  }
  return null;
}

/**
 * Validates any IPv4 or IPv6 literal against private, loopback, link-local,
 * metadata, unspecified, multicast, IPv4-mapped IPv6, and special-purpose ranges.
 * Returns a human-readable block reason or null if permitted.
 */
export function getBlockedIpReason(
  rawIp: string,
  options: { allowLoopback?: boolean } = {},
): string | null {
  const normalized = rawIp.trim().replace(/^\[/, '').replace(/\]$/, '');
  if (!normalized) return 'Empty IP address';
  if (normalized.includes('%')) return 'IPv6 zone identifiers are prohibited';

  if (net.isIPv4(normalized)) {
    const v4 = parseIpv4ToUint32(normalized);
    if (v4 === null) return 'Malformed or non-canonical IPv4 literal';
    return checkBlockedIpv4Uint32(v4, options);
  }

  if (net.isIPv6(normalized)) {
    const v6 = parseIpv6ToBigInt(normalized);
    if (v6 === null) return 'Malformed IPv6 literal';

    if (options.allowLoopback && v6 === 1n) {
      return null;
    }

    // Check IPv4-mapped IPv6 (::ffff:0:0/96) and IPv4-compatible IPv6 (::/96, excluding ::0 and ::1 checked above)
    const upper96 = v6 >> 32n;
    if (upper96 === 0xffffn || (upper96 === 0n && v6 > 1n)) {
      const embeddedV4 = Number(v6 & 0xffffffffn) >>> 0;
      const reason = checkBlockedIpv4Uint32(embeddedV4, options);
      if (reason) {
        return `Blocked IPv4-mapped IPv6 destination (${reason})`;
      }
      // Reject IPv4-mapped IPv6 even if otherwise unspecified/public when not pure public IPv4?
      // Wait: if embedded V4 is legitimately public, fail-safe: block IPv4-compatible (::/96) altogether.
      if (upper96 === 0n) {
        return 'Blocked deprecated IPv4-compatible IPv6 address';
      }
    }

    for (const cidr of BLOCKED_IPV6_CIDRS) {
      if ((v6 & cidr.mask) === cidr.base) {
        return `Blocked IPv6 destination (${cidr.label})`;
      }
    }
    return null;
  }

  return 'Unrecognized IP literal format';
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
]);

const BLOCKED_HOST_SUFFIXES = ['.localhost', '.local', '.internal', '.arpa', '.localdomain'];

/**
 * Detects obfuscated numeric/octal/hex/shortened IPv4 representations in the raw URL authority
 * before WHATWG URL normalization can hide them.
 */
function hasObfuscatedIpAuthority(rawUrl: string): boolean {
  const afterScheme = rawUrl.trim().replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');
  const authority = afterScheme.split(/[\\/?#]/)[0] ?? '';
  if (!authority) return true;
  if (authority.includes('@')) return true;

  // Strip port if not IPv6 bracketed
  let rawHost = authority;
  if (rawHost.startsWith('[')) {
    const closeIdx = rawHost.indexOf(']');
    if (closeIdx === -1) return true;
    rawHost = rawHost.slice(1, closeIdx);
    // Reject zone IDs cleanly
    if (rawHost.includes('%')) return true;
    return false;
  }

  const colonIdx = rawHost.lastIndexOf(':');
  if (colonIdx !== -1) {
    rawHost = rawHost.slice(0, colonIdx);
  }
  rawHost = rawHost.replace(/\.+$/, '').toLowerCase();

  if (!rawHost) return true;
  // Single integer IP (e.g., 2130706433, 0, 0x7f000001)
  if (/^\d+$/.test(rawHost) || /^0x[0-9a-f]+$/i.test(rawHost)) {
    return true;
  }
  const labels = rawHost.split('.');
  // Check numeric dot-separated obfuscated forms: hex octets, octal leading zeroes, shortened 2-3 part IPs
  const allNumericLike = labels.every((lbl) => /^(0x[0-9a-f]+|0[0-7]+|\d+)$/i.test(lbl));
  if (allNumericLike) {
    if (labels.length !== 4) return true;
    for (const lbl of labels) {
      if (lbl.startsWith('0x') || lbl.startsWith('0X')) return true;
      if (lbl.length > 1 && lbl.startsWith('0')) return true;
    }
  }
  return false;
}

export function normalizeHostname(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/^\[/, '').replace(/\]$/, '').replace(/\.+$/, '');
}

export function isLoopbackHostname(rawHost: string): boolean {
  const host = normalizeHostname(rawHost);
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') {
    return true;
  }
  const v4 = parseIpv4ToUint32(host);
  if (v4 !== null) {
    return ((v4 & IPV4_LOOPBACK_CIDR.mask) >>> 0) === IPV4_LOOPBACK_CIDR.base;
  }
  if (net.isIPv6(host)) {
    const v6 = parseIpv6ToBigInt(host);
    return v6 === 1n;
  }
  return false;
}

/**
 * Validates and canonicalizes an outbound MCP HTTP(S) URL synchronously.
 * Rejects embedded credentials, non-HTTPS protocols (unless explicitly allowed),
 * obfuscated IP literals, zone IDs, reserved internal hostnames, and blocked IP literals.
 */
export function validateAndCanonicalizeMcpUrl(
  rawEndpoint: string,
  options: { allowInsecureHttp: boolean; allowLoopbackHttp?: boolean },
): URL {
  const trimmed = rawEndpoint.trim();
  if (!trimmed) {
    throw new SsrfBlockedError('INVALID_MCP_ENDPOINT', 'MCP endpoint URL must not be empty', 400);
  }
  if (/[\x00-\x1f\x7f\s]/.test(trimmed)) {
    throw new SsrfBlockedError('INVALID_MCP_ENDPOINT', 'MCP endpoint URL contains invalid whitespace or control characters', 400);
  }
  if (hasObfuscatedIpAuthority(trimmed)) {
    throw new SsrfBlockedError('SSRF_OBFUSCATED_HOST', 'Rejected malformed, embedded-credential, or obfuscated IP endpoint', 403);
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new SsrfBlockedError('INVALID_MCP_ENDPOINT', 'Invalid MCP endpoint URL syntax', 400);
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new SsrfBlockedError('INVALID_MCP_ENDPOINT', `Unsupported MCP endpoint protocol: ${parsed.protocol}`, 400);
  }

  if (parsed.username || parsed.password) {
    throw new SsrfBlockedError('SSRF_EMBEDDED_CREDENTIALS', 'MCP endpoint URL must not embed credentials', 400);
  }

  const normalizedHost = normalizeHostname(parsed.hostname);
  if (!normalizedHost) {
    throw new SsrfBlockedError('INVALID_MCP_ENDPOINT', 'MCP endpoint URL hostname is empty', 400);
  }

  const loopbackHost = isLoopbackHostname(normalizedHost);
  const allowLoopback = Boolean(options.allowLoopbackHttp);

  if (parsed.protocol !== 'https:') {
    const permittedHttp = options.allowInsecureHttp || (allowLoopback && loopbackHost);
    if (!permittedHttp) {
      throw new SsrfBlockedError('INVALID_MCP_ENDPOINT', 'External MCP endpoint must use https:// when TLS is enforced', 400);
    }
  }

  // Hostname-level SSRF checks
  if (net.isIP(normalizedHost) !== 0) {
    const blockedReason = getBlockedIpReason(normalizedHost, { allowLoopback });
    if (blockedReason) {
      throw new SsrfBlockedError('SSRF_BLOCKED_DESTINATION', blockedReason, 403);
    }
  } else {
    const isLocalhost = normalizedHost === 'localhost';
    if (isLocalhost) {
      if (!allowLoopback) {
        throw new SsrfBlockedError('SSRF_BLOCKED_DESTINATION', 'Loopback hostname localhost is prohibited by SSRF policy', 403);
      }
    } else {
      if (BLOCKED_HOSTNAMES.has(normalizedHost)) {
        throw new SsrfBlockedError('SSRF_BLOCKED_DESTINATION', `Internal hostname "${normalizedHost}" is prohibited by SSRF policy`, 403);
      }
      for (const suffix of BLOCKED_HOST_SUFFIXES) {
        if (normalizedHost.endsWith(suffix)) {
          throw new SsrfBlockedError('SSRF_BLOCKED_DESTINATION', `Internal DNS suffix "${suffix}" is prohibited by SSRF policy`, 403);
        }
      }
      if (!normalizedHost.includes('.')) {
        throw new SsrfBlockedError('SSRF_BLOCKED_DESTINATION', `Single-label hostname "${normalizedHost}" is prohibited by SSRF policy`, 403);
      }
    }
  }

  parsed.hash = '';
  return parsed;
}

export const defaultDnsLookup: DnsLookupFn = async (hostname: string) => {
  const results = await dns.promises.lookup(hostname, { all: true, verbatim: true });
  return results.map((r) => ({
    address: r.address,
    family: r.family === 6 ? 6 : 4,
  }));
};

export interface ValidatedDestination {
  url: URL;
  canonicalEndpoint: string;
  normalizedHost: string;
  port: number;
  pinnedAddress: DnsResolvedAddress;
  allValidatedAddresses: DnsResolvedAddress[];
}

/**
 * Resolves the target hostname BEFORE establishing any network connection,
 * validates EVERY returned IPv4/IPv6 record against SSRF blocklists,
 * and returns a pinned address to bind directly at TCP/TLS dial time.
 */
export async function resolveAndValidateMcpDestination(
  rawEndpoint: string,
  options: SsrfPolicyOptions,
): Promise<ValidatedDestination> {
  const url = validateAndCanonicalizeMcpUrl(rawEndpoint, options);
  const normalizedHost = normalizeHostname(url.hostname);
  const port = url.port
    ? Number.parseInt(url.port, 10)
    : url.protocol === 'https:'
      ? 443
      : 80;
  const allowLoopback = Boolean(options.allowLoopbackHttp);

  if (net.isIP(normalizedHost) !== 0) {
    const family = (net.isIPv6(normalizedHost) ? 6 : 4) as 4 | 6;
    const reason = getBlockedIpReason(normalizedHost, { allowLoopback });
    if (reason) {
      throw new SsrfBlockedError('SSRF_BLOCKED_DESTINATION', reason, 403);
    }
    const addr: DnsResolvedAddress = { address: normalizedHost, family };
    return {
      url,
      canonicalEndpoint: url.toString(),
      normalizedHost,
      port,
      pinnedAddress: addr,
      allValidatedAddresses: [addr],
    };
  }

  const lookupFn = options.dnsLookup ?? defaultDnsLookup;
  let records: DnsResolvedAddress[];
  try {
    records = await lookupFn(normalizedHost);
  } catch (err) {
    throw new SsrfBlockedError(
      'SSRF_DNS_RESOLUTION_FAILED',
      `Failed to resolve MCP hostname "${normalizedHost}": ${err instanceof Error ? err.message : 'DNS error'}`,
      502,
    );
  }

  if (!Array.isArray(records) || records.length === 0) {
    throw new SsrfBlockedError(
      'SSRF_DNS_RESOLUTION_FAILED',
      `MCP hostname "${normalizedHost}" resolved to zero IP addresses`,
      502,
    );
  }

  const allowLoopbackHere = allowLoopback && normalizedHost === 'localhost';
  for (const record of records) {
    const reason = getBlockedIpReason(record.address, { allowLoopback: allowLoopbackHere });
    if (reason) {
      throw new SsrfBlockedError(
        'SSRF_BLOCKED_DESTINATION',
        `Hostname "${normalizedHost}" resolved to prohibited address (${reason})`,
        403,
      );
    }
  }

  return {
    url,
    canonicalEndpoint: url.toString(),
    normalizedHost,
    port,
    pinnedAddress: records[0],
    allValidatedAddresses: records,
  };
}

/**
 * Creates a Web-Fetch-compatible function for StreamableHTTPClientTransport and backend clients that:
 * 1. Validates URL syntax and hostnames on every call.
 * 2. Resolves DNS once per connection attempt and rejects if ANY returned IP is prohibited.
 * 3. Pins Node's http.request / https.request socket `lookup` directly to the validated IP
 *    (handling both single-result and `opts.all` Happy Eyeballs calls) with `agent: false`
 *    so OS DNS cannot be re-queried / rebound between validation and TCP/TLS dial and sockets are
 *    never pooled across destinations.
 * 4. Verifies `socket.remoteAddress` at TCP `'connect'` time as defense-in-depth.
 * 5. Blocks HTTP 3xx redirects completely so redirects cannot bypass SSRF validation.
 */
export function createSsrfSafeFetch(
  options: SsrfPolicyOptions,
): (input: string | URL, init?: RequestInit) => Promise<Response> {
  return async (input: string | URL, init?: RequestInit): Promise<Response> => {
    const rawUrl = typeof input === 'string' ? input : input.toString();
    const validated = await resolveAndValidateMcpDestination(rawUrl, options);

    const targetUrl = validated.url;
    const isHttps = targetUrl.protocol === 'https:';
    const allowLoopback = Boolean(options.allowLoopbackHttp);
    const allowLoopbackHere =
      allowLoopback && (isLoopbackHostname(validated.normalizedHost) || validated.normalizedHost === 'localhost');

    const headers = new Headers(init?.headers);
    if (!headers.has('host')) {
      headers.set('host', targetUrl.host);
    }
    const headerRecord: Record<string, string> = {};
    headers.forEach((value, key) => {
      headerRecord[key] = value;
    });

    // Convert optional RequestInit body into Buffer
    let bodyBuf: Buffer | undefined;
    if (init?.body !== undefined && init?.body !== null) {
      if (typeof init.body === 'string') {
        bodyBuf = Buffer.from(init.body, 'utf8');
      } else if (Buffer.isBuffer(init.body)) {
        bodyBuf = init.body;
      } else if (init.body instanceof Uint8Array) {
        bodyBuf = Buffer.from(init.body);
      } else {
        throw new Error('Unsupported outbound request body type');
      }
    }

    const pinnedIp = validated.pinnedAddress.address;
    const pinnedFamily = validated.pinnedAddress.family;

    return new Promise<Response>((resolve, reject) => {
      let settled = false;
      const fail = (err: Error) => {
        if (!settled) {
          settled = true;
          reject(err);
        }
      };

      const pinnedLookup = (
        _hostname: string,
        opts: unknown,
        cb?: (err: NodeJS.ErrnoException | null, address: unknown, family?: number) => void,
      ) => {
        if (typeof opts === 'function') {
          (opts as (err: null, address: string, family: number) => void)(
            null,
            pinnedIp,
            pinnedFamily,
          );
          return;
        }
        if (
          opts &&
          typeof opts === 'object' &&
          'all' in opts &&
          (opts as { all?: boolean }).all &&
          cb
        ) {
          cb(null, [{ address: pinnedIp, family: pinnedFamily }]);
          return;
        }
        if (cb) {
          cb(null, pinnedIp, pinnedFamily);
        }
      };

      const reqOpts: https.RequestOptions = {
        protocol: targetUrl.protocol,
        hostname: validated.normalizedHost,
        port: validated.port,
        path: `${targetUrl.pathname}${targetUrl.search}`,
        method: init?.method ?? 'GET',
        headers: headerRecord,
        agent: false, // Disable connection pooling reuse across destinations
        lookup: pinnedLookup as http.RequestOptions['lookup'],
        signal: init?.signal ?? undefined,
        ...(isHttps ? { servername: validated.normalizedHost } : {}),
      };

      const clientModule = isHttps ? https : http;
      const req = clientModule.request(reqOpts, (nodeRes) => {
        const status = nodeRes.statusCode ?? 500;
        if (status >= 300 && status < 400) {
          nodeRes.resume();
          req.destroy();
          fail(
            new SsrfBlockedError(
              'SSRF_REDIRECT_BLOCKED',
              `Outbound HTTP redirect (HTTP ${status}) blocked by Gateway SSRF protection`,
              403,
            ),
          );
          return;
        }

        const respHeaders = new Headers();
        for (const [k, v] of Object.entries(nodeRes.headers)) {
          if (Array.isArray(v)) {
            for (const item of v) respHeaders.append(k, item);
          } else if (v !== undefined) {
            respHeaders.set(k, v);
          }
        }

        const hasNoBodyStatus = status === 204 || status === 205 || status === 304;
        const body = hasNoBodyStatus ? null : (Readable.toWeb(nodeRes) as unknown as BodyInit);
        settled = true;
        resolve(
          new Response(body, {
            status,
            statusText: nodeRes.statusMessage ?? '',
            headers: respHeaders,
          }),
        );
      });

      req.on('socket', (socket) => {
        socket.once('connect', () => {
          const remoteIp = socket.remoteAddress;
          if (!remoteIp) {
            socket.destroy(new SsrfBlockedError('SSRF_SOCKET_UNVERIFIED', 'Missing remote socket address', 403));
            return;
          }
          const blockedReason = getBlockedIpReason(remoteIp, { allowLoopback: allowLoopbackHere });
          if (blockedReason) {
            socket.destroy(
              new SsrfBlockedError(
                'SSRF_BLOCKED_DESTINATION',
                `Connected socket IP "${remoteIp}" violated SSRF policy (${blockedReason})`,
                403,
              ),
            );
          }
        });
      });

      req.on('error', (err) => {
        fail(err instanceof Error ? err : new Error(String(err)));
      });

      if (bodyBuf && bodyBuf.length > 0) {
        req.write(bodyBuf);
      }
      req.end();
    });
  };
}
