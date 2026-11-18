import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { Transport } from '@modelcontextprotocol/sdk/shared/transport.js';
import type { AuditRecorder } from '../observability/audit.ts';
import {
  createSsrfSafeFetch,
  type DnsLookupFn,
} from '../security/ssrf-guard.ts';
import { BaseMcpUpstreamAdapter } from './mcp-transport.ts';

export class StreamableHttpMcpTransportAdapter extends BaseMcpUpstreamAdapter {
  private readonly endpointUrl: string;
  private readonly upstreamAuthHeader?: string;
  private readonly customHeaders?: Record<string, string>;
  private readonly fetchImpl: (input: string | URL, init?: RequestInit) => Promise<Response>;

  constructor(options: {
    endpointUrl: string;
    upstreamAuthHeader?: string;
    customHeaders?: Record<string, string>;
    defaultTimeoutMs: number;
    audit: AuditRecorder;
    allowInsecureHttp?: boolean;
    allowLoopbackHttp?: boolean;
    dnsLookup?: DnsLookupFn;
    fetchOverride?: (input: string | URL, init?: RequestInit) => Promise<Response>;
  }) {
    super({
      transportType: 'streamable-http',
      defaultTimeoutMs: options.defaultTimeoutMs,
      audit: options.audit,
    });
    this.endpointUrl = options.endpointUrl;
    this.upstreamAuthHeader = options.upstreamAuthHeader;
    this.customHeaders = options.customHeaders;
    this.fetchImpl =
      options.fetchOverride ??
      createSsrfSafeFetch({
        allowInsecureHttp: options.allowInsecureHttp ?? false,
        allowLoopbackHttp: options.allowLoopbackHttp ?? false,
        dnsLookup: options.dnsLookup,
      });
  }

  protected createTransport(): Transport {
    const headers: Record<string, string> = {};
    if (this.customHeaders) {
      for (const [k, v] of Object.entries(this.customHeaders)) {
        headers[k] = v;
      }
    }
    if (this.upstreamAuthHeader) {
      headers.authorization = this.upstreamAuthHeader;
    }
    return new StreamableHTTPClientTransport(new URL(this.endpointUrl), {
      fetch: this.fetchImpl,
      requestInit: {
        headers,
      },
    });
  }
}
