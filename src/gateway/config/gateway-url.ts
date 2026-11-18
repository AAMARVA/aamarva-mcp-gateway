import type { Request } from 'express';
import type { GatewayConfig } from './validation.ts';

export interface GatewayReachableUrlResolution {
  baseUrl: string | null;
  source: 'config' | 'request' | 'unconfigured';
  warning?: string;
}

export interface SubjectMcpTarget {
  transport: 'stdio' | 'streamable-http';
  endpoint: string;
  configuredFromSubjectUrl: boolean;
}

function normalizeRemoteIp(ip: string | undefined): string {
  if (!ip) return '';
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

function isTrustedProxyPeer(req: Request, trustedProxies: string[]): boolean {
  if (trustedProxies.length === 0) return false;
  const remoteIp = normalizeRemoteIp(req.socket?.remoteAddress);
  return trustedProxies.some((p) => normalizeRemoteIp(p) === remoteIp);
}

/**
 * Resolves the Gateway's own externally reachable base URL strictly from
 * explicit deployment configuration (GATEWAY_PUBLIC_URL) or reliable request context.
 * Never invents localhost/example domains and never substitutes the Subject MCP Server URL.
 */
export function resolveGatewayReachableBaseUrl(
  config: GatewayConfig,
  req?: Request,
): GatewayReachableUrlResolution {
  if (config.gatewayPublicUrl && config.gatewayPublicUrl.trim() !== '') {
    try {
      const parsed = new URL(config.gatewayPublicUrl.trim());
      return {
        baseUrl: parsed.toString().replace(/\/+$/, ''),
        source: 'config',
      };
    } catch {
      return {
        baseUrl: null,
        source: 'unconfigured',
        warning: 'Configured GATEWAY_PUBLIC_URL is invalid',
      };
    }
  }

  if (req) {
    const trustedProxy = isTrustedProxyPeer(req, config.security.trustedProxies);
    const forwardedHost = trustedProxy ? req.header('x-forwarded-host')?.split(',')[0]?.trim() : undefined;
    const rawHost = forwardedHost || req.header('host')?.trim();
    const forwardedProto = trustedProxy ? req.header('x-forwarded-proto')?.split(',')[0]?.trim().toLowerCase() : undefined;
    const isSocketEncrypted = Boolean(
      (req.socket as { encrypted?: boolean } | undefined)?.encrypted,
    );
    const scheme =
      forwardedProto === 'https' || forwardedProto === 'http'
        ? forwardedProto
        : isSocketEncrypted
          ? 'https'
          : 'http';

    if (rawHost && !/[\s/@\\]/.test(rawHost)) {
      try {
        const candidate = new URL(`${scheme}://${rawHost}`);
        return {
          baseUrl: candidate.origin,
          source: 'request',
        };
      } catch {
        // Fall through cleanly to unconfigured
      }
    }
  }

  return {
    baseUrl: null,
    source: 'unconfigured',
    warning:
      'Gateway externally reachable base URL is not configured (set GATEWAY_PUBLIC_URL) and cannot be derived from request context.',
  };
}

/**
 * Resolves the customer's configured Subject MCP Server target exclusively from config.mcp.
 * Never derives the Subject MCP Server URL from the Gateway's own public URL.
 */
export function resolveConfiguredSubjectMcpTarget(config: GatewayConfig): SubjectMcpTarget | null {
  if (config.mcp.transport === 'streamable-http') {
    if (!config.mcp.httpUrl || config.mcp.httpUrl.trim() === '') {
      return null;
    }
    return {
      transport: 'streamable-http',
      endpoint: config.mcp.httpUrl.trim(),
      configuredFromSubjectUrl: true,
    };
  }

  return {
    transport: 'stdio',
    endpoint: `stdio://${config.mcpServerId}`,
    configuredFromSubjectUrl: false,
  };
}
