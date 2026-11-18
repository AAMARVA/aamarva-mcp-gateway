import type { AamarvaBackendClient } from '../aamarva/aamarva-client.ts';
import type { GatewaySession } from '../core/authorization-context.ts';
import { createExecutionContext } from '../core/execution-context.ts';
import type { McpConnectionManager } from '../mcp/connection-manager.ts';
import type { McpUpstreamAdapter } from '../mcp/mcp-transport.ts';
import type { ResponseForwarder } from '../mcp/response-forwarder.ts';
import type { ToolDiscoveryService } from '../mcp/tool-discovery.ts';
import type { ToolExecutionService } from '../mcp/tool-execution.ts';
import type { AuditRecorder } from '../observability/audit.ts';
import type { GatewayMetrics } from '../observability/metrics.ts';
import { validateRelayBindings } from './request-validator.ts';
import type { ProxyHttpResult, ProxyResponseHandler } from './response-handler.ts';
import type { SessionValidator } from './session-validator.ts';

export class ExecutionProxy {
  private readonly gatewayId: string;
  private readonly mcpServerId: string;
  private readonly sessionValidator: SessionValidator;
  private readonly toolDiscovery: ToolDiscoveryService;
  private readonly toolExecution: ToolExecutionService;
  private readonly forwarder: ResponseForwarder;
  private readonly responseHandler: ProxyResponseHandler;
  private readonly audit: AuditRecorder;
  private readonly metrics: GatewayMetrics;
  private readonly aamarvaClient?: AamarvaBackendClient;
  private readonly connectionManager?: McpConnectionManager;
  private readonly defaultAdapter?: McpUpstreamAdapter;

  constructor(options: {
    gatewayId: string;
    mcpServerId: string;
    sessionValidator: SessionValidator;
    toolDiscovery: ToolDiscoveryService;
    toolExecution: ToolExecutionService;
    forwarder: ResponseForwarder;
    responseHandler: ProxyResponseHandler;
    audit: AuditRecorder;
    metrics: GatewayMetrics;
    aamarvaClient?: AamarvaBackendClient;
    connectionManager?: McpConnectionManager;
    defaultAdapter?: McpUpstreamAdapter;
  }) {
    this.gatewayId = options.gatewayId;
    this.mcpServerId = options.mcpServerId;
    this.sessionValidator = options.sessionValidator;
    this.toolDiscovery = options.toolDiscovery;
    this.toolExecution = options.toolExecution;
    this.forwarder = options.forwarder;
    this.responseHandler = options.responseHandler;
    this.audit = options.audit;
    this.metrics = options.metrics;
    this.aamarvaClient = options.aamarvaClient;
    this.connectionManager = options.connectionManager;
    this.defaultAdapter = options.defaultAdapter;
  }

  async initializeSession(params: {
    session: GatewaySession;
    correlationId: string;
    timeoutMs?: number;
  }): Promise<ProxyHttpResult> {
    const sessionCheck = await this.sessionValidator.validate({
      sessionId: params.session.sessionId,
      agentId: params.session.agentId,
      accountId: params.session.accountId,
      mcpServerId: params.session.mcpServerId,
      gatewayId: params.session.gatewayId,
    });
    if (!sessionCheck.valid || !sessionCheck.session) {
      this.metrics.incMcpExecutionsDenied();
      const statusCode =
        sessionCheck.code === 'SESSION_EXPIRED' ||
        sessionCheck.code === 'AUTHORIZATION_EXPIRED' ||
        sessionCheck.code === 'SESSION_REVOKED'
          ? 401
          : 403;
      return this.responseHandler.denied(
        sessionCheck.code ?? 'SESSION_INVALID',
        sessionCheck.reason ?? 'Invalid session',
        params.correlationId,
        statusCode,
      );
    }

    try {
      const adapterRes = await this.resolveSessionAdapter({
        session: sessionCheck.session,
        requestId: params.correlationId,
        accountId: sessionCheck.session.accountId,
        agentId: sessionCheck.session.agentId,
        mcpServerId: sessionCheck.session.mcpServerId,
        integrationId: sessionCheck.session.scope.integrationId,
        connectionId: sessionCheck.session.scope.connectionId,
        expectedEndpoint: sessionCheck.session.scope.canonicalEndpoint,
        correlationId: params.correlationId,
      });
      if (!adapterRes.ok) {
        return adapterRes.result;
      }

      const adapter = adapterRes.adapterOverride ?? this.defaultAdapter;
      if (!adapter) {
        return this.responseHandler.denied(
          'MCP_UPSTREAM_UNAVAILABLE',
          'No upstream MCP transport adapter is configured',
          params.correlationId,
          502,
        );
      }

      await adapter.connect();
      if (adapter.ping) {
        await adapter.ping({ timeoutMs: params.timeoutMs });
      }
      const status = adapter.getStatus();
      if (!adapter.isConnected() || !status.connected || !status.negotiatedProtocolVersion) {
        throw new Error('Upstream MCP server did not complete initialization');
      }

      return this.responseHandler.success({
        protocolVersion: status.negotiatedProtocolVersion,
        capabilities: status.serverCapabilities ?? {},
        ...(status.serverInfo ? { serverInfo: status.serverInfo } : {}),
        correlationId: params.correlationId,
      });
    } catch (err) {
      this.audit.record({
        event: 'MCP_TRANSPORT_ERROR',
        outcome: 'failure',
        message: `Upstream MCP initialize failed: ${err instanceof Error ? err.message : 'error'}`,
        correlationId: params.correlationId,
        sessionId: params.session.sessionId,
        agentId: params.session.agentId,
        accountId: params.session.accountId,
        mcpServerId: params.session.mcpServerId,
      });
      return this.responseHandler.upstreamError(err, params.correlationId);
    }
  }

  async pingSession(params: {
    session: GatewaySession;
    correlationId: string;
    timeoutMs?: number;
  }): Promise<ProxyHttpResult> {
    const sessionCheck = await this.sessionValidator.validate({
      sessionId: params.session.sessionId,
      agentId: params.session.agentId,
      accountId: params.session.accountId,
      mcpServerId: params.session.mcpServerId,
      gatewayId: params.session.gatewayId,
    });
    if (!sessionCheck.valid || !sessionCheck.session) {
      const statusCode =
        sessionCheck.code === 'SESSION_EXPIRED' ||
        sessionCheck.code === 'AUTHORIZATION_EXPIRED' ||
        sessionCheck.code === 'SESSION_REVOKED'
          ? 401
          : 403;
      return this.responseHandler.denied(
        sessionCheck.code ?? 'SESSION_INVALID',
        sessionCheck.reason ?? 'Invalid session',
        params.correlationId,
        statusCode,
      );
    }

    try {
      const adapterRes = await this.resolveSessionAdapter({
        session: sessionCheck.session,
        requestId: params.correlationId,
        accountId: sessionCheck.session.accountId,
        agentId: sessionCheck.session.agentId,
        mcpServerId: sessionCheck.session.mcpServerId,
        integrationId: sessionCheck.session.scope.integrationId,
        connectionId: sessionCheck.session.scope.connectionId,
        expectedEndpoint: sessionCheck.session.scope.canonicalEndpoint,
        correlationId: params.correlationId,
      });
      if (!adapterRes.ok) {
        return adapterRes.result;
      }

      const adapter = adapterRes.adapterOverride ?? this.defaultAdapter;
      if (!adapter) {
        return this.responseHandler.denied(
          'MCP_UPSTREAM_UNAVAILABLE',
          'No upstream MCP transport adapter is configured',
          params.correlationId,
          502,
        );
      }

      await adapter.connect();
      if (adapter.ping) {
        await adapter.ping({ timeoutMs: params.timeoutMs });
      }
      return this.responseHandler.success({ correlationId: params.correlationId });
    } catch (err) {
      return this.responseHandler.upstreamError(err, params.correlationId);
    }
  }

  private async resolveSessionAdapter(params: {
    session: GatewaySession;
    requestId: string;
    accountId: string;
    agentId: string;
    mcpServerId: string;
    integrationId?: string;
    connectionId?: string;
    expectedEndpoint?: string;
    correlationId: string;
    toolName?: string;
  }): Promise<{ ok: true; adapterOverride?: McpUpstreamAdapter } | { ok: false; result: ProxyHttpResult }> {
    const { session } = params;

    if (params.connectionId && session.scope.connectionId !== params.connectionId) {
      this.metrics.incMcpExecutionsDenied();
      this.audit.record({
        event: 'CONNECTION_SUBSTITUTION_BLOCKED',
        outcome: 'denied',
        message: 'Session substitution attempt rejected: session is not bound to requested connectionId',
        correlationId: params.correlationId,
        requestId: params.requestId,
        sessionId: session.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
        toolName: params.toolName,
      });
      return {
        ok: false,
        result: this.responseHandler.denied(
          'SESSION_SUBSTITUTION_BLOCKED',
          'Session is not bound to the requested connectionId',
          params.correlationId,
          403,
        ),
      };
    }

    if (params.integrationId && session.scope.integrationId !== params.integrationId) {
      this.metrics.incMcpExecutionsDenied();
      this.audit.record({
        event: 'CONNECTION_SUBSTITUTION_BLOCKED',
        outcome: 'denied',
        message: 'Integration substitution attempt rejected: session is not bound to requested integrationId',
        correlationId: params.correlationId,
        requestId: params.requestId,
        sessionId: session.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
        toolName: params.toolName,
      });
      return {
        ok: false,
        result: this.responseHandler.denied(
          'INTEGRATION_MISMATCH',
          'Session is not bound to the requested integrationId',
          params.correlationId,
          403,
        ),
      };
    }

    if (params.expectedEndpoint && !session.scope.connectionId && !session.scope.integrationId) {
      this.metrics.incMcpExecutionsDenied();
      this.audit.record({
        event: 'CONNECTION_SUBSTITUTION_BLOCKED',
        outcome: 'denied',
        message: 'Endpoint substitution rejected on session without verified MCP connection',
        correlationId: params.correlationId,
        requestId: params.requestId,
        sessionId: session.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
        toolName: params.toolName,
      });
      return {
        ok: false,
        result: this.responseHandler.denied(
          'CONNECTION_NOT_VERIFIED',
          'Session is not bound to a verified MCP connection endpoint',
          params.correlationId,
          403,
        ),
      };
    }

    const effectiveConnectionId = params.connectionId ?? session.scope.connectionId;
    const effectiveIntegrationId = params.integrationId ?? session.scope.integrationId;

    if (!effectiveConnectionId && !effectiveIntegrationId && !params.expectedEndpoint) {
      return { ok: true, adapterOverride: undefined };
    }

    if (!this.connectionManager) {
      this.metrics.incMcpExecutionsDenied();
      return {
        ok: false,
        result: this.responseHandler.denied(
          'CONNECTION_MANAGER_UNAVAILABLE',
          'Verified connection manager is unavailable',
          params.correlationId,
          403,
        ),
      };
    }

    const resolved = await this.connectionManager.resolveConnectionForAccount({
      connectionId: effectiveConnectionId,
      integrationId: effectiveIntegrationId,
      accountId: params.accountId,
      mcpServerId: params.mcpServerId,
      expectedEndpoint: params.expectedEndpoint ?? session.scope.canonicalEndpoint,
    });

    if (!resolved.ok) {
      this.metrics.incMcpExecutionsDenied();
      this.audit.record({
        event: 'CONNECTION_SUBSTITUTION_BLOCKED',
        outcome: 'denied',
        message: resolved.message,
        correlationId: params.correlationId,
        requestId: params.requestId,
        sessionId: session.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
        toolName: params.toolName,
        details: { code: resolved.code },
      });
      return {
        ok: false,
        result: this.responseHandler.denied(
          resolved.code,
          resolved.message,
          params.correlationId,
          resolved.statusCode,
        ),
      };
    }

    return { ok: true, adapterOverride: resolved.adapter };
  }

  async listAuthorizedTools(params: {
    requestId: string;
    sessionId: string;
    agentId: string;
    accountId: string;
    mcpServerId: string;
    gatewayId: string;
    integrationId?: string;
    connectionId?: string;
    expectedEndpoint?: string;
    signal?: AbortSignal;
  }): Promise<ProxyHttpResult> {
    const ctx = createExecutionContext({
      gatewayId: this.gatewayId,
      mcpServerId: params.mcpServerId,
      requestId: params.requestId,
      sessionId: params.sessionId,
      agentId: params.agentId,
      accountId: params.accountId,
    });

    const bindingCheck = validateRelayBindings(params, this.gatewayId, this.mcpServerId, {
      allowDynamicServer: Boolean(this.connectionManager),
    });
    if (!bindingCheck.valid) {
      this.metrics.incMcpExecutionsDenied();
      this.audit.record({
        event: 'MCP_TOOL_DENIED',
        outcome: 'denied',
        message: bindingCheck.message ?? 'Relay binding check failed',
        correlationId: ctx.correlationId,
        requestId: params.requestId,
        sessionId: params.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
      });
      return this.responseHandler.denied(
        bindingCheck.code ?? 'BINDING_MISMATCH',
        bindingCheck.message ?? 'Binding mismatch',
        ctx.correlationId,
        403,
      );
    }

    const sessionCheck = await this.sessionValidator.validate({
      sessionId: params.sessionId,
      agentId: params.agentId,
      accountId: params.accountId,
      mcpServerId: params.mcpServerId,
      gatewayId: params.gatewayId,
    });

    if (!sessionCheck.valid || !sessionCheck.session) {
      this.metrics.incMcpExecutionsDenied();
      const statusCode =
        sessionCheck.code === 'SESSION_EXPIRED' || sessionCheck.code === 'SESSION_REVOKED'
          ? 401
          : 403;
      this.audit.record({
        event: 'MCP_TOOL_DENIED',
        outcome: 'denied',
        message: sessionCheck.reason ?? 'Session validation failed for tools/list',
        correlationId: ctx.correlationId,
        requestId: params.requestId,
        sessionId: params.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        details: { code: sessionCheck.code },
      });
      return this.responseHandler.denied(
        sessionCheck.code ?? 'SESSION_INVALID',
        sessionCheck.reason ?? 'Invalid session',
        ctx.correlationId,
        statusCode,
      );
    }

    let adapterOverride: McpUpstreamAdapter | undefined;
    try {
      const adapterRes = await this.resolveSessionAdapter({
        session: sessionCheck.session,
        requestId: params.requestId,
        accountId: params.accountId,
        agentId: params.agentId,
        mcpServerId: params.mcpServerId,
        integrationId: params.integrationId,
        connectionId: params.connectionId,
        expectedEndpoint: params.expectedEndpoint,
        correlationId: ctx.correlationId,
      });
      if (!adapterRes.ok) {
        return adapterRes.result;
      }
      adapterOverride = adapterRes.adapterOverride;

      const tools = await this.toolDiscovery.listAuthorizedTools(sessionCheck.session, {
        signal: params.signal,
        adapterOverride,
      });
      this.metrics.incMcpToolsListed();
      this.audit.record({
        event: 'MCP_TOOLS_LISTED',
        outcome: 'success',
        message: `Listed ${tools.length} scope-authorized tool(s) from upstream MCP server`,
        correlationId: ctx.correlationId,
        requestId: params.requestId,
        sessionId: params.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
      });

      return this.responseHandler.success({
        ...this.forwarder.formatToolsList({
          requestId: params.requestId,
          sessionId: params.sessionId,
          mcpServerId: params.mcpServerId,
          tools,
        }),
        correlationId: ctx.correlationId,
      });
    } catch (err) {
      this.audit.record({
        event: 'MCP_TRANSPORT_ERROR',
        outcome: 'failure',
        message: `Upstream MCP tools/list failed: ${err instanceof Error ? err.message : 'error'}`,
        correlationId: ctx.correlationId,
        requestId: params.requestId,
        sessionId: params.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
      });
      return this.responseHandler.upstreamError(err, ctx.correlationId);
    }
  }

  async executeAuthorizedTool(params: {
    requestId: string;
    sessionId: string;
    agentId: string;
    accountId: string;
    mcpServerId: string;
    gatewayId: string;
    integrationId?: string;
    connectionId?: string;
    expectedEndpoint?: string;
    toolName: string;
    arguments: Record<string, unknown>;
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<ProxyHttpResult> {
    const ctx = createExecutionContext({
      gatewayId: this.gatewayId,
      mcpServerId: params.mcpServerId,
      requestId: params.requestId,
      sessionId: params.sessionId,
      agentId: params.agentId,
      accountId: params.accountId,
      toolName: params.toolName,
    });

    const bindingCheck = validateRelayBindings(params, this.gatewayId, this.mcpServerId, {
      allowDynamicServer: Boolean(this.connectionManager),
    });
    if (!bindingCheck.valid) {
      this.metrics.incMcpExecutionsDenied();
      this.audit.record({
        event: 'MCP_TOOL_DENIED',
        outcome: 'denied',
        message: bindingCheck.message ?? 'Relay binding check failed',
        correlationId: ctx.correlationId,
        requestId: params.requestId,
        sessionId: params.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        toolName: params.toolName,
      });
      return this.responseHandler.denied(
        bindingCheck.code ?? 'BINDING_MISMATCH',
        bindingCheck.message ?? 'Binding mismatch',
        ctx.correlationId,
        403,
      );
    }

    const sessionCheck = await this.sessionValidator.validate({
      sessionId: params.sessionId,
      agentId: params.agentId,
      accountId: params.accountId,
      mcpServerId: params.mcpServerId,
      gatewayId: params.gatewayId,
      toolName: params.toolName,
    });

    if (!sessionCheck.valid || !sessionCheck.session) {
      this.metrics.incMcpExecutionsDenied();
      const statusCode =
        sessionCheck.code === 'SESSION_EXPIRED' || sessionCheck.code === 'SESSION_REVOKED'
          ? 401
          : 403;
      this.audit.record({
        event: 'MCP_TOOL_DENIED',
        outcome: 'denied',
        message: sessionCheck.reason ?? 'Authorization denied before reaching MCP server',
        correlationId: ctx.correlationId,
        requestId: params.requestId,
        sessionId: params.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
        toolName: params.toolName,
        details: { code: sessionCheck.code },
      });

      await this.aamarvaClient?.reportExecutionEvent({
        eventType: 'MCP_TOOL_DENIED',
        gatewayId: this.gatewayId,
        mcpServerId: params.mcpServerId,
        sessionId: params.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        requestId: params.requestId,
        toolName: params.toolName,
        outcome: 'denied',
        timestamp: new Date().toISOString(),
      });

      return this.responseHandler.denied(
        sessionCheck.code ?? 'UNAUTHORIZED_TOOL',
        sessionCheck.reason ?? 'Unauthorized execution',
        ctx.correlationId,
        statusCode,
      );
    }

    try {
      const adapterRes = await this.resolveSessionAdapter({
        session: sessionCheck.session,
        requestId: params.requestId,
        accountId: params.accountId,
        agentId: params.agentId,
        mcpServerId: params.mcpServerId,
        integrationId: params.integrationId,
        connectionId: params.connectionId,
        expectedEndpoint: params.expectedEndpoint,
        correlationId: ctx.correlationId,
        toolName: params.toolName,
      });
      if (!adapterRes.ok) {
        return adapterRes.result;
      }

      const result = await this.toolExecution.executeTool({
        session: sessionCheck.session,
        toolName: params.toolName,
        arguments: params.arguments,
        timeoutMs: params.timeoutMs,
        signal: params.signal,
        adapterOverride: adapterRes.adapterOverride,
      });

      this.metrics.incMcpExecutionsAllowed();
      this.audit.record({
        event: 'MCP_TOOL_EXECUTED',
        outcome: result.isError ? 'failure' : 'success',
        message: result.isError
          ? `Upstream MCP tool "${params.toolName}" returned tool-level error`
          : `Forwarded authorized MCP tool "${params.toolName}" execution`,
        correlationId: ctx.correlationId,
        requestId: params.requestId,
        sessionId: params.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
        toolName: params.toolName,
        details: { isError: Boolean(result.isError) },
      });

      await this.aamarvaClient?.reportExecutionEvent({
        eventType: 'MCP_TOOL_EXECUTED',
        gatewayId: this.gatewayId,
        mcpServerId: params.mcpServerId,
        sessionId: params.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        requestId: params.requestId,
        toolName: params.toolName,
        outcome: result.isError ? 'failure' : 'success',
        timestamp: new Date().toISOString(),
      });

      return this.responseHandler.success({
        ...this.forwarder.formatToolCallResult({
          requestId: params.requestId,
          sessionId: params.sessionId,
          mcpServerId: params.mcpServerId,
          toolName: params.toolName,
          result,
        }),
        correlationId: ctx.correlationId,
      });
    } catch (err) {
      this.metrics.incMcpExecutionsFailed();
      this.audit.record({
        event: 'MCP_TOOL_FAILED',
        outcome: 'failure',
        message: `MCP tool execution failed: ${err instanceof Error ? err.message : 'unknown error'}`,
        correlationId: ctx.correlationId,
        requestId: params.requestId,
        sessionId: params.sessionId,
        agentId: params.agentId,
        accountId: params.accountId,
        mcpServerId: params.mcpServerId,
        toolName: params.toolName,
      });
      return this.responseHandler.upstreamError(err, ctx.correlationId);
    }
  }
}
