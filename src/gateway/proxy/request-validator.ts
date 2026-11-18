export interface RelayBindingValidationInput {
  requestId: string;
  sessionId: string;
  agentId: string;
  accountId: string;
  mcpServerId: string;
  gatewayId: string;
  integrationId?: string;
  connectionId?: string;
  expectedEndpoint?: string;
  toolName?: string;
}

export function validateRelayBindings(
  input: RelayBindingValidationInput,
  expectedGatewayId: string,
  expectedMcpServerId: string,
  options?: { allowDynamicServer?: boolean },
): { valid: boolean; code?: string; message?: string } {
  if (input.gatewayId !== expectedGatewayId) {
    return {
      valid: false,
      code: 'GATEWAY_MISMATCH',
      message: 'Request gatewayId does not match this Gateway installation',
    };
  }
  if (!input.mcpServerId || input.mcpServerId.trim() === '') {
    return {
      valid: false,
      code: 'SERVER_MISMATCH',
      message: 'Request mcpServerId must be non-empty',
    };
  }
  const hasConnectionBinding = Boolean(input.connectionId || input.integrationId || options?.allowDynamicServer);
  if (!hasConnectionBinding && input.mcpServerId !== expectedMcpServerId) {
    return {
      valid: false,
      code: 'SERVER_MISMATCH',
      message: 'Request mcpServerId does not match configured upstream MCP server',
    };
  }
  if (input.toolName !== undefined && input.toolName.trim() === '') {
    return {
      valid: false,
      code: 'INVALID_TOOL_NAME',
      message: 'Tool name must be non-empty',
    };
  }
  return { valid: true };
}
