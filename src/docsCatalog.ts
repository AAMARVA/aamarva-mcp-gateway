import readmeMd from '../README.md?raw';
import aamarvaIntegrationMd from '../docs/AAMARVA_INTEGRATION.md?raw';
import apiReferenceMd from '../docs/API_REFERENCE.md?raw';
import architectureMd from '../docs/ARCHITECTURE.md?raw';
import authorizationFlowMd from '../docs/AUTHORIZATION_FLOW.md?raw';
import configurationMd from '../docs/CONFIGURATION.md?raw';
import deploymentMd from '../docs/DEPLOYMENT.md?raw';
import mcpIntegrationMd from '../docs/MCP_INTEGRATION.md?raw';
import securityMd from '../docs/SECURITY.md?raw';
import troubleshootingMd from '../docs/TROUBLESHOOTING.md?raw';

export interface DocSection {
  id: string;
  title: string;
  path: string;
  content: string;
}

export const DOC_SECTIONS: DocSection[] = [
  {
    id: 'overview',
    title: 'Overview',
    path: 'README.md',
    content: readmeMd,
  },
  {
    id: 'architecture',
    title: 'Architecture',
    path: 'docs/ARCHITECTURE.md',
    content: architectureMd,
  },
  {
    id: 'authorization-flow',
    title: 'Authorization Flow',
    path: 'docs/AUTHORIZATION_FLOW.md',
    content: authorizationFlowMd,
  },
  {
    id: 'security',
    title: 'Security & Cryptography',
    path: 'docs/SECURITY.md',
    content: securityMd,
  },
  {
    id: 'api-reference',
    title: 'API Reference',
    path: 'docs/API_REFERENCE.md',
    content: apiReferenceMd,
  },
  {
    id: 'mcp-integration',
    title: 'MCP Integration',
    path: 'docs/MCP_INTEGRATION.md',
    content: mcpIntegrationMd,
  },
  {
    id: 'aamarva-integration',
    title: 'AAMARVA Integration',
    path: 'docs/AAMARVA_INTEGRATION.md',
    content: aamarvaIntegrationMd,
  },
  {
    id: 'configuration',
    title: 'Configuration',
    path: 'docs/CONFIGURATION.md',
    content: configurationMd,
  },
  {
    id: 'deployment',
    title: 'Deployment',
    path: 'docs/DEPLOYMENT.md',
    content: deploymentMd,
  },
  {
    id: 'troubleshooting',
    title: 'Troubleshooting',
    path: 'docs/TROUBLESHOOTING.md',
    content: troubleshootingMd,
  },
];
