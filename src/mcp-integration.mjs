import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { ROOT, boundedPath } from './store.mjs';
import { BrickkenWorkspace, BrickkenWorkspaceError } from './brickken-workspace.mjs';
import { runMcpStdio } from './mcp-stdio.mjs';

const operationId = { type: 'string', minLength: 8, maxLength: 80, pattern: '^[A-Za-z0-9_-]+$' };
const schema = (properties, required = Object.keys(properties)) => ({
  type: 'object', properties, required, additionalProperties: false
});

export const integrationTools = Object.freeze([
  {
    name: 'get_context',
    description: 'Read the separate Sepolia preparation workspace. Its source is an offline fixture, with no live API or chain state claim.',
    inputSchema: schema({}),
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  {
    name: 'plan_execute',
    description: 'Create the fixed Sepolia workflow preview. The owner must approve its exact hash in the web workspace.',
    inputSchema: schema({ operationId }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: 'preflight',
    description: 'Revalidate the owner approval, current workspace revision and all five unsigned envelopes. It does not sign or broadcast.',
    inputSchema: schema({ operationId }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false }
  },
  {
    name: 'execute_approved',
    description: 'Stop at the signing boundary unless an authorized adapter exists. The default returns SIGNING_ROUTE_UNAVAILABLE and never broadcasts.',
    inputSchema: schema({ operationId }),
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  },
  {
    name: 'get_receipt',
    description: 'Read the local operation receipt. Unsigned or blocked operations have no transaction hash.',
    inputSchema: schema({ operationId }),
    annotations: { readOnlyHint: true, openWorldHint: false }
  }
]);

function strict(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) {
    throw new BrickkenWorkspaceError('INVALID_INPUT', 'The tool arguments do not match the allowed structure.');
  }
}
function operationSummary(operation) {
  return {
    operationId: operation.operationId,
    status: operation.status,
    previewHash: operation.previewHash,
    approved: operation.approval !== null,
    envelopeCount: operation.envelopes?.length ?? 0,
    receipt: operation.receipt
  };
}
function resultContent(result, isError = false) {
  return {
    content: [{ type: 'text', text: JSON.stringify(result) }],
    ...(isError ? {} : { structuredContent: result }),
    isError
  };
}

export class McpIntegrationSession {
  constructor(workspace) {
    this.workspace = workspace;
    this.initialized = false;
    this.ready = false;
  }

  handle(message) {
    const id = message?.id;
    const response = result => ({ jsonrpc: '2.0', id, result });
    const error = (code, text) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message: text } });
    if (!message || Array.isArray(message) || message.jsonrpc !== '2.0' || typeof message.method !== 'string' ||
        (id !== undefined && typeof id !== 'string' && typeof id !== 'number')) return error(-32600, 'Invalid Request');
    if (id === undefined) {
      if (message.method === 'notifications/initialized' && this.initialized) this.ready = true;
      return null;
    }
    if (message.method === 'initialize') {
      if (this.initialized) return error(-32600, 'Already initialized');
      if (typeof message.params?.protocolVersion !== 'string' || !message.params?.clientInfo || !message.params?.capabilities) {
        return error(-32602, 'Invalid initialization');
      }
      this.initialized = true;
      return response({
        protocolVersion: '2025-06-18',
        capabilities: { tools: {} },
        serverInfo: { name: 'mandate-desk-sepolia-preparation', version: '0.2.0-preview.1' },
        instructions: 'Offline fixture preparation only. Owner approval is available only in the web workspace. This server cannot approve owner actions, use API keys, sign, pay or broadcast.'
      });
    }
    if (message.method === 'ping') return response({});
    if (!this.ready) return error(-32000, 'Initialize the session first');
    if (message.method === 'tools/list') return response({ tools: integrationTools });
    if (message.method !== 'tools/call') return error(-32601, 'Method not found');
    const { name, arguments: input = {} } = message.params ?? {};
    if (!integrationTools.some(tool => tool.name === name)) return error(-32602, 'Unknown tool');
    try {
      let result;
      if (name === 'get_context') {
        strict(input, []);
        const state = this.workspace.read();
        result = {
          mode: state.mode,
          revision: state.revision,
          signingRouteAvailable: false,
          chainWriteAuthorized: false,
          operations: state.operations.map(operationSummary)
        };
      } else {
        strict(input, ['operationId']);
        if (name === 'plan_execute') {
          const operation = this.workspace.planExecute(input);
          result = {
            operationId: operation.operationId,
            status: operation.status,
            preview: operation.preview,
            previewHash: operation.previewHash,
            ownerApprovalRequired: true,
            chainWriteAuthorized: false
          };
        } else if (name === 'preflight') result = this.workspace.preflight(input);
        else if (name === 'execute_approved') result = this.workspace.executeApproved(input);
        else result = this.workspace.getReceipt(input);
      }
      return response(resultContent(result));
    } catch (err) {
      const safe = err instanceof BrickkenWorkspaceError ? {
        code: err.code,
        message: err.message,
        ...(err.details === undefined ? {} : { receipt: err.details })
      } : { code: 'INTERNAL', message: 'The local Sepolia preparation operation failed.' };
      return response(resultContent(safe, true));
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    if (args.length && (args.length !== 2 || args[0] !== '--data')) throw new Error('Invalid arguments');
    const directory = args.length ? boundedPath(path.resolve(ROOT, args[1])) : path.join(ROOT, 'data');
    runMcpStdio(new McpIntegrationSession(new BrickkenWorkspace(directory)));
  } catch {
    console.error('Mandate Desk Sepolia preparation MCP startup failed');
    process.exitCode = 1;
  }
}
