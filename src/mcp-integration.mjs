import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { ROOT, boundedPath } from './store.mjs';
import { BrickkenLiveWorkspace, BrickkenWorkspace, BrickkenWorkspaceError } from './brickken-workspace.mjs';
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
        serverInfo: { name: 'mandate-desk-sepolia-preparation', version: '0.3.0-preview.1' },
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

const liveOperationId = { type: 'string', pattern: '^live_[a-f0-9]{32}_execute$' };

// Live tools. The agent can reach only the execute operation that the owner
// approved in the owner workspace; every owner action stays out of this list.
export const liveIntegrationTools = Object.freeze([
  {
    name: 'get_context',
    description: 'Read the live Ethereum Sepolia run from the local workspace: its status, the one owner-approved execute operation and the approved transfer. No network request.',
    inputSchema: schema({}),
    annotations: { readOnlyHint: true, openWorldHint: false }
  },
  {
    name: 'preflight',
    description: 'Read-only Ethereum Sepolia check of the owner-approved execute operation at the latest block: AgentMandate.canExecute and a simulation of the exact executor call. It never signs or broadcasts.',
    inputSchema: schema({ operationId: liveOperationId }),
    annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true }
  },
  {
    name: 'execute_approved',
    description: 'Execute or resume the single owner-approved execute operation on Ethereum Sepolia through Brickken client-signed preparation, the local signer, broadcast and receipt verification. It transfers testnet tokens from the principal to the approved recipient. Repeating the same operationId returns the recorded receipt and sends nothing. It cannot approve, grant, revoke, change the plan or read keys.',
    inputSchema: schema({ operationId: liveOperationId }),
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true }
  },
  {
    name: 'get_receipt',
    description: 'Read the recorded receipt of the execute operation from the local live journal: state, Brickken txId, Ethereum transaction hash, block and semantic verification. No network request.',
    inputSchema: schema({ operationId: liveOperationId }),
    annotations: { readOnlyHint: true, openWorldHint: false }
  }
]);

export class McpLiveSession {
  constructor(workspace) {
    this.workspace = workspace;
    this.initialized = false;
    this.ready = false;
  }

  async handle(message) {
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
        serverInfo: { name: 'mandate-desk-sepolia-live', version: '0.3.0-preview.1' },
        instructions: 'Live Ethereum Sepolia run. This agent server can only execute the operation the owner approved in the owner workspace. Owner approval, grant, revoke and cleanup are not available here, and the server cannot read keys, pay or change the plan.'
      });
    }
    if (message.method === 'ping') return response({});
    if (!this.ready) return error(-32000, 'Initialize the session first');
    if (message.method === 'tools/list') return response({ tools: liveIntegrationTools });
    if (message.method !== 'tools/call') return error(-32601, 'Method not found');
    const { name, arguments: input = {} } = message.params ?? {};
    if (!liveIntegrationTools.some(tool => tool.name === name)) return error(-32602, 'Unknown tool');
    try {
      let result;
      if (name === 'get_context') {
        strict(input, []);
        result = this.workspace.agentContext();
      } else {
        strict(input, ['operationId']);
        if (name === 'preflight') result = await this.workspace.agentPreflight(input);
        else if (name === 'execute_approved') result = await this.workspace.agentExecute(input);
        else result = this.workspace.agentReceipt(input);
      }
      return response(resultContent(result));
    } catch (err) {
      const safe = err instanceof BrickkenWorkspaceError ? {
        code: err.code,
        message: err.message,
        ...(err.details === undefined ? {} : { details: err.details })
      } : { code: 'INTERNAL', message: 'The live Sepolia operation failed.' };
      return response(resultContent(safe, true));
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    // --live selects the agent side of an owner-approved Sepolia run; without it
    // the server keeps the offline fixture and its unavailable signing route.
    const live = args[0] === '--live';
    const rest = live ? args.slice(1) : args;
    if (rest.length && (rest.length !== 2 || rest[0] !== '--data')) throw new Error('Invalid arguments');
    const directory = rest.length ? boundedPath(path.resolve(ROOT, rest[1])) : path.join(ROOT, 'data');
    runMcpStdio(live
      ? new McpLiveSession(new BrickkenLiveWorkspace(directory, { role: 'agent' }))
      : new McpIntegrationSession(new BrickkenWorkspace(directory)));
  } catch {
    console.error('Mandate Desk Sepolia preparation MCP startup failed');
    process.exitCode = 1;
  }
}
