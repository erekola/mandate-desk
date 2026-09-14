import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Store, ROOT, boundedPath } from './store.mjs';
import * as domain from './domain.mjs';

const idSchema = { type: 'string', minLength: 8, maxLength: 80 };
const schema = (properties, required = Object.keys(properties)) => ({ type: 'object', properties, required, additionalProperties: false });
export const tools = [
  { name: 'get_context', description: 'Read the local simulation, mandate and demo balances. No live chain or API access.', inputSchema: schema({}), annotations: { readOnlyHint: true, openWorldHint: false } },
  { name: 'plan_transfers', description: 'Create an immutable simulated transfer plan. Reusing the operationId with the same transfers returns the original plan.', inputSchema: schema({ operationId: idSchema, transfers: { type: 'array', minItems: 1, maxItems: 20, items: schema({ to: { type: 'string', pattern: '^0x[0-9a-fA-F]{40}$' }, amount: { type: 'string' } }) } }), annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
  { name: 'preflight_plan', description: 'Check an existing plan against local mandate limits, recipients, demo balance and allowance. May mark the plan blocked.', inputSchema: schema({ operationId: idSchema }), annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false } },
  { name: 'execute_approved_plan', description: 'Apply an owner-approved plan to the simulated ledger once. Approval must come from the owner UI. Never broadcasts a transaction.', inputSchema: schema({ operationId: idSchema, planHash: { type: 'string', pattern: '^[0-9a-f]{64}$' } }), annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false } },
  { name: 'get_receipt', description: 'Read a plan and its local simulation evidence. transactionHash is always null.', inputSchema: schema({ operationId: idSchema }), annotations: { readOnlyHint: true, openWorldHint: false } }
];
export class McpSession {
  constructor(store) { this.store = store; this.initialized = false; this.ready = false; }
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
      if (typeof message.params?.protocolVersion !== 'string' || !message.params?.clientInfo || !message.params?.capabilities) return error(-32602, 'Invalid initialization');
      this.initialized = true;
      return response({ protocolVersion: '2025-06-18', capabilities: { tools: {} },
        serverInfo: { name: 'mandate-desk-simulation', version: '0.1.1' },
        instructions: 'Local simulation only. Owner approval is performed in the UI. This server cannot grant mandates, approve its own plans, use API keys, sign, pay, or broadcast.' });
    }
    if (message.method === 'ping') return response({});
    if (!this.ready) return error(-32000, 'Initialize the session first');
    if (message.method === 'tools/list') return response({ tools });
    if (message.method !== 'tools/call') return error(-32601, 'Method not found');
    const { name, arguments: input = {} } = message.params ?? {};
    if (!tools.some(tool => tool.name === name)) return error(-32602, 'Unknown tool');
    try {
      let result;
      if (name === 'get_context') { domain.strictObject(input, []); result = this.store.read(); }
      else if (name === 'get_receipt') { domain.strictObject(input, ['operationId']); result = domain.getReceipt(this.store.read(), input.operationId); }
      else result = this.store.transact(state => {
        if (name === 'plan_transfers') return domain.plan(state, input);
        if (name === 'preflight_plan') { domain.strictObject(input, ['operationId']); return domain.preflight(state, input.operationId); }
        domain.strictObject(input, ['operationId', 'planHash']); return domain.execute(state, input.operationId, input.planHash);
      });
      return response({ content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: false });
    } catch (err) {
      const safe = err instanceof domain.DomainError ? { code: err.code, message: err.message } : { code: 'INTERNAL', message: 'Local operation failed.' };
      return response({ content: [{ type: 'text', text: JSON.stringify(safe) }], isError: true });
    }
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    if (args.length && (args.length !== 2 || args[0] !== '--data')) throw new Error('Invalid arguments');
    const directory = args.length ? boundedPath(path.resolve(ROOT, args[1])) : path.join(ROOT, 'data');
    const session = new McpSession(new Store(directory));
    const maxLineBytes = 65536;
    let pending = Buffer.alloc(0);
    let discardingOversizedLine = false;
    const writeOversizedLineError = () => process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: null, error: { code: -32700, message: `Parse error: input line exceeds ${maxLineBytes} bytes` }
    }) + '\n');
    const handleLine = line => {
      if (!line.toString('utf8').trim()) return;
      let reply;
      try { reply = session.handle(JSON.parse(line.toString('utf8'))); }
      catch { reply = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }; }
      if (reply) process.stdout.write(JSON.stringify(reply) + '\n');
    };
    process.stdin.on('data', chunk => {
      let offset = 0;
      while (offset < chunk.length) {
        if (discardingOversizedLine) {
          const end = chunk.indexOf(0x0a, offset);
          if (end === -1) return;
          discardingOversizedLine = false;
          offset = end + 1;
          continue;
        }
        const end = chunk.indexOf(0x0a, offset);
        if (end !== -1) {
          const part = chunk.subarray(offset, end);
          const rawLength = pending.length + part.length;
          const trailingByte = part.length ? part[part.length - 1] : pending[pending.length - 1];
          const lineLength = rawLength - (trailingByte === 0x0d ? 1 : 0);
          if (lineLength > maxLineBytes) writeOversizedLineError();
          else {
            const rawLine = pending.length ? Buffer.concat([pending, part], rawLength) : part;
            handleLine(trailingByte === 0x0d ? rawLine.subarray(0, -1) : rawLine);
          }
          pending = Buffer.alloc(0);
          offset = end + 1;
          continue;
        }
        const part = chunk.subarray(offset);
        const combinedLength = pending.length + part.length;
        const trailingByte = part.length ? part[part.length - 1] : pending[pending.length - 1];
        const pendingLimit = maxLineBytes + (trailingByte === 0x0d ? 1 : 0);
        if (combinedLength > pendingLimit) {
          writeOversizedLineError();
          pending = Buffer.alloc(0);
          discardingOversizedLine = true;
        } else {
          pending = pending.length ? Buffer.concat([pending, part], combinedLength) : Buffer.from(part);
        }
        return;
      }
    });
  } catch { console.error('Mandate Desk MCP startup failed'); process.exitCode = 1; }
}
