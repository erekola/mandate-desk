import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { Store, ROOT } from '../src/store.mjs';
import { createApp } from '../src/server.mjs';
import { McpSession } from '../src/mcp.mjs';
import { RECIPIENT } from '../src/domain.mjs';

function store() { const parent = path.join(ROOT, 'test-output'); fs.mkdirSync(parent, { recursive: true }); return new Store(fs.mkdtempSync(path.join(parent, 'interface-'))); }
function ready(session) {
  const reply = session.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', clientInfo: { name: 'test', version: '1' }, capabilities: {} } });
  assert.equal(reply.result.protocolVersion, '2025-06-18');
  session.handle({ jsonrpc: '2.0', method: 'notifications/initialized' });
}
const call = (session, name, args = {}) => session.handle({ jsonrpc: '2.0', id: randomUUID(), method: 'tools/call', params: { name, arguments: args } });

test('MCP exposes only five tools and cannot approve its own plan', () => {
  const session = new McpSession(store());
  assert.equal(call(session, 'get_context').error.code, -32000); ready(session);
  const list = session.handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' }).result.tools;
  assert.deepEqual(list.map(tool => tool.name), ['get_context', 'plan_transfers', 'preflight_plan', 'execute_approved_plan', 'get_receipt']);
  assert.equal(call(session, 'approve_plan').error.code, -32602);
  const op = call(session, 'plan_transfers', { operationId: randomUUID(), transfers: [{ to: RECIPIENT, amount: '30' }] }).result.structuredContent;
  call(session, 'preflight_plan', { operationId: op.id });
  const denied = call(session, 'execute_approved_plan', { operationId: op.id, planHash: op.planHash });
  assert.equal(denied.result.isError, true); assert.equal(JSON.parse(denied.result.content[0].text).code, 'NOT_APPROVED');
});
test('MCP input schemas are enforced beyond discovery metadata', () => {
  const session = new McpSession(store()); ready(session);
  assert.equal(call(session, 'get_context', { privateKey: 'fake' }).result.isError, true);
  const reply = call(session, 'plan_transfers', { operationId: randomUUID(), transfers: [{ to: RECIPIENT, amount: '30', calldata: '0x' }] });
  assert.equal(reply.result.isError, true);
});
test('HTTP owner workflow, CSRF and origin enforcement, persistence and duplicate execution', async t => {
  const server = createApp({ store: store() }); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const get = route => fetch(base + route);
  assert.equal((await get('/')).status, 200);
  assert.equal((await get('/../../package.json')).status, 404);
  assert.equal((await fetch(base + '/api/state', { headers: { Origin: 'https://example.com' } })).status, 403);
  const wrongHostStatus = await new Promise((resolve, reject) => {
    const req = http.get(base + '/api/state', { headers: { Host: 'attacker.invalid' } }, res => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject);
  });
  assert.equal(wrongHostStatus, 403);
  const { csrf } = await (await get('/api/session')).json();
  const post = (route, body, token = csrf) => fetch(base + route, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Mandate-CSRF': token }, body: JSON.stringify(body) });
  assert.equal((await post('/api/revoke', {}, 'invalid')).status, 403);
  const { result: op } = await (await post('/api/plan', { operationId: randomUUID(), transfers: [{ to: RECIPIENT, amount: '30' }] })).json();
  assert.equal((await post('/api/execute', { operationId: op.id, planHash: op.planHash })).status, 400);
  assert.equal((await post('/api/preflight', { operationId: op.id })).status, 200);
  assert.equal((await post('/api/approve', { operationId: op.id, planHash: op.planHash })).status, 200);
  const executed = await (await post('/api/execute', { operationId: op.id, planHash: op.planHash })).json();
  assert.equal(executed.result.status, 'simulated');
  await post('/api/execute', { operationId: op.id, planHash: op.planHash });
  const state = await (await get('/api/state')).json(); assert.equal(state.policy.used, '30000000');
  assert.equal((await get('/api/export')).headers.get('content-disposition'), 'attachment; filename="mandate-desk-demo.json"');
  const run = await (await post('/api/scenario', {})).json(); assert.equal(run.result.passed, true);
});
test('MCP stdio process emits only JSON-RPC and completes initialization and discovery', async () => {
  const isolated = store(); const child = spawn(process.execPath, [path.join(ROOT, 'src', 'mcp.mjs'), '--data', isolated.directory], { cwd: ROOT, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  let stdout = '', stderr = ''; child.stdout.on('data', chunk => { stdout += chunk; }); child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdin.end([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'get_context', arguments: {} } }
  ].map(value => JSON.stringify(value)).join('\n') + '\n');
  const [code] = await once(child, 'close'); assert.equal(code, 0); assert.equal(stderr, '');
  const messages = stdout.trim().split('\n').map(line => JSON.parse(line)); assert.equal(messages.length, 3);
  assert.equal(messages[1].result.tools.length, 5); assert.equal(messages[2].result.structuredContent.mode, 'simulation');
});
