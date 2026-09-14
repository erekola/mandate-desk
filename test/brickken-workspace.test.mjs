import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import {
  BrickkenWorkspace,
  BrickkenWorkspaceError
} from '../src/brickken-workspace.mjs';
import { BrickkenJournal } from '../src/brickken-journal.mjs';
import { McpIntegrationSession } from '../src/mcp-integration.mjs';
import { Store, ROOT } from '../src/store.mjs';
import { createApp } from '../src/server.mjs';
import { sha256Canonical } from '../src/brickken-intent.mjs';

function fixture() {
  const parent = path.join(ROOT, 'test-output');
  fs.mkdirSync(parent, { recursive: true });
  const directory = fs.mkdtempSync(path.join(parent, 'workspace-'));
  let now = 1_800_000_000;
  const workspace = new BrickkenWorkspace(directory, { now: () => now });
  return { directory, workspace, setNow: value => { now = value; } };
}
function ready(session) {
  session.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
    protocolVersion: '2025-06-18', clientInfo: { name: 'test', version: '1' }, capabilities: {}
  } });
  session.handle({ jsonrpc: '2.0', method: 'notifications/initialized' });
}
const call = (session, name, args = {}) => session.handle({
  jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name, arguments: args }
});

test('fixed proposal creates five complete envelopes and stops at the unavailable signing route', () => {
  const { directory, workspace } = fixture();
  const simulation = new Store(directory);
  const stateBefore = fs.readFileSync(simulation.file);
  const operation = workspace.planExecute({ operationId: 'workspace_flow_001' });
  assert.equal(operation.preview.proposal.chainId, '11155111');
  assert.equal(operation.preview.proposal.amount, '10000');
  assert.equal(operation.preview.provenance.networkRead, false);
  assert.equal(operation.preview.approvalMeaning.chainWriteAuthorized, false);
  assert.deepEqual(operation.preview.actions.map(item => item.action), ['setAction', 'approve', 'grant', 'execute', 'revoke']);
  assert.equal(workspace.planExecute({ operationId: operation.operationId }).previewHash, operation.previewHash);

  const approved = workspace.approve({ operationId: operation.operationId, previewHash: operation.previewHash });
  assert.equal(approved.approval.previewHash, operation.previewHash);
  assert.equal(approved.approval.authorizesSigning, false);
  assert.equal(approved.approval.chainWriteAuthorized, false);
  assert.deepEqual(approved.envelopes.map(item => item.action), ['setAction', 'approve', 'grant', 'execute', 'revoke']);
  assert.ok(approved.envelopes.every(item => item.scope.signingReady === false && item.scope.chainWriteAuthorized === false));
  assert.equal(workspace.preflight({ operationId: operation.operationId }).ready, true);

  let first;
  assert.throws(() => workspace.executeApproved({ operationId: operation.operationId }), error => {
    first = error.details;
    return error instanceof BrickkenWorkspaceError && error.code === 'SIGNING_ROUTE_UNAVAILABLE' &&
      error.details.signed === false && error.details.broadcast === false &&
      error.details.chainWriteAttempted === false && error.details.transactionHash === null;
  });
  const journal = new BrickkenJournal({ directory: path.join(directory, 'brickken-journal') });
  assert.equal(journal.list().length, 5);
  const pending = journal.get(`${operation.operationId}_execute`);
  assert.equal(pending.state, 'pending');
  assert.equal(pending.operationKind, 'execute');
  assert.equal(pending.transaction.from, approved.envelopes.find(item => item.action === 'execute').transaction.from);
  assert.throws(() => workspace.executeApproved({ operationId: operation.operationId }), error => {
    assert.deepEqual(error.details, first);
    return error.code === 'SIGNING_ROUTE_UNAVAILABLE';
  });
  assert.deepEqual(fs.readFileSync(simulation.file), stateBefore);
});

test('approval expires, a workspace revision invalidates it and persisted-envelope tampering is rejected', () => {
  const expiry = fixture();
  const expiring = expiry.workspace.planExecute({ operationId: 'workspace_expiry_001' });
  expiry.workspace.approve({ operationId: expiring.operationId, previewHash: expiring.previewHash });
  expiry.setNow(1_800_000_300);
  assert.throws(() => expiry.workspace.preflight({ operationId: expiring.operationId }), { code: 'STALE_APPROVAL' });

  const revision = fixture();
  const first = revision.workspace.planExecute({ operationId: 'workspace_revision_001' });
  revision.workspace.approve({ operationId: first.operationId, previewHash: first.previewHash });
  revision.workspace.planExecute({ operationId: 'workspace_revision_002' });
  assert.throws(() => revision.workspace.preflight({ operationId: first.operationId }), { code: 'STALE_APPROVAL' });

  const mutation = fixture();
  const planned = mutation.workspace.planExecute({ operationId: 'workspace_mutation_001' });
  mutation.workspace.approve({ operationId: planned.operationId, previewHash: planned.previewHash });
  const persisted = JSON.parse(fs.readFileSync(mutation.workspace.file, 'utf8'));
  const received = persisted.operations[0].envelopes[0];
  received.transaction.nonce = '9';
  const { envelopeHash: _oldHash, ...envelopePayload } = received;
  received.envelopeHash = sha256Canonical(envelopePayload);
  persisted.selfHash = sha256Canonical({
    schemaVersion: persisted.schemaVersion,
    mode: persisted.mode,
    revision: persisted.revision,
    operations: persisted.operations
  });
  fs.writeFileSync(mutation.workspace.file, JSON.stringify(persisted, null, 2));
  assert.throws(() => mutation.workspace.preflight({ operationId: planned.operationId }));
});

test('workspace size guard preserves the prior readable history', () => {
  const { workspace } = fixture();
  workspace.planExecute({ operationId: 'workspace_size_guard_001' });
  const persisted = JSON.parse(fs.readFileSync(workspace.file, 'utf8'));
  persisted.operations[0].receipt = { padding: '' };
  persisted.selfHash = sha256Canonical({
    schemaVersion: persisted.schemaVersion,
    mode: persisted.mode,
    revision: persisted.revision,
    operations: persisted.operations
  });
  const maximum = 32 * 1024 * 1024;
  const baseSize = Buffer.byteLength(JSON.stringify(persisted, null, 2));
  persisted.operations[0].receipt.padding = 'x'.repeat(maximum - baseSize - 256);
  persisted.selfHash = sha256Canonical({
    schemaVersion: persisted.schemaVersion,
    mode: persisted.mode,
    revision: persisted.revision,
    operations: persisted.operations
  });
  const nearLimit = JSON.stringify(persisted, null, 2);
  assert.ok(Buffer.byteLength(nearLimit) < maximum);
  fs.writeFileSync(workspace.file, nearLimit);
  const before = fs.readFileSync(workspace.file);
  assert.throws(
    () => workspace.planExecute({ operationId: 'workspace_size_guard_002' }),
    { code: 'WORKSPACE_TOO_LARGE' }
  );
  assert.deepEqual(fs.readFileSync(workspace.file), before);
  assert.equal(workspace.read().operations.length, 1);
});

test('integration MCP exposes no owner action and returns the precise signing boundary error', () => {
  const { workspace } = fixture();
  const session = new McpIntegrationSession(workspace);
  ready(session);
  const tools = session.handle({ jsonrpc: '2.0', id: 3, method: 'tools/list' }).result.tools;
  assert.deepEqual(tools.map(item => item.name), ['get_context', 'plan_execute', 'preflight', 'execute_approved', 'get_receipt']);
  assert.equal(tools.some(item => ['approve', 'grant', 'revoke'].includes(item.name)), false);
  const planned = call(session, 'plan_execute', { operationId: 'workspace_mcp_001' }).result.structuredContent;
  assert.equal(planned.ownerApprovalRequired, true);
  workspace.approve({ operationId: planned.operationId, previewHash: planned.previewHash });
  assert.equal(call(session, 'preflight', { operationId: planned.operationId }).result.structuredContent.ready, true);
  const stopped = call(session, 'execute_approved', { operationId: planned.operationId });
  assert.equal(stopped.result.isError, true);
  assert.equal(JSON.parse(stopped.result.content[0].text).code, 'SIGNING_ROUTE_UNAVAILABLE');
  assert.equal(JSON.parse(stopped.result.content[0].text).receipt.transactionHash, null);
});

test('HTTP serves the separate workspace and keeps owner approval out of agent tools', async t => {
  const { directory, workspace } = fixture();
  const server = createApp({ store: new Store(directory), integrationWorkspace: workspace });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(base + '/integration')).status, 200);
  assert.equal((await fetch(base + '/integration.mjs')).status, 200);
  const { csrf } = await (await fetch(base + '/api/session')).json();
  const post = (route, body) => fetch(base + route, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Mandate-CSRF': csrf }, body: JSON.stringify(body)
  });
  const planned = await (await post('/api/integration/plan', { operationId: 'workspace_http_001' })).json();
  assert.equal(planned.result.preview.approvalMeaning.authorizesBroadcast, false);
  const approved = await (await post('/api/integration/approve', {
    operationId: planned.result.operationId, previewHash: planned.result.previewHash
  })).json();
  assert.equal(approved.result.envelopes.length, 5);
  assert.equal((await post('/api/integration/preflight', { operationId: planned.result.operationId })).status, 200);
  const stopped = await post('/api/integration/execute', { operationId: planned.result.operationId });
  assert.equal(stopped.status, 409);
  const body = await stopped.json();
  assert.equal(body.error, 'SIGNING_ROUTE_UNAVAILABLE');
  assert.equal(body.receipt.transactionHash, null);
});

test('HTTP returns the original bounded workspace error when persisted data is corrupt', async t => {
  const { directory, workspace } = fixture();
  const server = createApp({ store: new Store(directory), integrationWorkspace: workspace });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  fs.writeFileSync(workspace.file, '{"schemaVersion":1}');
  const response = await fetch(`http://127.0.0.1:${server.address().port}/api/integration/state`);
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), {
    error: 'WORKSPACE_INVALID',
    message: 'The Sepolia workspace file has an invalid structure.'
  });
});

test('integration MCP stdio completes initialization and exposes the separate tool set', async () => {
  const parent = path.join(ROOT, 'test-output');
  fs.mkdirSync(parent, { recursive: true });
  const directory = fs.mkdtempSync(path.join(parent, 'workspace-mcp-stdio-'));
  const relative = path.relative(ROOT, directory);
  const child = spawn(process.execPath, [path.join(ROOT, 'src', 'mcp-integration.mjs'), '--data', relative], {
    cwd: ROOT, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdin.end([
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'external-fixture', version: '1' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'get_context', arguments: {} } }
  ].map(message => JSON.stringify(message)).join('\n') + '\n');
  const [code] = await once(child, 'close');
  assert.equal(code, 0);
  assert.equal(stderr, '');
  const messages = stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(messages.length, 3);
  assert.deepEqual(messages[1].result.tools.map(item => item.name), ['get_context', 'plan_execute', 'preflight', 'execute_approved', 'get_receipt']);
  assert.equal(messages[2].result.structuredContent.mode, 'offline-fixture');
});
