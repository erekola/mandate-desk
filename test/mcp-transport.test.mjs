import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { ROOT } from '../src/store.mjs';

const initialize = (id = 0, name = 'transport-test') => ({
  jsonrpc: '2.0', id, method: 'initialize',
  params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name, version: '1' } }
});
const initialized = { jsonrpc: '2.0', method: 'notifications/initialized' };
const ping = id => ({ jsonrpc: '2.0', id, method: 'ping' });

function startMcp() {
  const parent = path.join(ROOT, 'test-output');
  fs.mkdirSync(parent, { recursive: true });
  const directory = fs.mkdtempSync(path.join(parent, 'mcp-transport-'));
  const child = spawn(process.execPath, [path.join(ROOT, 'src', 'mcp.mjs'), '--data', directory], {
    cwd: ROOT, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  return { child, output: () => ({ stdout, stderr }) };
}

async function finish(run) {
  const [code] = await once(run.child, 'close');
  const { stdout, stderr } = run.output();
  const messages = stdout.trim() ? stdout.trim().split('\n').map(line => JSON.parse(line)) : [];
  return { code, stderr, messages };
}

async function runPayload(payload) {
  const run = startMcp();
  run.child.stdin.end(payload);
  return finish(run);
}

function line(value, ending = '\n') { return JSON.stringify(value) + ending; }

function exactLimitInitialize(id, name) {
  const message = initialize(id, name);
  message.params.clientInfo.pad = '';
  const baseBytes = Buffer.byteLength(JSON.stringify(message), 'utf8');
  message.params.clientInfo.pad = 'x'.repeat(65536 - baseBytes);
  const payload = Buffer.from(JSON.stringify(message), 'utf8');
  assert.equal(payload.length, 65536);
  return payload;
}

function write(child, chunk) {
  return new Promise((resolve, reject) => {
    child.stdin.write(chunk, error => error ? reject(error) : resolve());
  });
}

test('MCP answers a 3000-ping burst without applying the line limit to the whole chunk', { timeout: 20000 }, async () => {
  const requests = [initialize(), initialized];
  for (let id = 1; id <= 3000; id += 1) requests.push(ping(id));
  const result = await runPayload(requests.map(value => line(value)).join(''));
  assert.equal(result.code, 0);
  assert.equal(result.stderr, '');
  assert.equal(result.messages.length, 3001);
  assert.equal(result.messages[0].result.serverInfo.version, '0.1.1');
  assert.deepEqual(result.messages.slice(1).map(message => message.id), Array.from({ length: 3000 }, (_, index) => index + 1));
});

test('MCP rejects one oversized complete line and processes the next line', { timeout: 10000 }, async () => {
  const oversized = JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'ping', params: { pad: 'x'.repeat(70000) } });
  const payload = line(initialize()) + line(initialized) + oversized + '\n' + line(ping(10));
  const result = await runPayload(payload);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, '');
  assert.equal(result.messages.length, 3);
  assert.equal(result.messages[1].error.code, -32700);
  assert.match(result.messages[1].error.message, /exceeds 65536 bytes/);
  assert.equal(result.messages[2].id, 10);
  assert.deepEqual(result.messages[2].result, {});
});

test('MCP bounds an oversized unterminated line across chunks and recovers after its newline', { timeout: 10000 }, async () => {
  const run = startMcp();
  run.child.stdin.write(line(initialize()) + line(initialized));
  run.child.stdin.write('{"jsonrpc":"2.0","id":11,"method":"ping","params":{"pad":"');
  run.child.stdin.write('x'.repeat(65536));
  run.child.stdin.end('discarded-tail"}}\n' + line(ping(12)));
  const result = await finish(run);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, '');
  assert.equal(result.messages.length, 3);
  assert.equal(result.messages.filter(message => message.error?.code === -32700).length, 1);
  assert.match(result.messages[1].error.message, /exceeds 65536 bytes/);
  assert.equal(result.messages[2].id, 12);
  assert.deepEqual(result.messages[2].result, {});
});

test('MCP preserves split UTF-8 characters and accepts CRLF framing', { timeout: 10000 }, async () => {
  const run = startMcp();
  const firstLine = exactLimitInitialize(21, 'probe-é');
  const splitAt = firstLine.indexOf(Buffer.from('é')) + 1;
  assert.ok(splitAt > 0);
  await write(run.child, firstLine.subarray(0, splitAt));
  await write(run.child, firstLine.subarray(splitAt));
  await write(run.child, '\r');
  await new Promise(resolve => setTimeout(resolve, 50));
  run.child.stdin.end(Buffer.from('\n' + line(initialized, '\r\n') + line(ping(22), '\r\n'), 'utf8'));
  const result = await finish(run);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, '');
  assert.equal(result.messages.length, 2);
  assert.equal(result.messages[0].id, 21);
  assert.equal(result.messages[0].result.serverInfo.version, '0.1.1');
  assert.equal(result.messages[1].id, 22);
});

test('MCP rejects a non-LF byte after the one allowed trailing CR and then recovers', { timeout: 10000 }, async () => {
  const run = startMcp();
  await write(run.child, exactLimitInitialize(31, 'cr-boundary'));
  await write(run.child, '\r');
  await new Promise(resolve => setTimeout(resolve, 50));
  run.child.stdin.end('x\n' + line(ping(32)));
  const result = await finish(run);
  assert.equal(result.code, 0);
  assert.equal(result.stderr, '');
  assert.equal(result.messages.length, 2);
  assert.equal(result.messages[0].error.code, -32700);
  assert.match(result.messages[0].error.message, /exceeds 65536 bytes/);
  assert.equal(result.messages[1].id, 32);
  assert.deepEqual(result.messages[1].result, {});
});
