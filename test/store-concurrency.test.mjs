import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import * as d from '../src/domain.mjs';
import { Store, ROOT } from '../src/store.mjs';
import { createApp } from '../src/server.mjs';

function directory() {
  const parent = path.join(ROOT, 'test-output');
  fs.mkdirSync(parent, { recursive: true });
  return fs.mkdtempSync(path.join(parent, 'store-concurrency-'));
}

function addPlan(state) {
  return d.plan(state, {
    operationId: randomUUID(),
    transfers: [{ to: d.RECIPIENT, amount: '1' }]
  });
}

function temporaryFiles(directoryPath) {
  return fs.readdirSync(directoryPath).filter(name => name.endsWith('.tmp'));
}

test('rename is retried while a reader holds the file', async () => {
  const store = new Store(directory());
  const child = spawn(process.execPath, ['-e', [
    "const fs = require('node:fs');",
    "const descriptor = fs.openSync(process.env.HOLD_FILE, 'r');",
    "process.stdout.write('ready\\n');",
    "setTimeout(() => { fs.closeSync(descriptor); process.exit(0); }, Number(process.env.HOLD_MS));"
  ].join(' ')], {
    env: { ...process.env, HOLD_FILE: store.file, HOLD_MS: '150' },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true
  });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk; });
  await once(child.stdout, 'data');

  const operation = store.transact(addPlan);
  const [exitCode] = await once(child, 'close');

  assert.equal(exitCode, 0, stderr);
  assert.equal(store.read().operations.some(item => item.id === operation.id), true);
  assert.deepEqual(temporaryFiles(store.directory), []);
  assert.equal(fs.existsSync(store.lock), false);
});

test('exhausted rename retries fail closed as STORE_BUSY', () => {
  const store = new Store(directory());
  const before = fs.readFileSync(store.file);
  const descriptor = fs.openSync(store.file, 'r');
  try {
    assert.throws(() => store.transact(addPlan), {
      code: 'STORE_BUSY',
      message: 'The demo state is busy. Try again later.'
    });
  } finally {
    fs.closeSync(descriptor);
  }

  assert.deepEqual(fs.readFileSync(store.file), before);
  assert.deepEqual(temporaryFiles(store.directory), []);
  assert.equal(fs.existsSync(store.lock), false);
});

test('a stale lock permits constructor reads and HTTP reads but blocks writes', async t => {
  const original = new Store(directory());
  const lockRecord = { pid: 424242, at: '2026-09-12T08:00:00.000Z' };
  const lockBytes = JSON.stringify(lockRecord);
  fs.writeFileSync(original.lock, lockBytes, { flag: 'wx' });

  const notices = [];
  const originalConsoleError = console.error;
  console.error = message => { notices.push(String(message)); };
  let reopened;
  try {
    reopened = new Store(original.directory);
  } finally {
    console.error = originalConsoleError;
  }

  assert.equal(reopened.read().revision, original.read().revision);
  assert.throws(() => reopened.transact(addPlan), {
    code: 'STORE_BUSY',
    message: 'The demo state is busy. Try again later.'
  });
  assert.equal(fs.readFileSync(original.lock, 'utf8'), lockBytes);
  assert.deepEqual(notices, [
    `Mandate Desk storage lock present and not removed: ${original.lock}; pid=424242; at=2026-09-12T08:00:00.000Z`
  ]);

  const server = createApp({ store: reopened });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;

  const stateResponse = await fetch(base + '/api/state');
  assert.equal(stateResponse.status, 200);
  const { csrf } = await (await fetch(base + '/api/session')).json();
  const writeResponse = await fetch(base + '/api/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Mandate-CSRF': csrf },
    body: '{}'
  });
  assert.equal(writeResponse.status, 409);
  assert.equal((await writeResponse.json()).error, 'STORE_BUSY');
  assert.equal(fs.readFileSync(original.lock, 'utf8'), lockBytes);
});

test('invalid lock contents are never echoed', () => {
  const original = new Store(directory());
  const privateContents = '{"pid":"secret-pid","at":"secret-time","extra":"do-not-print"}';
  fs.writeFileSync(original.lock, privateContents, { flag: 'wx' });
  const notices = [];
  const originalConsoleError = console.error;
  console.error = message => { notices.push(String(message)); };
  try {
    new Store(original.directory);
  } finally {
    console.error = originalConsoleError;
  }
  assert.equal(notices.length, 1);
  assert.match(notices[0], /state\.lock$/);
  for (const value of ['secret-pid', 'secret-time', 'do-not-print']) assert.equal(notices[0].includes(value), false);
});
