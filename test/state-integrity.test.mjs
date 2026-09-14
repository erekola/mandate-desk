import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import * as d from '../src/domain.mjs';
import { Store, ROOT } from '../src/store.mjs';
import { createApp } from '../src/server.mjs';
function prepare(s, amount = '30') { const op = d.plan(s, { operationId: randomUUID(), transfers: [{ to: d.RECIPIENT, amount }] }); d.preflight(s, op.id); d.approve(s, op.id, op.planHash); return op; }
function simulated() { const s = d.newState(), op = prepare(s); d.execute(s, op.id, op.planHash); return s; }
function directory() { fs.mkdirSync(path.join(ROOT, 'test-output'), { recursive: true }); return fs.mkdtempSync(path.join(ROOT, 'test-output/invariants-')); }

test('malformed and inconsistent stores are rejected with STORE_INVALID and preserved byte for byte', async t => {
  const cases = {
    'A empty operation': s => { s.operations = [{}]; },
    'B null operation': s => { s.operations = [null]; },
    'C null recipients': s => { s.policy.recipients = null; },
    'C string recipients': s => { s.policy.recipients = 'nope'; },
    'D missing policy': s => { delete s.policy; },
    'missing ledger': s => { delete s.ledger; },
    'E ledger and usage reset': s => { s.policy.used = '0'; s.ledger.principalBalance = d.units('1000'); },
    'G plan and hashes rewritten': s => { const op = s.operations[0]; op.plan.transfers[0].amount = d.units('60'); op.planHash = d.digest(op.plan); op.inputHash = d.digest(op.plan.transfers); op.approval.planHash = op.planHash; },
    'H invalid revision': s => { s.revision = 'x'; },
    'H unsafe integer revision': s => { s.revision = Number.MAX_SAFE_INTEGER + 1; },
    'I duplicate operation ID': s => { s.operations.push(structuredClone(s.operations[0])); },
    'invalid policy limit': s => { s.policy.maxTransaction = '0'; },
    'missing approval': s => { s.operations[0].approval = null; },
    'unknown operation status': s => { s.operations[0].status = 'confirmed'; },
    'null check': s => { s.operations[0].checks[0] = null; },
    'receipt missing': s => { s.operations[0].receipt = null; },
    'receipt ledger altered': s => { s.operations[0].receipt.after.principalBalance = d.units('999'); },
    'receipt outcome altered': s => { s.operations[0].receipt.outcome = 'confirmed'; },
    'unexplained recipient balance': s => { s.ledger.recipients[d.SECOND_RECIPIENT] = '1'; },
    'null event': s => { s.events[0] = null; },
    'null scenario': s => { s.scenarios.push(null); }
  };
  for (const [name, alter] of Object.entries(cases)) await t.test(name, () => {
    const store = new Store(directory()), state = simulated(); alter(state);
    fs.writeFileSync(store.file, JSON.stringify(state)); const before = fs.readFileSync(store.file);
    assert.throws(() => d.validateState(state), { code: 'STORE_INVALID' });
    assert.throws(() => new Store(store.directory), { code: 'STORE_INVALID' });
    assert.deepEqual(fs.readFileSync(store.file), before);
  });
});

test('valid histories reconcile across new grants, multiple scenarios and out-of-order execution', () => {
  const s = d.newState(); d.validateState(s);
  d.scenario(s); d.validateState(s); d.scenario(s); d.validateState(s);
  d.grant(s, { maxTransaction: '60', maxCumulative: '100', recipients: [d.RECIPIENT] });
  const first = prepare(s, '20'), second = prepare(s, '30');
  d.execute(s, second.id, second.planHash); d.execute(s, first.id, first.planHash); d.validateState(s);
  d.grant(s, { maxTransaction: '60', maxCumulative: '100', recipients: [d.SECOND_RECIPIENT] }); d.validateState(s);
  assert.equal(s.ledger.principalBalance, d.units('790'));
});

test('revocation has the specific reason and approving an already blocked request preserves its receipt', () => {
  const s = d.newState(), op = prepare(s); d.revoke(s); d.execute(s, op.id, op.planHash);
  assert.equal(op.receipt.reason, 'POLICY_ACTIVE'); const receipt = structuredClone(op.receipt), events = s.events.length;
  assert.equal(d.approve(s, op.id, op.planHash), op); assert.deepEqual(op.receipt, receipt); assert.equal(s.events.length, events); d.validateState(s);
});

test('a fresh grant after revocation still reports POLICY_CURRENT for the earlier approved plan', () => {
  const s = d.newState(), op = prepare(s); d.revoke(s);
  d.grant(s, { maxTransaction: '60', maxCumulative: '100', recipients: [d.RECIPIENT] });
  d.execute(s, op.id, op.planHash); assert.equal(op.receipt.reason, 'POLICY_CURRENT'); d.validateState(s);
});

test('blocked receipts cannot contradict an existing blocked event', () => {
  const s = d.newState(), op = prepare(s); d.revoke(s); d.execute(s, op.id, op.planHash);
  op.checks.forEach(check => { check.ok = check.code !== 'RECIPIENT'; }); op.receipt.reason = 'RECIPIENT';
  assert.throws(() => d.validateState(s), { code: 'STORE_INVALID' });
});

test('legacy 0.1.0 POLICY_CURRENT revocation receipts remain valid without rewriting history', () => {
  const s = d.newState(), op = prepare(s); d.revoke(s); d.execute(s, op.id, op.planHash);
  const active = op.checks.findIndex(c => c.code === 'POLICY_ACTIVE'), current = op.checks.findIndex(c => c.code === 'POLICY_CURRENT');
  [op.checks[active], op.checks[current]] = [op.checks[current], op.checks[active]];
  op.receipt.reason = 'POLICY_CURRENT'; s.events.at(-1).detail.reason = 'POLICY_CURRENT';
  let previous = null;
  for (const entry of s.events) { entry.previousHash = previous; const { hash, ...payload } = entry; entry.hash = d.digest(payload); previous = entry.hash; }
  const before = JSON.stringify(s); d.validateState(s); assert.equal(JSON.stringify(s), before);
});

test('corruption after server startup returns STORE_INVALID while preserving the saved file', async t => {
  const store = new Store(directory()), server = createApp({ store });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise(resolve => server.close(resolve)));
  const state = store.read(); state.operations.push({}); fs.writeFileSync(store.file, JSON.stringify(state)); const before = fs.readFileSync(store.file);
  const response = await fetch(`http://127.0.0.1:${server.address().port}/api/state`); const body = await response.json();
  assert.equal(response.status, 400); assert.equal(body.error, 'STORE_INVALID'); assert.match(body.message, /saved demo state could not be read/);
  assert.deepEqual(fs.readFileSync(store.file), before);
});
