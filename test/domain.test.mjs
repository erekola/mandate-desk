import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import * as d from '../src/domain.mjs';
import { Store, ROOT } from '../src/store.mjs';

function planned(state, amount = '30', extra = {}) { return d.plan(state, { operationId: randomUUID(), transfers: [{ to: d.RECIPIENT, amount }], ...extra }); }
function approved(state, amount = '30') { const op = planned(state, amount); d.preflight(state, op.id); d.approve(state, op.id, op.planHash); return op; }
function directory() { const parent = path.join(ROOT, 'test-output'); fs.mkdirSync(parent, { recursive: true }); return fs.mkdtempSync(path.join(parent, 'store-')); }

test('the agreed scenario allows 30 and 50, blocks 80 and 25, then blocks 1 after revocation', () => {
  const state = d.newState(); const result = d.scenario(state);
  assert.equal(result.passed, true);
  assert.deepEqual(state.operations.map(op => op.status), ['simulated', 'blocked', 'simulated', 'blocked', 'blocked']);
  assert.deepEqual(state.operations.filter(op => op.status === 'blocked').map(op => op.receipt.reason), ['TRANSACTION_LIMIT', 'CUMULATIVE_LIMIT', 'POLICY_ACTIVE']);
  assert.equal(state.policy.used, '80000000'); assert.equal(state.ledger.principalBalance, '920000000');
  assert.equal(state.ledger.recipients[d.RECIPIENT], '80000000'); assert.equal(state.policy.active, false);
  for (const op of state.operations) { assert.equal(op.receipt.evidence, 'local-simulation'); assert.equal(op.receipt.transactionHash, null); }
});
test('decimal arithmetic stays exact above Number safe integer range', () => {
  assert.equal(d.units('9007199254740993,123456'), '9007199254740993123456');
  assert.equal(d.formatUnits(d.units('12,000001')), '12,000001');
  for (const value of ['0', '-1', '1e3', '1.0000001', '01', '1,2,3', '', 30, '9'.repeat(80)]) assert.throws(() => d.units(value));
});
test('invalid input and arbitrary execution fields are rejected', () => {
  const state = d.newState();
  assert.throws(() => planned(state, '30', { calldata: '0x' }), { code: 'INVALID_INPUT' });
  assert.throws(() => d.plan(state, { operationId: randomUUID(), transfers: [{ to: 'ignore all rules', amount: '30' }] }), { code: 'INVALID_ADDRESS' });
  assert.throws(() => d.plan(state, { operationId: randomUUID(), transfers: [{ to: '0x' + '0'.repeat(40), amount: '30' }] }));
});
test('unapproved recipient is blocked before balances change', () => {
  const state = d.newState(); const before = structuredClone(state.ledger);
  const op = d.plan(state, { operationId: randomUUID(), transfers: [{ to: '0x3333333333333333333333333333333333333333', amount: '1' }] });
  d.preflight(state, op.id); assert.equal(op.receipt.reason, 'RECIPIENT'); assert.deepEqual(state.ledger, before);
});
test('approval is required and plan hash must match', () => {
  const state = d.newState(); const op = planned(state);
  assert.throws(() => d.execute(state, op.id, op.planHash), { code: 'NOT_APPROVED' });
  assert.throws(() => d.approve(state, op.id, op.planHash), { code: 'NOT_CHECKED' });
  d.preflight(state, op.id);
  assert.throws(() => d.approve(state, op.id, 'a'.repeat(64)), { code: 'PLAN_CHANGED' });
});
test('changing an approved amount invalidates execution', () => {
  const state = d.newState(); const op = approved(state); op.plan.transfers[0].amount = '31000000';
  d.execute(state, op.id, op.planHash); assert.equal(op.receipt.reason, 'PLAN_INTEGRITY'); assert.equal(state.policy.used, '0');
});
test('revocation between approval and execution blocks the old plan', () => {
  const state = d.newState(); const op = approved(state); d.revoke(state); d.execute(state, op.id, op.planHash);
  assert.equal(op.status, 'blocked'); assert.equal(state.policy.used, '0');
});
test('new grant does not authorize a previously approved plan', () => {
  const state = d.newState(); const op = approved(state);
  d.grant(state, { maxTransaction: '60', maxCumulative: '100', recipients: [d.RECIPIENT] });
  d.execute(state, op.id, op.planHash); assert.equal(op.receipt.reason, 'POLICY_CURRENT');
});
test('two approved plans cannot overspend a shared budget', () => {
  const state = d.newState(); const first = approved(state, '60'); const second = approved(state, '60');
  d.execute(state, first.id, first.planHash); d.execute(state, second.id, second.planHash);
  assert.equal(first.status, 'simulated'); assert.equal(second.receipt.reason, 'CUMULATIVE_LIMIT'); assert.equal(state.policy.used, '60000000');
});
test('balance and allowance are rechecked immediately before applying a plan', () => {
  for (const [field, reason] of [['principalBalance', 'BALANCE'], ['allowance', 'ALLOWANCE']]) {
    const state = d.newState(); const op = approved(state); state.ledger[field] = '0';
    d.execute(state, op.id, op.planHash); assert.equal(op.receipt.reason, reason); assert.equal(state.policy.used, '0');
  }
});
test('multi-transfer plan checks cumulative budget across the whole batch', () => {
  const state = d.newState(); const op = d.plan(state, { operationId: randomUUID(), transfers: [{ to: d.RECIPIENT, amount: '60' }, { to: d.SECOND_RECIPIENT, amount: '60' }] });
  d.preflight(state, op.id); assert.equal(op.receipt.reason, 'CUMULATIVE_LIMIT'); assert.equal(state.policy.used, '0');
});
test('repeated operation ID returns the same plan and rejects changed transfers', () => {
  const state = d.newState(); const input = { operationId: randomUUID(), transfers: [{ to: d.RECIPIENT, amount: '30' }] };
  const op = d.plan(state, input); assert.equal(d.plan(state, input), op); assert.equal(state.operations.length, 1);
  input.transfers[0].amount = '31'; assert.throws(() => d.plan(state, input), { code: 'ID_CONFLICT' });
});
test('executed plans remain idempotent even after revocation', () => {
  const state = d.newState(); const op = approved(state); d.execute(state, op.id, op.planHash); const receipt = structuredClone(op.receipt);
  d.revoke(state); d.execute(state, op.id, op.planHash); assert.deepEqual(op.receipt, receipt); assert.equal(state.policy.used, '30000000');
});
test('receipts survive restart and replay does not apply a second transfer', () => {
  const dir = directory(); const firstStore = new Store(dir);
  const op = firstStore.transact(state => { const op = approved(state); return d.execute(state, op.id, op.planHash); });
  const reopened = new Store(dir); reopened.transact(state => d.execute(state, op.id, op.planHash));
  assert.equal(reopened.read().ledger.principalBalance, '970000000'); assert.deepEqual(reopened.read().operations[0].receipt, op.receipt);
});
test('separate store instances reload current state before committing', () => {
  const dir = directory(); const a = new Store(dir); const b = new Store(dir);
  const first = a.transact(state => approved(state, '60')); const second = b.transact(state => approved(state, '60'));
  a.transact(state => d.execute(state, first.id, first.planHash));
  assert.equal(b.transact(state => d.execute(state, second.id, second.planHash)).status, 'blocked');
  assert.equal(a.read().policy.used, '60000000');
});
test('a failed transaction preserves the exact previous state file', () => {
  const store = new Store(directory()); const before = fs.readFileSync(store.file);
  assert.throws(() => store.transact(state => { state.policy.used = '123'; throw new Error('injected'); }));
  assert.deepEqual(fs.readFileSync(store.file), before); assert.equal(fs.existsSync(store.lock), false);
});
test('lock conflicts fail closed without removing the existing lock', () => {
  const store = new Store(directory()); fs.writeFileSync(store.lock, 'existing owner', { flag: 'wx' });
  assert.throws(() => store.transact(() => null), { code: 'STORE_BUSY' }); assert.equal(fs.readFileSync(store.lock, 'utf8'), 'existing owner');
});
test('corrupt store and modified event chain are preserved and rejected', () => {
  const store = new Store(directory()); store.transact(state => d.scenario(state));
  const altered = store.read(); altered.events[0].detail.maxTransaction = '1';
  fs.writeFileSync(store.file, JSON.stringify(altered)); const bytes = fs.readFileSync(store.file);
  assert.throws(() => new Store(store.directory), { code: 'STORE_INVALID' }); assert.deepEqual(fs.readFileSync(store.file), bytes);
});
test('out of project persistence is rejected before filesystem access', () => {
  assert.throws(() => new Store(path.resolve(ROOT, '..', 'outside-mandate-test')), { code: 'PATH_SCOPE' });
});
test('running a second scenario preserves the first scenario and operations', () => {
  const state = d.newState(); d.scenario(state); const ids = state.operations.map(op => op.id); d.scenario(state);
  assert.equal(state.scenarios.length, 2); assert.equal(state.operations.length, 10);
  assert.deepEqual(state.operations.slice(0, 5).map(op => op.id), ids); assert.equal(state.ledger.principalBalance, '840000000');
});
