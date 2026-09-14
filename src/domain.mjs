import { createHash, randomUUID } from 'node:crypto';

export const PRINCIPAL = '0x1F5ED27Aef8367bc8eA936Ec562b776A1399E5D4';
export const AGENT = '0x18Ff8b19E9E9cc35c7F10b1c690BB84D56CC9442';
export const RECIPIENT = '0x1111111111111111111111111111111111111111';
export const SECOND_RECIPIENT = '0x2222222222222222222222222222222222222222';
export const ASSET = Object.freeze({ id: 'simulation:MDT', symbol: 'MDT', decimals: 6, address: null });
const UINT256 = (1n << 256n) - 1n;
const TERMINAL = new Set(['simulated', 'blocked']);

export class DomainError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
export function fail(code, message) { throw new DomainError(code, message); }
export function strictObject(value, keys, required = keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(k => !keys.includes(k)) || required.some(k => !(k in value))) {
    fail('INVALID_INPUT', 'The request fields do not match the allowed structure.');
  }
}
export function address(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value) || /^0x0{40}$/.test(value)) {
    fail('INVALID_ADDRESS', 'Enter a valid Ethereum address.');
  }
  return value.toLowerCase();
}
export function units(value, decimals = ASSET.decimals) {
  if (typeof value !== 'string' || value.length > 80 || !/^(0|[1-9]\d*)([.,]\d+)?$/.test(value)) {
    fail('INVALID_AMOUNT', 'Enter a positive amount without thousands separators.');
  }
  const [whole, fraction = ''] = value.replace(',', '.').split('.');
  if (fraction.length > decimals) fail('DECIMALS', 'The amount has too many decimal places.');
  const amount = BigInt(whole) * 10n ** BigInt(decimals) + BigInt(fraction.padEnd(decimals, '0') || '0');
  if (amount <= 0n || amount > UINT256) fail('INVALID_AMOUNT', 'The amount must be positive and within the token numeric range.');
  return amount.toString();
}
export function formatUnits(value, decimals = ASSET.decimals) {
  const amount = BigInt(value);
  const whole = amount / 10n ** BigInt(decimals);
  const fraction = (amount % 10n ** BigInt(decimals)).toString().padStart(decimals, '0').replace(/0+$/, '');
  return whole.toString() + (fraction ? ',' + fraction : '');
}
export function digest(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
const now = () => new Date().toISOString();

export function newState() {
  return {
    schemaVersion: 1, mode: 'simulation', revision: 0,
    asset: { ...ASSET }, principal: PRINCIPAL.toLowerCase(), agent: AGENT.toLowerCase(),
    policy: { id: randomUUID(), version: 1, active: true, chainId: '11155111',
      maxTransaction: units('60'), maxCumulative: units('100'), used: '0',
      recipients: [RECIPIENT, SECOND_RECIPIENT], createdAt: now(), revokedAt: null },
    ledger: { principalBalance: units('1000'), allowance: units('1000'), recipients: {} },
    operations: [], events: [], scenarios: []
  };
}
export function validateState(state) {
  const invalid = () => fail('STORE_INVALID', 'The saved demo state could not be read. The file was preserved.');
  const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const id = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{8,80}$/.test(value);
  const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const integer = value => Number.isSafeInteger(value) && value >= 0;
  const timestamp = value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value));
  const account = value => typeof value === 'string' && /^0x[0-9a-f]{40}$/.test(value) && !/^0x0{40}$/.test(value);
  const quantity = value => typeof value === 'string' && /^(0|[1-9]\d{0,77})$/.test(value) && BigInt(value) <= UINT256;
  const ledgerShape = value => record(value) && quantity(value.principalBalance) && quantity(value.allowance) &&
    record(value.recipients) && Object.entries(value.recipients).every(([to, amount]) => account(to) && quantity(amount));
  const policy = state?.policy;
  if (!record(state) || state.schemaVersion !== 1 || state.mode !== 'simulation' || !integer(state.revision) ||
      state.asset?.id !== ASSET.id || state.asset.symbol !== ASSET.symbol || state.asset.decimals !== ASSET.decimals || state.asset.address !== null ||
      state.principal !== PRINCIPAL.toLowerCase() || state.agent !== AGENT.toLowerCase() ||
      !Array.isArray(state.operations) || state.operations.length > 2000 || !Array.isArray(state.events) || !Array.isArray(state.scenarios) ||
      !record(policy) || !id(policy.id) || !integer(policy.version) || policy.version < 1 || typeof policy.active !== 'boolean' ||
      policy.chainId !== '11155111' || !timestamp(policy.createdAt) || (policy.active ? policy.revokedAt !== null : !timestamp(policy.revokedAt)) ||
      !Array.isArray(policy.recipients) || !policy.recipients.length || policy.recipients.length > 20 ||
      !policy.recipients.every(account) || new Set(policy.recipients).size !== policy.recipients.length ||
      !record(state.ledger) || !record(state.ledger.recipients)) invalid();
  const eventTypes = new Set(['planned', 'checked', 'approved', 'simulated', 'blocked', 'granted', 'revoked', 'scenario']);
  const plannedEvents = new Map(), approvedEvents = new Map(), simulatedEvents = new Map(), blockedEvents = new Map();
  let previous = null;
  for (const [index, entry] of state.events.entries()) {
    if (!record(entry) || entry.index !== index + 1 || !eventTypes.has(entry.type) || !timestamp(entry.at) ||
        !id(entry.policyId) || !record(entry.detail) || !hash(entry.hash) ||
        (['planned', 'checked', 'approved', 'simulated', 'blocked'].includes(entry.type) ? !id(entry.operationId) : entry.operationId !== null)) invalid();
    const { hash: eventHash, ...payload } = entry;
    if (payload.previousHash !== previous || digest(payload) !== eventHash) fail('STORE_INVALID', 'The activity log checksum does not match.');
    previous = eventHash;
    if (entry.type === 'blocked') { if (blockedEvents.has(entry.operationId)) invalid(); blockedEvents.set(entry.operationId, entry); }
    const table = entry.type === 'planned' ? plannedEvents : entry.type === 'approved' ? approvedEvents : entry.type === 'simulated' ? simulatedEvents : null;
    if (table) { if (table.has(entry.operationId) || !hash(entry.detail.planHash)) invalid(); table.set(entry.operationId, entry); }
  }
  for (const value of [policy.maxTransaction, policy.maxCumulative, policy.used,
    state.ledger.principalBalance, state.ledger.allowance, ...Object.values(state.ledger.recipients)]) {
    if (!quantity(value)) fail('STORE_INVALID', 'The demo state contains invalid amounts.');
  }
  if (BigInt(policy.used) > BigInt(policy.maxCumulative)) fail('STORE_INVALID', 'Demo spending exceeds the mandate.');
  if (BigInt(policy.maxTransaction) <= 0n || BigInt(policy.maxCumulative) <= 0n || BigInt(policy.maxTransaction) > BigInt(policy.maxCumulative) || !ledgerShape(state.ledger)) invalid();
  const statuses = new Set(['planned', 'checked', 'approved', 'simulated', 'blocked']);
  const codes = new Set(['PLAN_INTEGRITY', 'SIMULATION_ONLY', 'IDENTITY', 'POLICY_CURRENT', 'POLICY_ACTIVE', 'RECIPIENT', 'TRANSACTION_LIMIT', 'CUMULATIVE_LIMIT', 'BALANCE', 'ALLOWANCE']);
  const operations = new Map(), executed = [];
  for (const op of state.operations) {
    if (!record(op) || !id(op.id) || operations.has(op.id) || !statuses.has(op.status) || !timestamp(op.createdAt) ||
        !record(op.plan) || !Array.isArray(op.plan.transfers) || !op.plan.transfers.length || op.plan.transfers.length > 20 ||
        !hash(op.planHash) || !hash(op.inputHash) || !Array.isArray(op.checks)) invalid();
    const p = op.plan;
    if (p.mode !== 'simulation' || p.chainId !== '11155111' || p.principal !== state.principal || p.agent !== state.agent ||
        p.assetId !== ASSET.id || p.tokenAddress !== null || !id(p.policyId) || !integer(p.policyVersion) || p.policyVersion < 1 || p.policyVersion > policy.version ||
        !p.transfers.every(t => record(t) && account(t.to) && quantity(t.amount) && BigInt(t.amount) > 0n) ||
        digest(p) !== op.planHash || digest(p.transfers) !== op.inputHash || plannedEvents.get(op.id)?.detail.planHash !== op.planHash ||
        plannedEvents.get(op.id)?.policyId !== p.policyId) invalid();
    if (op.checks.length !== (op.status === 'planned' ? 0 : codes.size) ||
        !op.checks.every(c => record(c) && codes.has(c.code) && typeof c.ok === 'boolean') || new Set(op.checks.map(c => c.code)).size !== op.checks.length) invalid();
    if (op.status === 'blocked' ? !op.checks.some(c => !c.ok) : op.checks.some(c => !c.ok)) invalid();
    if (op.approval !== null && (!record(op.approval) || op.approval.planHash !== op.planHash || op.approval.actor !== 'local-owner-ui' ||
        !timestamp(op.approval.at) || approvedEvents.get(op.id)?.detail.planHash !== op.planHash)) invalid();
    if ((['approved', 'simulated'].includes(op.status) && !op.approval) || (['planned', 'checked'].includes(op.status) && op.approval !== null)) invalid();
    if (TERMINAL.has(op.status)) {
      const receipt = op.receipt;
      if (!record(receipt) || receipt.evidence !== 'local-simulation' || receipt.transactionHash !== null || !timestamp(receipt.at) || receipt.outcome !== op.status) invalid();
      if (op.status === 'blocked') {
        if (receipt.reason !== op.checks.find(c => !c.ok)?.code ||
            (blockedEvents.has(op.id) && blockedEvents.get(op.id).detail.reason !== receipt.reason)) invalid();
      }
      else {
        if (!ledgerShape(receipt.before) || !ledgerShape(receipt.after) || !quantity(receipt.cumulativeUsed) ||
            simulatedEvents.get(op.id)?.detail.planHash !== op.planHash) invalid();
        executed.push(op);
      }
    } else if (op.receipt !== null) invalid();
    operations.set(op.id, op);
  }
  for (const entry of state.events) if (entry.operationId !== null && !operations.has(entry.operationId)) invalid();
  const recipients = {}, usage = new Map();
  let balance = BigInt(units('1000'));
  const matchesLedger = value => value.principalBalance === balance.toString() && value.allowance === balance.toString() &&
    Object.keys(value.recipients).length === Object.keys(recipients).length && Object.entries(recipients).every(([to, amount]) => value.recipients[to] === amount.toString());
  // Plans can execute out of preparation order. Reconcile receipts in execution-event order.
  executed.sort((a, b) => simulatedEvents.get(a.id).index - simulatedEvents.get(b.id).index);
  for (const op of executed) {
    if (!matchesLedger(op.receipt.before)) invalid();
    const total = op.plan.transfers.reduce((sum, t) => sum + BigInt(t.amount), 0n);
    if (simulatedEvents.get(op.id).detail.amount !== total.toString()) invalid();
    balance -= total;
    for (const t of op.plan.transfers) recipients[t.to] = (recipients[t.to] ?? 0n) + BigInt(t.amount);
    const cumulative = (usage.get(op.plan.policyId) ?? 0n) + total; usage.set(op.plan.policyId, cumulative);
    if (balance < 0n || !matchesLedger(op.receipt.after) || op.receipt.cumulativeUsed !== cumulative.toString()) invalid();
  }
  if (!matchesLedger(state.ledger) || policy.used !== (usage.get(policy.id) ?? 0n).toString()) invalid();
  const scenarioIds = new Set();
  for (const s of state.scenarios) {
    if (!record(s) || !id(s.id) || scenarioIds.has(s.id) || !timestamp(s.at) || typeof s.passed !== 'boolean' ||
        !Array.isArray(s.operationIds) || s.operationIds.length !== 5 || new Set(s.operationIds).size !== 5 ||
        !s.operationIds.every(opId => operations.has(opId)) || !Array.isArray(s.expected) || !Array.isArray(s.actual) ||
        s.expected.join(',') !== 'simulated,blocked,simulated,blocked,blocked' || s.actual.length !== 5 ||
        !s.actual.every((status, index) => status === operations.get(s.operationIds[index]).status) ||
        s.passed !== s.actual.every((status, index) => status === s.expected[index])) invalid();
    scenarioIds.add(s.id);
  }
  return state;
}
function event(state, type, operationId, detail = {}) {
  const payload = { index: state.events.length + 1, at: now(), type, operationId,
    policyId: state.policy.id, detail, previousHash: state.events.at(-1)?.hash ?? null };
  state.events.push({ ...payload, hash: digest(payload) });
}
function operation(state, id) {
  const found = state.operations.find(op => op.id === id);
  if (!found) fail('NOT_FOUND', 'The transfer request was not found.');
  return found;
}
function planPayload(state, transfers) {
  return { mode: state.mode, chainId: state.policy.chainId, principal: state.principal,
    agent: state.agent, assetId: state.asset.id, tokenAddress: null,
    policyId: state.policy.id, policyVersion: state.policy.version, transfers };
}
export function plan(state, input) {
  strictObject(input, ['operationId', 'transfers']);
  if (typeof input.operationId !== 'string' || !/^[a-zA-Z0-9_-]{8,80}$/.test(input.operationId)) {
    fail('INVALID_ID', 'The request ID is invalid.');
  }
  if (!Array.isArray(input.transfers) || input.transfers.length < 1 || input.transfers.length > 20) {
    fail('INVALID_INPUT', 'Provide between one and twenty transfers.');
  }
  const transfers = input.transfers.map(t => {
    strictObject(t, ['to', 'amount']);
    return { to: address(t.to), amount: units(t.amount) };
  });
  const inputHash = digest(transfers);
  const existing = state.operations.find(op => op.id === input.operationId);
  if (existing) {
    if (existing.inputHash !== inputHash) fail('ID_CONFLICT', 'The ID belongs to a different transfer request.');
    return existing;
  }
  if (state.operations.length >= 2000) fail('DEMO_FULL', 'The demo activity limit has been reached. Preserve the log before continuing.');
  const payload = planPayload(state, transfers);
  const op = { id: input.operationId, inputHash, plan: payload, planHash: digest(payload),
    createdAt: now(), status: 'planned', checks: [], approval: null, receipt: null };
  state.operations.push(op);
  event(state, 'planned', op.id, { planHash: op.planHash });
  return op;
}
function checks(state, op) {
  const total = op.plan.transfers.reduce((sum, t) => sum + BigInt(t.amount), 0n);
  return [
    { code: 'PLAN_INTEGRITY', ok: digest(op.plan) === op.planHash },
    { code: 'SIMULATION_ONLY', ok: op.plan.mode === 'simulation' && op.plan.assetId === ASSET.id && op.plan.tokenAddress === null },
    { code: 'IDENTITY', ok: op.plan.principal === state.principal && op.plan.agent === state.agent && op.plan.chainId === '11155111' },
    { code: 'POLICY_ACTIVE', ok: state.policy.active },
    { code: 'POLICY_CURRENT', ok: op.plan.policyId === state.policy.id && op.plan.policyVersion === state.policy.version },
    { code: 'RECIPIENT', ok: op.plan.transfers.every(t => state.policy.recipients.includes(t.to)) },
    { code: 'TRANSACTION_LIMIT', ok: op.plan.transfers.every(t => BigInt(t.amount) <= BigInt(state.policy.maxTransaction)) },
    { code: 'CUMULATIVE_LIMIT', ok: total + BigInt(state.policy.used) <= BigInt(state.policy.maxCumulative) },
    { code: 'BALANCE', ok: total <= BigInt(state.ledger.principalBalance) },
    { code: 'ALLOWANCE', ok: total <= BigInt(state.ledger.allowance) }
  ];
}
function block(state, op, results) {
  op.status = 'blocked'; op.checks = results;
  op.receipt = { evidence: 'local-simulation', transactionHash: null, at: now(),
    outcome: 'blocked', reason: results.find(c => !c.ok)?.code ?? 'UNKNOWN' };
  event(state, 'blocked', op.id, { reason: op.receipt.reason });
  return op;
}
export function preflight(state, id) {
  const op = operation(state, id);
  if (TERMINAL.has(op.status)) return op;
  const results = checks(state, op);
  if (results.some(c => !c.ok)) return block(state, op, results);
  op.checks = results;
  if (op.status !== 'approved') op.status = 'checked';
  event(state, 'checked', op.id);
  return op;
}
export function approve(state, id, planHash) {
  const op = operation(state, id);
  if (op.planHash !== planHash) fail('PLAN_CHANGED', 'The transfer request changed. Review the new plan.');
  if (TERMINAL.has(op.status) || op.status === 'approved') return op;
  if (op.status !== 'checked') fail('NOT_CHECKED', 'Check the transfer request before approving it.');
  const results = checks(state, op);
  if (results.some(c => !c.ok)) return block(state, op, results);
  op.approval = { planHash, at: now(), actor: 'local-owner-ui' };
  op.status = 'approved';
  event(state, 'approved', op.id, { planHash });
  return op;
}
export function execute(state, id, planHash) {
  const op = operation(state, id);
  if (op.planHash !== planHash) fail('PLAN_CHANGED', 'The execution request does not match the approved plan.');
  if (TERMINAL.has(op.status)) return op;
  if (op.status !== 'approved' || op.approval?.planHash !== planHash) {
    fail('NOT_APPROVED', 'Owner approval is missing.');
  }
  const results = checks(state, op);
  if (results.some(c => !c.ok)) return block(state, op, results);
  const total = op.plan.transfers.reduce((sum, t) => sum + BigInt(t.amount), 0n);
  const before = structuredClone(state.ledger);
  state.ledger.principalBalance = (BigInt(before.principalBalance) - total).toString();
  state.ledger.allowance = (BigInt(before.allowance) - total).toString();
  state.policy.used = (BigInt(state.policy.used) + total).toString();
  for (const t of op.plan.transfers) {
    state.ledger.recipients[t.to] = (BigInt(state.ledger.recipients[t.to] ?? '0') + BigInt(t.amount)).toString();
  }
  op.checks = results; op.status = 'simulated';
  op.receipt = { evidence: 'local-simulation', transactionHash: null, at: now(), outcome: 'simulated',
    before, after: structuredClone(state.ledger), cumulativeUsed: state.policy.used };
  event(state, 'simulated', op.id, { amount: total.toString(), planHash });
  return op;
}
export function revoke(state) {
  if (state.policy.active) {
    state.policy.active = false; state.policy.revokedAt = now(); state.policy.version++;
    event(state, 'revoked', null);
  }
  return state.policy;
}
export function grant(state, input) {
  strictObject(input, ['maxTransaction', 'maxCumulative', 'recipients']);
  const maxTransaction = units(input.maxTransaction);
  const maxCumulative = units(input.maxCumulative);
  if (BigInt(maxTransaction) > BigInt(maxCumulative)) fail('INVALID_LIMITS', 'The limit per transfer must not exceed the total limit.');
  if (!Array.isArray(input.recipients) || !input.recipients.length || input.recipients.length > 20) fail('INVALID_INPUT', 'Provide between one and twenty allowed recipients.');
  const recipients = [...new Set(input.recipients.map(address))];
  state.policy = { id: randomUUID(), version: state.policy.version + 1, active: true,
    chainId: '11155111', maxTransaction, maxCumulative, used: '0', recipients, createdAt: now(), revokedAt: null };
  event(state, 'granted', null, { maxTransaction, maxCumulative, recipients });
  return state.policy;
}
export function getReceipt(state, id) { return operation(state, id); }
export function scenario(state) {
  const scenarioId = randomUUID();
  // A new grant does not erase previous operations, balances, or evidence.
  grant(state, { maxTransaction: '60', maxCumulative: '100', recipients: [RECIPIENT, SECOND_RECIPIENT] });
  if (BigInt(state.ledger.principalBalance) < BigInt(units('80')) || BigInt(state.ledger.allowance) < BigInt(units('80'))) {
    fail('DEMO_BALANCE', 'The example sequence requires at least 80 demo tokens and a matching allowance.');
  }
  const ids = [];
  for (const amount of ['30', '80', '50', '25', '1']) {
    if (amount === '1') revoke(state);
    const op = plan(state, { operationId: randomUUID(), transfers: [{ to: RECIPIENT, amount }] });
    ids.push(op.id);
    preflight(state, op.id);
    if (op.status === 'checked') { approve(state, op.id, op.planHash); execute(state, op.id, op.planHash); }
  }
  const expected = ['simulated', 'blocked', 'simulated', 'blocked', 'blocked'];
  const actual = ids.map(id => operation(state, id).status);
  const result = { id: scenarioId, at: now(), operationIds: ids, expected, actual,
    passed: actual.every((value, i) => value === expected[i]) && state.policy.used === units('80') };
  state.scenarios.push(result);
  event(state, 'scenario', null, { scenarioId, passed: result.passed });
  return result;
}
