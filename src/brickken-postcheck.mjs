// Offline semantic postchecks for normalized, block-bound Ethereum fixtures.
// ABI evidence (verified source/ABI, read 2026-09-14):
// https://eth-sepolia.blockscout.com/api/v2/smart-contracts/0xd68e1bb972ca4ef7f5764fbf6d685a6dfc26778e
// https://eth-sepolia.blockscout.com/api/v2/smart-contracts/0xff666ccd01541cd7abcabb70dba1cffec8c01d9b
// The executor emits no setAction event; that operation is proven by its exact
// transaction identity and the post-state of actions(selector).

/**
 * All five verifiers accept one closed normalized envelope:
 * `{schemaVersion:1, operationKind, expected:{transaction,semantics},
 * transaction, receipt, before, after, observedAt}`.
 *
 * `expected.transaction` has hash, chainId, from, to, value, data, nonce,
 * type, gasLimit, maxPriorityFeePerGas and maxFeePerGas. `transaction` adds
 * blockNumber and blockHash. All uints are decimal strings and type is 2.
 * `receipt` is exactly `{transactionHash,status:1,from,to,blockNumber,
 * blockHash,logs}`. Each raw log is exactly `{address,topics,data,
 * transactionHash,blockNumber,blockHash,logIndex,removed:false}`.
 * `before` and `after` are `{blockNumber,blockHash,state}`; before must be from
 * an earlier block and after must be bound to the receipt block.
 *
 * Per-operation semantics/state:
 * Each verifier's second argument is a separately retained trustedExpected;
 * the observed envelope's expected member must match it exactly.
 * - setAction: semantics executor/owner/selector/supported/hasAmount/amountIndex; state action.
 * - approve: semantics token/owner/spender/amount; state allowance.
 * - grant: semantics registry/agent/principal/complianceProvider/asset/
 *   validFrom/validUntil/identityRef/metadata/action/maxTransactionValue/
 *   maxCumulativeValue; state mandate/actionEnabled.
 * - execute: semantics registry/executor/token/agent/principal/recipient/action/
 *   amount/maxTransactionValue/maxCumulativeValue/canExecuteAfter; state
 *   principalBalance/recipientBalance/allowance/mandate/
 *   canExecute.
 * - revoke: semantics registry/agent/principal/revokedBy; state mandate/
 *   actionEnabled/canExecute.
 *
 * Inputs are decoded fixture observations, not trusted RPC proof. Successful
 * reports retain that limit in scope and do not claim confirmation depth or
 * independent-provider authenticity.
 */
import { EXECUTE_SELECTOR, SET_ACTION_SELECTOR } from './brickken-executor.mjs';

export const EVENT_TOPICS = Object.freeze({
  ActionEnabled: '0x316f74c6786cc19120fec870fcd1b65bbbd870b16d68279ae2c078d6d841489c',
  ExecutionRecorded: '0x9965291c5f1e655978720fae88e659c3ca252225e140537d71d73f171957c286',
  MandateGranted: '0xa720148a55b2de704c883b2621c396494982d2fa5d5d0eb46b1edf895fe3ab83',
  MandateRevoked: '0x1f38774437a6ad21407eb7409f803938005636221a15641c63dea2d13aacbbd6',
  Approval: '0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925',
  Transfer: '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
});

const verifiedReports = new WeakSet();
export function isVerifiedBrickkenPostcheck(value) { return verifiedReports.has(value); }

const EXPECTED_TX_KEYS = [
  'hash', 'chainId', 'from', 'to', 'value', 'data', 'nonce', 'type', 'gasLimit',
  'maxPriorityFeePerGas', 'maxFeePerGas'
];
const OBSERVED_TX_KEYS = [...EXPECTED_TX_KEYS, 'blockNumber', 'blockHash'];
const RECEIPT_KEYS = ['transactionHash', 'status', 'from', 'to', 'blockNumber', 'blockHash', 'logs'];
const LOG_KEYS = ['address', 'topics', 'data', 'transactionHash', 'blockNumber', 'blockHash', 'logIndex', 'removed'];
const MANDATE_KEYS = [
  'agent', 'validFrom', 'validUntil', 'principal', 'revoked', 'complianceProvider',
  'identityRef', 'asset', 'maxTransactionValue', 'maxCumulativeValue',
  'cumulativeUsed', 'metadata'
];
const SCOPE = Object.freeze({
  normalizedFixtureInputOnly: true,
  abiSourceMatched: true,
  rpcAuthenticityVerified: false,
  independentRpcVerified: false,
  confirmationDepthVerified: false
});
// Live runs feed the same verifiers with block-bound Sepolia RPC reads. Their
// reports say so; two-source block agreement and depth live in the live journal.
const LIVE_SCOPE = Object.freeze({
  normalizedFixtureInputOnly: false,
  blockBoundRpcObservation: true,
  abiSourceMatched: true,
  rpcAuthenticityVerified: false,
  independentRpcVerified: false,
  confirmationDepthVerified: false
});
// A cleanup revocation may end a mandate that was already non-executable, so
// its report records the prior executability and claims no demonstration that
// the revoke itself removed the right to execute.
const LIVE_CLEANUP_REVOCATION_SCOPE = Object.freeze({ ...LIVE_SCOPE, cleanupRevocation: true, revocationEffectDemonstrated: false });

export class BrickkenPostcheckError extends Error {
  constructor(code) { super(code); this.name = 'BrickkenPostcheckError'; this.code = code; }
}
function fail(code) { throw new BrickkenPostcheckError(code); }
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value));
}
function shape(value, keys, code = 'STRUCTURE') {
  if (!plain(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) fail(code);
}
function uint(value) {
  if (typeof value !== 'string' || value.length > 78 || !/^(0|[1-9][0-9]*)$/.test(value)) fail('INTEGER');
  return value;
}
function address(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) fail('ADDRESS');
  return value.toLowerCase();
}
function hash32(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value)) fail('HASH');
  return value.toLowerCase();
}
function bytes(value, maximumBytes = 256 * 1024) {
  if (typeof value !== 'string' || !/^0x(?:[0-9a-fA-F]{2})*$/.test(value) || (value.length - 2) / 2 > maximumBytes) fail('BYTES');
  return value.toLowerCase();
}
function iso(value) {
  if (typeof value !== 'string' || new Date(value).toISOString() !== value) fail('TIME');
  return value;
}
function bool(value) { if (typeof value !== 'boolean') fail('BOOLEAN'); return value; }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (plain(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function equal(left, right) { return canonical(left) === canonical(right); }
function check(condition, code) { if (!condition) fail(code); }
function normalizedTransaction(value, observed) {
  shape(value, observed ? OBSERVED_TX_KEYS : EXPECTED_TX_KEYS, 'TRANSACTION');
  const result = {
    hash: hash32(value.hash), chainId: uint(value.chainId), from: address(value.from), to: address(value.to),
    value: uint(value.value), data: bytes(value.data), nonce: uint(value.nonce), type: value.type,
    gasLimit: uint(value.gasLimit), maxPriorityFeePerGas: uint(value.maxPriorityFeePerGas),
    maxFeePerGas: uint(value.maxFeePerGas)
  };
  if (result.type !== 2 || BigInt(result.maxPriorityFeePerGas) > BigInt(result.maxFeePerGas)) fail('TRANSACTION');
  if (observed) {
    result.blockNumber = uint(value.blockNumber); result.blockHash = hash32(value.blockHash);
  }
  return result;
}
function normalizeLog(value, receipt) {
  shape(value, LOG_KEYS, 'LOG');
  if (!Array.isArray(value.topics) || value.topics.length < 1 || value.topics.length > 4) fail('LOG');
  const result = {
    address: address(value.address), topics: value.topics.map(hash32), data: bytes(value.data, 4096),
    transactionHash: hash32(value.transactionHash), blockNumber: uint(value.blockNumber),
    blockHash: hash32(value.blockHash), logIndex: uint(value.logIndex), removed: bool(value.removed)
  };
  check(result.transactionHash === receipt.transactionHash && result.blockNumber === receipt.blockNumber &&
    result.blockHash === receipt.blockHash && result.removed === false, 'LOG_IDENTITY');
  return result;
}
function normalizeReceipt(value) {
  shape(value, RECEIPT_KEYS, 'RECEIPT');
  const result = {
    transactionHash: hash32(value.transactionHash), status: value.status,
    from: address(value.from), to: address(value.to), blockNumber: uint(value.blockNumber),
    blockHash: hash32(value.blockHash), logs: []
  };
  if (result.status !== 1 || !Array.isArray(value.logs) || value.logs.length > 256) fail('RECEIPT_STATUS');
  result.logs = value.logs.map(log => normalizeLog(log, result));
  const indexes = new Set();
  for (const log of result.logs) {
    if (indexes.has(log.logIndex)) fail('LOG_IDENTITY');
    indexes.add(log.logIndex);
  }
  return result;
}
function snapshot(value, stateKeys) {
  shape(value, ['blockNumber', 'blockHash', 'state'], 'SNAPSHOT');
  uint(value.blockNumber); hash32(value.blockHash); shape(value.state, stateKeys, 'SNAPSHOT_STATE');
  return value;
}
function topicAddress(value) {
  const topic = hash32(value);
  if (!topic.startsWith('0x' + '0'.repeat(24))) fail('EVENT_PADDING');
  return address('0x' + topic.slice(-40));
}
function topicBytes32(value) { return hash32(value); }
function words(data, count) {
  const value = bytes(data, 32 * count);
  if (value.length !== 2 + count * 64) fail('EVENT_DATA');
  return Array.from({ length: count }, (_, index) => value.slice(2 + index * 64, 2 + (index + 1) * 64));
}
function wordAddress(value) {
  if (!value.startsWith('0'.repeat(24))) fail('EVENT_PADDING');
  return address('0x' + value.slice(24));
}
function wordUint(value, bits = 256) {
  if (!/^[0-9a-f]{64}$/.test(value)) fail('EVENT_DATA');
  const parsed = BigInt('0x' + value);
  if (parsed >= (1n << BigInt(bits))) fail('EVENT_WIDTH');
  return parsed.toString();
}
function oneEvent(receipt, contract, topic) {
  const matches = receipt.logs.filter(log => log.address === address(contract) && log.topics[0] === topic);
  if (matches.length !== 1) fail('EVENT_COUNT');
  return matches[0];
}
function mandate(value) {
  shape(value, MANDATE_KEYS, 'MANDATE');
  return {
    agent: address(value.agent), validFrom: uint(value.validFrom), validUntil: uint(value.validUntil),
    principal: address(value.principal), revoked: bool(value.revoked), complianceProvider: address(value.complianceProvider),
    identityRef: hash32(value.identityRef), asset: address(value.asset), maxTransactionValue: uint(value.maxTransactionValue),
    maxCumulativeValue: uint(value.maxCumulativeValue), cumulativeUsed: uint(value.cumulativeUsed), metadata: hash32(value.metadata)
  };
}
function normalizeEnvelope(input, trustedExpected, operationKind, semanticKeys, stateKeys) {
  shape(input, ['schemaVersion', 'operationKind', 'expected', 'transaction', 'receipt', 'before', 'after', 'observedAt']);
  if (input.schemaVersion !== 1 || input.operationKind !== operationKind) fail('OPERATION_KIND');
  shape(input.expected, ['transaction', 'semantics'], 'EXPECTED');
  shape(trustedExpected, ['transaction', 'semantics'], 'TRUSTED_EXPECTATION_REQUIRED');
  check(equal(input.expected, trustedExpected), 'TRUSTED_EXPECTATION_MISMATCH');
  shape(input.expected.semantics, semanticKeys, 'SEMANTICS');
  const expected = normalizedTransaction(input.expected.transaction, false);
  const transaction = normalizedTransaction(input.transaction, true);
  const receipt = normalizeReceipt(input.receipt);
  const before = snapshot(input.before, stateKeys);
  const after = snapshot(input.after, stateKeys);
  iso(input.observedAt);
  const { blockNumber, blockHash, ...minedTransaction } = transaction;
  check(equal(minedTransaction, expected), 'TRANSACTION_IDENTITY');
  check(receipt.transactionHash === transaction.hash && receipt.from === transaction.from && receipt.to === transaction.to &&
    receipt.blockNumber === blockNumber && receipt.blockHash === blockHash, 'RECEIPT_IDENTITY');
  check(after.blockNumber === receipt.blockNumber && after.blockHash.toLowerCase() === receipt.blockHash &&
    BigInt(before.blockNumber) < BigInt(receipt.blockNumber), 'SNAPSHOT_IDENTITY');
  return { semantics: input.expected.semantics, expected, transaction, receipt, before, after, observedAt: input.observedAt };
}
function report(operationKind, normalized, checks, scope = SCOPE) {
  const value = deepFreeze({
    schemaVersion: 1, kind: 'brickken-semantic-postcheck', operationKind,
    transactionHash: normalized.transaction.hash, blockNumber: normalized.receipt.blockNumber,
    blockHash: normalized.receipt.blockHash, verified: true, checks, scope,
    observedAt: normalized.observedAt
  });
  verifiedReports.add(value);
  return value;
}
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value); for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}
function scopeFor(options) {
  if (options === undefined) return SCOPE;
  if (!plain(options) || options.observationSource !== 'sepolia-rpc-block-bound') fail('OPTIONS');
  const keys = Object.keys(options);
  if (keys.length === 1) return LIVE_SCOPE;
  if (keys.length === 2 && options.cleanupRevocation === true) return LIVE_CLEANUP_REVOCATION_SCOPE;
  return fail('OPTIONS');
}
function actionState(value) {
  shape(value, ['supported', 'hasAmount', 'amountIndex'], 'ACTION_STATE');
  if (!Number.isSafeInteger(value.amountIndex) || value.amountIndex < 0 || value.amountIndex > 255) fail('ACTION_STATE');
  return { supported: bool(value.supported), hasAmount: bool(value.hasAmount), amountIndex: value.amountIndex };
}

export function verifySetActionPostcheck(input, trustedExpected, options) {
  const scope = scopeFor(options);
  const n = normalizeEnvelope(input, trustedExpected, 'setAction', ['executor', 'owner', 'selector', 'supported', 'hasAmount', 'amountIndex'], ['action']);
  const s = n.semantics;
  if (typeof s.selector !== 'string' || !/^0x[0-9a-fA-F]{8}$/.test(s.selector) ||
      !Number.isSafeInteger(s.amountIndex) || s.amountIndex < 0 || s.amountIndex > 255) fail('SEMANTICS');
  const before = actionState(n.before.state.action), after = actionState(n.after.state.action);
  const expectedAfter = { supported: bool(s.supported), hasAmount: bool(s.hasAmount), amountIndex: s.amountIndex };
  check(n.transaction.from === address(s.owner) && n.transaction.to === address(s.executor), 'SEMANTIC_TRANSACTION_MISMATCH');
  const setActionData = n.transaction.data;
  check(setActionData.length === 2 + 4 * 2 + 4 * 64 && setActionData.slice(0, 10) === SET_ACTION_SELECTOR &&
    // bytes4 is left-aligned in its ABI word, as the executor encoder and ethers produce it.
    setActionData.slice(10, 74) === s.selector.slice(2).toLowerCase() + '0'.repeat(56) &&
    BigInt('0x' + setActionData.slice(74, 138)) === (s.supported ? 1n : 0n) &&
    BigInt('0x' + setActionData.slice(138, 202)) === (s.hasAmount ? 1n : 0n) &&
    BigInt('0x' + setActionData.slice(202, 266)) === BigInt(s.amountIndex), 'SEMANTIC_CALLDATA_MISMATCH');
  check(equal(after, expectedAfter) && !equal(before, after), 'ACTION_STATE_MISMATCH');
  return report('setAction', n, ['exact-transaction', 'receipt-block-identity', 'action-state-transition'], scope);
}

export function verifyApprovePostcheck(input, trustedExpected, options) {
  const scope = scopeFor(options);
  const n = normalizeEnvelope(input, trustedExpected, 'approve', ['token', 'owner', 'spender', 'amount'], ['allowance']);
  const s = n.semantics;
  const token = address(s.token), owner = address(s.owner), spender = address(s.spender), amount = uint(s.amount);
  const before = uint(n.before.state.allowance), after = uint(n.after.state.allowance);
  check(n.transaction.from === owner && n.transaction.to === token, 'SEMANTIC_TRANSACTION_MISMATCH');
  const approvalData = n.transaction.data;
  check(approvalData.length === 2 + 68 * 2 && approvalData.slice(0, 10) === '0x095ea7b3' &&
    wordAddress(approvalData.slice(10, 74)) === spender && wordUint(approvalData.slice(74, 138)) === amount,
  'SEMANTIC_CALLDATA_MISMATCH');
  check(after === amount, 'ALLOWANCE_MISMATCH');
  const event = oneEvent(n.receipt, token, EVENT_TOPICS.Approval);
  check(event.topics.length === 3 && topicAddress(event.topics[1]) === owner && topicAddress(event.topics[2]) === spender &&
    wordUint(words(event.data, 1)[0]) === amount, 'APPROVAL_EVENT_MISMATCH');
  return report('approve', n, ['exact-transaction', 'receipt-block-identity', 'approval-event', `allowance:${before}->${after}`], scope);
}

export function verifyGrantPostcheck(input, trustedExpected, options) {
  const scope = scopeFor(options);
  const n = normalizeEnvelope(input, trustedExpected, 'grant', [
    'registry', 'agent', 'principal', 'complianceProvider', 'asset', 'validFrom', 'validUntil',
    'identityRef', 'metadata', 'action', 'maxTransactionValue', 'maxCumulativeValue'
  ], ['mandate', 'actionEnabled']);
  const s = n.semantics;
  const expected = {
    agent: address(s.agent), validFrom: uint(s.validFrom), validUntil: uint(s.validUntil), principal: address(s.principal),
    revoked: false, complianceProvider: address(s.complianceProvider), identityRef: hash32(s.identityRef), asset: address(s.asset),
    maxTransactionValue: uint(s.maxTransactionValue), maxCumulativeValue: uint(s.maxCumulativeValue), cumulativeUsed: '0',
    metadata: hash32(s.metadata)
  };
  const beforeMandate = n.before.state.mandate === null ? null : mandate(n.before.state.mandate);
  const afterMandate = mandate(n.after.state.mandate);
  check(n.transaction.from === expected.principal && n.transaction.to === address(s.registry), 'SEMANTIC_TRANSACTION_MISMATCH');
  const grantCallData = n.transaction.data;
  const grantWords = words('0x' + grantCallData.slice(10), 17);
  check(grantCallData.slice(0, 10) === '0xc6a4ad00' && wordUint(grantWords[0]) === '64' && wordUint(grantWords[1]) === '512' &&
    wordAddress(grantWords[2]) === expected.agent && wordUint(grantWords[3], 48) === expected.validFrom &&
    wordUint(grantWords[4], 48) === expected.validUntil && wordAddress(grantWords[5]) === expected.principal &&
    wordAddress(grantWords[6]) === expected.complianceProvider && '0x' + grantWords[7] === expected.identityRef &&
    wordAddress(grantWords[8]) === expected.asset && wordUint(grantWords[9]) === expected.maxTransactionValue &&
    wordUint(grantWords[10]) === expected.maxCumulativeValue && '0x' + grantWords[11] === expected.metadata &&
    wordUint(grantWords[12]) === '384' && wordUint(grantWords[13]) === '0' && wordUint(grantWords[14]) === '1' &&
    '0x' + grantWords[15] === hash32(s.action) && wordUint(grantWords[16]) === '0', 'SEMANTIC_CALLDATA_MISMATCH');
  // Two before-states are accepted, both read from the registry's state machine
  // (AgentMandate.grantMandate reverts only for an active mandate, and
  // revokeMandate sets the revoked flag without clearing the enabled actions):
  // a first grant for the pair, where no mandate or a revoked one exists and
  // the action is not enabled; and a reuse of the same agent and principal
  // pair, where the earlier mandate is revoked and the action stayed enabled.
  // An active earlier mandate, a different pair or an enabled action without a
  // revoked mandate of this pair is stale state.
  const samePair = beforeMandate !== null && beforeMandate.agent === expected.agent && beforeMandate.principal === expected.principal;
  const firstGrant = (beforeMandate === null || beforeMandate.revoked === true) && n.before.state.actionEnabled === false;
  const pairReuse = samePair && beforeMandate.revoked === true && n.before.state.actionEnabled === true;
  check(firstGrant || pairReuse, 'STALE_GRANT_STATE');
  check(equal(afterMandate, expected) && n.after.state.actionEnabled === true, 'MANDATE_STATE_MISMATCH');
  const registry = address(s.registry), granted = oneEvent(n.receipt, registry, EVENT_TOPICS.MandateGranted);
  const enabled = oneEvent(n.receipt, registry, EVENT_TOPICS.ActionEnabled);
  const grantData = words(granted.data, 5);
  check(granted.topics.length === 3 && topicAddress(granted.topics[1]) === expected.agent &&
    topicAddress(granted.topics[2]) === expected.principal && wordAddress(grantData[0]) === expected.complianceProvider &&
    wordAddress(grantData[1]) === expected.asset && wordUint(grantData[2], 48) === expected.validFrom &&
    wordUint(grantData[3], 48) === expected.validUntil && '0x' + grantData[4] === expected.metadata,
  'MANDATE_GRANTED_EVENT_MISMATCH');
  check(enabled.topics.length === 4 && topicAddress(enabled.topics[1]) === expected.agent &&
    topicAddress(enabled.topics[2]) === expected.principal && topicBytes32(enabled.topics[3]) === hash32(s.action) &&
    enabled.data === '0x', 'ACTION_ENABLED_EVENT_MISMATCH');
  return report('grant', n, ['exact-transaction', 'receipt-block-identity', 'mandate-granted-event', 'action-enabled-event', 'mandate-state'], scope);
}

export function verifyExecutePostcheck(input, trustedExpected, options) {
  const scope = scopeFor(options);
  const n = normalizeEnvelope(input, trustedExpected, 'execute', ['registry', 'executor', 'token', 'agent', 'principal', 'recipient', 'action', 'amount', 'maxTransactionValue', 'maxCumulativeValue', 'canExecuteAfter'],
    ['principalBalance', 'recipientBalance', 'allowance', 'mandate', 'canExecute']);
  const s = n.semantics;
  const registry = address(s.registry), token = address(s.token), agent = address(s.agent), principal = address(s.principal),
    recipient = address(s.recipient), action = hash32(s.action), amount = BigInt(uint(s.amount));
  const beforeMandate = mandate(n.before.state.mandate), afterMandate = mandate(n.after.state.mandate);
  const beforePrincipal = BigInt(uint(n.before.state.principalBalance));
  const afterPrincipal = BigInt(uint(n.after.state.principalBalance));
  const beforeRecipient = BigInt(uint(n.before.state.recipientBalance));
  const afterRecipient = BigInt(uint(n.after.state.recipientBalance));
  const beforeAllowance = BigInt(uint(n.before.state.allowance));
  const afterAllowance = BigInt(uint(n.after.state.allowance));
  check(n.transaction.from === agent && n.transaction.to === address(s.executor), 'SEMANTIC_TRANSACTION_MISMATCH');
  check(beforeMandate.agent === agent && beforeMandate.principal === principal && beforeMandate.asset === token &&
    beforeMandate.maxTransactionValue === uint(s.maxTransactionValue) &&
    beforeMandate.maxCumulativeValue === uint(s.maxCumulativeValue), 'MANDATE_SEMANTICS_MISMATCH');
  const callData = n.transaction.data;
  const outerWords = words('0x' + callData.slice(10), 7);
  const innerLength = Number(BigInt('0x' + outerWords[2]));
  const inner = '0x' + outerWords.slice(3).join('').slice(0, innerLength * 2);
  check(callData.slice(0, 10) === EXECUTE_SELECTOR && wordAddress(outerWords[0]) === token &&
    wordUint(outerWords[1]) === '64' && innerLength === 100 && inner.slice(0, 10) === '0x23b872dd' &&
    wordAddress(inner.slice(10, 74)) === principal && wordAddress(inner.slice(74, 138)) === recipient &&
    wordUint(inner.slice(138, 202)) === amount.toString(), 'SEMANTIC_CALLDATA_MISMATCH');
  check(n.before.state.canExecute === true && n.after.state.canExecute === bool(s.canExecuteAfter), 'EXECUTABILITY_MISMATCH');
  check(beforePrincipal >= amount && beforeAllowance >= amount && afterPrincipal === beforePrincipal - amount &&
    afterRecipient === beforeRecipient + amount && afterAllowance === beforeAllowance - amount,
  'TOKEN_DELTA_MISMATCH');
  const expectedMandate = { ...beforeMandate, cumulativeUsed: (BigInt(beforeMandate.cumulativeUsed) + amount).toString() };
  check(equal(afterMandate, expectedMandate), 'CUMULATIVE_DELTA_MISMATCH');
  const transfer = oneEvent(n.receipt, token, EVENT_TOPICS.Transfer);
  check(transfer.topics.length === 3 && topicAddress(transfer.topics[1]) === principal &&
    topicAddress(transfer.topics[2]) === recipient && wordUint(words(transfer.data, 1)[0]) === amount.toString(),
  'TRANSFER_EVENT_MISMATCH');
  const execution = oneEvent(n.receipt, registry, EVENT_TOPICS.ExecutionRecorded);
  const executionData = words(execution.data, 2);
  check(execution.topics.length === 4 && topicAddress(execution.topics[1]) === agent &&
    topicAddress(execution.topics[2]) === principal && topicBytes32(execution.topics[3]) === action &&
    wordUint(executionData[0]) === amount.toString() && wordUint(executionData[1]) === afterMandate.cumulativeUsed,
  'EXECUTION_EVENT_MISMATCH');
  return report('execute', n, [
    'exact-transaction', 'receipt-block-identity', 'transfer-event', 'execution-recorded-event',
    'balance-deltas', 'allowance-delta', 'cumulative-delta'
  ], scope);
}

export function verifyRevokePostcheck(input, trustedExpected, options) {
  const scope = scopeFor(options);
  const n = normalizeEnvelope(input, trustedExpected, 'revoke', ['registry', 'agent', 'principal', 'revokedBy'],
    ['mandate', 'actionEnabled', 'canExecute']);
  const s = n.semantics;
  const before = mandate(n.before.state.mandate), after = mandate(n.after.state.mandate);
  check(n.transaction.from === address(s.revokedBy) && n.transaction.to === address(s.registry) &&
    before.agent === address(s.agent) && before.principal === address(s.principal), 'SEMANTIC_TRANSACTION_MISMATCH');
  const revokeWords = words('0x' + n.transaction.data.slice(10), 5);
  check(n.transaction.data.slice(0, 10) === '0x5e20639e' && wordAddress(revokeWords[0]) === address(s.agent) &&
    wordAddress(revokeWords[1]) === address(s.principal) && wordUint(revokeWords[2]) === '0' && wordUint(revokeWords[3]) === '128' &&
    wordUint(revokeWords[4]) === '0', 'SEMANTIC_CALLDATA_MISMATCH');
  check(before.revoked === false && after.revoked === true && equal({ ...before, revoked: true }, after), 'REVOCATION_STATE_MISMATCH');
  const cleanup = scope.cleanupRevocation === true;
  const beforeExecutable = bool(n.before.state.canExecute);
  // The normal demonstration requires an executable mandate before the revoke;
  // cleanup only requires that nothing is executable after it.
  check(n.before.state.actionEnabled === n.after.state.actionEnabled && typeof n.before.state.actionEnabled === 'boolean' &&
    (cleanup || beforeExecutable === true) && n.after.state.canExecute === false, 'REVOCATION_EFFECT_MISMATCH');
  const event = oneEvent(n.receipt, s.registry, EVENT_TOPICS.MandateRevoked);
  const eventData = words(event.data, 1);
  check(event.topics.length === 3 && topicAddress(event.topics[1]) === address(s.agent) &&
    topicAddress(event.topics[2]) === address(s.principal) && wordAddress(eventData[0]) === address(s.revokedBy),
  'MANDATE_REVOKED_EVENT_MISMATCH');
  const checks = ['exact-transaction', 'receipt-block-identity', 'mandate-revoked-event', 'revocation-state'];
  checks.push(cleanup ? `cleanup-revocation:before-executable-${beforeExecutable}:after-executable-false` : 'post-revoke-denial-state');
  return report('revoke', n, checks, scope);
}
