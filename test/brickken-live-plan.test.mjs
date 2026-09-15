// Independent test suite for src/brickken-live-plan.mjs. Every calldata,
// read-call and decoder check is cross-verified against the pinned ethers
// bundle used as an independent ABI encoder/decoder (see
// test/brickken-lifecycle.test.mjs for the same pattern), not against the
// module's own internal encoders.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import {
  LIVE_PROPOSAL_FILE,
  LIVE_PROPOSAL_HASH,
  LIVE_COMPLIANCE_PROVIDER,
  LIVE_TOKEN,
  LIVE_READ_ENDPOINTS,
  LIVE_WRITE_STEPS,
  LIVE_STEP_SIGNER,
  LIVE_CONTROL_IDS,
  GRANT_START_TOLERANCE_SECONDS,
  MAX_APPROVAL_LIFETIME_SECONDS,
  RECORDER_ROLE,
  loadLiveProposal,
  validateLiveProposal,
  liveExecutionCall,
  encodeExecuteProbe,
  grantValidFrom,
  expectedCalldata,
  stepTarget,
  stepSignerAddress,
  facadeBody,
  validateFacadeBody,
  checkLiveTransaction,
  maxStepCostWei,
  requiredWei,
  readCalls,
  decodeUintReturn,
  decodeBoolReturn,
  decodeAddressReturn,
  decodeActionSpecReturn,
  decodeMandateReturn,
  decodeRevert,
  controlCalls,
  buildRunApproval,
  validateRunApproval
} from '../src/brickken-live-plan.mjs';
import {
  KNOWN_AGENT, KNOWN_PRINCIPAL, SEPOLIA_CHAIN_ID, TRANSFER_FROM_ACTION, TRANSFER_FROM_SELECTOR
} from '../src/brickken-intent.mjs';
import { PROVISIONED_EXECUTOR } from '../src/brickken-executor.mjs';
import { RAMS_REGISTRY } from '../src/brickken-mandate.mjs';
import { EMPTY_METADATA } from '../src/brickken-lifecycle.mjs';
import { SANDBOX_IDENTITY_REF } from '../src/brickken-prepare.mjs';
import { SEPOLIA_RPC_ENDPOINTS } from '../src/brickken-rpc.mjs';
import { BRICKKEN_RAMS_PREPARE_PATHS } from '../src/brickken-http.mjs';

const require = createRequire(import.meta.url);
const ethers = require('../vendor/ethers-6.17.0/ethers.umd.min.cjs');
const AbiCoder = ethers.AbiCoder.defaultAbiCoder();

// Independent ABI fragments, matching the verified Sepolia deployment ABIs
// described in the review brief, never the module's own encoders.
const mandateAbi = [
  'function grantMandate((address agent,uint48 validFrom,uint48 validUntil,address principal,address complianceProvider,bytes32 identityRef,address asset,uint256 maxTransactionValue,uint256 maxCumulativeValue,bytes32 metadata,bytes32[] actions,uint256 deadline) p,bytes signature)',
  'function revokeMandate(address agent,address principal,uint256 deadline,bytes signature)',
  'function canExecute(address agent,address principal,address asset,bytes32 action,uint256 amount) view returns (bool)',
  'function getMandate(address agent,address principal) view returns (address agent,uint48 validFrom,uint48 validUntil,address principal,bool revoked,address complianceProvider,bytes32 identityRef,address asset,uint256 maxTransactionValue,uint256 maxCumulativeValue,uint256 cumulativeUsed,bytes32 metadata)',
  'function isActionEnabled(address,address,bytes32) view returns (bool)',
  'function isFrozen(address) view returns (bool)',
  'function hasRole(bytes32,address) view returns (bool)',
  'error CannotExecute(address agent,address target,bytes4 selector,uint256 amount)'
];
const executorAbi = [
  'function setAction(bytes4,bool,bool,uint8)',
  'function execute(address target,bytes data)',
  'function actions(bytes4) view returns (bool,bool,uint8)',
  'function rams() view returns (address)',
  'function principal() view returns (address)',
  'function owner() view returns (address)',
  'error OwnableUnauthorizedAccount(address account)'
];
const erc20Abi = [
  'function approve(address spender,uint256 amount) returns (bool)',
  'function transferFrom(address from,address to,uint256 amount) returns (bool)',
  'function balanceOf(address) view returns (uint256)',
  'function allowance(address,address) view returns (uint256)',
  'function decimals() view returns (uint8)'
];
const mandateIface = new ethers.Interface(mandateAbi);
const executorIface = new ethers.Interface(executorAbi);
const erc20Iface = new ethers.Interface(erc20Abi);

const proposal = loadLiveProposal();

function flipLastHexChar(data) {
  const last = data.slice(-1);
  return data.slice(0, -1) + (last === '0' ? '1' : '0');
}

function baseTx(step, overrides = {}) {
  const validFrom = 1_700_000_500;
  const data = step === 'grant' ? expectedCalldata(proposal, 'grant', { validFrom }) : expectedCalldata(proposal, step);
  return {
    chainId: SEPOLIA_CHAIN_ID,
    from: stepSignerAddress(proposal, step),
    to: stepTarget(proposal, step),
    value: '0',
    data,
    nonce: '7',
    gasLimit: String(proposal.gasLimitCaps[step]),
    type: 2,
    maxPriorityFeePerGas: proposal.fees.maxPriorityFeePerGas,
    maxFeePerGas: proposal.fees.maxFeePerGas,
    ...overrides
  };
}

// ---------------------------------------------------------------------------
// 1. Proposal loading, hash pinning and cross-module constant agreement.

test('loadLiveProposal loads and validates the repository proposal file', () => {
  const loaded = loadLiveProposal();
  assert.equal(loaded.kind, 'live-sepolia-proposal');
  assert.equal(loaded.proposalHash, LIVE_PROPOSAL_HASH);
  assert.equal(loaded.chainId, SEPOLIA_CHAIN_ID);
});

test('validateLiveProposal rejects a changed field while the stated proposalHash stays the original', () => {
  const raw = JSON.parse(fs.readFileSync(LIVE_PROPOSAL_FILE, 'utf8'));
  const mutated = structuredClone(raw);
  mutated.limits.maxTransactionValue = '9999';
  assert.throws(() => validateLiveProposal(mutated), { code: 'PROPOSAL_HASH' });
});

test('live constants agree with the RPC and HTTP modules and the proposal binds the exported addresses', () => {
  assert.deepEqual(LIVE_READ_ENDPOINTS, SEPOLIA_RPC_ENDPOINTS);
  assert.deepEqual(proposal.routes.brickkenApi.prepare, BRICKKEN_RAMS_PREPARE_PATHS);
  assert.equal(proposal.principal, KNOWN_PRINCIPAL);
  assert.equal(proposal.agent, KNOWN_AGENT);
  assert.equal(proposal.executor, PROVISIONED_EXECUTOR);
  assert.equal(proposal.registry, RAMS_REGISTRY);
  assert.equal(proposal.complianceProvider, LIVE_COMPLIANCE_PROVIDER);
  assert.equal(proposal.identityRef, SANDBOX_IDENTITY_REF);
  assert.equal(proposal.token.address, LIVE_TOKEN);
});

// ---------------------------------------------------------------------------
// 2. expectedCalldata for every write step, byte-identical to independent
// ethers encoding; grantValidFrom round-trips and rejects bad input.

test('expectedCalldata for setAction matches the independent AgentExecutor encoding', () => {
  const data = expectedCalldata(proposal, 'setAction');
  const independent = executorIface.encodeFunctionData('setAction', [TRANSFER_FROM_SELECTOR, true, true, 2]).toLowerCase();
  assert.equal(data, independent);
});

test('expectedCalldata for approve(15000) and approveReset(0) match the independent ERC-20 encoding', () => {
  assert.equal(proposal.limits.allowance, '15000');
  const approveData = expectedCalldata(proposal, 'approve');
  assert.equal(approveData, erc20Iface.encodeFunctionData('approve', [proposal.executor, 15000n]).toLowerCase());
  const resetData = expectedCalldata(proposal, 'approveReset');
  assert.equal(resetData, erc20Iface.encodeFunctionData('approve', [proposal.executor, 0n]).toLowerCase());
});

test('expectedCalldata for execute matches execute(token, transferFrom(principal, recipient, 10000))', () => {
  assert.equal(proposal.amounts.execute, '10000');
  const data = expectedCalldata(proposal, 'execute');
  const inner = erc20Iface.encodeFunctionData('transferFrom', [proposal.principal, proposal.recipient.address, 10000n]);
  const independent = executorIface.encodeFunctionData('execute', [proposal.token.address, inner]).toLowerCase();
  assert.equal(data, independent);
});

test('expectedCalldata for revoke matches the independent AgentMandate revokeMandate encoding', () => {
  const data = expectedCalldata(proposal, 'revoke');
  const independent = mandateIface.encodeFunctionData('revokeMandate', [KNOWN_AGENT, KNOWN_PRINCIPAL, 0n, '0x']).toLowerCase();
  assert.equal(data, independent);
});

test('expectedCalldata for grant matches the independent AgentMandate grantMandate encoding for two validFrom values', () => {
  for (const validFrom of [1_700_000_000, 1_850_000_000]) {
    const data = expectedCalldata(proposal, 'grant', { validFrom });
    const p = [
      KNOWN_AGENT, validFrom, validFrom + proposal.mandateValiditySeconds, KNOWN_PRINCIPAL,
      LIVE_COMPLIANCE_PROVIDER, SANDBOX_IDENTITY_REF, proposal.token.address,
      BigInt(proposal.limits.maxTransactionValue), BigInt(proposal.limits.maxCumulativeValue),
      EMPTY_METADATA, [TRANSFER_FROM_ACTION], 0n
    ];
    const independent = mandateIface.encodeFunctionData('grantMandate', [p, '0x']).toLowerCase();
    assert.equal(data, independent);
  }
});

test('grantValidFrom round-trips the validFrom word out of grant calldata', () => {
  for (const validFrom of [1_700_000_000, 1_850_000_000]) {
    const data = expectedCalldata(proposal, 'grant', { validFrom });
    assert.equal(grantValidFrom(data), validFrom);
  }
});

test('grantValidFrom rejects a foreign selector and wrong-length calldata', () => {
  const data = expectedCalldata(proposal, 'grant', { validFrom: 1_700_000_000 });
  assert.throws(() => grantValidFrom('0xdeadbeef' + data.slice(10)), { code: 'CALLDATA' });
  assert.throws(() => grantValidFrom(data.slice(0, -2)), { code: 'CALLDATA' });
  assert.throws(() => grantValidFrom(data + '00'), { code: 'CALLDATA' });
});

// ---------------------------------------------------------------------------
// 3. encodeExecuteProbe for the three proposal probe amounts.

test('encodeExecuteProbe matches the independent execute(token, transferFrom(...)) encoding for 11000, 2500 and 10000', () => {
  for (const amount of [11000n, 2500n, 10000n]) {
    const data = encodeExecuteProbe(proposal, amount.toString());
    const inner = erc20Iface.encodeFunctionData('transferFrom', [proposal.principal, proposal.recipient.address, amount]);
    const independent = executorIface.encodeFunctionData('execute', [proposal.token.address, inner]).toLowerCase();
    assert.equal(data, independent);
  }
  assert.equal(encodeExecuteProbe(proposal, '10000'), expectedCalldata(proposal, 'execute'));
});

// ---------------------------------------------------------------------------
// 4. readCalls: every to/data pair byte-identical to independent encoding.

test('readCalls produce to/data byte-identical to the independent ABI encoding for every read', () => {
  const calls = readCalls(proposal);
  const cases = [
    [calls.canExecute('7500'), proposal.registry,
      mandateIface.encodeFunctionData('canExecute', [proposal.agent, proposal.principal, proposal.token.address, TRANSFER_FROM_ACTION, 7500n])],
    [calls.getMandate(), proposal.registry,
      mandateIface.encodeFunctionData('getMandate', [proposal.agent, proposal.principal])],
    [calls.isActionEnabled(), proposal.registry,
      mandateIface.encodeFunctionData('isActionEnabled', [proposal.agent, proposal.principal, TRANSFER_FROM_ACTION])],
    [calls.isFrozen(), proposal.registry,
      mandateIface.encodeFunctionData('isFrozen', [proposal.agent])],
    [calls.hasRecorderRole(), proposal.registry,
      mandateIface.encodeFunctionData('hasRole', [RECORDER_ROLE, proposal.executor])],
    [calls.balanceOf(proposal.principal), proposal.token.address,
      erc20Iface.encodeFunctionData('balanceOf', [proposal.principal])],
    [calls.allowance(), proposal.token.address,
      erc20Iface.encodeFunctionData('allowance', [proposal.principal, proposal.executor])],
    [calls.decimals(), proposal.token.address,
      erc20Iface.encodeFunctionData('decimals', [])],
    [calls.executorAction(), proposal.executor,
      executorIface.encodeFunctionData('actions', [TRANSFER_FROM_SELECTOR])],
    [calls.executorRams(), proposal.executor,
      executorIface.encodeFunctionData('rams', [])],
    [calls.executorPrincipal(), proposal.executor,
      executorIface.encodeFunctionData('principal', [])],
    [calls.executorOwner(), proposal.executor,
      executorIface.encodeFunctionData('owner', [])]
  ];
  for (const [call, to, independentData] of cases) {
    assert.equal(call.to, to);
    assert.equal(call.data, independentData.toLowerCase());
  }
});

// ---------------------------------------------------------------------------
// 5. Decoders.

test('decodeUintReturn decodes a uint256 return word', () => {
  const data = AbiCoder.encode(['uint256'], [123456789n]);
  assert.equal(decodeUintReturn(data), '123456789');
});

test('decodeBoolReturn decodes true/false and rejects a non-boolean word value of 2', () => {
  assert.equal(decodeBoolReturn(AbiCoder.encode(['bool'], [true])), true);
  assert.equal(decodeBoolReturn(AbiCoder.encode(['bool'], [false])), false);
  const dirty = '0x' + '0'.repeat(63) + '2';
  assert.throws(() => decodeBoolReturn(dirty), { code: 'RETURN_DATA' });
});

test('decodeAddressReturn decodes a clean address word and rejects dirty high-byte padding', () => {
  const clean = AbiCoder.encode(['address'], [proposal.executor]);
  assert.equal(decodeAddressReturn(clean), proposal.executor);
  const dirty = '0x' + '1' + '0'.repeat(23) + proposal.executor.slice(2);
  assert.throws(() => decodeAddressReturn(dirty), { code: 'RETURN_DATA' });
});

test('decodeActionSpecReturn matches the independent actions() return decoding', () => {
  const data = executorIface.encodeFunctionResult('actions', [true, true, 2]);
  const decoded = decodeActionSpecReturn(data);
  const independent = executorIface.decodeFunctionResult('actions', data);
  assert.deepEqual(decoded, { supported: true, hasAmount: true, amountIndex: 2 });
  assert.equal(decoded.supported, independent[0]);
  assert.equal(decoded.hasAmount, independent[1]);
  assert.equal(decoded.amountIndex, Number(independent[2]));
});

test('decodeMandateReturn returns null for a zero-agent mandate', () => {
  const zeroAddress = '0x' + '0'.repeat(40);
  const zeroData = mandateIface.encodeFunctionResult('getMandate', [
    zeroAddress, 0, 0, zeroAddress, false, zeroAddress, '0x' + '0'.repeat(64),
    zeroAddress, 0n, 0n, 0n, '0x' + '0'.repeat(64)
  ]);
  assert.equal(decodeMandateReturn(zeroData), null);
});

test('decodeMandateReturn decodes a populated mandate field by field against the independent ABI decoding', () => {
  const values = [
    KNOWN_AGENT, 1_700_000_000, 1_703_600_000, KNOWN_PRINCIPAL, true, LIVE_COMPLIANCE_PROVIDER,
    SANDBOX_IDENTITY_REF, proposal.token.address, 10000n, 15000n, 5000n, EMPTY_METADATA
  ];
  const data = mandateIface.encodeFunctionResult('getMandate', values);
  const decoded = decodeMandateReturn(data);
  const independent = mandateIface.decodeFunctionResult('getMandate', data);
  assert.equal(decoded.agent, independent[0].toLowerCase());
  assert.equal(decoded.validFrom, independent[1].toString());
  assert.equal(decoded.validUntil, independent[2].toString());
  assert.equal(decoded.principal, independent[3].toLowerCase());
  assert.equal(decoded.revoked, independent[4]);
  assert.equal(decoded.complianceProvider, independent[5].toLowerCase());
  assert.equal(decoded.identityRef, independent[6].toLowerCase());
  assert.equal(decoded.asset, independent[7].toLowerCase());
  assert.equal(decoded.maxTransactionValue, independent[8].toString());
  assert.equal(decoded.maxCumulativeValue, independent[9].toString());
  assert.equal(decoded.cumulativeUsed, independent[10].toString());
  assert.equal(decoded.metadata, independent[11].toLowerCase());
});

test('decodeRevert decodes CannotExecute arguments against the independent error encoding', () => {
  const data = mandateIface.encodeErrorResult('CannotExecute', [proposal.agent, proposal.executor, TRANSFER_FROM_SELECTOR, 11000n]);
  const decoded = decodeRevert(data);
  assert.equal(decoded.name, 'CannotExecute');
  assert.equal(decoded.selector, data.slice(0, 10));
  assert.deepEqual(decoded.args, {
    agent: proposal.agent, target: proposal.executor, selector: TRANSFER_FROM_SELECTOR, amount: '11000'
  });
});

test('decodeRevert decodes OwnableUnauthorizedAccount against the independent error encoding', () => {
  const data = executorIface.encodeErrorResult('OwnableUnauthorizedAccount', [proposal.principal]);
  const decoded = decodeRevert(data);
  assert.equal(decoded.name, 'OwnableUnauthorizedAccount');
  assert.deepEqual(decoded.args, { account: proposal.principal });
});

test('decodeRevert names an unknown selector without arguments, and returns null for null or short data', () => {
  const unknown = decodeRevert('0x12345678' + '00'.repeat(32));
  assert.equal(unknown.name, null);
  assert.equal(unknown.selector, '0x12345678');
  assert.equal(unknown.args, null);
  assert.deepEqual(decodeRevert(null), { selector: null, name: null, args: null });
  assert.deepEqual(decodeRevert('0x1234'), { selector: null, name: null, args: null });
});

// ---------------------------------------------------------------------------
// 6. facadeBody.

test('facadeBody builds the exact key set and values for setAction, grant, execute and revoke', () => {
  const setAction = facadeBody(proposal, 'setAction', { nonce: '3', gasLimit: '80000' });
  assert.deepEqual(setAction, {
    chainId: SEPOLIA_CHAIN_ID, nonce: 3, gasLimit: '80000',
    signerAddress: proposal.principal, executorAddress: proposal.executor,
    selector: TRANSFER_FROM_SELECTOR, supported: true, hasAmount: true, amountIndex: 2
  });

  const validFrom = 1_750_000_000;
  const grant = facadeBody(proposal, 'grant', { nonce: '4', gasLimit: '350000', validFrom });
  assert.deepEqual(grant, {
    chainId: SEPOLIA_CHAIN_ID, nonce: 4, gasLimit: '350000',
    signerAddress: proposal.principal, agent: proposal.agent, principal: proposal.principal,
    validFrom, validUntil: validFrom + proposal.mandateValiditySeconds,
    complianceProvider: proposal.complianceProvider, identityRef: proposal.identityRef,
    asset: proposal.token.address, maxTransactionValue: proposal.limits.maxTransactionValue,
    maxCumulativeValue: proposal.limits.maxCumulativeValue, metadata: EMPTY_METADATA,
    actions: [TRANSFER_FROM_SELECTOR], agentMandateAddress: proposal.registry
  });

  const execute = facadeBody(proposal, 'execute', { nonce: '5', gasLimit: '250000' });
  const innerCalldata = liveExecutionCall(proposal).intent.innerCalldata;
  assert.deepEqual(execute, {
    chainId: SEPOLIA_CHAIN_ID, nonce: 5, gasLimit: '250000',
    signerAddress: proposal.agent, executorAddress: proposal.executor,
    target: proposal.token.address, data: innerCalldata
  });
  // Raw facade mode: target is the token and data is the inner transferFrom
  // calldata itself, never the executor's outer execute(address,bytes) wrapper.
  assert.notEqual(execute.data, expectedCalldata(proposal, 'execute'));
  assert.equal(execute.data, erc20Iface.encodeFunctionData(
    'transferFrom', [proposal.principal, proposal.recipient.address, 10000n]
  ).toLowerCase());

  const revoke = facadeBody(proposal, 'revoke', { nonce: '6', gasLimit: '120000' });
  assert.deepEqual(revoke, {
    chainId: SEPOLIA_CHAIN_ID, nonce: 6, gasLimit: '120000',
    signerAddress: proposal.principal, agent: proposal.agent, principal: proposal.principal,
    agentMandateAddress: proposal.registry
  });
});

test('facadeBody rejects an RPC-route step, an out-of-range gas limit and a non-numeric nonce', () => {
  assert.throws(() => facadeBody(proposal, 'approve', { nonce: '1', gasLimit: '50000' }), { code: 'ROUTE' });
  const cap = proposal.gasLimitCaps.setAction;
  assert.throws(() => facadeBody(proposal, 'setAction', { nonce: '1', gasLimit: String(BigInt(cap) + 1n) }), { code: 'GAS_LIMIT' });
  assert.throws(() => facadeBody(proposal, 'setAction', { nonce: '1', gasLimit: '20999' }), { code: 'GAS_LIMIT' });
  assert.throws(() => facadeBody(proposal, 'setAction', { nonce: '12a', gasLimit: '50000' }), { code: 'NONCE' });
});

// ---------------------------------------------------------------------------
// 7. validateFacadeBody.

test('validateFacadeBody accepts the plan\'s own body for every brickken-api step', () => {
  const setAction = facadeBody(proposal, 'setAction', { nonce: '3', gasLimit: '80000' });
  assert.deepEqual(validateFacadeBody(proposal, 'setAction', setAction, 1_700_000_000), setAction);

  const validFrom = 1_700_000_100;
  const grant = facadeBody(proposal, 'grant', { nonce: '4', gasLimit: '350000', validFrom });
  assert.deepEqual(validateFacadeBody(proposal, 'grant', grant, validFrom), grant);

  const execute = facadeBody(proposal, 'execute', { nonce: '5', gasLimit: '250000' });
  assert.deepEqual(validateFacadeBody(proposal, 'execute', execute, 1_700_000_000), execute);

  const revoke = facadeBody(proposal, 'revoke', { nonce: '6', gasLimit: '120000' });
  assert.deepEqual(validateFacadeBody(proposal, 'revoke', revoke, 1_700_000_000), revoke);
});

test('validateFacadeBody rejects an extra key, a changed amount, a changed execute recipient, a stale grant window and a string nonce', () => {
  const setAction = facadeBody(proposal, 'setAction', { nonce: '3', gasLimit: '80000' });
  assert.throws(() => validateFacadeBody(proposal, 'setAction', { ...setAction, extra: true }, 1_700_000_000), { code: 'BODY_MISMATCH' });

  const validFrom = 1_700_000_100;
  const grant = facadeBody(proposal, 'grant', { nonce: '4', gasLimit: '350000', validFrom });
  assert.throws(() => validateFacadeBody(proposal, 'grant', { ...grant, maxTransactionValue: '1' }, validFrom), { code: 'BODY_MISMATCH' });
  assert.throws(() => validateFacadeBody(proposal, 'grant', grant, validFrom + GRANT_START_TOLERANCE_SECONDS + 1), { code: 'GRANT_WINDOW' });
  assert.throws(() => validateFacadeBody(proposal, 'grant', { ...grant, nonce: '4' }, validFrom), { code: 'NONCE' });

  const execute = facadeBody(proposal, 'execute', { nonce: '5', gasLimit: '250000' });
  const differentRecipient = erc20Iface.encodeFunctionData(
    'transferFrom', [proposal.principal, KNOWN_AGENT, 10000n]
  ).toLowerCase();
  assert.throws(() => validateFacadeBody(proposal, 'execute', { ...execute, data: differentRecipient }, 1_700_000_000), { code: 'BODY_MISMATCH' });
});

// ---------------------------------------------------------------------------
// 8. checkLiveTransaction.

test('checkLiveTransaction accepts a correctly built transaction for every write step', () => {
  for (const step of LIVE_WRITE_STEPS) {
    const tx = baseTx(step);
    const checked = checkLiveTransaction(proposal, step, tx, { nonce: tx.nonce });
    assert.equal(checked.to, stepTarget(proposal, step));
    assert.equal(checked.from, stepSignerAddress(proposal, step));
  }
});

test('checkLiveTransaction rejects wrong chain, signer, target, native value, calldata and nonce', () => {
  const step = 'setAction'; // an owner-signed step
  const good = baseTx(step);
  assert.throws(() => checkLiveTransaction(proposal, step, { ...good, chainId: '1' }), { code: 'WRONG_CHAIN' });
  assert.throws(() => checkLiveTransaction(proposal, step, { ...good, from: proposal.agent }), { code: 'WRONG_SIGNER' });
  assert.throws(() => checkLiveTransaction(proposal, step, { ...good, to: proposal.registry }), { code: 'WRONG_TARGET' });
  assert.throws(() => checkLiveTransaction(proposal, step, { ...good, value: '1' }), { code: 'NATIVE_VALUE' });
  assert.throws(() => checkLiveTransaction(proposal, step, { ...good, data: flipLastHexChar(good.data) }), { code: 'CALLDATA_MISMATCH' });
  assert.throws(() => checkLiveTransaction(proposal, step, good, { nonce: '999' }), { code: 'NONCE_MISMATCH' });

  // The reverse signer case: execute is agent-signed, so the owner is wrong here.
  const executeGood = baseTx('execute');
  assert.throws(() => checkLiveTransaction(proposal, 'execute', { ...executeGood, from: proposal.principal }), { code: 'WRONG_SIGNER' });
});

test('checkLiveTransaction rejects gas above the step cap and fees above the proposal ceilings', () => {
  const step = 'execute';
  const good = baseTx(step);
  assert.throws(() => checkLiveTransaction(proposal, step, {
    ...good, gasLimit: String(BigInt(proposal.gasLimitCaps[step]) + 1n)
  }), { code: 'GAS_LIMIT_CEILING' });
  assert.throws(() => checkLiveTransaction(proposal, step, {
    ...good, maxFeePerGas: String(BigInt(proposal.fees.maxFeePerGas) + 1n)
  }), { code: 'FEE_CEILING' });
  assert.throws(() => checkLiveTransaction(proposal, step, {
    ...good, maxPriorityFeePerGas: String(BigInt(proposal.fees.maxPriorityFeePerGas) + 1n)
  }), { code: 'PRIORITY_FEE_CEILING' });
});

test('checkLiveTransaction rejects a type 0 transaction and a priority fee above the max fee', () => {
  const step = 'approve';
  const good = baseTx(step);
  assert.throws(() => checkLiveTransaction(proposal, step, { ...good, type: 0 }), { code: 'TRANSACTION_TYPE' });
  assert.throws(() => checkLiveTransaction(proposal, step, {
    ...good, maxPriorityFeePerGas: String(BigInt(good.maxFeePerGas) + 1n)
  }), { code: 'TRANSACTION_FEES' });
});

// ---------------------------------------------------------------------------
// 9. controlCalls.

test('controlCalls returns the four control ids with exact labels, expectations, probes and view calls', () => {
  assert.equal(LIVE_CONTROL_IDS.length, 4);
  assert.deepEqual(LIVE_CONTROL_IDS, [
    'control-transaction-cap', 'control-cumulative-cap', 'control-before-revoke', 'control-after-revoke'
  ]);

  const txCap = controlCalls(proposal, 'control-transaction-cap');
  assert.deepEqual(txCap.map(c => c.label), ['execute-within-transaction-cap', 'execute-over-transaction-cap']);
  assert.deepEqual(txCap.map(c => c.expect), ['success', 'revert:CannotExecute']);
  for (const call of txCap) {
    assert.equal(call.from, proposal.agent);
    assert.equal(call.to, proposal.executor);
    assert.equal(call.value, '0');
  }
  assert.equal(txCap[0].data, encodeExecuteProbe(proposal, proposal.amounts.execute));
  assert.equal(txCap[1].data, encodeExecuteProbe(proposal, proposal.amounts.overTransactionCapProbe));

  const cumCap = controlCalls(proposal, 'control-cumulative-cap');
  assert.deepEqual(cumCap.map(c => c.label), ['can-execute-remaining-cumulative', 'can-execute-over-cumulative']);
  assert.deepEqual(cumCap.map(c => c.expect), ['true', 'false']);
  for (const call of cumCap) {
    assert.equal(call.from, null);
    assert.equal(call.to, proposal.registry);
  }

  const beforeRevoke = controlCalls(proposal, 'control-before-revoke');
  assert.deepEqual(beforeRevoke.map(c => c.label), ['execute-before-revoke']);
  assert.equal(beforeRevoke[0].expect, 'success');
  assert.equal(beforeRevoke[0].from, proposal.agent);
  assert.equal(beforeRevoke[0].data, encodeExecuteProbe(proposal, proposal.amounts.revocationProbe));

  const afterRevoke = controlCalls(proposal, 'control-after-revoke');
  assert.deepEqual(afterRevoke.map(c => c.label), ['execute-after-revoke', 'can-execute-after-revoke']);
  assert.deepEqual(afterRevoke.map(c => c.expect), ['revert:CannotExecute', 'false']);
  assert.equal(afterRevoke[0].from, proposal.agent);
  assert.equal(afterRevoke[1].from, null);
  assert.equal(afterRevoke[1].to, proposal.registry);
});

test('controlCalls rejects an unknown control id', () => {
  assert.throws(() => controlCalls(proposal, 'control-unknown'), { code: 'CONTROL' });
});

// ---------------------------------------------------------------------------
// 10. requiredWei and maxStepCostWei.

test('maxStepCostWei and requiredWei equal the gas cap times the proposal maxFeePerGas, summed per signer role', () => {
  for (const step of LIVE_WRITE_STEPS) {
    assert.equal(
      maxStepCostWei(proposal, step),
      (BigInt(proposal.gasLimitCaps[step]) * BigInt(proposal.fees.maxFeePerGas)).toString()
    );
  }
  const totals = requiredWei(proposal, LIVE_WRITE_STEPS);
  let owner = 0n;
  let agent = 0n;
  for (const step of LIVE_WRITE_STEPS) {
    const cost = BigInt(proposal.gasLimitCaps[step]) * BigInt(proposal.fees.maxFeePerGas);
    if (LIVE_STEP_SIGNER[step] === 'agent') agent += cost; else owner += cost;
  }
  assert.equal(totals.owner, owner.toString());
  assert.equal(totals.agent, agent.toString());
});

// ---------------------------------------------------------------------------
// 11. buildRunApproval / validateRunApproval.

test('buildRunApproval / validateRunApproval JSON round-trip validates', () => {
  const createdAt = new Date('2026-09-14T00:00:00.000Z').toISOString();
  const notAfter = new Date('2026-09-15T00:00:00.000Z').toISOString();
  const preflight = { blockNumber: '9000000', observedAt: createdAt };
  const approval = buildRunApproval(proposal, { createdAt, notAfter, preflight });
  const roundTripped = JSON.parse(JSON.stringify(approval));
  const validated = validateRunApproval(roundTripped, proposal);
  assert.deepEqual(validated, approval);
});

test('validateRunApproval rejects a changed write calldata, fee, notAfter, preflight or approvalSha256', () => {
  const createdAt = new Date('2026-09-14T00:00:00.000Z').toISOString();
  const notAfter = new Date('2026-09-15T00:00:00.000Z').toISOString();
  const approval = buildRunApproval(proposal, { createdAt, notAfter, preflight: { note: 'baseline' } });
  const base = JSON.parse(JSON.stringify(approval));
  assert.equal(base.writes[3].step, 'execute');

  const badWrite = structuredClone(base);
  badWrite.writes[3].calldata = flipLastHexChar(badWrite.writes[3].calldata);
  assert.throws(() => validateRunApproval(badWrite, proposal), { code: 'APPROVAL_INTEGRITY' });

  const badFee = structuredClone(base);
  badFee.fees.maxFeePerGas = String(BigInt(badFee.fees.maxFeePerGas) + 1n);
  assert.throws(() => validateRunApproval(badFee, proposal), { code: 'APPROVAL_INTEGRITY' });

  const badNotAfter = structuredClone(base);
  badNotAfter.notAfter = new Date(Date.parse(badNotAfter.notAfter) + 1000).toISOString();
  assert.throws(() => validateRunApproval(badNotAfter, proposal), { code: 'APPROVAL_INTEGRITY' });

  const badPreflight = structuredClone(base);
  badPreflight.preflight.note = 'changed';
  assert.throws(() => validateRunApproval(badPreflight, proposal), { code: 'APPROVAL_INTEGRITY' });

  const badSha = structuredClone(base);
  badSha.approvalSha256 = '0'.repeat(64);
  assert.throws(() => validateRunApproval(badSha, proposal), { code: 'APPROVAL_INTEGRITY' });
});

test('buildRunApproval rejects a lifetime of zero or more than four days, and accepts exactly four days', () => {
  const createdAt = new Date('2026-09-14T00:00:00.000Z').toISOString();
  assert.throws(() => buildRunApproval(proposal, { createdAt, notAfter: createdAt, preflight: null }), { code: 'APPROVAL_LIFETIME' });
  const tooLong = new Date(Date.parse(createdAt) + MAX_APPROVAL_LIFETIME_SECONDS * 1000 + 1000).toISOString();
  assert.throws(() => buildRunApproval(proposal, { createdAt, notAfter: tooLong, preflight: null }), { code: 'APPROVAL_LIFETIME' });
  const exact = new Date(Date.parse(createdAt) + MAX_APPROVAL_LIFETIME_SECONDS * 1000).toISOString();
  assert.doesNotThrow(() => buildRunApproval(proposal, { createdAt, notAfter: exact, preflight: null }));
});

test('buildRunApproval writes: the grant entry carries a null calldata and a calldataRule; the others carry exact calldata', () => {
  const createdAt = new Date('2026-09-14T00:00:00.000Z').toISOString();
  const notAfter = new Date('2026-09-15T00:00:00.000Z').toISOString();
  const approval = buildRunApproval(proposal, { createdAt, notAfter, preflight: null });
  assert.equal(approval.writes.length, LIVE_WRITE_STEPS.length);
  for (const entry of approval.writes) {
    if (entry.step === 'grant') {
      assert.equal(entry.calldata, null);
      assert.match(entry.calldataRule, /grantMandate/);
    } else {
      assert.equal(entry.calldata, expectedCalldata(proposal, entry.step));
      assert.equal(entry.calldataRule, 'exact');
    }
  }
});
