// Separate, durable Sepolia preparation workspace. The default route reads a
// reviewed local fixture and creates unsigned transactions only. It has no
// HTTP client, wallet, signing or broadcast capability.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { boundedPath, ROOT } from './store.mjs';
import {
  KNOWN_AGENT,
  KNOWN_PRINCIPAL,
  TRANSFER_FROM_ACTION,
  canonicalJson,
  sha256Canonical
} from './brickken-intent.mjs';
import {
  PROVISIONED_EXECUTOR,
  buildOfflineActionSetupCall,
  validateOfflineExecutionCall
} from './brickken-executor.mjs';
import {
  RAMS_REGISTRY,
  buildDirectMandatePlan,
  buildDirectRevokePlan
} from './brickken-mandate.mjs';
import {
  DIRECT_LIFECYCLE_DEADLINE,
  EMPTY_METADATA,
  EMPTY_SIGNATURE,
  buildOfflineDirectGrantCall,
  buildOfflineDirectRevokeCall
} from './brickken-lifecycle.mjs';
import {
  SANDBOX_IDENTITY_REF,
  buildExpectedExecutionPreparation,
  validateExecutePrepareResponse
} from './brickken-prepare.mjs';
import {
  UNSIGNED_ENVELOPE_ACTIONS,
  buildApproveEnvelope,
  buildExecuteEnvelope,
  buildGrantEnvelope,
  buildRevokeEnvelope,
  buildSetActionEnvelope,
  validateUnsignedEnvelope
} from './brickken-envelope.mjs';
import { BrickkenJournal } from './brickken-journal.mjs';

const PROPOSAL_FILE = boundedPath(path.join(ROOT, 'integration', 'demo-proposal.json'));
const WORKSPACE_FILE = 'brickken-workspace.json';
const WORKSPACE_LOCK = 'brickken-workspace.lock';
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const WAIT = new Int32Array(new SharedArrayBuffer(4));
const PROVIDER = '0xa90d2503d5d9b80ecc27856ff76f892b8c02f278';
const ACTION_BINDINGS = Object.freeze({
  setAction: Object.freeze({ nonce: '0', type: 2, gasLimit: '100000', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000' }),
  approve: Object.freeze({ nonce: '1', type: 2, gasLimit: '100000', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000' }),
  grant: Object.freeze({ nonce: '2', type: 2, gasLimit: '400000', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000' }),
  execute: Object.freeze({ nonce: '0', type: 2, gasLimit: '200000', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000' }),
  revoke: Object.freeze({ nonce: '3', type: 2, gasLimit: '150000', maxPriorityFeePerGas: '1000000000', maxFeePerGas: '2000000000' })
});
const RESOURCE_LIMITS = Object.freeze({
  maxGasLimit: '500000',
  maxPriorityFeePerGas: '1500000000',
  maxFeePerGas: '3000000000',
  maxTotalGasCost: '1000000000000000'
});
const OPERATION_KEYS = [
  'operationId', 'createdAt', 'createdAtSeconds', 'plannedRevision', 'inputHash',
  'preview', 'previewHash', 'status', 'approval', 'envelopes', 'receipt'
];

export class BrickkenWorkspaceError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'BrickkenWorkspaceError';
    this.code = code;
    this.details = details;
  }
}

function fail(code, message, details) { throw new BrickkenWorkspaceError(code, message, details); }
function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(value));
}
function shape(value, keys, code = 'WORKSPACE_INVALID') {
  if (!plain(value) || Object.keys(value).length !== keys.length ||
      keys.some(key => !Object.hasOwn(value, key))) fail(code, 'The Sepolia workspace file has an invalid structure.');
}
function identifier(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{8,80}$/.test(value)) {
    fail('INVALID_OPERATION_ID', 'The operation ID must use 8 to 80 letters, numbers, underscores or hyphens.');
  }
  return value;
}
function second(value) {
  if (!Number.isSafeInteger(value) || value <= 0) fail('INVALID_TIME', 'The workspace requires an exact current time.');
  return value;
}
function sha(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail('WORKSPACE_INVALID', 'A stored hash is invalid.');
  return value;
}
function clone(value) { return structuredClone(value); }
function documentHash(value) {
  return sha256Canonical({ schemaVersion: value.schemaVersion, mode: value.mode, revision: value.revision, operations: value.operations });
}
function newDocument() {
  const value = { schemaVersion: 1, mode: 'offline-fixture', revision: 0, operations: [], selfHash: '' };
  value.selfHash = documentHash(value);
  return value;
}
function verifyEnvelopeSelfHash(value) {
  if (!plain(value)) fail('WORKSPACE_INVALID', 'A stored unsigned envelope is invalid.');
  const { envelopeHash, ...payload } = value;
  if (sha(envelopeHash) !== sha256Canonical(payload) || value.sourceHash !== sha256Canonical(value.source)) {
    fail('WORKSPACE_INVALID', 'A stored unsigned envelope changed after preparation.');
  }
}
function validateOperation(value) {
  shape(value, OPERATION_KEYS);
  identifier(value.operationId);
  if (typeof value.createdAt !== 'string' || new Date(value.createdAt).toISOString() !== value.createdAt ||
      !Number.isSafeInteger(value.createdAtSeconds) || value.createdAtSeconds <= 0 ||
      !Number.isSafeInteger(value.plannedRevision) || value.plannedRevision < 1) {
    fail('WORKSPACE_INVALID', 'A stored operation time or revision is invalid.');
  }
  sha(value.inputHash); sha(value.previewHash);
  const expectedPreview = previewFor(value.operationId, value.createdAtSeconds, value.plannedRevision);
  if (canonicalJson(value.preview) !== canonicalJson(expectedPreview) ||
      sha256Canonical(value.preview) !== value.previewHash || value.preview.operationId !== value.operationId ||
      value.inputHash !== sha256Canonical({ operationId: value.operationId, proposalHash: value.preview.proposalHash })) {
    fail('WORKSPACE_INVALID', 'A stored review hash no longer matches its preview.');
  }
  if (!['planned', 'approved', 'signing_unavailable'].includes(value.status)) {
    fail('WORKSPACE_INVALID', 'A stored operation status is invalid.');
  }
  if (value.envelopes !== null && (!Array.isArray(value.envelopes) || value.envelopes.length !== 5)) {
    fail('WORKSPACE_INVALID', 'A stored operation must contain all five unsigned envelopes.');
  }
  for (const envelope of value.envelopes ?? []) verifyEnvelopeSelfHash(envelope);
  if ((value.approval === null) !== (value.envelopes === null)) {
    fail('WORKSPACE_INVALID', 'Stored approval and envelope state do not match.');
  }
  if (value.approval !== null) {
    shape(value.approval, [
      'previewHash', 'approvedAt', 'expiresAt', 'stateRevision',
      'authorizesSigning', 'authorizesBroadcast', 'chainWriteAuthorized'
    ]);
    if (value.approval.previewHash !== value.previewHash ||
        !Number.isSafeInteger(value.approval.approvedAt) || value.approval.approvedAt <= 0 ||
        !Number.isSafeInteger(value.approval.expiresAt) || value.approval.expiresAt <= value.approval.approvedAt ||
        value.approval.expiresAt - value.approval.approvedAt > 300 ||
        !Number.isSafeInteger(value.approval.stateRevision) || value.approval.stateRevision < value.plannedRevision ||
        value.approval.authorizesSigning !== false || value.approval.authorizesBroadcast !== false ||
        value.approval.chainWriteAuthorized !== false) {
      fail('WORKSPACE_INVALID', 'The stored owner approval does not match its fixed review boundary.');
    }
  }
  return value;
}
function validateDocument(value) {
  shape(value, ['schemaVersion', 'mode', 'revision', 'operations', 'selfHash']);
  if (value.schemaVersion !== 1 || value.mode !== 'offline-fixture' ||
      !Number.isSafeInteger(value.revision) || value.revision < 0 ||
      !Array.isArray(value.operations) || value.operations.length > 1000 ||
      sha(value.selfHash) !== documentHash(value)) {
    fail('WORKSPACE_INVALID', 'The Sepolia workspace file failed its integrity check.');
  }
  const ids = new Set();
  for (const operation of value.operations) {
    validateOperation(operation);
    if (ids.has(operation.operationId)) fail('WORKSPACE_INVALID', 'The Sepolia workspace contains a duplicate operation ID.');
    ids.add(operation.operationId);
  }
  return value;
}
function serializeDocument(value) {
  validateDocument(value);
  const serialized = JSON.stringify(value, null, 2);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_FILE_BYTES) {
    fail('WORKSPACE_TOO_LARGE', 'The Sepolia workspace reached its local size limit. Existing history was preserved.');
  }
  return serialized;
}

function loadProposal() {
  let proposal;
  try { proposal = JSON.parse(fs.readFileSync(PROPOSAL_FILE, 'utf8')); }
  catch { fail('FIXTURE_UNAVAILABLE', 'The reviewed offline proposal could not be read.'); }
  if (!plain(proposal) || proposal.kind !== 'offline-demo-proposal' || proposal.scope?.offlineOnly !== true ||
      proposal.scope?.signingReady !== false || proposal.scope?.chainWriteAuthorized !== false) {
    fail('FIXTURE_INVALID', 'The proposal is not the reviewed offline fixture.');
  }
  const { proposalHash, ...payload } = proposal;
  if (typeof proposalHash !== 'string' || sha256Canonical(payload) !== proposalHash) {
    fail('FIXTURE_INVALID', 'The offline proposal hash does not match its contents.');
  }
  const executionCall = validateOfflineExecutionCall(proposal.permittedExecutionCall);
  if (proposalHash !== 'cbaa46eb8eb86cf2b03ea1239df0b240a69a343fe9e7a792dd6f7fd119872e22' ||
      proposal.recipient?.address?.toLowerCase() !== executionCall.intent.policy.recipient ||
      proposal.asset?.address?.toLowerCase() !== executionCall.intent.policy.token ||
      proposal.proposedLimits?.permittedTransferRaw !== executionCall.intent.transfer.amount ||
      proposal.proposedLimits?.validitySeconds !== 1800) {
    fail('FIXTURE_INVALID', 'The fixed Sepolia proposal no longer matches the reviewed transaction intent.');
  }
  return { proposal, executionCall };
}

function references(mandatePlan, revokePlan, executionCall) {
  const body = mandatePlan.request.body;
  const grant = {
    schemaVersion: 1,
    kind: 'rams-direct-grant-reference',
    mandatePlanHash: mandatePlan.planHash,
    executionCallHash: executionCall.callHash,
    registry: RAMS_REGISTRY,
    caller: KNOWN_PRINCIPAL,
    agent: KNOWN_AGENT,
    principal: KNOWN_PRINCIPAL,
    complianceProvider: PROVIDER,
    identityRef: body.identityRef,
    asset: executionCall.intent.policy.token,
    maxTransactionValue: executionCall.intent.policy.maxTransactionValue,
    maxCumulativeValue: executionCall.intent.policy.maxCumulativeValue,
    validFrom: body.validFrom,
    validUntil: body.validUntil,
    metadata: EMPTY_METADATA,
    actions: [TRANSFER_FROM_ACTION],
    deadline: DIRECT_LIFECYCLE_DEADLINE,
    signature: EMPTY_SIGNATURE
  };
  const revoke = {
    schemaVersion: 1,
    kind: 'rams-direct-revoke-reference',
    revokePlanHash: revokePlan.planHash,
    mandatePlanHash: mandatePlan.planHash,
    registry: RAMS_REGISTRY,
    caller: KNOWN_PRINCIPAL,
    agent: KNOWN_AGENT,
    principal: KNOWN_PRINCIPAL,
    deadline: DIRECT_LIFECYCLE_DEADLINE,
    signature: EMPTY_SIGNATURE
  };
  return { grant, revoke };
}

function baseArtifacts(createdAtSeconds) {
  const { proposal, executionCall } = loadProposal();
  const mandatePlan = buildDirectMandatePlan(executionCall, {
    validFrom: createdAtSeconds,
    validUntil: createdAtSeconds + proposal.proposedLimits.validitySeconds
  }, createdAtSeconds);
  const revokePlan = buildDirectRevokePlan();
  const reference = references(mandatePlan, revokePlan, executionCall);
  const actionCall = buildOfflineActionSetupCall();
  const grantCall = buildOfflineDirectGrantCall(mandatePlan, executionCall, createdAtSeconds, reference.grant);
  const revokeCall = buildOfflineDirectRevokeCall(revokePlan, mandatePlan, executionCall, createdAtSeconds, reference.revoke);
  return { proposal, executionCall, mandatePlan, revokePlan, reference, actionCall, grantCall, revokeCall };
}

function transactionDraft(call, binding) {
  return {
    chainId: call.chainId,
    from: call.from,
    to: call.to,
    value: call.value,
    data: call.data,
    ...binding
  };
}
function previewFor(operationId, createdAtSeconds, plannedRevision) {
  const artifacts = baseArtifacts(createdAtSeconds);
  const calls = {
    setAction: artifacts.actionCall.call,
    approve: {
      chainId: artifacts.executionCall.call.chainId,
      from: KNOWN_PRINCIPAL,
      to: artifacts.executionCall.intent.policy.token,
      value: '0',
      data: '0x095ea7b3' + '0'.repeat(24) + PROVISIONED_EXECUTOR.slice(2) +
        BigInt(artifacts.executionCall.intent.policy.allowance).toString(16).padStart(64, '0')
    },
    grant: artifacts.grantCall.call,
    execute: artifacts.executionCall.call,
    revoke: artifacts.revokeCall.call
  };
  const actions = UNSIGNED_ENVELOPE_ACTIONS.map(action => ({
    action,
    ownerAction: action !== 'execute',
    transaction: transactionDraft(calls[action], ACTION_BINDINGS[action])
  }));
  return {
    schemaVersion: 1,
    kind: 'sepolia-offline-workflow-preview',
    operationId,
    plannedRevision,
    proposalHash: artifacts.proposal.proposalHash,
    proposal: {
      chainId: artifacts.proposal.asset.chainId,
      principal: KNOWN_PRINCIPAL,
      agent: KNOWN_AGENT,
      executor: PROVISIONED_EXECUTOR,
      registry: RAMS_REGISTRY,
      identityRef: SANDBOX_IDENTITY_REF,
      token: artifacts.executionCall.intent.policy.token,
      recipient: artifacts.executionCall.intent.policy.recipient,
      amount: artifacts.executionCall.intent.transfer.amount,
      maxTransactionValue: artifacts.executionCall.intent.policy.maxTransactionValue,
      maxCumulativeValue: artifacts.executionCall.intent.policy.maxCumulativeValue,
      allowance: artifacts.executionCall.intent.policy.allowance,
      mandateValiditySeconds: artifacts.proposal.proposedLimits.validitySeconds
    },
    actions,
    provenance: {
      source: 'integration/demo-proposal.json',
      sourceKind: 'reviewed-offline-fixture',
      networkRead: false,
      apiKeyUsed: false,
      liveStateClaimed: false
    },
    approvalMeaning: {
      exactPreviewOnly: true,
      createsUnsignedEnvelopes: true,
      authorizesSigning: false,
      authorizesBroadcast: false,
      chainWriteAuthorized: false
    }
  };
}

function buildEnvelopes(operation, approvedAt) {
  const artifacts = baseArtifacts(operation.createdAtSeconds);
  if (approvedAt >= artifacts.mandatePlan.request.body.validUntil) {
    fail('PLAN_EXPIRED', 'The 30-minute mandate proposal expired. Prepare a fresh review.');
  }
  const approvalExpiresAt = Math.min(approvedAt + 300, artifacts.mandatePlan.request.body.validUntil);
  const guard = {
    identityRef: SANDBOX_IDENTITY_REF,
    provisioningEvidenceSha256: sha256Canonical({
      kind: 'reviewed-offline-fixture-provenance',
      proposalHash: artifacts.proposal.proposalHash
    }),
    observedAt: approvedAt,
    expiresAt: approvalExpiresAt,
    approvalHash: operation.previewHash,
    approvedAt,
    approvalExpiresAt,
    ...RESOURCE_LIMITS
  };
  const expectation = buildExpectedExecutionPreparation(artifacts.executionCall, {
    nonce: ACTION_BINDINGS.execute.nonce,
    type: ACTION_BINDINGS.execute.type
  }, {
    identityRef: guard.identityRef,
    provisioningEvidenceSha256: guard.provisioningEvidenceSha256,
    observedAt: guard.observedAt,
    expiresAt: guard.expiresAt,
    ...RESOURCE_LIMITS
  });
  const preparedTransaction = { ...expectation.expected.transaction, ...ACTION_BINDINGS.execute };
  const preparation = validateExecutePrepareResponse(JSON.stringify({
    transactions: [preparedTransaction],
    txId: `fixture_${operation.operationId}`
  }), expectation, approvedAt);
  return [
    buildSetActionEnvelope(artifacts.actionCall, ACTION_BINDINGS.setAction, guard, approvedAt),
    buildApproveEnvelope(artifacts.executionCall, artifacts.executionCall.intent.policy.allowance, ACTION_BINDINGS.approve, guard, approvedAt),
    buildGrantEnvelope({
      grantCall: artifacts.grantCall,
      mandatePlan: artifacts.mandatePlan,
      executionCall: artifacts.executionCall,
      reference: artifacts.reference.grant
    }, ACTION_BINDINGS.grant, guard, approvedAt),
    buildExecuteEnvelope({
      preparation,
      preparationExpectation: expectation,
      trustedPreparationHash: preparation.preparationHash
    }, ACTION_BINDINGS.execute, guard, approvedAt),
    buildRevokeEnvelope({
      revokeCall: artifacts.revokeCall,
      revokePlan: artifacts.revokePlan,
      mandatePlan: artifacts.mandatePlan,
      executionCall: artifacts.executionCall,
      reference: artifacts.reference.revoke
    }, ACTION_BINDINGS.revoke, guard, approvedAt)
  ];
}

function findOperation(state, operationId) {
  const operation = state.operations.find(item => item.operationId === identifier(operationId));
  if (!operation) fail('OPERATION_NOT_FOUND', 'The Sepolia preparation operation was not found.');
  return operation;
}

function checkApproved(state, operation, nowSeconds) {
  const now = second(nowSeconds);
  if (!operation.approval || !operation.envelopes) {
    fail('OWNER_APPROVAL_REQUIRED', 'The owner must approve the exact preview hash in the Sepolia workspace.');
  }
  if (operation.approval.previewHash !== operation.previewHash ||
      operation.approval.chainWriteAuthorized !== false) {
    fail('APPROVAL_INVALID', 'The stored owner approval does not match the reviewed preview.');
  }
  if (state.revision !== operation.approval.stateRevision) {
    fail('STALE_APPROVAL', 'The workspace changed after approval. Prepare and approve a fresh review.');
  }
  if (now < operation.approval.approvedAt || now >= operation.approval.expiresAt) {
    fail('STALE_APPROVAL', 'The owner approval expired. Approve the exact preview again or prepare a fresh review.');
  }
  // Rebuild trusted expectations from the fixed proposal, the deterministic
  // preview inputs and the recorded owner approval time. A sibling copy in
  // the mutable workspace file is never accepted as its own trust anchor.
  const trustedEnvelopes = buildEnvelopes(operation, operation.approval.approvedAt);
  for (let index = 0; index < operation.envelopes.length; index++) {
    validateUnsignedEnvelope(operation.envelopes[index], trustedEnvelopes[index], now);
  }
  return {
    operationId: operation.operationId,
    ready: true,
    previewHash: operation.previewHash,
    approvedAt: operation.approval.approvedAt,
    approvalExpiresAt: operation.approval.expiresAt,
    stateRevision: state.revision,
    envelopeCount: operation.envelopes.length,
    signingRouteAvailable: false,
    chainWriteAuthorized: false
  };
}

export class BrickkenWorkspace {
  constructor(directory = path.join(ROOT, 'data'), { now = () => Math.floor(Date.now() / 1000), journal } = {}) {
    if (typeof now !== 'function') fail('INVALID_TIME', 'The workspace clock is invalid.');
    this.now = () => second(now());
    this.directory = boundedPath(directory);
    fs.mkdirSync(this.directory, { recursive: true });
    this.file = boundedPath(path.join(this.directory, WORKSPACE_FILE));
    this.lock = boundedPath(path.join(this.directory, WORKSPACE_LOCK));
    this.journal = journal ?? new BrickkenJournal({ directory: boundedPath(path.join(this.directory, 'brickken-journal')) });
    if (fs.existsSync(this.file)) this.read();
    else this.#write(newDocument());
  }

  read() {
    try {
      if (fs.statSync(this.file).size > MAX_FILE_BYTES) fail('WORKSPACE_INVALID', 'The Sepolia workspace file exceeds its size limit.');
      return clone(validateDocument(JSON.parse(fs.readFileSync(this.file, 'utf8'))));
    } catch (error) {
      if (error instanceof BrickkenWorkspaceError) throw error;
      fail('WORKSPACE_INVALID', 'The Sepolia workspace file could not be read. It was preserved.');
    }
  }

  planExecute({ operationId }) {
    identifier(operationId);
    const existing = this.read().operations.find(item => item.operationId === operationId);
    if (existing) return clone(existing);
    return this.#transact(state => {
      const duplicate = state.operations.find(item => item.operationId === operationId);
      if (duplicate) return duplicate;
      const createdAtSeconds = this.now();
      const plannedRevision = state.revision + 1;
      const preview = previewFor(operationId, createdAtSeconds, plannedRevision);
      const previewHash = sha256Canonical(preview);
      const operation = {
        operationId,
        createdAt: new Date(createdAtSeconds * 1000).toISOString(),
        createdAtSeconds,
        plannedRevision,
        inputHash: sha256Canonical({ operationId, proposalHash: preview.proposalHash }),
        preview,
        previewHash,
        status: 'planned',
        approval: null,
        envelopes: null,
        receipt: null
      };
      state.operations.push(operation);
      return operation;
    });
  }

  approve({ operationId, previewHash }) {
    sha(previewHash);
    const snapshot = this.read();
    const existing = findOperation(snapshot, operationId);
    const currentNow = this.now();
    if (previewHash !== existing.previewHash) fail('PREVIEW_HASH_MISMATCH', 'Approval applies only to the exact preview shown in this workspace.');
    if (existing.approval && snapshot.revision === existing.approval.stateRevision && currentNow < existing.approval.expiresAt) {
      return clone(existing);
    }
    const result = this.#transact(state => {
      const operation = findOperation(state, operationId);
      if (previewHash !== operation.previewHash) fail('PREVIEW_HASH_MISMATCH', 'Approval applies only to the exact preview shown in this workspace.');
      if (operation.receipt) fail('OPERATION_FINAL', 'This operation already has a final local receipt.');
      const now = this.now();
      if (operation.approval && state.revision === operation.approval.stateRevision && now < operation.approval.expiresAt) {
        return operation;
      }
      if (state.revision !== operation.plannedRevision &&
          (!operation.approval || state.revision !== operation.approval.stateRevision)) {
        fail('STALE_PREVIEW', 'The workspace changed after this preview. Prepare a fresh review.');
      }
      const envelopes = buildEnvelopes(operation, now);
      operation.approval = {
        previewHash: operation.previewHash,
        approvedAt: now,
        expiresAt: envelopes[0].guard.approvalExpiresAt,
        stateRevision: state.revision + 1,
        authorizesSigning: false,
        authorizesBroadcast: false,
        chainWriteAuthorized: false
      };
      operation.envelopes = clone(envelopes);
      operation.status = 'approved';
      return operation;
    });
    return result;
  }

  preflight({ operationId }) {
    const state = this.read();
    return checkApproved(state, findOperation(state, operationId), this.now());
  }

  executeApproved({ operationId }) {
    const state = this.read();
    const operation = findOperation(state, operationId);
    if (operation.receipt) {
      fail(operation.receipt.code, operation.receipt.message, clone(operation.receipt));
    }
    checkApproved(state, operation, this.now());
    this.#ensureJournal(operation);
    const receipt = this.#transact(current => {
      const target = findOperation(current, operationId);
      if (target.receipt) return target.receipt;
      checkApproved(current, target, this.now());
      const at = this.now();
      target.status = 'signing_unavailable';
      target.receipt = {
        operationId,
        outcome: 'blocked',
        code: 'SIGNING_ROUTE_UNAVAILABLE',
        message: 'No authorized signing adapter is configured. The unsigned envelopes remain local.',
        recordedAt: new Date(at * 1000).toISOString(),
        previewHash: target.previewHash,
        envelopeHash: target.envelopes.find(envelope => envelope.action === 'execute').envelopeHash,
        signed: false,
        broadcast: false,
        chainWriteAttempted: false,
        transactionHash: null,
        stateRevision: current.revision + 1
      };
      return target.receipt;
    });
    fail(receipt.code, receipt.message, receipt);
  }

  getReceipt({ operationId }) {
    const operation = findOperation(this.read(), operationId);
    return operation.receipt ? clone(operation.receipt) : {
      operationId: operation.operationId,
      outcome: 'pending',
      status: operation.status,
      previewHash: operation.previewHash,
      signed: false,
      broadcast: false,
      chainWriteAttempted: false,
      transactionHash: null
    };
  }

  #ensureJournal(operation) {
    for (const envelope of operation.envelopes) {
      const execute = envelope.action === 'execute';
      this.journal.createPending({
        operationId: `${operation.operationId}_${envelope.action}`,
        operationKind: envelope.action,
        txId: execute ? envelope.source.preparation.txId : `${operation.operationId}_${envelope.action}`,
        preparationHash: execute ? envelope.source.trustedPreparationHash : envelope.envelopeHash,
        transaction: envelope.transaction,
        createdAt: new Date(operation.approval.approvedAt * 1000).toISOString()
      });
    }
  }

  #transact(change) {
    let descriptor;
    try { descriptor = fs.openSync(this.lock, 'wx'); }
    catch { fail('WORKSPACE_BUSY', 'The Sepolia workspace is busy. Try again.'); }
    let temporary;
    try {
      fs.writeFileSync(descriptor, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
      const state = this.read();
      const result = change(state);
      state.revision += 1;
      state.selfHash = documentHash(state);
      const serialized = serializeDocument(state);
      temporary = boundedPath(path.join(this.directory, `brickken-workspace-${randomUUID()}.tmp`));
      fs.writeFileSync(temporary, serialized, { flag: 'wx' });
      fs.renameSync(temporary, this.file);
      temporary = null;
      return clone(result);
    } finally {
      if (temporary && fs.existsSync(temporary)) fs.unlinkSync(temporary);
      if (descriptor !== undefined) fs.closeSync(descriptor);
      if (fs.existsSync(this.lock)) fs.unlinkSync(this.lock);
    }
  }

  #write(value) {
    const temporary = boundedPath(path.join(this.directory, `brickken-workspace-${randomUUID()}.tmp`));
    try {
      fs.writeFileSync(temporary, serializeDocument(value), { flag: 'wx' });
      fs.renameSync(temporary, this.file);
    } finally {
      if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
    }
  }
}

export function createOperationId() { return `sepolia_${randomUUID()}`; }
