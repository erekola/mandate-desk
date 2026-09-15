// Separate, durable Sepolia workspaces. BrickkenWorkspace reads a reviewed
// local fixture and creates unsigned transactions only; it has no HTTP client,
// wallet, signing or broadcast capability. BrickkenLiveWorkspace, at the end of
// this file, runs an owner-approved Sepolia run through the live adapter and a
// separately started signer process.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
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
import { BrickkenJournal, LiveBrickkenJournal } from './brickken-journal.mjs';
import {
  LIVE_CONTROL_IDS,
  LIVE_STEP_ROUTE,
  LIVE_STEP_SIGNER,
  LIVE_WRITE_STEPS,
  buildRunApproval,
  decodeBoolReturn,
  decodeMandateReturn,
  decodeRevert,
  decodeUintReturn,
  expectedCalldata,
  grantValidFrom,
  loadLiveProposal,
  readCalls,
  validateRunApproval
} from './brickken-live-plan.mjs';
import { EVENT_TOPICS } from './brickken-postcheck.mjs';
import { PROCESS_CODE_IDENTITY_SHA256, codeIdentityEvidence, computeCodeIdentity, readGitHead } from './code-identity.mjs';
import {
  LiveSignerClient,
  LiveStepExecutor,
  checkControlCanonicity,
  checkRunFinality,
  classifyLiveError,
  createLiveRpcs,
  readLivePreflight,
  runLiveControl
} from './brickken-live-adapter.mjs';
import { LiveLockError, acquireLiveLock } from './live-lock.mjs';
import { evaluateLiveRunCompleteness } from './brickken-live-completeness.mjs';

const PROPOSAL_FILE = boundedPath(path.join(ROOT, 'integration', 'demo-proposal.json'));
const WORKSPACE_FILE = 'brickken-workspace.json';
const WORKSPACE_LOCK = 'brickken-workspace.lock';
const MAX_FILE_BYTES = 32 * 1024 * 1024;
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

// ---------------------------------------------------------------------------
// Live Sepolia run workspace. It is separate from the offline fixture workspace
// above: its own files under <data>/live, an owner approval bound to the run
// approval hash instead of a workspace revision, background jobs for the owner
// phases, and receipts derived from the live journal so the owner page, the MCP
// server and the evidence files cannot report different outcomes. Normal
// progress of one run never invalidates its next step.

const LIVE_WORKSPACE_KIND = 'mandate-desk-live-workspace';
const LIVE_APPROVAL_LIFETIME_MS = 96 * 3600 * 1000;
const LIVE_STEP_WAIT_MS = 30 * 60 * 1000;
// After the approval expired a resume only tracks recorded transactions by
// reads, for this long per resume, before it stops with the code that names
// the missing recovery authorization.
const LIVE_TRACKING_WAIT_MS = 5 * 60 * 1000;
const LIVE_AGENT_CALL_MS = 40_000;
// Journal states in which a recorded transaction is followed by reads.
const LIVE_TRACKING_STATES = Object.freeze(['broadcast', 'uncertain', 'confirmed']);
// The phase that owns each write, for a run whose confirmation was withdrawn.
const STEP_PHASE = Object.freeze({
  setAction: 'owner-setup', approve: 'owner-setup', grant: 'owner-setup',
  execute: 'agent-execute', revoke: 'owner-revocation', approveReset: 'owner-revocation'
});
// The write whose existence ends the lifecycle stage a control belongs to.
const CONTROL_DEPENDENT_STEP = Object.freeze({
  'control-transaction-cap': 'execute', 'control-cumulative-cap': 'revoke',
  'control-before-revoke': 'revoke', 'control-after-revoke': 'approveReset'
});
const LIVE_FINAL_STATUSES = Object.freeze(['completed', 'stopped']);
const LIVE_RUN_STATUSES = Object.freeze([
  'awaiting-owner-approval', 'owner-approved', 'owner-setup-running', 'awaiting-agent', 'agent-executing',
  'awaiting-owner-revocation', 'owner-revocation-running', 'completed', 'cleanup-running', 'stopped'
]);
const LIVE_PHASES = Object.freeze([null, 'owner-setup', 'agent-execute', 'owner-revocation', 'cleanup']);
const LIVE_RUN_KEYS = [
  'runId', 'createdAt', 'notAfter', 'approvalSha256', 'approvalFile', 'status', 'phase', 'ownerApproval',
  'preflightBlockers', 'steps', 'controls', 'replays', 'stop', 'cleanup', 'finality', 'updatedAt'
];
// Added after the first live workspace files existed; a run without it still validates.
const LIVE_RUN_OPTIONAL_KEYS = ['codeIdentitySha256'];
const EXPLORER_TX = 'https://sepolia.etherscan.io/tx/';
const STOP_DETAIL_KEYS = [
  'layer', 'step', 'check', 'rpcCode', 'status', 'signerStatus', 'apiErrorCode', 'transactionHash', 'nonce', 'field',
  'endpoint', 'operationId', 'controlId', 'blockers', 'revert', 'cause', 'method', 'baseFeePerGas', 'estimate',
  'balanceWei', 'steps', 'blockHash', 'purpose', 'notAfter', 'attempts', 'journalState', 'backoffUntil', 'lockFile',
  'controlIds', 'missing', 'to', 'from', 'reason', 'required', 'confirmationsPrimary', 'confirmationsSecondary',
  'dependencyOperationId', 'codeIdentitySha256', 'processCodeIdentitySha256', 'diskCodeIdentitySha256', 'phase',
  'platform', 'packageDirectory', 'attributed', 'mandate'
];

function liveDocumentHash(value) {
  return sha256Canonical({ schemaVersion: value.schemaVersion, kind: value.kind, proposalHash: value.proposalHash, runs: value.runs });
}
function isoAt(milliseconds) { return new Date(milliseconds).toISOString(); }
// The evidence document of the source bytes on disk right now: the stable
// identity (src/code-identity.mjs) plus the recording time and the git head as
// metadata. The stable hash is the value a run is approved for and compared
// against before every write; the metadata never changes it.
function identityNow(recordedAt) {
  const identity = computeCodeIdentity();
  return { codeIdentitySha256: identity.codeIdentitySha256, evidence: codeIdentityEvidence(identity, { recordedAt, gitHead: readGitHead() }) };
}
// The mandate a grant calldata of the reviewed plan creates, by identity field.
function grantMandateFromCalldata(data) {
  const word = index => data.slice(10 + index * 64, 10 + (index + 1) * 64);
  const addressOf = index => '0x' + word(index).slice(24);
  const uintOf = index => BigInt('0x' + word(index)).toString();
  return {
    agent: addressOf(2), validFrom: uintOf(3), validUntil: uintOf(4), principal: addressOf(5), complianceProvider: addressOf(6),
    identityRef: '0x' + word(7), asset: addressOf(8), maxTransactionValue: uintOf(9), maxCumulativeValue: uintOf(10), metadata: '0x' + word(11)
  };
}
function sameMandateIdentity(mandate, planned) {
  return Object.keys(planned).every(key => mandate[key] === planned[key]);
}
// Maps a live lock refusal to the workspace code of the file it concerns.
function lockFailure(error, prefix) {
  if (!(error instanceof LiveLockError)) return error;
  const file = error.details?.lockFile ?? null;
  if (error.code === 'LOCK_INVALID') {
    return new BrickkenWorkspaceError(`${prefix}_LOCK_INVALID`,
      `The ${file} file has unreadable content and was left in place. Check that no Mandate Desk process is running, then remove it by hand.`, { lockFile: file });
  }
  if (error.code === 'LOCK_DIRECTORY_MISSING') {
    return new BrickkenWorkspaceError(`${prefix}_LOCK_DIRECTORY_MISSING`,
      `The folder of the ${file} file does not exist any more. Nothing was written; check the data directory before retrying.`, { lockFile: file });
  }
  if (error.code === 'LOCK_UNSUPPORTED') {
    return new BrickkenWorkspaceError(`${prefix}_LOCK_UNSUPPORTED`,
      `The live lock needs an exclusive file open bound to the process, which could not be verified on ${error.details?.platform ?? 'this platform'}. The live run works on Windows.`,
      { lockFile: file, platform: error.details?.platform ?? null });
  }
  return new BrickkenWorkspaceError(error.code,
    prefix === 'LIVE_RUN' ? 'Another live action is running. Wait for it to finish.' : 'The live workspace is busy. Try again.',
    { lockFile: file, purpose: error.details?.purpose ?? null });
}
function safeDetails(details) {
  const result = {};
  for (const key of STOP_DETAIL_KEYS) {
    if (details && Object.hasOwn(details, key) && details[key] !== undefined) result[key] = JSON.parse(JSON.stringify(details[key]));
  }
  return result;
}
function stepStatus(record, planned) {
  if (!planned) return 'skipped';
  if (!record) return 'waiting';
  return {
    pending: 'prepared', signed: 'signed', broadcast: 'sent', uncertain: 'uncertain',
    confirmed: 'confirmed', semantically_verified: 'verified', reverted: 'failed'
  }[record.state];
}
// Every failure inside a live job keeps a code and the layer that refused.
function liveFailure(error, step = null) {
  if (error instanceof BrickkenWorkspaceError) {
    return { code: error.code, message: error.message, details: { layer: 'workspace', step, ...safeDetails(error.details) } };
  }
  const classified = classifyLiveError(error, step);
  return {
    code: classified.code,
    message: `The live run stopped with ${classified.code} at the ${classified.details.layer ?? 'adapter'} layer.`,
    details: safeDetails({ step, ...classified.details })
  };
}
function workspaceFailure(error, step = null) {
  if (error instanceof BrickkenWorkspaceError) return error;
  const failure = liveFailure(error, step);
  return new BrickkenWorkspaceError(failure.code, failure.message, failure.details);
}
function validateLiveRun(run) {
  shape(run, [...LIVE_RUN_KEYS, ...LIVE_RUN_OPTIONAL_KEYS.filter(key => plain(run) && Object.hasOwn(run, key))]);
  if (Object.hasOwn(run, 'codeIdentitySha256') && !/^[a-f0-9]{64}$/.test(run.codeIdentitySha256)) fail('LIVE_WORKSPACE_INVALID', 'A stored live run is invalid.');
  if (!/^live_[a-f0-9]{32}$/.test(run.runId) || !LIVE_RUN_STATUSES.includes(run.status) || !LIVE_PHASES.includes(run.phase) ||
      !/^[a-f0-9]{64}$/.test(run.approvalSha256) || run.approvalFile !== `run-approval-${run.approvalSha256.slice(0, 16)}.json` ||
      !Array.isArray(run.preflightBlockers) || !Array.isArray(run.replays) || !plain(run.steps) || !plain(run.controls)) {
    fail('LIVE_WORKSPACE_INVALID', 'A stored live run is invalid.');
  }
  for (const step of LIVE_WRITE_STEPS) {
    shape(run.steps[step], ['planned', 'skipReason', 'operationId'], 'LIVE_WORKSPACE_INVALID');
    if (run.steps[step].operationId !== `${run.runId}_${step}`) fail('LIVE_WORKSPACE_INVALID', 'A stored live step identity is invalid.');
  }
  for (const id of LIVE_CONTROL_IDS) if (!Object.hasOwn(run.controls, id)) fail('LIVE_WORKSPACE_INVALID', 'A stored live control is missing.');
  return run;
}
function validateLiveDocument(value, proposalHash) {
  shape(value, ['schemaVersion', 'kind', 'proposalHash', 'runs', 'selfHash'], 'LIVE_WORKSPACE_INVALID');
  if (value.schemaVersion !== 1 || value.kind !== LIVE_WORKSPACE_KIND || value.proposalHash !== proposalHash ||
      !Array.isArray(value.runs) || value.runs.length > 200 || value.selfHash !== liveDocumentHash(value)) {
    fail('LIVE_WORKSPACE_INVALID', 'The live workspace file failed its integrity check. It was preserved.');
  }
  const ids = new Set();
  for (const run of value.runs) {
    validateLiveRun(run);
    if (ids.has(run.runId)) fail('LIVE_WORKSPACE_INVALID', 'The live workspace contains a duplicate run.');
    ids.add(run.runId);
  }
  if (value.runs.filter(run => !LIVE_FINAL_STATUSES.includes(run.status)).length > 1) {
    fail('LIVE_WORKSPACE_INVALID', 'The live workspace contains more than one open run.');
  }
  return value;
}

export class BrickkenLiveWorkspace {
  #jobs = new Map();

  // evidencePackageRoot is where tools/export-live-evidence.mjs writes the public
  // package (verification/ by default); a recording binds to the package there.
  constructor(directory, { role, rpcs, signer, now = () => Date.now(), sleep, pollMs, verifySignedTransaction, fetchImpl = globalThis.fetch, evidencePackageRoot = 'verification' } = {}) {
    if (!['owner', 'agent'].includes(role)) fail('INVALID_ROLE', 'The live workspace needs the owner or agent role.');
    if (typeof now !== 'function') fail('INVALID_TIME', 'The live workspace clock is invalid.');
    if (typeof evidencePackageRoot !== 'string' || !/^[A-Za-z0-9._\/-]{1,200}$/.test(evidencePackageRoot)) fail('INVALID_INPUT', 'The evidence package root is invalid.');
    this.role = role;
    this.evidencePackageRoot = evidencePackageRoot;
    this.nowMs = () => {
      const value = now();
      if (!Number.isSafeInteger(value) || value <= 0) fail('INVALID_TIME', 'The live workspace requires an exact current time.');
      return value;
    };
    this.sleep = sleep;
    this.pollMs = pollMs;
    this.verifySignedTransaction = verifySignedTransaction;
    this.directory = boundedPath(directory);
    this.liveDirectory = boundedPath(path.join(this.directory, 'live'));
    fs.mkdirSync(this.liveDirectory, { recursive: true });
    this.file = boundedPath(path.join(this.liveDirectory, 'live-workspace.json'));
    this.lock = boundedPath(path.join(this.liveDirectory, 'live-workspace.lock'));
    this.runLock = boundedPath(path.join(this.liveDirectory, 'live-run.lock'));
    try { this.proposal = loadLiveProposal(); }
    catch { fail('LIVE_PROPOSAL_INVALID', 'The reviewed live proposal could not be validated.'); }
    this.journal = new LiveBrickkenJournal({ directory: path.join(this.liveDirectory, 'journal') });
    this.rpcs = rpcs ?? createLiveRpcs({ fetchImpl });
    this.signer = signer ?? new LiveSignerClient({ dataDirectory: this.directory, role, fetchImpl });
    if (fs.existsSync(this.file)) this.read();
    else {
      const document = { schemaVersion: 1, kind: LIVE_WORKSPACE_KIND, proposalHash: this.proposal.proposalHash, runs: [], selfHash: '' };
      document.selfHash = liveDocumentHash(document);
      this.#write(document);
    }
  }

  read() {
    try {
      if (fs.statSync(this.file).size > MAX_FILE_BYTES) fail('LIVE_WORKSPACE_INVALID', 'The live workspace file exceeds its size limit.');
      return clone(validateLiveDocument(JSON.parse(fs.readFileSync(this.file, 'utf8')), this.proposal.proposalHash));
    } catch (error) {
      if (error instanceof BrickkenWorkspaceError) throw error;
      fail('LIVE_WORKSPACE_INVALID', 'The live workspace file could not be read. It was preserved.');
    }
  }

  view() {
    const document = this.read();
    const open = document.runs.find(run => !LIVE_FINAL_STATUSES.includes(run.status)) ?? null;
    return {
      mode: 'live-sepolia',
      role: this.role,
      proposal: {
        proposalHash: this.proposal.proposalHash, network: this.proposal.network, chainId: this.proposal.chainId,
        principal: this.proposal.principal, agent: this.proposal.agent, executor: this.proposal.executor,
        registry: this.proposal.registry, token: this.proposal.token.address, tokenDecimals: this.proposal.token.decimals,
        recipient: this.proposal.recipient.address, limits: { ...this.proposal.limits }, amounts: { ...this.proposal.amounts },
        mandateValiditySeconds: this.proposal.mandateValiditySeconds, fees: { ...this.proposal.fees },
        persistentConfiguration: this.proposal.persistentConfiguration, recipientEnforcement: this.proposal.recipientEnforcement
      },
      activeRunId: open?.runId ?? null,
      runs: document.runs.map(run => this.#runView(run))
    };
  }

  async signerStatus() {
    try {
      const status = await this.signer.status();
      return {
        available: true, role: status.role, approvalSha256: status.approvalSha256, codeIdentitySha256: status.codeIdentitySha256 ?? null,
        notAfter: status.notAfter, active: status.active, signedSteps: Array.isArray(status.signed) ? status.signed.map(item => item.step) : []
      };
    } catch (error) {
      return { available: false, code: classifyLiveError(error).code };
    }
  }

  approvalDocument(runId) {
    const run = this.#run(runId);
    let value;
    try { value = JSON.parse(fs.readFileSync(boundedPath(path.join(this.liveDirectory, run.approvalFile)), 'utf8')); }
    catch { fail('APPROVAL_UNAVAILABLE', 'The run approval file could not be read.'); }
    let approval;
    try { approval = validateRunApproval(value, this.proposal); }
    catch { fail('APPROVAL_INVALID', 'The run approval file does not match the reviewed plan.'); }
    if (approval.approvalSha256 !== run.approvalSha256) fail('APPROVAL_INVALID', 'The run approval file changed after preparation.');
    return approval;
  }

  // ---- owner ---------------------------------------------------------------

  async prepareRun() {
    this.#requireRole('owner');
    if (this.read().runs.some(run => !LIVE_FINAL_STATUSES.includes(run.status))) {
      fail('LIVE_RUN_OPEN', 'Finish or stop the open live run before preparing another.');
    }
    const lease = this.#acquireRunLock('prepare', null);
    try {
      const preflight = await readLivePreflight({ proposal: this.proposal, rpcs: this.rpcs, now: this.nowMs, sleep: this.sleep });
      const createdAtMs = this.nowMs();
      const approval = buildRunApproval(this.proposal, {
        createdAt: isoAt(createdAtMs), notAfter: isoAt(createdAtMs + LIVE_APPROVAL_LIFETIME_MS), preflight
      });
      // The approval hash binds the operational plan and the preflight only. The
      // source bytes are identified separately by their stable hash, so a run
      // approval names both hashes. The process that prepares the run must be
      // running the bytes on disk, otherwise the identity it records is not its own.
      const { codeIdentitySha256, evidence: identity } = identityNow(approval.createdAt);
      if (codeIdentitySha256 !== PROCESS_CODE_IDENTITY_SHA256) {
        fail('CODE_IDENTITY_MISMATCH', 'The source code on disk differs from the code this process started with. Restart the owner workspace from the current code before preparing a plan.',
          { phase: 'prepare', processCodeIdentitySha256: PROCESS_CODE_IDENTITY_SHA256, diskCodeIdentitySha256: codeIdentitySha256 });
      }
      const approvalFile = `run-approval-${approval.approvalSha256.slice(0, 16)}.json`;
      fs.writeFileSync(boundedPath(path.join(this.liveDirectory, approvalFile)), JSON.stringify(approval, null, 2), { flag: 'wx' });
      const runId = `live_${randomUUID().replaceAll('-', '')}`;
      const run = {
        runId,
        createdAt: approval.createdAt,
        notAfter: approval.notAfter,
        approvalSha256: approval.approvalSha256,
        approvalFile,
        status: 'awaiting-owner-approval',
        phase: null,
        ownerApproval: null,
        preflightBlockers: structuredClone(preflight.blockers),
        steps: Object.fromEntries(LIVE_WRITE_STEPS.map(step => [step, {
          planned: preflight.plannedWrites.includes(step),
          skipReason: preflight.plannedWrites.includes(step) ? null : 'EXECUTOR_ACTION_ALREADY_CONFIGURED',
          operationId: `${runId}_${step}`
        }])),
        controls: Object.fromEntries(LIVE_CONTROL_IDS.map(id => [id, null])),
        replays: [],
        stop: null,
        cleanup: null,
        finality: null,
        updatedAt: approval.createdAt,
        codeIdentitySha256
      };
      this.#mutate(document => {
        if (document.runs.some(item => !LIVE_FINAL_STATUSES.includes(item.status))) {
          fail('LIVE_RUN_OPEN', 'Finish or stop the open live run before preparing another.');
        }
        document.runs.push(run);
      });
      this.#evidence(runId, 'preflight-plan', preflight);
      this.#evidence(runId, 'code-identity', identity);
      this.#evidence(runId, 'run-approval', approval);
      return { run: this.#runView(this.#run(runId)), approval, codeIdentitySha256 };
    } catch (error) {
      throw workspaceFailure(error);
    } finally {
      lease.release();
    }
  }

  // The owner approves two hashes: the exact plan and the exact source
  // identity the run was prepared from. Both are stored in the approval record
  // and both are checked again before every write of the run.
  approveRun({ runId, approvalSha256, codeIdentitySha256 }) {
    this.#requireRole('owner');
    if (typeof approvalSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(approvalSha256)) fail('INVALID_INPUT', 'The approval hash is invalid.');
    if (typeof codeIdentitySha256 !== 'string' || !/^[a-f0-9]{64}$/.test(codeIdentitySha256)) fail('INVALID_INPUT', 'The code identity hash is invalid.');
    const approval = this.approvalDocument(runId);
    if (approval.approvalSha256 !== approvalSha256) fail('APPROVAL_HASH_MISMATCH', 'Approval applies only to the exact plan hash shown for this run.');
    const run = this.#run(runId);
    if (run.codeIdentitySha256 !== codeIdentitySha256) fail('CODE_IDENTITY_MISMATCH', 'Approval applies only to the exact source code identity shown for this run.', { phase: 'approve', codeIdentitySha256: run.codeIdentitySha256 ?? null });
    this.#requireCodeIdentity(run, 'approve', { evidence: false });
    this.#update(runId, item => {
      if (item.status === 'owner-approved' && item.ownerApproval?.approvalSha256 === approvalSha256 && item.ownerApproval?.codeIdentitySha256 === codeIdentitySha256) return;
      if (item.status !== 'awaiting-owner-approval') fail('RUN_STATE', 'This run is not waiting for owner approval.');
      if (this.nowMs() >= Date.parse(item.notAfter)) fail('APPROVAL_EXPIRED', 'This plan expired. Prepare a fresh plan.');
      item.ownerApproval = { approvedAt: isoAt(this.nowMs()), approvalSha256, codeIdentitySha256 };
      item.status = 'owner-approved';
    });
    return this.#runView(this.#run(runId));
  }

  async startOwnerSetup({ runId }) {
    this.#requireRole('owner');
    const run = this.#run(runId);
    if (!(run.status === 'owner-approved' || (run.status === 'stopped' && run.phase === 'owner-setup'))) {
      fail('RUN_STATE', 'Owner setup starts only after the owner approves the exact plan.');
    }
    return this.#start(run, 'owner-setup', 'owner-setup-running', lease => this.#ownerSetup(runId, lease));
  }

  async startOwnerRevocation({ runId }) {
    this.#requireRole('owner');
    const run = await this.#reconcileExecute(runId);
    if (!(run.status === 'awaiting-owner-revocation' || (run.status === 'stopped' && run.phase === 'owner-revocation'))) {
      fail('RUN_STATE', 'Revocation starts after the approved execute step is verified.');
    }
    if (this.journal.find(run.steps.execute.operationId)?.state !== 'semantically_verified') {
      fail('RUN_STATE', 'The approved execute step is not verified yet.');
    }
    return this.#start(run, 'owner-revocation', 'owner-revocation-running', lease => this.#ownerRevocation(runId, lease));
  }

  async startCleanup({ runId }) {
    this.#requireRole('owner');
    const run = await this.#reconcileExecute(runId);
    if (!run.ownerApproval || ['completed', 'awaiting-owner-approval', 'owner-approved'].includes(run.status)) {
      fail('RUN_STATE', 'Cleanup is available for an approved run that stopped before completion.');
    }
    // The owner's process cannot resend the agent's execute bytes, so an unsettled
    // execute is left to the agent's own execute_approved before cleanup runs.
    const executeRecord = this.journal.find(run.steps.execute.operationId);
    if (run.status === 'agent-executing' || (executeRecord && LIVE_TRACKING_STATES.includes(executeRecord.state))) {
      fail('RUN_STATE', 'The agent execute step is not settled. Let the agent call execute_approved again, or wait for its transaction to resolve, before cleanup.', { step: 'execute', journalState: executeRecord?.state ?? null });
    }
    if (!['stopped', 'awaiting-agent', 'awaiting-owner-revocation'].includes(run.status)) {
      fail('RUN_STATE', 'Wait for the running phase to stop before cleanup.');
    }
    return this.#start(run, 'cleanup', 'cleanup-running', lease => this.#cleanup(runId, lease));
  }

  async resumeRun({ runId }) {
    this.#requireRole('owner');
    const run = this.#run(runId);
    const running = ['owner-setup-running', 'owner-revocation-running', 'cleanup-running'].includes(run.status) && !this.#jobs.has(runId);
    if (!(run.status === 'stopped' || running) || !['owner-setup', 'owner-revocation', 'cleanup'].includes(run.phase)) {
      fail('RUN_STATE', 'Only a stopped owner phase can be resumed.');
    }
    const status = { 'owner-setup': 'owner-setup-running', 'owner-revocation': 'owner-revocation-running', cleanup: 'cleanup-running' }[run.phase];
    if (this.nowMs() >= Date.parse(run.notAfter)) {
      // After expiry nothing is prepared, signed or sent again. Recorded
      // transactions are still followed by reads so a late confirmation is kept.
      if (!this.#trackableSteps(run).length) {
        fail('APPROVAL_EXPIRED', 'The run approval expired and no recorded transaction is left to track. Further writes need a new approval.');
      }
      return this.#start(run, run.phase, status, lease => this.#trackOnly(runId, lease), { trackingOnly: true });
    }
    const work = {
      'owner-setup': lease => this.#ownerSetup(runId, lease),
      'owner-revocation': lease => this.#ownerRevocation(runId, lease),
      cleanup: lease => this.#cleanup(runId, lease)
    }[run.phase];
    return this.#start(run, run.phase, status, work);
  }

  async refreshFinality({ runId }) {
    this.#requireRole('owner');
    const run = this.#run(runId);
    // A finality result is evidence the completeness rule rests on; a process
    // running other code than the run was approved for does not produce one.
    this.#requireCodeIdentity(run, 'finality');
    const lease = this.#acquireRunLock('finality', runId);
    try {
      const executor = this.#executor(run, lease);
      await executor.recheck(this.#touchedOperationIds(run));
      // A withdrawn confirmation or a control block that left the canonical chain
      // changes the run's phase before finality is measured, so no idle status
      // outlives the evidence it rests on.
      this.#reconcileWithdrawn(runId);
      await this.#recheckControls(runId, { stopRun: true });
      // Every planned write and every control counts, so an unverified step or a
      // lost control keeps the run from being final.
      const current = this.#run(runId);
      const planned = LIVE_WRITE_STEPS.filter(step => current.steps[step].planned).map(step => current.steps[step].operationId);
      const controls = LIVE_CONTROL_IDS.map(id => ({ controlId: id, ...(current.controls[id] ?? { observed: false }) }));
      const finality = { checkedAt: isoAt(this.nowMs()), ...(await checkRunFinality({ rpcs: this.rpcs, journal: this.journal, operationIds: planned, controls })) };
      this.#evidence(runId, 'finality', finality);
      this.#update(runId, item => { item.finality = { checkedAt: finality.checkedAt, allFinalized: finality.allFinalized, entries: finality.entries }; });
      return finality;
    } catch (error) {
      throw workspaceFailure(error);
    } finally {
      lease.release();
    }
  }

  // Binds a recording to one completed run whose evidence is complete right now
  // and whose evidence package has been exported: the run, its approval and
  // plan hashes, the code identity, every write's hash and block, every control
  // block, the finality result the recording shows, and the SHA-256 of the
  // package's SHA256SUMS.json. The package must name this run, this approval,
  // this code identity, a complete export and the journal's transactions, so
  // the video and the package identify each other byte for byte (A1-F11).
  recordingBinding(runId, { packageDirectory = null } = {}) {
    this.#requireRole('owner');
    const run = this.#run(runId);
    // The completeness rule and this binding run in this process's code, so the
    // binding is produced only by the code the run was approved for.
    this.#requireCodeIdentity(run, 'recording', { evidence: false });
    const completeness = evaluateLiveRunCompleteness({
      run, journal: this.journal, evidenceDirectory: boundedPath(path.join(this.liveDirectory, 'evidence', run.runId))
    });
    if (!completeness.complete) {
      fail('RECORDING_RUN_INCOMPLETE', 'The selected run is not complete as evidence, so no recording is bound to it.', { missing: [...completeness.missing] });
    }
    const directory = packageDirectory ?? `${this.evidencePackageRoot}/sepolia-live-${run.runId.slice(5, 17)}`;
    if (typeof directory !== 'string' || !/^[A-Za-z0-9._\/-]{1,200}$/.test(directory)) fail('INVALID_INPUT', 'The evidence package directory is invalid.');
    const packagePath = boundedPath(path.join(ROOT, ...directory.split('/')));
    const sumsFile = path.join(packagePath, 'SHA256SUMS.json');
    if (!fs.existsSync(sumsFile)) {
      fail('RECORDING_PACKAGE_REQUIRED', 'The complete evidence package of this run has not been exported yet, so no recording is bound to it. Export the package first.', { packageDirectory: directory });
    }
    const transactions = LIVE_WRITE_STEPS.filter(step => run.steps[step].planned).map(step => {
      const record = this.journal.get(run.steps[step].operationId);
      return {
        step, operationId: record.operationId, transactionHash: record.signed.ethereumTransactionHash,
        blockNumber: record.confirmation.blockNumber, blockHash: record.confirmation.blockHash
      };
    });
    const sumsBytes = fs.readFileSync(sumsFile);
    let table;
    try {
      const sums = JSON.parse(sumsBytes.toString('utf8'));
      const tableBytes = fs.readFileSync(path.join(packagePath, 'transactions.json'));
      if (sums['transactions.json'] !== createHash('sha256').update(tableBytes).digest('hex')) throw new Error('SUMS');
      table = JSON.parse(tableBytes.toString('utf8'));
    } catch {
      fail('RECORDING_PACKAGE_MISMATCH', 'The evidence package could not be read, or its transaction table does not match its SHA256SUMS.json.', { packageDirectory: directory });
    }
    const named = item => table.transactions.find(row => row.operationId === item.operationId)?.transactionHash === item.transactionHash;
    if (!plain(table) || table.runId !== run.runId || table.approvalSha256 !== run.approvalSha256 || table.codeIdentitySha256 !== run.codeIdentitySha256 ||
        table.complete !== true || !Array.isArray(table.transactions) || !transactions.every(named)) {
      fail('RECORDING_PACKAGE_MISMATCH', 'The evidence package names another run, another approval, another code identity, an incomplete export or other transactions than the journal.', { packageDirectory: directory });
    }
    return {
      runId: run.runId,
      approvalSha256: run.approvalSha256,
      proposalHash: this.proposal.proposalHash,
      codeIdentitySha256: run.codeIdentitySha256 ?? null,
      ownerApprovedAt: run.ownerApproval.approvedAt,
      finality: { checkedAt: run.finality.checkedAt, allFinalized: run.finality.allFinalized },
      transactions,
      controls: LIVE_CONTROL_IDS.map(id => ({ id, blockNumber: run.controls[id].blockNumber, blockHash: run.controls[id].blockHash })),
      evidencePackage: { directory, sha256sumsSha256: createHash('sha256').update(sumsBytes).digest('hex') }
    };
  }

  whenIdle(runId) { return this.#jobs.get(runId) ?? Promise.resolve(); }

  // ---- agent ---------------------------------------------------------------

  agentContext() {
    this.#requireRole('agent');
    const open = this.read().runs.find(run => !LIVE_FINAL_STATUSES.includes(run.status)) ?? null;
    return {
      mode: 'live-sepolia',
      network: this.proposal.network,
      chainId: this.proposal.chainId,
      agent: this.proposal.agent,
      activeRun: open ? {
        runId: open.runId, status: open.status, approvalSha256: open.approvalSha256, notAfter: open.notAfter,
        executeOperationId: open.steps.execute.operationId,
        executeAvailable: ['awaiting-agent', 'agent-executing'].includes(open.status)
      } : null,
      approvedTransfer: {
        token: this.proposal.token.address, decimals: this.proposal.token.decimals,
        recipient: this.proposal.recipient.address, amount: this.proposal.amounts.execute
      },
      ownerActionsAvailable: false
    };
  }

  async agentPreflight({ operationId }) {
    this.#requireRole('agent');
    const run = this.#runByExecuteOperation(operationId);
    try {
      const { primary } = this.rpcs;
      const block = await primary.getBlock('latest');
      const ref = { blockHash: block.hash };
      const calls = readCalls(this.proposal);
      const canExecute = await primary.call(calls.canExecute(this.proposal.amounts.execute), ref);
      const simulation = await primary.call({ from: this.proposal.agent, to: this.proposal.executor, data: expectedCalldata(this.proposal, 'execute') }, ref);
      const mandate = await primary.call(calls.getMandate(), ref);
      return {
        operationId,
        runStatus: run.status,
        block: { number: block.number, hash: block.hash, timestamp: block.timestamp },
        canExecute: canExecute.ok ? decodeBoolReturn(canExecute.returnData) : null,
        executionSimulationSucceeded: simulation.ok,
        simulationRevert: simulation.ok ? null : decodeRevert(simulation.revertData),
        mandate: mandate.ok ? decodeMandateReturn(mandate.returnData) : null,
        journalState: this.journal.find(operationId)?.state ?? null,
        readOnly: true, signed: false, broadcast: false
      };
    } catch (error) {
      throw workspaceFailure(error, 'execute');
    }
  }

  async agentExecute({ operationId }) {
    this.#requireRole('agent');
    let run = this.#runByExecuteOperation(operationId);
    const existing = this.journal.find(operationId);
    if (existing?.state === 'semantically_verified') {
      // A verified execute first brings the workspace phase in line with the
      // journal, because a process may have ended between the journal write and
      // the workspace write; then the replay is recorded. Nothing is sent.
      try {
        run = await this.#reconcileExecute(run.runId);
        await this.#recordReplay(run.runId, this.journal.get(operationId));
      } catch (error) { throw workspaceFailure(error, 'execute'); }
      return this.agentReceipt({ operationId });
    }
    if (!(['awaiting-agent', 'agent-executing'].includes(run.status) || (run.status === 'stopped' && run.phase === 'agent-execute'))) {
      fail('EXECUTION_NOT_AVAILABLE', 'The owner setup for this operation is not complete, or the run moved past execution.');
    }
    const expired = this.nowMs() >= Date.parse(run.notAfter);
    // After expiry an already broadcast execute is still tracked by reads; nothing new is signed or sent.
    const trackingOnly = expired && existing !== null && LIVE_TRACKING_STATES.includes(existing.state);
    if (expired && !trackingOnly) fail('APPROVAL_EXPIRED', 'The run approval expired.');
    // The agent's own process must run the approved code; the owner's process cannot vouch for it.
    this.#requireCodeIdentity(run, 'agent-execute');
    if (!trackingOnly) await this.#requireSigner(run);
    const lease = this.#acquireRunLock('agent-execute', run.runId);
    try {
      if (!trackingOnly && !existing) await this.#requireControlCanonical(run.runId, 'control-transaction-cap');
      this.#update(run.runId, item => { item.status = 'agent-executing'; item.phase = 'agent-execute'; item.stop = null; });
      const executor = this.#executor(run, lease, { trackingOnly });
      const outcome = await executor.advance({ runId: run.runId, step: 'execute', deadlineMs: LIVE_AGENT_CALL_MS });
      if (outcome.done) this.#update(run.runId, item => { item.status = 'awaiting-owner-revocation'; item.phase = null; });
      else if (trackingOnly) {
        fail('RECOVERY_AUTHORIZATION_REQUIRED',
          'The approval expired while the execute transaction is unresolved. Its recorded bytes are tracked by reads only; sending them again needs a recovery authorization for exactly this hash.',
          { step: 'execute', transactionHash: outcome.transactionHash, notAfter: run.notAfter, journalState: outcome.state, attempts: outcome.attempts });
      }
    } catch (error) {
      this.#recordStop(run.runId, error, 'execute');
      throw workspaceFailure(error, 'execute');
    } finally {
      lease.release();
    }
    return this.agentReceipt({ operationId });
  }

  agentReceipt({ operationId }) {
    const run = this.#runByExecuteOperation(operationId);
    const view = this.#runView(run);
    return {
      operationId,
      runId: run.runId,
      runStatus: run.status,
      execute: view.steps.find(step => step.step === 'execute'),
      controls: view.controls,
      replays: view.replays,
      stop: view.stop,
      finality: view.finality
    };
  }

  // ---- phases ----------------------------------------------------------------

  async #ownerSetup(runId, lease) {
    const started = this.#touchedOperationIds(this.#run(runId)).length > 0;
    const preflight = await readLivePreflight({ proposal: this.proposal, rpcs: this.rpcs, now: this.nowMs, sleep: this.sleep });
    this.#evidence(runId, started ? `preflight-resume-${this.nowMs()}` : 'preflight-start', preflight);
    if (!started) this.#evidence(runId, 'code-identity-start', identityNow(isoAt(this.nowMs())).evidence);
    // On a resume the run's own earlier writes explain these readings.
    const expectedAfterStart = new Set([
      'ALLOWANCE_NOT_ZERO', 'MANDATE_NOT_REVOKED', 'OWNER_PENDING_TRANSACTION', 'SIMULATION_REVERTED',
      'OWNER_GAS_FUNDING', 'AGENT_GAS_FUNDING'
    ]);
    const blockers = preflight.blockers.filter(item => !(started && expectedAfterStart.has(item.code)));
    if (blockers.length) fail('PREFLIGHT_BLOCKED', 'The fresh Sepolia preflight found a blocker.', { blockers });
    const run = this.#run(runId);
    if (!run.steps.setAction.planned && preflight.plannedWrites.includes('setAction')) {
      fail('PLAN_CHANGED', 'The executor action changed after the plan was prepared. Prepare a fresh plan.');
    }
    if (run.steps.setAction.planned && !preflight.plannedWrites.includes('setAction') && !this.journal.find(run.steps.setAction.operationId)) {
      // The fresh state already matches the configuration, so the write is left out.
      this.#update(runId, item => { item.steps.setAction.planned = false; item.steps.setAction.skipReason = 'EXECUTOR_ACTION_ALREADY_CONFIGURED'; });
    }
    const executor = this.#executor(run, lease);
    for (const step of ['setAction', 'approve', 'grant']) {
      if (!this.#run(runId).steps[step].planned) continue;
      await this.#advanceUntilDone(executor, runId, step);
      await this.#recheckAndReconfirm(executor, runId);
    }
    if (!this.#run(runId).controls['control-transaction-cap']?.passed) {
      if (this.journal.find(run.steps.execute.operationId)) fail('CONTROL_ORDER', 'The transaction-cap control must run before execute.');
      await this.#control(runId, 'control-transaction-cap', lease);
    }
    this.#update(runId, item => { item.status = 'awaiting-agent'; item.phase = null; });
  }

  async #ownerRevocation(runId, lease) {
    const run = this.#run(runId);
    const executor = this.#executor(run, lease);
    // A reorganisation while the run waited may have withdrawn the execute verification or a control block.
    await this.#recheckAndReconfirm(executor, runId);
    for (const controlId of ['control-cumulative-cap', 'control-before-revoke']) {
      if (this.#run(runId).controls[controlId]?.passed) continue;
      if (this.journal.find(run.steps.revoke.operationId)) fail('CONTROL_ORDER', 'The pre-revocation controls must run before revoke.');
      await this.#control(runId, controlId, lease);
    }
    await this.#advanceUntilDone(executor, runId, 'revoke');
    await this.#recheckAndReconfirm(executor, runId);
    if (!this.#run(runId).controls['control-after-revoke']?.passed) {
      if (this.journal.find(run.steps.approveReset.operationId)) fail('CONTROL_ORDER', 'The revocation control must run before the allowance reset.');
      await this.#control(runId, 'control-after-revoke', lease);
    }
    await this.#advanceUntilDone(executor, runId, 'approveReset');
    await this.#recheckAndReconfirm(executor, runId);
    this.#update(runId, item => { item.status = 'completed'; item.phase = null; });
  }

  async #cleanup(runId, lease) {
    const run = this.#run(runId);
    // Cleanup may revoke a mandate that is already non-executable, so its revoke
    // verifier records the prior executability instead of requiring it.
    const executor = this.#executor(run, lease, { cleanup: true });
    // Resolve every transaction that may already be on chain before deciding
    // anything. A grant or approve that is confirmed on chain but whose semantic
    // postcheck fails stays confirmed: cleanup does not need that demonstration
    // to succeed, it attributes the chain effect separately below (N1).
    const postcheckFailed = {};
    for (const step of LIVE_WRITE_STEPS) {
      const record = this.journal.find(run.steps[step].operationId);
      if (!record || !['broadcast', 'uncertain', 'confirmed'].includes(record.state)) continue;
      try { await this.#advanceUntilDone(executor, runId, step); }
      catch (error) {
        if (error?.code !== 'SEMANTIC_CHECK_FAILED' || !['grant', 'approve'].includes(step)) throw error;
        postcheckFailed[step] = safeDetails(error.details);
        this.#evidence(runId, `cleanup-postcheck-failed-${step}`, { step, code: error.code, details: postcheckFailed[step], at: isoAt(this.nowMs()) });
      }
    }
    const unsent = LIVE_WRITE_STEPS.filter(step => this.journal.find(run.steps[step].operationId)?.state === 'signed');
    if (unsent.length) {
      fail('UNSENT_SIGNATURE_BLOCKS_CLEANUP', 'A signed transaction was never broadcast, and its nonce blocks further owner writes. A new decision is needed.', { steps: unsent });
    }
    const verified = step => this.journal.find(run.steps[step].operationId)?.state === 'semantically_verified';
    const attribution = {};
    for (const step of ['approve', 'grant']) {
      const record = this.journal.find(run.steps[step].operationId);
      if (record?.state === 'confirmed') attribution[step] = await this.#attributeWrite(runId, step, record);
    }
    const proven = step => verified(step) || attribution[step]?.attributed === true;
    const grantRecord = this.journal.find(run.steps.grant.operationId);
    const plannedMandate = grantRecord?.signed ? grantMandateFromCalldata(grantRecord.transaction.data) : null;
    let revokedByCleanup = false;
    let allowanceResetByCleanup = false;
    const problems = [];
    let reads = await this.#mandateAndAllowance();
    if (reads.mandate && !reads.mandate.revoked) {
      // Only the mandate this run granted is revoked: its identity fields must
      // equal the run's grant calldata and the grant must be verified or attributed.
      // The two failures get their own codes: another mandate on chain, or this
      // run's mandate whose grant could not be attributed from both sources.
      const sameIdentity = plannedMandate !== null && sameMandateIdentity(reads.mandate, plannedMandate);
      if (sameIdentity && proven('grant')) {
        if (!verified('revoke')) {
          await this.#advanceUntilDone(executor, runId, 'revoke');
          revokedByCleanup = true;
          reads = await this.#mandateAndAllowance();
        }
      } else if (!sameIdentity) {
        problems.push({
          code: 'CLEANUP_FOREIGN_MANDATE',
          message: 'An active mandate on chain is not the one this run granted, so cleanup does not revoke it. The evidence is kept; the mandate needs a separate decision.',
          details: { mandate: reads.mandate, attributed: attribution.grant?.attributed ?? null }
        });
      } else {
        problems.push({
          code: 'CLEANUP_GRANT_UNATTRIBUTED',
          message: 'The active mandate on chain carries this run\'s grant identity, but the grant is neither verified nor attributed from both read sources, so cleanup does not revoke it. The evidence is kept; check the read sources and run cleanup again.',
          details: { mandate: reads.mandate, attributed: attribution.grant?.attributed ?? null, reason: attribution.grant?.reason ?? null }
        });
      }
    }
    if (reads.allowance !== '0') {
      if (proven('approve')) {
        if (!verified('approveReset')) {
          await this.#advanceUntilDone(executor, runId, 'approveReset');
          allowanceResetByCleanup = true;
          reads = await this.#mandateAndAllowance();
        }
      } else {
        problems.push({
          code: 'CLEANUP_UNATTRIBUTED_ALLOWANCE',
          message: 'A non-zero allowance on chain is not attributed to this run\'s approve, so cleanup does not reset it. The evidence is kept; the allowance needs a separate decision.',
          details: { attributed: attribution.approve?.attributed ?? null }
        });
      }
    }
    const cleanup = {
      completedAt: isoAt(this.nowMs()), revokedByCleanup, allowanceResetByCleanup,
      mandateRevoked: reads.mandate ? reads.mandate.revoked : null, allowance: reads.allowance, block: reads.block,
      attribution: Object.fromEntries(Object.entries(attribution).map(([step, item]) => [step, { attributed: item.attributed, reason: item.reason }])),
      postcheckFailed: Object.keys(postcheckFailed),
      problems: problems.map(item => item.code)
    };
    this.#evidence(runId, 'cleanup', cleanup);
    this.#update(runId, item => { item.cleanup = cleanup; item.status = 'stopped'; item.phase = null; });
    if (problems.length) fail(problems[0].code, problems[0].message, problems[0].details);
  }

  // Cleanup acts only on chain effects it can attribute to this run. A confirmed
  // grant or approve whose semantic postcheck failed is attributed by its receipt
  // on both sources (hash, sender, target, status, block), its calldata rebuilt
  // from the reviewed plan, the one event the write must emit on both sources,
  // and the block-bound state after it read from both sources. Anything less
  // leaves the effect unattributed, and cleanup stops rather than revoke or
  // reset what it cannot prove is its own. The result is written as evidence.
  async #attributeWrite(runId, step, record) {
    const proposal = this.proposal;
    const { primary, secondary } = this.rpcs;
    const hash = record.signed.ethereumTransactionHash;
    const result = { step, operationId: record.operationId, transactionHash: hash, blockHash: record.confirmation.blockHash, attributed: false, reason: null, checkedAt: isoAt(this.nowMs()) };
    const finish = reason => {
      result.reason = reason;
      result.attributed = reason === null;
      this.#evidence(runId, `cleanup-attribution-${step}`, result);
      return result;
    };
    const [receiptA, receiptB] = await Promise.all([primary.getTransactionReceipt(hash), secondary.getTransactionReceipt(hash)]);
    const identity = receipt => Boolean(receipt) && receipt.transactionHash === hash && receipt.status === 1 &&
      receipt.from === record.transaction.from && receipt.to === record.transaction.to && receipt.blockHash === record.confirmation.blockHash;
    if (!identity(receiptA) || !identity(receiptB)) return finish('RECEIPT_IDENTITY');
    const expectedData = step === 'grant'
      ? expectedCalldata(proposal, 'grant', { validFrom: grantValidFrom(record.transaction.data) })
      : expectedCalldata(proposal, 'approve');
    if (record.transaction.data !== expectedData) return finish('CALLDATA');
    const topic = step === 'grant' ? EVENT_TOPICS.MandateGranted : EVENT_TOPICS.Approval;
    const contract = step === 'grant' ? proposal.registry : proposal.token.address;
    const expectedTopics = step === 'grant' ? [proposal.agent, proposal.principal] : [proposal.principal, proposal.executor];
    const topicAddress = value => '0x' + String(value).slice(26);
    for (const receipt of [receiptA, receiptB]) {
      const events = receipt.logs.filter(log => log.address === contract && log.topics[0] === topic);
      if (events.length !== 1 || events[0].topics.length !== 3 ||
          topicAddress(events[0].topics[1]) !== expectedTopics[0] || topicAddress(events[0].topics[2]) !== expectedTopics[1]) return finish('EVENT');
    }
    const ref = { blockHash: record.confirmation.blockHash };
    const calls = readCalls(proposal);
    if (step === 'grant') {
      const [a, b] = await Promise.all([primary.call(calls.getMandate(), ref), secondary.call(calls.getMandate(), ref)]);
      if (!a.ok || !b.ok) return finish('READ_REVERTED');
      const mandateA = decodeMandateReturn(a.returnData);
      const mandateB = decodeMandateReturn(b.returnData);
      if (!mandateA || !mandateB || canonicalJson(mandateA) !== canonicalJson(mandateB)) return finish('SOURCE_STATE_DISAGREEMENT');
      if (mandateA.revoked !== false || mandateA.cumulativeUsed !== '0' || !sameMandateIdentity(mandateA, grantMandateFromCalldata(record.transaction.data))) return finish('STATE');
      result.mandate = mandateA;
    } else {
      const [a, b] = await Promise.all([primary.call(calls.allowance(), ref), secondary.call(calls.allowance(), ref)]);
      if (!a.ok || !b.ok) return finish('READ_REVERTED');
      const allowanceA = decodeUintReturn(a.returnData);
      if (allowanceA !== decodeUintReturn(b.returnData)) return finish('SOURCE_STATE_DISAGREEMENT');
      if (allowanceA !== BigInt('0x' + record.transaction.data.slice(74, 138)).toString()) return finish('STATE');
      result.allowance = allowanceA;
    }
    return finish(null);
  }

  // ---- helpers ---------------------------------------------------------------

  async #start(run, phase, status, work, { trackingOnly = false } = {}) {
    if (this.#jobs.has(run.runId)) fail('LIVE_JOB_RUNNING', 'A live phase is already running for this run.');
    // Every phase, tracking-only included, runs only on the approved code: a
    // changed process would otherwise mark new semantic results and evidence.
    this.#requireCodeIdentity(run, phase);
    if (!trackingOnly) {
      if (this.nowMs() >= Date.parse(run.notAfter)) fail('APPROVAL_EXPIRED', 'The run approval expired.');
      await this.#requireSigner(run);
    }
    const lease = this.#acquireRunLock(phase, run.runId);
    try {
      this.#update(run.runId, item => { item.status = status; item.phase = phase; item.stop = null; });
    } catch (error) {
      lease.release();
      throw error;
    }
    const job = (async () => {
      try { await work(lease); }
      catch (error) { this.#recordStop(run.runId, error); }
      finally {
        lease.release();
        this.#jobs.delete(run.runId);
      }
    })();
    this.#jobs.set(run.runId, job);
    return { started: true, run: this.#runView(this.#run(run.runId)) };
  }

  async #requireSigner(run) {
    let status;
    try { status = await this.signer.status(); }
    catch (error) { throw workspaceFailure(error); }
    if (status?.approvalSha256 !== run.approvalSha256) fail('SIGNER_APPROVAL_MISMATCH', 'The running signer was started with a different run approval.');
    if (status.codeIdentitySha256 !== run.codeIdentitySha256) {
      fail('SIGNER_CODE_IDENTITY_MISMATCH', 'The running signer reports another source code identity than this run was approved for.',
        { codeIdentitySha256: run.codeIdentitySha256 ?? null, processCodeIdentitySha256: status.codeIdentitySha256 ?? null });
    }
    if (status.active !== true) fail('SIGNER_APPROVAL_NOT_ACTIVE', 'The running signer reports that the run approval is not active.');
    if (status.role !== this.role) fail('SIGNER_ROLE_MISMATCH', 'The signer token does not belong to this role.');
  }

  // The run's approved code identity must equal both the identity of this
  // process, read when it started, and the identity on disk right now. Anything
  // else stops with CODE_IDENTITY_MISMATCH before a preparation, a signature or
  // a send; recorded transactions and existing evidence stay as they are.
  #requireCodeIdentity(run, phase, { evidence = true } = {}) {
    const expected = run.codeIdentitySha256 ?? null;
    let disk;
    try { disk = computeCodeIdentity().codeIdentitySha256; }
    catch (error) {
      fail('CODE_IDENTITY_MISMATCH', 'The source tree could not be identified, so nothing is prepared, signed or sent.', { phase, codeIdentitySha256: expected, reason: error?.code ?? 'CODE_IDENTITY_UNREADABLE' });
    }
    const observation = {
      phase, role: this.role, checkedAt: isoAt(this.nowMs()), codeIdentitySha256: expected,
      processCodeIdentitySha256: PROCESS_CODE_IDENTITY_SHA256, diskCodeIdentitySha256: disk,
      match: expected !== null && expected === PROCESS_CODE_IDENTITY_SHA256 && expected === disk
    };
    if (evidence) this.#evidence(run.runId, `code-identity-${phase}-${this.nowMs()}`, observation);
    if (!observation.match) {
      fail('CODE_IDENTITY_MISMATCH', 'The source code identity differs from the one this run was approved for. Nothing is prepared, signed or sent; restore the approved code, or prepare a fresh plan from the current code.',
        { phase, codeIdentitySha256: expected, processCodeIdentitySha256: PROCESS_CODE_IDENTITY_SHA256, diskCodeIdentitySha256: disk });
    }
    return observation;
  }

  // A recheck withdraws the verification of a step whose block changed. Such a
  // step is tracked, confirmed and verified again before the run moves on.
  async #recheckAndReconfirm(executor, runId) {
    await executor.recheck(this.#touchedOperationIds(this.#run(runId)));
    const run = this.#run(runId);
    for (const step of LIVE_WRITE_STEPS) {
      const record = this.journal.find(run.steps[step].operationId);
      if (record && LIVE_TRACKING_STATES.includes(record.state)) {
        await this.#advanceUntilDone(executor, runId, step);
      }
    }
    await this.#recheckControls(runId, { stopRun: false });
  }

  // lease is the run lock lease of the calling phase; the executor refuses to
  // act once this process no longer holds it. trackingOnly and cleanup select
  // the read-only and the cleanup revocation behaviour of the adapter.
  #executor(run, lease = null, { trackingOnly = false, cleanup = false } = {}) {
    return new LiveStepExecutor({
      proposal: this.proposal, rpcs: this.rpcs, signer: this.signer, journal: this.journal,
      approvalSha256: run.approvalSha256, now: this.nowMs, sleep: this.sleep, pollMs: this.pollMs,
      verifySignedTransaction: this.verifySignedTransaction,
      onEvidence: (name, value) => this.#evidence(run.runId, name, value),
      notAfter: run.notAfter, trackingOnly, cleanup,
      assertOwnership: () => this.#requireLease(lease),
      assertCodeIdentity: () => this.#requireCodeIdentity(run, 'write', { evidence: false })
    });
  }

  #requireLease(lease) {
    if (lease !== null && !lease.holds()) {
      fail('LIVE_RUN_LOCK_LOST', 'This process no longer holds the live run lock. The step stopped before any further action.', { lockFile: 'live-run.lock' });
    }
  }

  async #advanceUntilDone(executor, runId, step) {
    const started = this.nowMs();
    const limit = executor.trackingOnly ? LIVE_TRACKING_WAIT_MS : LIVE_STEP_WAIT_MS;
    while (true) {
      const outcome = await executor.advance({ runId, step, deadlineMs: 60_000 });
      this.#update(runId, item => { item.updatedAt = isoAt(this.nowMs()); });
      if (outcome.done) return outcome;
      if (this.nowMs() - started > limit) {
        const details = { step, transactionHash: outcome.transactionHash, journalState: outcome.state, attempts: outcome.attempts, backoffUntil: outcome.backoffUntil };
        if (outcome.waitingFor) {
          fail('DEPENDENCY_NOT_PROGRESSED',
            `The ${step} write waited for an earlier write of this run to read at the required depth from both sources, and it did not within the phase's time. Nothing was signed; resume once both sources agree again.`,
            { ...details, ...outcome.waitingFor });
        }
        if (executor.trackingOnly) {
          fail('RECOVERY_AUTHORIZATION_REQUIRED',
            `The approval expired while the ${step} transaction is unresolved. Its recorded bytes are tracked by reads only; sending them again needs a recovery authorization for exactly this hash.`,
            { ...details, notAfter: executor.notAfter });
        }
        fail('STEP_TIMEOUT', `The ${step} transaction did not finish in time. Its recorded state is kept for a resume.`, details);
      }
    }
  }

  async #control(runId, controlId, lease = null) {
    this.#requireLease(lease);
    const control = await runLiveControl({ proposal: this.proposal, rpcs: this.rpcs, controlId, now: this.nowMs, sleep: this.sleep });
    this.#evidence(runId, controlId, control);
    this.#update(runId, item => {
      item.controls[controlId] = {
        observed: true, passed: control.passed, blockNumber: control.block.number, blockHash: control.block.hash,
        observedAt: control.observedAt, interpretation: control.interpretation, canonical: true
      };
    });
    if (!control.passed) fail('CONTROL_FAILED', `The read-only control ${controlId} did not meet its expectations.`, { controlId });
  }

  // The cleanup decision reads come from both sources at one block hash.
  async #mandateAndAllowance() {
    const { primary, secondary } = this.rpcs;
    const sleep = this.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms)));
    const block = await primary.getBlock('latest');
    let secondaryBlock = null;
    for (let attempt = 0; attempt < 12 && !secondaryBlock; attempt++) {
      secondaryBlock = await secondary.getBlock({ blockHash: block.hash });
      if (!secondaryBlock) await sleep(this.pollMs ?? 5_000);
    }
    if (!secondaryBlock) fail('SOURCE_LAGGING', 'The second read source did not return the block the cleanup reads use.', { blockHash: block.hash });
    const ref = { blockHash: block.hash };
    const calls = readCalls(this.proposal);
    const read = async rpc => {
      const mandate = await rpc.call(calls.getMandate(), ref);
      const allowance = await rpc.call(calls.allowance(), ref);
      if (!mandate.ok || !allowance.ok) fail('READ_REVERTED', 'A cleanup read reverted.');
      return { mandate: decodeMandateReturn(mandate.returnData), allowance: decodeUintReturn(allowance.returnData) };
    };
    const [a, b] = await Promise.all([read(primary), read(secondary)]);
    if (canonicalJson(a) !== canonicalJson(b)) fail('SOURCE_STATE_DISAGREEMENT', 'The two read sources disagree on the mandate or the allowance at the same block.', { blockHash: block.hash });
    return { block: { number: block.number, hash: block.hash }, mandate: a.mandate, allowance: a.allowance };
  }

  async #recordReplay(runId, record) {
    const { primary } = this.rpcs;
    const calls = readCalls(this.proposal);
    const block = await primary.getBlock('latest');
    const ref = { blockHash: block.hash };
    const agentNonce = await primary.getTransactionCount(this.proposal.agent, ref);
    const principal = await primary.call(calls.balanceOf(this.proposal.principal), ref);
    const recipient = await primary.call(calls.balanceOf(this.proposal.recipient.address), ref);
    if (!principal.ok || !recipient.ok) fail('READ_REVERTED', 'A replay balance read reverted.');
    let after = null;
    try {
      const postcheck = JSON.parse(fs.readFileSync(this.#evidencePath(runId, `${record.operationId}-postcheck`), 'utf8'));
      after = postcheck?.envelope?.after?.state ?? null;
    } catch { /* The comparison below reports the missing evidence. */ }
    const expectedAgentNonce = (BigInt(record.transaction.nonce) + 1n).toString();
    const principalTokenBalance = decodeUintReturn(principal.returnData);
    const recipientTokenBalance = decodeUintReturn(recipient.returnData);
    const observation = {
      observedAt: isoAt(this.nowMs()),
      operationId: record.operationId,
      block: { number: block.number, hash: block.hash },
      journalState: record.state,
      transactionHash: record.signed.ethereumTransactionHash,
      agentNonce,
      expectedAgentNonce,
      newAgentTransaction: agentNonce !== expectedAgentNonce,
      principalTokenBalance,
      principalBalanceAfterExecute: after?.principalBalance ?? null,
      recipientTokenBalance,
      recipientBalanceAfterExecute: after?.recipientBalance ?? null,
      signed: false,
      broadcast: false
    };
    // The recipient may receive tokens from anyone, so only the principal side decides.
    observation.passed = observation.newAgentTransaction === false && after !== null &&
      principalTokenBalance === after.principalBalance;
    const count = this.#run(runId).replays.length + 1;
    this.#evidence(runId, `replay-${count}`, observation);
    this.#update(runId, item => {
      item.replays.push({
        observedAt: observation.observedAt, blockNumber: block.number, passed: observation.passed,
        newAgentTransaction: observation.newAgentTransaction, transactionHash: observation.transactionHash
      });
      if (item.replays.length > 20) item.replays.shift();
    });
    return observation;
  }

  // ---- reconciliation -------------------------------------------------------

  #trackableSteps(run) {
    return LIVE_WRITE_STEPS.filter(step => run.steps[step].planned &&
      LIVE_TRACKING_STATES.includes(this.journal.find(run.steps[step].operationId)?.state));
  }

  // Tracking-only resume after the approval expired: recorded transactions are
  // followed by reads and verified if they land; nothing is prepared, signed or
  // sent. The run then stops with APPROVAL_EXPIRED, because every further write
  // needs a new approval.
  async #trackOnly(runId, lease) {
    const run = this.#run(runId);
    const executor = this.#executor(run, lease, { trackingOnly: true });
    for (const step of this.#trackableSteps(run)) await this.#advanceUntilDone(executor, runId, step);
    fail('APPROVAL_EXPIRED', 'Tracking finished. The run approval expired, so every further write needs a new approval.');
  }

  // A process may end between the journal write that verified execute and the
  // workspace write that moves the run on. The journal records what happened on
  // chain, so the phase is derived from it under the run lock, after a fresh
  // canonicity check of the confirmation. Nothing is signed or sent here.
  async #reconcileExecute(runId) {
    const run = this.#run(runId);
    const executeStatuses = ['awaiting-agent', 'agent-executing'];
    const inWindow = executeStatuses.includes(run.status) || (run.status === 'stopped' && run.phase === 'agent-execute');
    const record = this.journal.find(run.steps.execute.operationId);
    if (!inWindow || record?.state !== 'semantically_verified') return run;
    this.#requireCodeIdentity(run, 'reconcile', { evidence: false });
    const lease = this.#acquireRunLock('reconcile', runId);
    try {
      // The phase moves on only while the execute block still reads at the
      // required depth from both sources; the same rule as before any new write.
      const progression = await this.#executor(run, lease).progression(record.operationId);
      if (!progression.eligible) return this.#run(runId);
      this.#update(runId, item => {
        if (executeStatuses.includes(item.status) || (item.status === 'stopped' && item.phase === 'agent-execute')) {
          item.status = 'awaiting-owner-revocation'; item.phase = null; item.stop = null;
        }
      });
      return this.#run(runId);
    } catch (error) {
      throw workspaceFailure(error, 'execute');
    } finally {
      lease.release();
    }
  }

  // An idle run whose confirmation was withdrawn by a recheck goes back to the
  // phase that owns the step, as a stopped phase that resume or execute_approved
  // continues with the same recorded transaction. Nothing new is signed.
  #reconcileWithdrawn(runId) {
    const run = this.#run(runId);
    if (!['completed', 'awaiting-agent', 'awaiting-owner-revocation'].includes(run.status)) return;
    const withdrawn = this.#trackableSteps(run);
    if (!withdrawn.length) return;
    const step = withdrawn[0];
    const record = this.journal.find(run.steps[step].operationId);
    this.#update(runId, item => {
      item.status = 'stopped';
      item.phase = STEP_PHASE[step];
      item.stop = {
        code: 'CONFIRMATION_WITHDRAWN',
        message: `The ${step} confirmation was withdrawn by a block reorganisation. The same recorded transaction is tracked again before the run can complete.`,
        at: isoAt(this.nowMs()),
        details: { layer: 'chain', step, transactionHash: record.signed.ethereumTransactionHash, journalState: record.state }
      };
    });
  }

  // Re-reads every control block from both sources. A control whose block left
  // the canonical chain loses its result. Before the dependent write exists the
  // phase observes it again at the same lifecycle stage; afterwards a later
  // measurement cannot replace the lost evidence, so the run stops.
  async #recheckControls(runId, { stopRun }) {
    const run = this.#run(runId);
    const observed = LIVE_CONTROL_IDS
      .filter(id => run.controls[id]?.observed && run.controls[id].canonical !== false)
      .map(id => ({ controlId: id, blockNumber: run.controls[id].blockNumber, blockHash: run.controls[id].blockHash }));
    if (!observed.length) return [];
    const lost = (await checkControlCanonicity({ rpcs: this.rpcs, controls: observed })).filter(item => item.canonical === false);
    if (!lost.length) return [];
    const at = isoAt(this.nowMs());
    this.#update(runId, item => {
      for (const entry of lost) {
        item.controls[entry.controlId] = {
          ...item.controls[entry.controlId], passed: false, canonical: false, invalidatedAt: at, invalidationReason: 'BLOCK_NOT_CANONICAL'
        };
      }
    });
    for (const entry of lost) this.#evidence(runId, `${entry.controlId}-invalidated-${this.nowMs()}`, { ...entry, invalidatedAt: at });
    const current = this.#run(runId);
    const irreplaceable = lost.map(entry => entry.controlId)
      .filter(id => this.journal.find(current.steps[CONTROL_DEPENDENT_STEP[id]].operationId));
    if (!irreplaceable.length) return lost;
    const message = 'A read-only control block left the canonical chain after the write that depended on it. A later measurement cannot replace that evidence: the run is incomplete as evidence and needs cleanup or a new approval.';
    if (!stopRun) fail('CONTROL_EVIDENCE_LOST', message, { controlIds: irreplaceable });
    // A withdrawn write keeps the phase that tracks it (set by #reconcileWithdrawn
    // just before), so the same transaction can still be followed; otherwise the
    // stopped run has no phase to resume and cleanup is the way out.
    const trackable = this.#trackableSteps(current);
    this.#update(runId, item => {
      item.status = 'stopped'; item.phase = trackable.length ? STEP_PHASE[trackable[0]] : null;
      item.stop = { code: 'CONTROL_EVIDENCE_LOST', message, at, details: { layer: 'chain', controlIds: irreplaceable } };
    });
    return lost;
  }

  // Before the first execute attempt the transaction-cap control must still be
  // canonical; otherwise the owner observes it again by resuming setup.
  async #requireControlCanonical(runId, controlId) {
    const run = this.#run(runId);
    const control = run.controls[controlId];
    if (!control?.observed || control.passed !== true) return;
    const query = { controlId, blockNumber: control.blockNumber, blockHash: control.blockHash };
    let [result] = await checkControlCanonicity({ rpcs: this.rpcs, controls: [query] });
    // A source that has no block at the control height yet gets a bounded wait
    // inside this call before the call stops as unresolved.
    const sleep = this.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms)));
    for (let attempt = 0; attempt < 6 && result.canonical === null; attempt++) {
      await sleep(this.pollMs ?? 5_000);
      [result] = await checkControlCanonicity({ rpcs: this.rpcs, controls: [query] });
    }
    if (result.canonical === true) return;
    if (result.canonical === null) {
      // No source disagrees, but both did not confirm: nothing is decided from
      // that. The control keeps its result and the agent calls execute again.
      this.#update(runId, item => { item.phase = 'agent-execute'; });
      fail('CONTROL_UNRESOLVED', `A read source did not return the ${controlId} block, so its canonicity is unresolved right now. Nothing was signed; call execute_approved again once both sources answer.`, { controlIds: [controlId] });
    }
    const at = isoAt(this.nowMs());
    this.#update(runId, item => {
      item.controls[controlId] = { ...item.controls[controlId], passed: false, canonical: false, invalidatedAt: at, invalidationReason: 'BLOCK_NOT_CANONICAL' };
      item.phase = 'owner-setup';
    });
    fail('CONTROL_WITHDRAWN', `The ${controlId} block left the canonical chain before execute. The owner resumes setup to observe the control again.`, { controlIds: [controlId] });
  }

  #recordStop(runId, error, step = null) {
    const failure = liveFailure(error, step);
    try {
      this.#update(runId, item => {
        item.stop = { code: failure.code, message: failure.message, at: isoAt(this.nowMs()), details: failure.details };
        item.status = 'stopped';
      });
    } catch { /* The job result stays visible through the journal. */ }
  }

  #runView(run) {
    const steps = LIVE_WRITE_STEPS.map(step => {
      const info = run.steps[step];
      const record = this.journal.find(info.operationId);
      const transactionHash = record?.signed?.ethereumTransactionHash ?? null;
      return {
        step, signer: LIVE_STEP_SIGNER[step], route: LIVE_STEP_ROUTE[step], planned: info.planned, skipReason: info.skipReason,
        operationId: info.operationId, status: stepStatus(record, info.planned), journalState: record?.state ?? null,
        apiTxId: record?.apiTxId ?? null, transactionHash, broadcastResult: record?.broadcast?.result ?? null,
        blockNumber: record?.confirmation?.blockNumber ?? null, blockHash: record?.confirmation?.blockHash ?? null,
        confirmations: record?.confirmation?.confirmations ?? null, receiptStatus: record?.confirmation?.receiptStatus ?? null,
        semanticallyVerified: record?.state === 'semantically_verified',
        // An explorer link appears only for a transaction with a recorded receipt.
        explorerUrl: record?.confirmation ? EXPLORER_TX + transactionHash : null
      };
    });
    return {
      runId: run.runId, status: run.status, phase: run.phase, createdAt: run.createdAt, notAfter: run.notAfter,
      approvalSha256: run.approvalSha256, codeIdentitySha256: run.codeIdentitySha256 ?? null,
      ownerApproved: run.ownerApproval !== null, ownerApproval: run.ownerApproval,
      preflightBlockers: run.preflightBlockers, steps,
      controls: LIVE_CONTROL_IDS.map(id => ({ id, ...(run.controls[id] ?? { observed: false }) })),
      replays: run.replays, stop: run.stop, cleanup: run.cleanup, finality: run.finality, updatedAt: run.updatedAt,
      jobRunning: this.#jobs.has(run.runId)
    };
  }

  #touchedOperationIds(run) {
    return LIVE_WRITE_STEPS.map(step => run.steps[step].operationId).filter(operationId => this.journal.find(operationId));
  }

  #requireRole(role) {
    if (this.role !== role) fail('ROLE_DENIED', role === 'owner' ? 'This action is available only in the owner workspace.' : 'This action is available only to the agent.');
  }

  #run(runId) {
    if (typeof runId !== 'string' || !/^live_[a-f0-9]{32}$/.test(runId)) fail('INVALID_INPUT', 'The run ID is invalid.');
    const run = this.read().runs.find(item => item.runId === runId);
    if (!run) fail('RUN_NOT_FOUND', 'The live run was not found.');
    return run;
  }

  #runByExecuteOperation(operationId) {
    if (typeof operationId !== 'string' || !/^live_[a-f0-9]{32}_execute$/.test(operationId)) {
      fail('INVALID_OPERATION_ID', 'Only the owner-approved execute operation of a live run can be used here.');
    }
    const run = this.read().runs.find(item => item.steps.execute.operationId === operationId);
    if (!run) fail('OPERATION_NOT_FOUND', 'The live execute operation was not found.');
    return run;
  }

  #evidencePath(runId, name) {
    if (!/^[A-Za-z0-9_-]{1,160}$/.test(name)) fail('INVALID_INPUT', 'The evidence name is invalid.');
    return boundedPath(path.join(this.liveDirectory, 'evidence', runId, `${name}.json`));
  }

  #evidence(runId, name, value) {
    const target = this.#evidencePath(runId, name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    const temporary = boundedPath(path.join(path.dirname(target), `${name}-${randomUUID()}.tmp`));
    fs.writeFileSync(temporary, JSON.stringify(value, null, 2), { flag: 'wx' });
    fs.renameSync(temporary, target);
  }

  // The run lock follows the shared live lock protocol (src/live-lock.mjs): an
  // exclusive file handle bound to the process, so a live holder refuses at
  // once, a holder whose process is gone is taken over by the next exclusive
  // open, and the returned lease proves ownership before every later action.
  #acquireRunLock(purpose, runId) {
    try {
      return acquireLiveLock(this.runLock, {
        holder: { role: this.role, purpose, runId }, now: this.nowMs, attempts: 3, waitMs: 10, busyCode: 'LIVE_RUN_BUSY'
      });
    } catch (error) {
      throw lockFailure(error, 'LIVE_RUN');
    }
  }

  #update(runId, change) {
    this.#mutate(document => {
      const run = document.runs.find(item => item.runId === runId);
      if (!run) fail('RUN_NOT_FOUND', 'The live run was not found.');
      change(run);
      run.updatedAt = isoAt(this.nowMs());
    });
  }

  // The short write lock uses the same protocol: a live holder makes the write
  // wait up to two seconds, a dead holder is taken over, and unreadable content
  // stops with LIVE_WORKSPACE_LOCK_INVALID instead of waiting forever.
  #mutate(change) {
    let lease;
    try {
      lease = acquireLiveLock(this.lock, {
        holder: { role: this.role, purpose: 'workspace-write' }, now: this.nowMs, attempts: 200, waitMs: 10, busyCode: 'LIVE_WORKSPACE_BUSY'
      });
    } catch (error) {
      throw lockFailure(error, 'LIVE_WORKSPACE');
    }
    try {
      const document = this.read();
      change(document);
      document.selfHash = liveDocumentHash(document);
      this.#write(document);
    } finally {
      lease.release();
    }
  }

  #write(document) {
    validateLiveDocument(document, this.proposal.proposalHash);
    const serialized = JSON.stringify(document, null, 2);
    if (Buffer.byteLength(serialized, 'utf8') > MAX_FILE_BYTES) fail('LIVE_WORKSPACE_TOO_LARGE', 'The live workspace reached its size limit.');
    const temporary = boundedPath(path.join(this.liveDirectory, `live-workspace-${randomUUID()}.tmp`));
    try {
      fs.writeFileSync(temporary, serialized, { flag: 'wx' });
      fs.renameSync(temporary, this.file);
    } finally {
      if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
    }
  }
}
