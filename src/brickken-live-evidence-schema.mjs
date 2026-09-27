// Closed field schemas for the public evidence package of a live run
// (tools/export-live-evidence.mjs). Each package member has a kind, and each
// kind lists every key path its writers can produce: object keys by name,
// array elements as [], so "calls[].decodedRevert.args.agent". A key whose
// path is not listed is outside the schema, at any depth, and the export stops
// on it. A listed path accepts any JSON value; its children must be listed
// too. The lists were derived from the writer of each kind, including the
// branches no test run produced, and checked against every evidence file the
// test suite and the live run of 15 September 2026 wrote. A writer that gains
// a field needs the same field here, or its package is refused.
import { LIVE_CONTROL_IDS, LIVE_WRITE_STEPS, STOP_DETAIL_KEYS } from './brickken-live-plan.mjs';

function under(prefix, paths) { return paths.map(item => `${prefix}.${item}`); }
// Every listed path with its parents; "calls[].label" also admits the key "calls".
function withParents(paths) {
  const all = new Set();
  for (const item of paths) {
    const parts = item.split('.');
    for (let index = 1; index <= parts.length; index++) {
      const prefix = parts.slice(0, index).join('.');
      all.add(prefix);
      if (prefix.endsWith('[]')) all.add(prefix.slice(0, -2));
    }
  }
  return Object.freeze(all);
}

// Shared shapes.
const MANDATE = ['agent', 'validFrom', 'validUntil', 'principal', 'revoked', 'complianceProvider', 'identityRef', 'asset',
  'maxTransactionValue', 'maxCumulativeValue', 'cumulativeUsed', 'metadata'];
// plan.decodeRevert: args are decoded for CannotExecute and OwnableUnauthorizedAccount only.
const REVERT = ['selector', 'name', 'args', ...under('args', ['agent', 'target', 'selector', 'amount', 'account'])];
const TRANSACTION = ['chainId', 'from', 'to', 'value', 'data', 'nonce', 'gasLimit', 'type', 'maxPriorityFeePerGas', 'maxFeePerGas'];
const LOG = ['address', 'topics', 'data', 'transactionHash', 'blockNumber', 'blockHash', 'logIndex', 'removed'];
const EVENT = ['transactionHash', 'blockNumber', 'blockHash', 'logIndex'];
const EXECUTOR_ACTION = ['supported', 'hasAmount', 'amountIndex'];
const CHAIN_FACTS = ['allowance', 'principalTokenBalance', 'recipientTokenBalance', 'mandate', ...under('mandate', MANDATE),
  'actionEnabled', 'agentFrozen', 'executorAction', ...under('executorAction', EXECUTOR_ACTION)];
// adapter postcheckState(): the union of the per-step state snapshots.
const POSTCHECK_STATE = ['action', ...under('action', EXECUTOR_ACTION), 'allowance', 'mandate', ...under('mandate', MANDATE),
  'actionEnabled', 'principalBalance', 'recipientBalance', 'canExecute'];
const SEMANTICS = ['action', 'agent', 'amount', 'amountIndex', 'asset', 'canExecuteAfter', 'complianceProvider', 'executor',
  'hasAmount', 'identityRef', 'maxCumulativeValue', 'maxTransactionValue', 'metadata', 'owner', 'principal', 'recipient',
  'registry', 'revokedBy', 'selector', 'spender', 'supported', 'token', 'validFrom', 'validUntil'];
// The x402 quote is the API's price metadata, stored as read and never paid.
// It is closed to the payment requirement fields of x402 versions 1 and 2 and
// to the extra fields the Brickken sandbox sent on 15 September 2026.
const X402_REQUIREMENT = ['scheme', 'network', 'amount', 'maxAmountRequired', 'asset', 'payTo', 'resource', 'description',
  'mimeType', 'maxTimeoutSeconds', 'extra', ...under('extra', ['name', 'version', 'assetTransferMethod', 'chainId',
    'displayPrice', 'operationChainId', 'paymentChainId', 'routeKey', 'tokenSymbol'])];
const X402_QUOTE = ['x402Quote', ...under('x402Quote', X402_REQUIREMENT), ...under('x402Quote[]', X402_REQUIREMENT)];
// A stop record's details keep the workspace's STOP_DETAIL_KEYS only; these
// are the nested shapes of the keys whose value is an object or an array.
const STOP_DETAILS = [...STOP_DETAIL_KEYS,
  ...under('blockers[]', ['code', 'detail']), ...under('revert', REVERT),
  ...under('tracked[]', ['step', 'code', 'journalState', 'transactionHash']), ...under('mandate', MANDATE)];
const GAS_ESTIMATE_STEPS = ['setAction', 'approve', 'grant', 'approveReset'];

const PREFLIGHT = ['schemaVersion', 'kind', 'observedAt', 'endpoints', 'endpoints.primary', 'endpoints.secondary', 'chainId',
  'block', ...under('block', ['number', 'hash', 'timestamp', 'baseFeePerGas']), 'secondaryBlockHashAgreed',
  'codeSha256', ...under('codeSha256', ['executor', 'registry', 'complianceProvider', 'token']),
  'executorBindings', ...under('executorBindings', ['rams', 'principal', 'owner', 'recorderRole']), 'tokenDecimals',
  'state', ...under('state', CHAIN_FACTS),
  'balancesWei', 'balancesWei.owner', 'balancesWei.agent',
  'nonces', ...under('nonces', ['owner', 'owner.latest', 'owner.pending', 'agent', 'agent.latest', 'agent.pending']),
  'suggestedPriorityFeePerGas', 'fees', 'fees.maxPriorityFeePerGas', 'fees.maxFeePerGas',
  'gasEstimates', ...GAS_ESTIMATE_STEPS.flatMap(step => [`gasEstimates.${step}`, `gasEstimates.${step}.reverted`,
    `gasEstimates.${step}.revert`, ...under(`gasEstimates.${step}.revert`, REVERT)]),
  'plannedWrites', 'requiredWei', ...under('requiredWei', ['atCurrentFees', 'atCurrentFees.owner', 'atCurrentFees.agent',
    'atApprovedFeeCeiling', 'atApprovedFeeCeiling.owner', 'atApprovedFeeCeiling.agent']),
  'blockers', 'blockers[].code', 'blockers[].detail'];

const CLEANUP = ['completedAt', 'revokedByCleanup', 'allowanceResetByCleanup', 'mandateRevoked', 'allowance',
  'block', 'block.number', 'block.hash',
  'attribution', ...['approve', 'grant'].flatMap(step => [`attribution.${step}`, `attribution.${step}.attributed`, `attribution.${step}.reason`]),
  'postcheckFailed', 'problems'];
const FINALITY_ENTRY = ['operationId', 'controlId', 'blockNumber', 'blockHash', 'finalized', 'reason'];

const SCHEMAS = Object.freeze({
  'run-approval': withParents(['schemaVersion', 'kind', 'proposalHash', 'network', 'chainId', 'createdAt', 'notAfter',
    ...under('signers', ['owner', 'agent']),
    ...under('contracts', ['executor', 'registry', 'complianceProvider', 'token']), 'identityRef', 'recipient',
    ...under('limits', ['maxTransactionValue', 'maxCumulativeValue', 'allowance', 'minimumPrincipalTokenBalance']),
    ...under('amounts', ['execute', 'overTransactionCapProbe', 'cumulativeAllowedProbe', 'cumulativeDeniedProbe', 'revocationProbe']),
    'mandateValiditySeconds',
    ...under('routes.brickkenApi', ['origin', 'authentication', 'executionMode', 'paymentFallback', 'send', 'status', 'openApiSha256',
      ...under('prepare', ['setAction', 'grant', 'execute', 'revoke'])]),
    ...under('routes.sepoliaRpc', ['operations', 'broadcastEndpoint']),
    ...under('routes.readEndpoints', ['primary', 'secondary']),
    ...under('fees', ['maxFeePerGas', 'maxPriorityFeePerGas']),
    ...under('budgetWei', ['owner', 'agent']),
    ...under('writes[]', ['step', 'signer', 'signerAddress', 'route', 'endpoint', 'target', 'nativeValue', 'calldata',
      'calldataRule', 'maxGasLimit', 'maxCostWei', 'prerequisites']),
    ...under('controls[]', ['id', 'broadcast', ...under('calls[]', ['label', 'from', 'to', 'value', 'data', 'expect'])]),
    'noncePolicy', 'confirmationPolicy', 'cleanup', 'persistentConfiguration',
    'preflight', ...under('preflight', PREFLIGHT), 'approvalSha256']),
  preflight: withParents(PREFLIGHT),
  'code-identity': withParents(['schemaVersion', 'kind', ...under('files[]', ['path', 'bytes', 'sha256']), 'codeIdentitySha256',
    'recordedAt', 'gitHead']),
  control: withParents(['schemaVersion', 'kind', 'controlId', 'observedAt', ...under('block', ['number', 'hash', 'timestamp']),
    'broadcast', 'transactionHash',
    ...under('calls[]', ['label', 'from', 'to', 'value', 'data', 'expect', ...under('result', ['ok', 'returnData', 'revertData']),
      'decodedRevert', ...under('decodedRevert', REVERT), 'secondaryAgrees', 'passed']),
    'facts', ...under('facts', CHAIN_FACTS), 'secondaryFactsAgree', ...under('conditions[]', ['id', 'holds']),
    'allowedLegPassed', 'passed', 'interpretation']),
  replay: withParents(['observedAt', 'operationId', ...under('block', ['number', 'hash']), 'journalState', 'transactionHash',
    'agentNonce', 'expectedAgentNonce', 'newAgentTransaction', 'principalTokenBalance', 'principalBalanceAfterExecute',
    'recipientTokenBalance', 'recipientBalanceAfterExecute', 'signed', 'broadcast', 'passed']),
  finality: withParents(['checkedAt', 'primaryFinalized', ...under('primaryFinalized', ['number', 'hash']),
    'secondaryFinalized', ...under('secondaryFinalized', ['number', 'hash']), 'entries', ...under('entries[]', FINALITY_ENTRY),
    'allFinalized']),
  cleanup: withParents(CLEANUP),
  'cleanup-allowance-origin': withParents(['checkedAt', ...under('block', ['number', 'hash']), 'attributed', 'reason',
    'events', ...under('events.primary[]', EVENT), ...under('events.secondary[]', EVENT), 'events.primary', 'events.secondary',
    'foreign', ...under('foreign[]', EVENT), 'principalNonce', ...under('principalNonce', ['primary', 'secondary', 'error']), 'error']),
  'cleanup-reset-refused': withParents(['code', 'at', ...STOP_DETAILS]),
  'step-preparation': withParents(['operationId', 'step', 'route', 'apiTxId', 'preparationHash', 'transaction',
    ...under('transaction', TRANSACTION), 'gasEstimate', 'preparedAt', ...under('observedBlock', ['number', 'hash', 'baseFeePerGas']),
    ...X402_QUOTE]),
  'step-receipt': withParents(['operationId', 'step', ...under('receipt', ['transactionHash', 'status', 'from', 'to', 'blockNumber',
    'blockHash', 'gasUsed', 'effectiveGasPrice', 'logs', ...under('logs[]', LOG)]), 'secondaryBlockHash', 'confirmations',
    'confirmationsPrimary', 'confirmationsSecondary']),
  'step-postcheck': withParents(['operationId', 'step',
    ...under('envelope', ['schemaVersion', 'operationKind',
      ...under('expected.transaction', ['hash', ...TRANSACTION]), 'expected.semantics', ...under('expected.semantics', SEMANTICS),
      ...under('transaction', ['hash', ...TRANSACTION, 'blockNumber', 'blockHash']),
      ...under('receipt', ['transactionHash', 'status', 'from', 'to', 'blockNumber', 'blockHash', 'logs', ...under('logs[]', LOG)]),
      ...['before', 'after'].flatMap(side => [`${side}.blockNumber`, `${side}.blockHash`, `${side}.state`, ...under(`${side}.state`, POSTCHECK_STATE)]),
      'observedAt']),
    ...under('report', ['schemaVersion', 'kind', 'operationKind', 'transactionHash', 'blockNumber', 'blockHash', 'verified', 'checks',
      ...under('scope', ['normalizedFixtureInputOnly', 'blockBoundRpcObservation', 'abiSourceMatched', 'rpcAuthenticityVerified',
        'independentRpcVerified', 'confirmationDepthVerified', 'cleanupRevocation', 'revocationEffectDemonstrated']), 'observedAt']),
    ...under('twoSourceObservation', [...under('parentBlock', ['number', 'hash']), ...under('receiptBlock', ['number', 'hash']),
      ...['before', 'after'].flatMap(side => [`${side}.agreed`, `${side}.primary`, `${side}.secondary`,
        ...under(`${side}.primary`, POSTCHECK_STATE), ...under(`${side}.secondary`, POSTCHECK_STATE)])])]),
  transactions: withParents(['schemaVersion', 'kind', 'network', 'chainId', 'runId', 'runStatus', 'complete', 'missing',
    'approvalSha256', 'proposalHash', 'codeIdentitySha256', 'exportCodeIdentitySha256', 'finalityCheckedAt', 'transactions',
    ...under('transactions[]', ['step', 'operation', 'route', 'signerRole', 'operationId', 'executed', 'skipReason',
      'signerAddress', 'to', 'nonce', 'calldata', 'gasLimit', 'maxFeePerGas', 'maxPriorityFeePerGas', 'brickkenTxId',
      'brickkenTxIdMeaning', 'preparationHash', 'transactionHash', 'explorerUrl', 'journalState', 'blockNumber', 'blockHash',
      'receiptStatus', 'confirmationsAtLastCheck', 'secondarySourceBlockHashAgreed', 'semanticVerification',
      ...under('semanticVerification', ['postcheckKind', 'transactionHash', 'blockNumber', 'blockHash', 'postcheckSha256', 'verifiedAt']),
      'finalizedOnBothSources'])]),
  run: withParents(['schemaVersion', 'kind', 'runId', 'status', 'createdAt', 'ownerApproval',
    ...under('ownerApproval', ['approvedAt', 'approvalSha256', 'codeIdentitySha256']), 'approvalSha256', 'codeIdentitySha256',
    'complete', 'missing', 'controls', ...under('controls[]', ['id', 'observed', 'passed', 'blockNumber', 'blockHash', 'observedAt',
      'interpretation', 'canonical', 'invalidatedAt', 'invalidationReason', 'finalizedOnBothSources']),
    'replays', ...under('replays[]', ['observedAt', 'blockNumber', 'passed', 'newAgentTransaction', 'transactionHash']),
    'stop', ...under('stop', ['at', 'code', 'message', 'details', ...under('details', STOP_DETAILS)]),
    'cleanup', ...under('cleanup', CLEANUP),
    'finality', ...under('finality', ['checkedAt', 'allFinalized', 'entries', ...under('entries[]', FINALITY_ENTRY)])])
});

const STEP_FILE = new RegExp(`^steps/(${LIVE_WRITE_STEPS.join('|')})-(preparation|receipt|postcheck)\\.json$`);
const CONTROL_FILE = new Set(LIVE_CONTROL_IDS.map(id => `controls/${id}.json`));
const FIXED_FILES = Object.freeze({
  'run-approval.json': 'run-approval', 'preflight-plan.json': 'preflight', 'preflight-start.json': 'preflight',
  'code-identity.json': 'code-identity', 'code-identity-start.json': 'code-identity', 'finality.json': 'finality',
  'cleanup.json': 'cleanup', 'cleanup-allowance-origin.json': 'cleanup-allowance-origin',
  'cleanup-allowance-origin-sign.json': 'cleanup-allowance-origin', 'transactions.json': 'transactions', 'run.json': 'run',
  'SHA256SUMS.json': 'sums'
});

// The kind of a package member, from its relative path, or null for a path
// the package does not have.
export function evidenceKindOf(relative) {
  if (typeof relative !== 'string') return null;
  if (Object.hasOwn(FIXED_FILES, relative)) return FIXED_FILES[relative];
  if (CONTROL_FILE.has(relative)) return 'control';
  if (/^replays\/replay-[1-9][0-9]{0,5}\.json$/.test(relative)) return 'replay';
  if (/^cleanup-reset-refused-[0-9]{1,17}\.json$/.test(relative)) return 'cleanup-reset-refused';
  const step = STEP_FILE.exec(relative);
  return step ? `step-${step[2]}` : null;
}

// Every place where a field outside the schema of `kind` sits in `value`,
// named by the known path of its parent ("(root)" for the top level). The
// unknown key itself is never returned, so no content of a member is echoed.
// An empty list means the value is inside its schema. A key is a plain name:
// one that is empty or carries a dot or a bracket could spell a listed path by
// itself ("block.hash" at the top level), so it is always outside.
const PLAIN_KEY = /^[^.[\]]+$/;
export function fieldsOutsideSchema(kind, value) {
  if (kind === 'sums') return sumsOutside(value);
  const allowed = SCHEMAS[kind];
  if (!allowed) return ['(no schema)'];
  const outside = [];
  const visit = (node, at) => {
    if (Array.isArray(node)) {
      for (const item of node) visit(item, `${at}[]`);
      return;
    }
    if (!node || typeof node !== 'object') return;
    for (const key of Object.keys(node)) {
      const child = at === '' ? key : `${at}.${key}`;
      if (!PLAIN_KEY.test(key) || !allowed.has(child)) { outside.push(at === '' ? '(root)' : at); continue; }
      visit(node[key], child);
    }
  };
  if (!value || typeof value !== 'object' || Array.isArray(value)) return ['(root)'];
  visit(value, '');
  return outside;
}

function sumsOutside(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return ['(root)'];
  const outside = [];
  for (const [relative, digest] of Object.entries(value)) {
    const kind = evidenceKindOf(relative);
    if (kind === null || kind === 'sums' || typeof digest !== 'string' || !/^[a-f0-9]{64}$/.test(digest)) outside.push('(root)');
  }
  return outside;
}

export const EVIDENCE_SCHEMA_KINDS = Object.freeze([...Object.keys(SCHEMAS), 'sums']);

// ---------------------------------------------------------------------------
// Required content, per kind (MD-02). fieldsOutsideSchema above only rejects a
// field the writer never produces; on its own an empty object passes it for
// every kind, because a closed schema of allowed paths states nothing about
// which of those paths must be present. The lists below were read from the
// writer of each kind (src/brickken-live-adapter.mjs, src/brickken-workspace.mjs)
// and checked against the real evidence files of the 15 September 2026 live run
// (verification/sepolia-live-c990e8a178b0/) and every fixture the test suite
// writes; a field the writer always sets is required, one it sets only on some
// branches (gitHead, apiTxId, x402Quote) is not. This is a completeness check,
// not a second closed schema: a value can satisfy every requirement here and
// still be rejected by fieldsOutsideSchema for a field outside its allowlist.
function isPlainObject(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function isNonEmptyArray(value) { return Array.isArray(value) && value.length > 0; }
function isHexHash32(value) { return typeof value === 'string' && /^0x[0-9a-f]{64}$/.test(value); }
function isSha256Hex(value) { return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value); }

// Every listed key present and not null/undefined; "(root)" if value is not a
// plain object at all, since no key of it can then be checked.
function requireKeys(value, keys) {
  if (!isPlainObject(value)) return ['(root):not-an-object'];
  return keys.filter(key => !Object.hasOwn(value, key) || value[key] === undefined || value[key] === null).map(key => `${key}:missing`);
}

const REQUIRED_CONTENT = Object.freeze({
  'run-approval': value => [
    ...requireKeys(value, ['schemaVersion', 'kind', 'proposalHash', 'approvalSha256', 'network', 'chainId', 'createdAt',
      'notAfter', 'signers', 'contracts', 'limits', 'amounts', 'writes', 'controls', 'preflight']),
    ...(isNonEmptyArray(value?.writes) ? [] : ['writes:not-a-non-empty-array']),
    ...(isNonEmptyArray(value?.controls) ? [] : ['controls:not-a-non-empty-array']),
    ...(isPlainObject(value?.signers) && typeof value.signers.owner === 'string' && typeof value.signers.agent === 'string' ? [] : ['signers:missing-fields']),
    ...(isPlainObject(value?.limits) && typeof value.limits.maxTransactionValue !== 'undefined' && typeof value.limits.maxCumulativeValue !== 'undefined' ? [] : ['limits:missing-fields'])
  ],
  preflight: value => [
    ...requireKeys(value, ['schemaVersion', 'kind', 'observedAt', 'chainId', 'block', 'state', 'codeSha256', 'executorBindings']),
    ...(isPlainObject(value?.block) && typeof value.block.number !== 'undefined' && typeof value.block.hash === 'string' ? [] : ['block:missing-fields']),
    ...(isPlainObject(value?.state) && Object.hasOwn(value.state, 'mandate') ? [] : ['state:missing-mandate'])
  ],
  'code-identity': value => [
    ...requireKeys(value, ['schemaVersion', 'kind', 'files', 'codeIdentitySha256', 'recordedAt']),
    ...(isNonEmptyArray(value?.files) ? [] : ['files:not-a-non-empty-array']),
    ...(isSha256Hex(value?.codeIdentitySha256) ? [] : ['codeIdentitySha256:not-a-sha256'])
  ],
  control: value => [
    ...requireKeys(value, ['schemaVersion', 'kind', 'controlId', 'observedAt', 'block', 'calls', 'facts', 'conditions', 'passed', 'interpretation']),
    ...(isPlainObject(value?.block) && typeof value.block.number !== 'undefined' && typeof value.block.hash === 'string' ? [] : ['block:missing-fields']),
    ...(isNonEmptyArray(value?.calls) ? [] : ['calls:not-a-non-empty-array']),
    ...(isNonEmptyArray(value?.conditions) ? [] : ['conditions:not-a-non-empty-array']),
    ...(isPlainObject(value?.facts) && Object.hasOwn(value.facts, 'mandate') ? [] : ['facts:missing-mandate']),
    ...(typeof value?.passed === 'boolean' ? [] : ['passed:not-a-boolean'])
  ],
  finality: value => [
    ...requireKeys(value, ['checkedAt', 'entries', 'allFinalized']),
    ...(Array.isArray(value?.entries) ? [] : ['entries:not-an-array']),
    ...(typeof value?.allFinalized === 'boolean' ? [] : ['allFinalized:not-a-boolean'])
  ],
  'step-preparation': value => [
    ...requireKeys(value, ['operationId', 'step', 'transaction', 'preparedAt', 'observedBlock']),
    ...(isPlainObject(value?.transaction) && typeof value.transaction.to === 'string' && typeof value.transaction.data === 'string' &&
      typeof value.transaction.nonce !== 'undefined' ? [] : ['transaction:missing-fields'])
  ],
  'step-receipt': value => [
    ...requireKeys(value, ['operationId', 'step', 'receipt', 'confirmations']),
    ...(isPlainObject(value?.receipt) && isHexHash32(value.receipt.transactionHash) && typeof value.receipt.status !== 'undefined' &&
      typeof value.receipt.blockNumber !== 'undefined' && typeof value.receipt.blockHash === 'string' ? [] : ['receipt:missing-fields'])
  ],
  'step-postcheck': value => [
    ...requireKeys(value, ['operationId', 'step', 'envelope', 'report', 'twoSourceObservation']),
    ...(isPlainObject(value?.envelope) && typeof value.envelope.observedAt === 'string' && isPlainObject(value.envelope.receipt) ? [] : ['envelope:missing-fields']),
    ...(isPlainObject(value?.report) && typeof value.report.verified === 'boolean' && isHexHash32(value.report.transactionHash) ? [] : ['report:missing-fields'])
  ]
});

// Every problem with the required content of `kind`, or [] if `value` has
// every field its writer always produces with a value of the expected shape.
// A kind with no entry above (replay, cleanup, transactions, run, the
// cleanup-* kinds and sums) is not covered by this check; fieldsOutsideSchema
// still applies to all of them.
export function fieldsMissingFromSchema(kind, value) {
  const check = REQUIRED_CONTENT[kind];
  return check ? check(value) : [];
}
