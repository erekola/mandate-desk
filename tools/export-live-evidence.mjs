// Builds the public evidence directory for one live Sepolia run from the local
// live workspace: the run approval, preflight and control observations, the
// preparation, receipt and semantic postcheck of every write, replay and
// finality records, a derived transaction table and SHA-256 sums. It never
// copies signed transaction bytes, the signer log, signer tokens or files from
// outside the run's evidence folder. The package is complete only when one
// explicit rule holds (src/brickken-live-completeness.mjs): every planned write
// verified, every control passed and still canonical, a finality result newer
// than the last change whose entries match the journal and the control records
// on both sources, and every required evidence file present. Anything less is
// refused unless --allow-incomplete is given; the table then says complete:false
// and lists what is missing.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { ROOT, boundedPath } from '../src/store.mjs';
import { LiveBrickkenJournal } from '../src/brickken-journal.mjs';
import { sha256Canonical } from '../src/brickken-intent.mjs';
import {
  LIVE_CONTROL_IDS,
  LIVE_STEP_ROUTE,
  LIVE_STEP_SIGNER,
  LIVE_WRITE_STEPS,
  loadLiveProposal,
  validateRunApproval
} from '../src/brickken-live-plan.mjs';
import { evaluateLiveRunCompleteness } from '../src/brickken-live-completeness.mjs';
import { PROCESS_CODE_IDENTITY_SHA256, computeCodeIdentity } from '../src/code-identity.mjs';

const EXPLORER_TX = 'https://sepolia.etherscan.io/tx/';
const OPERATIONS = Object.freeze({
  setAction: 'AgentExecutor.setAction(transferFrom selector, supported true, hasAmount true, amountIndex 2)',
  approve: 'ERC-20 approve(dedicated executor, allowance)',
  grant: 'AgentMandate.grantMandate for the agent, principal, token and limits in the run approval',
  execute: 'AgentExecutor.execute(token, transferFrom(principal, recipient, amount)) sent by the agent',
  revoke: 'AgentMandate.revokeMandate(agent, principal)',
  approveReset: 'ERC-20 approve(dedicated executor, 0)'
});

function stop(message) {
  console.error(`Evidence export stopped: ${message}`);
  process.exit(1);
}
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

function parseArguments(args) {
  const settings = { allowIncomplete: false, output: null };
  const usage = 'use --data <folder> --run <runId> [--allow-incomplete] [--output <folder>].';
  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    if (name === '--allow-incomplete') { settings.allowIncomplete = true; continue; }
    const value = args[index + 1];
    if (!['--data', '--run', '--output'].includes(name) || typeof value !== 'string' || !value) stop(usage);
    settings[name.slice(2)] = value;
    index += 1;
  }
  if (!settings.data || !/^live_[a-f0-9]{32}$/.test(settings.run ?? '')) stop(usage);
  return settings;
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return stop(`${path.relative(ROOT, file)} could not be read.`); }
}

function main() {
  const settings = parseArguments(process.argv.slice(2));
  const proposal = loadLiveProposal();
  const dataDirectory = boundedPath(path.resolve(ROOT, settings.data));
  const liveDirectory = boundedPath(path.join(dataDirectory, 'live'));
  const workspace = readJson(path.join(liveDirectory, 'live-workspace.json'));
  const { selfHash, ...payload } = workspace;
  if (workspace.kind !== 'mandate-desk-live-workspace' || selfHash !== sha256Canonical(payload)) stop('the live workspace failed its integrity check.');
  const run = workspace.runs.find(item => item.runId === settings.run);
  if (!run) stop('the run was not found.');
  if (run.status !== 'completed' && !settings.allowIncomplete) stop(`the run status is ${run.status}; use --allow-incomplete to export it as incomplete.`);
  const evidenceDirectory = boundedPath(path.join(liveDirectory, 'evidence', run.runId));
  const approval = readJson(path.join(evidenceDirectory, 'run-approval.json'));
  try { validateRunApproval(approval, proposal); } catch { stop('the run approval does not match the reviewed plan.'); }
  if (approval.approvalSha256 !== run.approvalSha256) stop('the run approval hash differs from the run.');
  const journal = new LiveBrickkenJournal({ directory: path.join(liveDirectory, 'journal') });
  // The completeness rule runs in this process's code, so a package counts as
  // complete only when this process and the files on disk carry the code
  // identity the run was approved for; otherwise the export is incomplete and
  // says why, and it is refused unless --allow-incomplete is given.
  const stored = evaluateLiveRunCompleteness({ run, journal, evidenceDirectory });
  let diskIdentity = null;
  try { diskIdentity = computeCodeIdentity().codeIdentitySha256; } catch { diskIdentity = null; }
  const identityMatches = typeof run.codeIdentitySha256 === 'string' && run.codeIdentitySha256 === PROCESS_CODE_IDENTITY_SHA256 && run.codeIdentitySha256 === diskIdentity;
  const missing = identityMatches ? [...stored.missing] : [...stored.missing, 'CODE_IDENTITY_MISMATCH:export'];
  const completeness = { complete: missing.length === 0, missing };
  if (!completeness.complete && !settings.allowIncomplete) {
    stop(`the run is not complete as evidence: ${completeness.missing.join(', ')}; use --allow-incomplete to export it as incomplete.`);
  }

  // --output exists for tests and rehearsals; the public package lives under verification/.
  const output = boundedPath(settings.output
    ? path.resolve(ROOT, settings.output)
    : path.join(ROOT, 'verification', `sepolia-live-${run.runId.slice(5, 17)}`));
  if (fs.existsSync(output)) stop(`${path.relative(ROOT, output)} already exists; nothing was overwritten.`);
  const written = new Map();
  const write = (relative, value) => {
    const target = boundedPath(path.join(output, relative));
    const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n';
    // Signed bytes stay local even after broadcast.
    if (/"signedTransaction"\s*:/.test(text)) stop(`${relative} would contain signed transaction bytes.`);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, text, { flag: 'wx' });
    written.set(relative, sha256(Buffer.from(text, 'utf8')));
  };
  const copyEvidence = (name, relative) => {
    const source = path.join(evidenceDirectory, `${name}.json`);
    const stat = fs.lstatSync(source, { throwIfNoEntry: false });
    if (!stat) return false;
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 8_000_000) stop('an evidence member is not a bounded regular file.');
    write(relative, readJson(source));
    return true;
  };

  const transactions = LIVE_WRITE_STEPS.map(step => {
    const info = run.steps[step];
    const record = journal.find(info.operationId);
    const base = { step, operation: OPERATIONS[step], route: LIVE_STEP_ROUTE[step], signerRole: LIVE_STEP_SIGNER[step], operationId: info.operationId };
    if (!info.planned) return { ...base, executed: false, skipReason: info.skipReason };
    if (!record) return { ...base, executed: false, skipReason: null };
    const hash = record.signed?.ethereumTransactionHash ?? null;
    copyEvidence(`${info.operationId}-preparation`, `steps/${step}-preparation.json`);
    copyEvidence(`${info.operationId}-receipt`, `steps/${step}-receipt.json`);
    copyEvidence(`${info.operationId}-postcheck`, `steps/${step}-postcheck.json`);
    return {
      ...base,
      executed: record.confirmation !== null,
      signerAddress: record.transaction.from,
      to: record.transaction.to,
      nonce: record.transaction.nonce,
      calldata: record.transaction.data,
      gasLimit: record.transaction.gasLimit,
      maxFeePerGas: record.transaction.maxFeePerGas,
      maxPriorityFeePerGas: record.transaction.maxPriorityFeePerGas,
      brickkenTxId: record.apiTxId,
      brickkenTxIdMeaning: record.apiTxId === null ? 'none: this write used the named Sepolia RPC route' : 'Brickken preparation ID, not a chain transaction hash',
      preparationHash: record.preparationHash,
      transactionHash: hash,
      explorerUrl: record.confirmation ? EXPLORER_TX + hash : null,
      journalState: record.state,
      blockNumber: record.confirmation?.blockNumber ?? null,
      blockHash: record.confirmation?.blockHash ?? null,
      receiptStatus: record.confirmation?.receiptStatus ?? null,
      confirmationsAtLastCheck: record.confirmation?.confirmations ?? null,
      secondarySourceBlockHashAgreed: record.confirmation ? record.confirmation.secondaryBlockHash === record.confirmation.blockHash : null,
      semanticVerification: record.semanticVerification
    };
  });
  const finalityEntries = new Map((run.finality?.entries ?? []).filter(entry => entry.operationId).map(entry => [entry.operationId, entry.finalized]));
  for (const item of transactions) item.finalizedOnBothSources = finalityEntries.get(item.operationId) ?? null;
  const controlFinality = new Map((run.finality?.entries ?? []).filter(entry => entry.controlId).map(entry => [entry.controlId, entry.finalized]));

  write('run-approval.json', approval);
  copyEvidence('preflight-plan', 'preflight-plan.json');
  copyEvidence('preflight-start', 'preflight-start.json');
  copyEvidence('code-identity', 'code-identity.json');
  copyEvidence('code-identity-start', 'code-identity-start.json');
  for (const id of LIVE_CONTROL_IDS) copyEvidence(id, `controls/${id}.json`);
  for (let index = 1; index <= run.replays.length + 20; index++) copyEvidence(`replay-${index}`, `replays/replay-${index}.json`);
  copyEvidence('finality', 'finality.json');
  copyEvidence('cleanup', 'cleanup.json');
  // Optional observations: their presence does not make an unfinished cleanup
  // complete. Only these exact names enter the public checksummed package.
  for (const name of ['cleanup-allowance-origin', 'cleanup-allowance-origin-sign']) copyEvidence(name, `${name}.json`);
  const refusals = fs.readdirSync(evidenceDirectory).filter(name => /^cleanup-reset-refused-[0-9]{1,17}\.json$/.test(name)).sort();
  if (refusals.length > 1000) stop('too many cleanup refusal observations.');
  for (const file of refusals) copyEvidence(file.slice(0, -5), file);
  write('transactions.json', {
    schemaVersion: 1,
    kind: 'mandate-desk-live-transactions',
    network: proposal.network,
    chainId: proposal.chainId,
    runId: run.runId,
    runStatus: run.status,
    complete: completeness.complete,
    missing: [...completeness.missing],
    approvalSha256: run.approvalSha256,
    proposalHash: proposal.proposalHash,
    codeIdentitySha256: run.codeIdentitySha256 ?? null,
    exportCodeIdentitySha256: PROCESS_CODE_IDENTITY_SHA256,
    finalityCheckedAt: run.finality?.checkedAt ?? null,
    transactions
  });
  write('run.json', {
    schemaVersion: 1,
    kind: 'mandate-desk-live-run',
    runId: run.runId,
    status: run.status,
    createdAt: run.createdAt,
    ownerApproval: run.ownerApproval,
    approvalSha256: run.approvalSha256,
    codeIdentitySha256: run.codeIdentitySha256 ?? null,
    complete: completeness.complete,
    missing: [...completeness.missing],
    controls: LIVE_CONTROL_IDS.map(id => ({ id, ...(run.controls[id] ?? { observed: false }), finalizedOnBothSources: controlFinality.get(id) ?? null })),
    replays: run.replays,
    stop: run.stop,
    cleanup: run.cleanup,
    finality: run.finality
  });
  const sums = Object.fromEntries([...written.entries()].sort(([a], [b]) => a.localeCompare(b)));
  write('SHA256SUMS.json', sums);
  console.log(`Evidence written to ${path.relative(ROOT, output)} (${written.size} files).`);
}

main();
