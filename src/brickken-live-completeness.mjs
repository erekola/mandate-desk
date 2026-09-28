// One explicit completeness rule for a live Sepolia run, shared by the evidence
// export, the recording binding and the owner workspace: every planned write
// semantically verified, every read-only control observed, passed and still
// canonical, a finality result that is newer than the last journal or control
// change and whose entries name the same operation ids and block hashes as the
// journal and the control records, every required evidence file present, and
// the two code identity documents valid by content and equal to the run's
// approved code identity. It reads saved state only; it never contacts the chain.
import fs from 'node:fs';
import path from 'node:path';
import { LIVE_CONTROL_IDS, LIVE_WRITE_STEPS } from './brickken-live-plan.mjs';
import { validateCodeIdentityEvidence } from './code-identity.mjs';
import { fieldsMissingFromSchema } from './brickken-live-evidence-schema.mjs';

export const LIVE_BASE_EVIDENCE_FILES = Object.freeze(['run-approval', 'preflight-plan', 'preflight-start', 'code-identity', 'code-identity-start', 'finality']);

// The members an exported package of a complete run must carry, named the way
// tools/export-live-evidence.mjs writes them. The recording binding refuses a
// package that lacks any of them, so a package is whole or it is nothing (R2-F04).
export function requiredEvidencePackageMembers(run) {
  const members = ['transactions.json', 'run.json', ...LIVE_BASE_EVIDENCE_FILES.map(name => `${name}.json`)];
  for (const id of LIVE_CONTROL_IDS) members.push(`controls/${id}.json`);
  for (const step of LIVE_WRITE_STEPS) {
    if (!run.steps[step].planned) continue;
    for (const suffix of ['preparation', 'receipt', 'postcheck']) members.push(`steps/${step}-${suffix}.json`);
  }
  return members;
}

function uintEqual(left, right) {
  try { return BigInt(left) === BigInt(right); } catch { return false; }
}

// The same consistency rules applied to either the run's own finality reading
// or a saved finality.json evidence file: an entry must exist for every
// semantically verified write and every passed, canonical control, naming the
// same block number and block hash the run itself recorded and marked
// finalized, and the reading itself must be no older than the run's last write
// or control change. Returns the list of problem codes, empty when consistent.
function finalityConsistencyProblems(finality, { latestChangeMs, records, controls }) {
  const problems = [];
  if (finality.allFinalized !== true) problems.push('FINALITY_NOT_ALL_FINALIZED');
  if (!(Date.parse(finality.checkedAt) >= latestChangeMs)) problems.push('FINALITY_OUTDATED');
  for (const step of LIVE_WRITE_STEPS) {
    const record = records[step];
    if (!record?.confirmation) continue;
    const entry = finality.entries.find(item => item.operationId === record.operationId);
    if (!entry) { problems.push(`FINALITY_ENTRY_MISSING:${step}`); continue; }
    if (!uintEqual(entry.blockNumber, record.confirmation.blockNumber) || entry.blockHash !== record.confirmation.blockHash) problems.push(`FINALITY_ENTRY_STALE:${step}`);
    if (entry.finalized !== true) problems.push(`FINALITY_ENTRY_NOT_FINALIZED:${step}`);
  }
  for (const id of LIVE_CONTROL_IDS) {
    const control = controls[id];
    if (!control?.observed) continue;
    const entry = finality.entries.find(item => item.controlId === id);
    if (!entry) { problems.push(`FINALITY_CONTROL_MISSING:${id}`); continue; }
    if (!uintEqual(entry.blockNumber, control.blockNumber) || entry.blockHash !== control.blockHash) problems.push(`FINALITY_CONTROL_STALE:${id}`);
    if (entry.finalized !== true) problems.push(`FINALITY_CONTROL_NOT_FINALIZED:${id}`);
  }
  return problems;
}

// The content-check kind of a required evidence file, from the base name
// evaluateLiveRunCompleteness uses for it (LIVE_BASE_EVIDENCE_FILES entries,
// a control ID, or "<operationId>-preparation|receipt|postcheck"). null for a
// name fieldsMissingFromSchema does not cover.
function evidenceContentKind(name) {
  if (name === 'run-approval') return 'run-approval';
  if (name === 'preflight-plan' || name === 'preflight-start') return 'preflight';
  if (name === 'code-identity' || name === 'code-identity-start') return 'code-identity';
  if (name === 'finality') return 'finality';
  if (LIVE_CONTROL_IDS.includes(name)) return 'control';
  if (name.endsWith('-preparation')) return 'step-preparation';
  if (name.endsWith('-receipt')) return 'step-receipt';
  if (name.endsWith('-postcheck')) return 'step-postcheck';
  return null;
}

// run: a stored live run; journal: an object with find(operationId);
// evidenceDirectory: the run's evidence folder, or null to skip the file check.
export function evaluateLiveRunCompleteness({ run, journal, evidenceDirectory = null }) {
  const missing = [];
  const note = code => missing.push(code);
  if (run.status !== 'completed') note('RUN_NOT_COMPLETED');
  let latestChangeMs = 0;
  const records = {};
  for (const step of LIVE_WRITE_STEPS) {
    const info = run.steps[step];
    if (!info.planned) continue;
    const record = journal.find(info.operationId);
    records[step] = record;
    if (!record || record.state !== 'semantically_verified') { note(`STEP_NOT_VERIFIED:${step}`); continue; }
    latestChangeMs = Math.max(latestChangeMs, Date.parse(record.updatedAt));
  }
  const controls = {};
  for (const id of LIVE_CONTROL_IDS) {
    const control = run.controls[id];
    controls[id] = control;
    if (!control || control.observed !== true) { note(`CONTROL_MISSING:${id}`); continue; }
    if (control.passed !== true) note(`CONTROL_NOT_PASSED:${id}`);
    if (control.canonical === false) note(`CONTROL_NOT_CANONICAL:${id}`);
    latestChangeMs = Math.max(latestChangeMs, Date.parse(control.observedAt));
  }
  const finality = run.finality;
  if (!finality || !Array.isArray(finality.entries)) note('FINALITY_MISSING');
  else for (const problem of finalityConsistencyProblems(finality, { latestChangeMs, records, controls })) note(problem);
  if (!/^[a-f0-9]{64}$/.test(run.codeIdentitySha256 ?? '')) note('CODE_IDENTITY_MISSING');
  if (evidenceDirectory !== null) {
    const required = [...LIVE_BASE_EVIDENCE_FILES, ...LIVE_CONTROL_IDS];
    for (const step of LIVE_WRITE_STEPS) {
      if (!run.steps[step].planned) continue;
      for (const suffix of ['preparation', 'receipt', 'postcheck']) required.push(`${run.steps[step].operationId}-${suffix}`);
    }
    for (const name of required) {
      const file = path.join(evidenceDirectory, `${name}.json`);
      if (!fs.existsSync(file)) { note(`EVIDENCE_FILE_MISSING:${name}`); continue; }
      const kind = evidenceContentKind(name);
      if (kind === null) continue;
      let parsed;
      try { parsed = JSON.parse(fs.readFileSync(file, 'utf8')); }
      catch { note(`EVIDENCE_FILE_INVALID:${name}`); continue; }
      const problems = fieldsMissingFromSchema(kind, parsed);
      if (problems.length) note(`EVIDENCE_FIELD_MISSING:${name}:${problems[0]}`);
    }
    // The saved finality.json evidence file was checked only against its field
    // schema above, which a placeholder or self-contradictory but well-typed
    // document still passes (NF-01). Cross-check its content against the run
    // the same way run.finality itself is checked just above, so a saved file
    // that disagrees with the run's own writes and controls cannot still leave
    // this evaluator reading complete.
    {
      const file = path.join(evidenceDirectory, 'finality.json');
      let saved;
      try { saved = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { saved = null; }
      if (saved && Array.isArray(saved.entries)) {
        for (const problem of finalityConsistencyProblems(saved, { latestChangeMs, records, controls })) note(`SAVED_FINALITY_${problem}`);
      }
    }

    // The receipt evidence names the same transaction the journal recorded as
    // signed for this step; a receipt content that is internally well-formed
    // but names a different hash is still wrong (MD-02's named cross-check).
    for (const step of LIVE_WRITE_STEPS) {
      const record = records[step];
      if (!record?.signed) continue;
      const file = path.join(evidenceDirectory, `${record.operationId}-receipt.json`);
      let parsed;
      try { parsed = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { continue; }
      if (typeof parsed?.receipt?.transactionHash === 'string' && parsed.receipt.transactionHash !== record.signed.ethereumTransactionHash) {
        note(`EVIDENCE_RECEIPT_HASH_MISMATCH:${step}`);
      }
    }
    // Existence is not enough for the identity documents: each is validated by
    // content and its stable hash must equal the identity the run was approved for.
    for (const name of ['code-identity', 'code-identity-start']) {
      const file = path.join(evidenceDirectory, `${name}.json`);
      if (!fs.existsSync(file)) continue;
      let stable;
      try { stable = validateCodeIdentityEvidence(JSON.parse(fs.readFileSync(file, 'utf8'))); }
      catch { note(`CODE_IDENTITY_EVIDENCE_INVALID:${name}`); continue; }
      if (stable !== run.codeIdentitySha256) note(`CODE_IDENTITY_EVIDENCE_MISMATCH:${name}`);
    }
  }
  return Object.freeze({ complete: missing.length === 0, missing: Object.freeze(missing) });
}
