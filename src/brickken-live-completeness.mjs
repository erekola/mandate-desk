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
  else {
    if (finality.allFinalized !== true) note('FINALITY_NOT_ALL_FINALIZED');
    if (!(Date.parse(finality.checkedAt) >= latestChangeMs)) note('FINALITY_OUTDATED');
    for (const step of LIVE_WRITE_STEPS) {
      const record = records[step];
      if (!record?.confirmation) continue;
      const entry = finality.entries.find(item => item.operationId === record.operationId);
      if (!entry) { note(`FINALITY_ENTRY_MISSING:${step}`); continue; }
      if (!uintEqual(entry.blockNumber, record.confirmation.blockNumber) || entry.blockHash !== record.confirmation.blockHash) note(`FINALITY_ENTRY_STALE:${step}`);
      if (entry.finalized !== true) note(`FINALITY_ENTRY_NOT_FINALIZED:${step}`);
    }
    for (const id of LIVE_CONTROL_IDS) {
      const control = controls[id];
      if (!control?.observed) continue;
      const entry = finality.entries.find(item => item.controlId === id);
      if (!entry) { note(`FINALITY_CONTROL_MISSING:${id}`); continue; }
      if (!uintEqual(entry.blockNumber, control.blockNumber) || entry.blockHash !== control.blockHash) note(`FINALITY_CONTROL_STALE:${id}`);
      if (entry.finalized !== true) note(`FINALITY_CONTROL_NOT_FINALIZED:${id}`);
    }
  }
  if (!/^[a-f0-9]{64}$/.test(run.codeIdentitySha256 ?? '')) note('CODE_IDENTITY_MISSING');
  if (evidenceDirectory !== null) {
    const required = [...LIVE_BASE_EVIDENCE_FILES, ...LIVE_CONTROL_IDS];
    for (const step of LIVE_WRITE_STEPS) {
      if (!run.steps[step].planned) continue;
      for (const suffix of ['preparation', 'receipt', 'postcheck']) required.push(`${run.steps[step].operationId}-${suffix}`);
    }
    for (const name of required) {
      if (!fs.existsSync(path.join(evidenceDirectory, `${name}.json`))) note(`EVIDENCE_FILE_MISSING:${name}`);
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
