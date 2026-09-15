// One lock protocol for the three live files: live-run.lock, live-workspace.lock
// and live-journal.lock. Every holder record names its process, a random owner
// id and the purpose, so a later process can tell a dead owner from a live one
// and a lease can prove that the file at the path is still its own before it
// removes it. A lock left by a process that no longer exists is taken over by
// renaming the exact stale file away (atomic on one volume) and checking that
// the moved bytes are the stale record that was read; a fresh live lock that
// the rename displaced is put back with a link that never overwrites. Invalid
// or empty content is never treated as dead on age alone: it is reported with
// a code and left in place for a person to inspect.
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

export const LIVE_LOCK_KIND = 'mandate-desk-live-lock';
// A writer needs microseconds between creating the file and writing the record;
// an invalid file younger than this is treated as in progress and retried.
export const INVALID_LOCK_GRACE_MS = 5_000;
const MAX_LOCK_BYTES = 4096;
const WAIT = new Int32Array(new SharedArrayBuffer(4));

export class LiveLockError extends Error {
  constructor(code, details = {}) {
    super(code);
    this.name = 'LiveLockError';
    this.code = code;
    this.details = details;
  }
}
function fail(code, details = {}) { throw new LiveLockError(code, details); }
function pause(milliseconds) { Atomics.wait(WAIT, 0, 0, milliseconds); }

export function pidAlive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { return error?.code === 'EPERM'; }
}

// Reads the holder record at a path: absent, invalid (empty, unreadable or not
// a holder record) or valid with the record.
export function readLockHolder(file) {
  let text;
  let mtimeMs = null;
  try {
    const stat = fs.lstatSync(file, { throwIfNoEntry: false });
    if (!stat) return { state: 'absent', record: null, mtimeMs: null };
    mtimeMs = stat.mtimeMs;
    if (!stat.isFile() || stat.size > MAX_LOCK_BYTES) return { state: 'invalid', record: null, mtimeMs };
    text = fs.readFileSync(file, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return { state: 'absent', record: null, mtimeMs: null };
    return { state: 'invalid', record: null, mtimeMs };
  }
  let record;
  try { record = JSON.parse(text); } catch { return { state: 'invalid', record: null, mtimeMs }; }
  if (!record || typeof record !== 'object' || Array.isArray(record) || record.kind !== LIVE_LOCK_KIND ||
      typeof record.ownerId !== 'string' || !/^[a-f0-9-]{36}$/.test(record.ownerId) ||
      !Number.isSafeInteger(record.pid) || record.pid < 1 ||
      typeof record.at !== 'string' || !Number.isFinite(Date.parse(record.at))) {
    return { state: 'invalid', record: null, mtimeMs };
  }
  return { state: 'valid', record, mtimeMs };
}

// Puts a displaced file back at the lock path without overwriting anything
// that appeared there meanwhile. Hard links are atomic and refuse EEXIST; a
// volume without them falls back to an exclusive copy.
function restoreDisplaced(claim, file) {
  try { fs.linkSync(claim, file); }
  catch (error) {
    if (error?.code === 'EEXIST') return false;
    fs.copyFileSync(claim, file, fs.constants.COPYFILE_EXCL);
  }
  try { fs.unlinkSync(claim); } catch { /* the link already carries the record */ }
  return true;
}

// Takes over the exact stale record that the caller read. Returns 'claimed'
// when the path is free for the caller, 'gone' when another process already
// took it, 'restored' when the rename caught a fresh live lock that was put
// back, and 'conflict' when a fresh lock could not be put back because a third
// lock appeared; the displaced record then stays in the claim file as evidence.
export function claimStaleLock(file, staleRecord) {
  const claim = `${file}.claim-${randomUUID()}`;
  try { fs.renameSync(file, claim); }
  catch (error) {
    if (error?.code === 'ENOENT') return { outcome: 'gone', claim: null };
    throw error;
  }
  const moved = readLockHolder(claim);
  if (moved.state === 'valid' && moved.record.ownerId === staleRecord.ownerId && moved.record.pid === staleRecord.pid) {
    try { fs.unlinkSync(claim); } catch { /* the claim file is ours alone */ }
    return { outcome: 'claimed', claim: null };
  }
  return restoreDisplaced(claim, file) ? { outcome: 'restored', claim: null } : { outcome: 'conflict', claim };
}

// A lease proves ownership by re-reading the file: the record at the path must
// still carry this lease's owner id. release() removes the file only then.
export function createLease(file, record) {
  let released = false;
  const holds = () => {
    const current = readLockHolder(file);
    return current.state === 'valid' && current.record.ownerId === record.ownerId && current.record.pid === record.pid;
  };
  return Object.freeze({
    file,
    ownerId: record.ownerId,
    record: Object.freeze({ ...record }),
    holds,
    release() {
      if (released) return false;
      released = true;
      if (!holds()) return false;
      try { fs.unlinkSync(file); } catch { /* removed by a takeover after our check; nothing else to do */ }
      return true;
    }
  });
}

// Acquires the lock at `file`. `holder` fields (role, purpose, runId) are
// written into the record. `attempts` and `waitMs` bound the wait for a live
// holder; a dead holder is taken over within the same call. Errors: busyCode
// for a live holder, LOCK_INVALID for unreadable content older than the grace
// period, LOCK_CONFLICT when a takeover displaced a fresh lock that could not
// be restored.
export function acquireLiveLock(file, { holder = {}, now = () => Date.now(), attempts = 1, waitMs = 10, busyCode = 'LOCK_BUSY' } = {}) {
  if (typeof file !== 'string' || !Number.isSafeInteger(attempts) || attempts < 1) fail('LOCK_CONFIGURATION');
  const ownerId = randomUUID();
  const name = path.basename(file);
  for (let attempt = 0; attempt < attempts; attempt++) {
    let descriptor = null;
    try { descriptor = fs.openSync(file, 'wx'); }
    catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      const current = readLockHolder(file);
      if (current.state === 'absent') continue;
      if (current.state === 'invalid') {
        // Real time on purpose: the file's mtime is real time even under a test clock.
        // A young invalid file may be a writer between create and write: an unclear
        // owner blocks like a live one. Only an old invalid file is reported as such.
        if (Date.now() - current.mtimeMs < INVALID_LOCK_GRACE_MS) {
          if (attempt < attempts - 1) { pause(waitMs); continue; }
          fail(busyCode, { lockFile: name, purpose: null });
        }
        fail('LOCK_INVALID', { lockFile: name });
      }
      const record = current.record;
      if (record.pid !== process.pid && !pidAlive(record.pid)) {
        const { outcome } = claimStaleLock(file, record);
        if (outcome === 'conflict') fail('LOCK_CONFLICT', { lockFile: name });
        continue;
      }
      if (attempt === attempts - 1) fail(busyCode, { lockFile: name, purpose: record.purpose ?? null });
      pause(waitMs);
      continue;
    }
    const record = { kind: LIVE_LOCK_KIND, ownerId, pid: process.pid, at: new Date(now()).toISOString(), ...holder };
    try {
      fs.writeFileSync(descriptor, JSON.stringify(record));
      fs.fsyncSync(descriptor);
    } finally {
      fs.closeSync(descriptor);
    }
    return createLease(file, record);
  }
  return fail(busyCode, { lockFile: name });
}
