// One lock protocol for the three live files: live-run.lock, live-workspace.lock
// and live-journal.lock. Ownership is an open file handle that the operating
// system keeps exclusive for the life of the holding process: the file is
// opened with libuv's exclusive flag, which on Windows is share mode 0, so no
// other process (and no other handle in this process) can open, read, rename
// or delete the file while the holder lives. A holder that exits or crashes
// loses the handle and the next acquirer opens the same path exclusively and
// writes its own record over the stale one. Nothing in this protocol compares
// a record and then acts on the pathname in a second step, so a stale takeover
// or an old release can never remove a newer holder's lock (A1-F03). The lock
// file is never unlinked: release() marks the record as released through the
// holder's own handle and closes it. On a platform where the exclusive open
// cannot be verified the lock refuses to work rather than fall back to a
// weaker protocol; the launcher and README name Windows as the platform.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';

export const LIVE_LOCK_KIND = 'mandate-desk-live-lock';
export const LIVE_LOCK_PROTOCOL = 'exclusive-handle';
const MAX_LOCK_BYTES = 4096;
const WAIT = new Int32Array(new SharedArrayBuffer(4));
// libuv's UV_FS_O_EXLOCK is 0x10000000 on Windows (public in uv/win.h) and
// Node passes numeric open flags through unchanged. BSD and macOS expose
// O_EXLOCK, which libuv turns into a non-blocking flock with O_NONBLOCK.
const EXCLUSIVE_FLAG = process.platform === 'win32' ? 0x10000000 : (fs.constants.O_EXLOCK ?? null);
const NONBLOCK_FLAG = process.platform === 'win32' ? 0 : (fs.constants.O_NONBLOCK ?? 0);
const CREATE_EXCLUSIVE = fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL;
const OPEN_EXISTING = fs.constants.O_RDWR;
// Codes that mean another handle holds the file right now.
const HELD_CODES = new Set(['EBUSY', 'EAGAIN', 'EWOULDBLOCK']);
// Codes that a pending operation on the same path can produce for a moment.
const RETRY_CODES = new Set(['EPERM', 'EACCES']);

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

function parseRecord(text) {
  let record;
  try { record = JSON.parse(text); } catch { return null; }
  if (!record || typeof record !== 'object' || Array.isArray(record) || record.kind !== LIVE_LOCK_KIND ||
      typeof record.ownerId !== 'string' || !/^[a-f0-9-]{36}$/.test(record.ownerId) ||
      !Number.isSafeInteger(record.pid) || record.pid < 1 ||
      typeof record.at !== 'string' || !Number.isFinite(Date.parse(record.at)) ||
      (record.releasedAt !== undefined && (typeof record.releasedAt !== 'string' || !Number.isFinite(Date.parse(record.releasedAt))))) {
    return null;
  }
  return record;
}

function readThroughDescriptor(descriptor) {
  const buffer = Buffer.alloc(MAX_LOCK_BYTES + 1);
  const length = fs.readSync(descriptor, buffer, 0, buffer.length, 0);
  if (length > MAX_LOCK_BYTES) return null;
  return parseRecord(buffer.toString('utf8', 0, length));
}

function writeThroughDescriptor(descriptor, record) {
  const bytes = Buffer.from(JSON.stringify(record), 'utf8');
  fs.ftruncateSync(descriptor, 0);
  fs.writeSync(descriptor, bytes, 0, bytes.length, 0);
  fs.fsyncSync(descriptor);
}

let exclusiveSupport = null;
// Measures once per process that the exclusive open really excludes a second
// open of the same file. Without that measurement no lock is granted.
export function exclusiveOpenSupported() {
  if (exclusiveSupport !== null) return exclusiveSupport;
  if (EXCLUSIVE_FLAG === null) { exclusiveSupport = false; return false; }
  const probe = path.join(os.tmpdir(), `mandate-desk-lock-probe-${process.pid}-${randomUUID()}`);
  let held = null;
  try {
    held = fs.openSync(probe, CREATE_EXCLUSIVE | EXCLUSIVE_FLAG | NONBLOCK_FLAG);
    try {
      const second = fs.openSync(probe, OPEN_EXISTING | EXCLUSIVE_FLAG | NONBLOCK_FLAG);
      fs.closeSync(second);
      exclusiveSupport = false;
    } catch (error) {
      exclusiveSupport = HELD_CODES.has(error?.code);
    }
  } catch {
    exclusiveSupport = false;
  } finally {
    if (held !== null) fs.closeSync(held);
    try { fs.unlinkSync(probe); } catch { /* the probe file is disposable */ }
  }
  return exclusiveSupport;
}

// Reads the holder record at a path for diagnostics: absent, held (a live
// process holds the exclusive handle, so the content cannot be read), invalid
// (empty, unreadable or not a holder record), released (a record whose holder
// released it) or valid (a record whose holder never released it: on Windows
// that holder is gone, because a live holder would make the read fail).
export function readLockHolder(file) {
  let stat;
  try { stat = fs.lstatSync(file, { throwIfNoEntry: false }); }
  catch (error) {
    if (error?.code === 'ENOENT') return { state: 'absent', record: null, mtimeMs: null };
    return { state: 'invalid', record: null, mtimeMs: null };
  }
  if (!stat) return { state: 'absent', record: null, mtimeMs: null };
  const mtimeMs = stat.mtimeMs;
  if (!stat.isFile() || stat.size > MAX_LOCK_BYTES) return { state: 'invalid', record: null, mtimeMs };
  let text;
  try { text = fs.readFileSync(file, 'utf8'); }
  catch (error) {
    if (error?.code === 'ENOENT') return { state: 'absent', record: null, mtimeMs: null };
    if (HELD_CODES.has(error?.code)) return { state: 'held', record: null, mtimeMs };
    return { state: 'invalid', record: null, mtimeMs };
  }
  const record = parseRecord(text);
  if (!record) return { state: 'invalid', record: null, mtimeMs };
  return { state: record.releasedAt === undefined ? 'valid' : 'released', record, mtimeMs };
}

// A lease is the open exclusive handle plus the record written through it.
// holds() proves ownership without touching the pathname's content: the handle
// is still open and the file at the path is still the file the handle names.
// release() writes the release time through the handle and closes it; it never
// unlinks, so a later holder's file is never removed by an earlier release.
function createLease(file, descriptor, record) {
  let released = false;
  const holds = () => {
    if (released) return false;
    try {
      const own = fs.fstatSync(descriptor);
      const current = fs.statSync(file, { throwIfNoEntry: false });
      if (!current || current.ino !== own.ino || current.dev !== own.dev) return false;
      const stored = readThroughDescriptor(descriptor);
      return stored !== null && stored.ownerId === record.ownerId && stored.pid === record.pid && stored.releasedAt === undefined;
    } catch {
      return false;
    }
  };
  return Object.freeze({
    file,
    protocol: LIVE_LOCK_PROTOCOL,
    ownerId: record.ownerId,
    record: Object.freeze({ ...record }),
    holds,
    release() {
      if (released) return false;
      released = true;
      try { writeThroughDescriptor(descriptor, { ...record, releasedAt: new Date().toISOString() }); }
      catch { /* the handle closes below; the next acquirer takes the record over */ }
      try { fs.closeSync(descriptor); } catch { /* already closed */ }
      return true;
    }
  });
}

// Acquires the lock at `file`. `holder` fields (role, purpose, runId) are
// written into the record. A live holder makes the call wait `attempts` times
// `waitMs` and then fail with busyCode; a holder whose process is gone, or
// that released the lock, is taken over within the same attempt. Errors:
// LOCK_UNSUPPORTED when the exclusive open cannot be verified on this
// platform, LOCK_DIRECTORY_MISSING when the lock's folder is gone, LOCK_INVALID
// for content that is not a holder record (it is left in place for a person to
// inspect), busyCode for a live holder.
export function acquireLiveLock(file, { holder = {}, now = () => Date.now(), attempts = 1, waitMs = 10, busyCode = 'LOCK_BUSY' } = {}) {
  if (typeof file !== 'string' || !Number.isSafeInteger(attempts) || attempts < 1) fail('LOCK_CONFIGURATION');
  const name = path.basename(file);
  if (!exclusiveOpenSupported()) fail('LOCK_UNSUPPORTED', { lockFile: name, platform: process.platform });
  const ownerId = randomUUID();
  for (let attempt = 0; attempt < attempts; attempt++) {
    let descriptor = null;
    let created = false;
    try {
      descriptor = fs.openSync(file, CREATE_EXCLUSIVE | EXCLUSIVE_FLAG | NONBLOCK_FLAG);
      created = true;
    } catch (error) {
      if (error?.code === 'ENOENT') fail('LOCK_DIRECTORY_MISSING', { lockFile: name });
      if (error?.code !== 'EEXIST') throw error;
      try {
        descriptor = fs.openSync(file, OPEN_EXISTING | EXCLUSIVE_FLAG | NONBLOCK_FLAG);
      } catch (inner) {
        if (inner?.code === 'ENOENT') continue;
        if (!HELD_CODES.has(inner?.code) && !RETRY_CODES.has(inner?.code)) throw inner;
        if (attempt === attempts - 1) fail(busyCode, { lockFile: name, purpose: null });
        pause(waitMs);
        continue;
      }
    }
    try {
      if (!created) {
        // This process holds the only handle, so the earlier holder is gone or
        // released. Content that is not a holder record is never taken over.
        let stat = null;
        try { stat = fs.fstatSync(descriptor); } catch { stat = null; }
        const current = stat && stat.size <= MAX_LOCK_BYTES ? readThroughDescriptor(descriptor) : null;
        if (current === null) fail('LOCK_INVALID', { lockFile: name });
      }
      const record = { kind: LIVE_LOCK_KIND, ownerId, pid: process.pid, at: new Date(now()).toISOString(), ...holder };
      writeThroughDescriptor(descriptor, record);
      const lease = createLease(file, descriptor, record);
      descriptor = null;
      return lease;
    } finally {
      if (descriptor !== null) fs.closeSync(descriptor);
    }
  }
  return fail(busyCode, { lockFile: name, purpose: null });
}
