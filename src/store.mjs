import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { newState, validateState, fail } from './domain.mjs';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const RENAME_ATTEMPTS = 25;
const RENAME_DELAY_MS = 10;
const RENAME_WAIT = new Int32Array(new SharedArrayBuffer(4));

export function boundedPath(target) {
  const resolved = path.resolve(target);
  if (!resolved.startsWith(ROOT + path.sep)) fail('PATH_SCOPE', 'The storage path is outside this project.');
  let current = resolved;
  while (true) {
    const entry = fs.lstatSync(current, { throwIfNoEntry: false });
    if (entry?.isSymbolicLink()) fail('PATH_SCOPE', 'A linked storage path cannot be used.');
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return resolved;
}

export class Store {
  constructor(directory = path.join(ROOT, 'data')) {
    this.directory = boundedPath(directory);
    fs.mkdirSync(this.directory, { recursive: true });
    this.file = path.join(this.directory, 'state.json');
    this.lock = path.join(this.directory, 'state.lock');
    boundedPath(this.file); boundedPath(this.lock);
    if (fs.lstatSync(this.lock, { throwIfNoEntry: false })) this.reportExistingLock();
    if (fs.lstatSync(this.file, { throwIfNoEntry: false })) this.read();
    else this.transact(() => null, { initialize: true });
  }
  reportExistingLock() {
    let pid;
    let at;
    try {
      const lock = JSON.parse(fs.readFileSync(this.lock, { encoding: 'utf8', flag: 'r' }));
      if (Number.isSafeInteger(lock?.pid) && lock.pid > 0) pid = lock.pid;
      if (typeof lock?.at === 'string' && new Date(lock.at).toISOString() === lock.at) at = lock.at;
    } catch {}
    const details = [pid === undefined ? null : `pid=${pid}`, at === undefined ? null : `at=${at}`].filter(Boolean);
    const lockPath = this.lock.replace(/[\u0000-\u001f\u007f]/g, '?');
    console.error(`Mandate Desk storage lock present and not removed: ${lockPath}${details.length ? `; ${details.join('; ')}` : ''}`);
  }
  read() {
    boundedPath(this.file);
    try {
      if (fs.statSync(this.file).size > 32 * 1024 * 1024) fail('STORE_INVALID', 'The demo file exceeds the size limit.');
      return validateState(JSON.parse(fs.readFileSync(this.file, 'utf8')));
    } catch (error) {
      if (error.code === 'STORE_INVALID') throw error;
      fail('STORE_INVALID', 'The saved demo state could not be read. The file was preserved.');
    }
  }
  transact(change, { initialize = false } = {}) {
    boundedPath(this.lock); boundedPath(this.file);
    let lock;
    try { lock = fs.openSync(this.lock, 'wx'); }
    catch { fail('STORE_BUSY', 'The demo state is busy. Try again later.'); }
    let temporary;
    try {
      fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, at: new Date().toISOString() }));
      const exists = fs.existsSync(this.file);
      const state = exists ? this.read() : newState();
      if (!exists && !initialize) fail('STORE_INVALID', 'The demo state file is missing.');
      if (exists && initialize) return null;
      const result = change(state);
      state.revision++;
      validateState(state);
      temporary = boundedPath(path.join(this.directory, `state-${randomUUID()}.tmp`));
      const descriptor = fs.openSync(temporary, 'wx');
      try { fs.writeFileSync(descriptor, JSON.stringify(state, null, 2)); fs.fsyncSync(descriptor); }
      finally { fs.closeSync(descriptor); }
      atomicRename(temporary, this.file); temporary = null;
      return structuredClone(result);
    } finally {
      if (temporary && fs.existsSync(temporary)) fs.unlinkSync(temporary);
      fs.closeSync(lock); fs.unlinkSync(this.lock);
    }
  }
}

function atomicRename(source, destination) {
  for (let attempt = 1; attempt <= RENAME_ATTEMPTS; attempt++) {
    try {
      fs.renameSync(source, destination);
      return;
    } catch (error) {
      if (!['EPERM', 'EACCES', 'EBUSY'].includes(error?.code)) throw error;
      if (attempt === RENAME_ATTEMPTS) fail('STORE_BUSY', 'The demo state is busy. Try again later.');
      Atomics.wait(RENAME_WAIT, 0, 0, RENAME_DELAY_MS);
    }
  }
}
