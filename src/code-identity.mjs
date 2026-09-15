// The identity of the source bytes a live Sepolia run is approved for. The
// stable hash covers one explicit, sorted file set (every regular file under
// src, public and tools, the live proposal, the vendored ethers bundle and
// package.json) and nothing that changes without a byte change: the recording
// time and the git head stay outside it as metadata. The same hash is computed
// three times for different purposes: once when this module is evaluated, as
// the identity of the process that loaded it (owner server, agent MCP server
// or signer); again from disk when a run is prepared, as the identity the owner
// approves; and again from disk before every write-capable action, so a changed
// file stops the run with CODE_IDENTITY_MISMATCH before a signature or a send.
// The process identity is the disk state read when this module is evaluated,
// before the application modules run; Node offers no later attestation of the
// bytes a process has loaded, and this module does not claim one.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { sha256Canonical } from './brickken-intent.mjs';

export const CODE_IDENTITY_SCHEMA_VERSION = 2;
export const CODE_IDENTITY_KIND = 'mandate-desk-code-identity';
export const CODE_IDENTITY_FOLDERS = Object.freeze(['src', 'public', 'tools']);
export const CODE_IDENTITY_FILES = Object.freeze(['integration/live-proposal.json', 'vendor/ethers-6.17.0/ethers.umd.min.cjs', 'package.json']);
const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const EVIDENCE_KEYS = ['schemaVersion', 'kind', 'files', 'codeIdentitySha256', 'recordedAt', 'gitHead'];
const FILE_KEYS = ['path', 'bytes', 'sha256'];

export class CodeIdentityError extends Error {
  constructor(code, details = {}) {
    super(code);
    this.name = 'CodeIdentityError';
    this.code = code;
    this.details = details;
  }
}
function fail(code, details = {}) { throw new CodeIdentityError(code, details); }
function sha256Hex(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

function walk(root, relative, out) {
  const entries = fs.readdirSync(path.join(root, ...relative.split('/')), { withFileTypes: true })
    .sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  for (const entry of entries) {
    const child = `${relative}/${entry.name}`;
    if (entry.isSymbolicLink()) fail('CODE_IDENTITY_LINK', { path: child });
    if (entry.isDirectory()) walk(root, child, out);
    else if (entry.isFile()) out.push(child);
    else fail('CODE_IDENTITY_ENTRY', { path: child });
  }
}

// The covered paths, sorted, relative to the project root with forward slashes.
export function coveredCodePaths(root = PROJECT_ROOT) {
  const out = [];
  for (const folder of CODE_IDENTITY_FOLDERS) {
    const stat = fs.lstatSync(path.join(root, folder), { throwIfNoEntry: false });
    if (!stat || stat.isSymbolicLink() || !stat.isDirectory()) fail('CODE_IDENTITY_MISSING', { path: folder });
    walk(root, folder, out);
  }
  for (const file of CODE_IDENTITY_FILES) {
    const stat = fs.lstatSync(path.join(root, ...file.split('/')), { throwIfNoEntry: false });
    if (!stat || stat.isSymbolicLink() || !stat.isFile()) fail('CODE_IDENTITY_MISSING', { path: file });
    out.push(file);
  }
  return out.sort();
}

// The stable hash: the schema version, the kind and the sorted file table only.
export function stableCodeIdentitySha256(identity) {
  return sha256Canonical({
    schemaVersion: identity.schemaVersion,
    kind: identity.kind,
    files: identity.files.map(file => ({ path: file.path, bytes: file.bytes, sha256: file.sha256 }))
  });
}

export function computeCodeIdentity(root = PROJECT_ROOT) {
  const files = coveredCodePaths(root).map(relative => {
    const bytes = fs.readFileSync(path.join(root, ...relative.split('/')));
    return Object.freeze({ path: relative, bytes: bytes.length, sha256: sha256Hex(bytes) });
  });
  const identity = { schemaVersion: CODE_IDENTITY_SCHEMA_VERSION, kind: CODE_IDENTITY_KIND, files: Object.freeze(files) };
  return Object.freeze({ ...identity, codeIdentitySha256: stableCodeIdentitySha256(identity) });
}

// gitHead is read from the .git files without running git; uncommitted edits
// show only in the file hashes, and a commit without a byte change does not
// change the stable hash.
export function readGitHead(root = PROJECT_ROOT) {
  try {
    const head = fs.readFileSync(path.join(root, '.git', 'HEAD'), 'utf8').trim();
    if (/^[a-f0-9]{40}$/.test(head)) return head;
    if (!/^ref: refs\/heads\/[A-Za-z0-9._\/-]+$/.test(head)) return null;
    const ref = head.slice(5);
    const loose = path.join(root, '.git', ...ref.split('/'));
    let value = null;
    if (fs.existsSync(loose)) value = fs.readFileSync(loose, 'utf8').trim();
    else {
      value = fs.readFileSync(path.join(root, '.git', 'packed-refs'), 'utf8').split('\n')
        .find(line => line.endsWith(' ' + ref))?.slice(0, 40) ?? null;
    }
    return value !== null && /^[a-f0-9]{40}$/.test(value) ? value : null;
  } catch {
    return null;
  }
}

// The evidence document written for a run: the stable identity plus metadata.
export function codeIdentityEvidence(identity, { recordedAt, gitHead = null }) {
  if (typeof recordedAt !== 'string' || !Number.isFinite(Date.parse(recordedAt))) fail('CODE_IDENTITY_TIME');
  return {
    schemaVersion: identity.schemaVersion,
    kind: identity.kind,
    files: identity.files.map(file => ({ path: file.path, bytes: file.bytes, sha256: file.sha256 })),
    codeIdentitySha256: identity.codeIdentitySha256,
    recordedAt,
    gitHead
  };
}

function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function shape(value, keys) {
  if (!plain(value)) fail('CODE_IDENTITY_EVIDENCE_INVALID', { reason: 'STRUCTURE' });
  const present = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (present.length !== expected.length || present.some((key, index) => key !== expected[index])) {
    fail('CODE_IDENTITY_EVIDENCE_INVALID', { reason: 'KEYS' });
  }
}

// Validates a stored evidence document by content, not existence: the shape,
// every file row, the sorted unique path set and the stable hash recomputed
// from the rows. Returns the stable hash.
export function validateCodeIdentityEvidence(value) {
  shape(value, EVIDENCE_KEYS);
  if (value.schemaVersion !== CODE_IDENTITY_SCHEMA_VERSION || value.kind !== CODE_IDENTITY_KIND) {
    fail('CODE_IDENTITY_EVIDENCE_INVALID', { reason: 'KIND' });
  }
  if (!Array.isArray(value.files) || value.files.length === 0 || value.files.length > 10_000) {
    fail('CODE_IDENTITY_EVIDENCE_INVALID', { reason: 'FILES' });
  }
  let previous = null;
  for (const file of value.files) {
    shape(file, FILE_KEYS);
    if (typeof file.path !== 'string' || !/^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/.test(file.path) ||
        file.path.split('/').some(part => part === '.' || part === '..')) {
      fail('CODE_IDENTITY_EVIDENCE_INVALID', { reason: 'PATH', path: String(file.path) });
    }
    if (previous !== null && !(file.path > previous)) fail('CODE_IDENTITY_EVIDENCE_INVALID', { reason: 'ORDER', path: file.path });
    previous = file.path;
    if (!Number.isSafeInteger(file.bytes) || file.bytes < 0) fail('CODE_IDENTITY_EVIDENCE_INVALID', { reason: 'BYTES', path: file.path });
    if (typeof file.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(file.sha256)) fail('CODE_IDENTITY_EVIDENCE_INVALID', { reason: 'SHA256', path: file.path });
  }
  if (typeof value.recordedAt !== 'string' || !Number.isFinite(Date.parse(value.recordedAt))) fail('CODE_IDENTITY_EVIDENCE_INVALID', { reason: 'TIME' });
  if (value.gitHead !== null && (typeof value.gitHead !== 'string' || !/^[a-f0-9]{40}$/.test(value.gitHead))) {
    fail('CODE_IDENTITY_EVIDENCE_INVALID', { reason: 'GIT_HEAD' });
  }
  const stable = stableCodeIdentitySha256(value);
  if (value.codeIdentitySha256 !== stable) fail('CODE_IDENTITY_EVIDENCE_INVALID', { reason: 'HASH' });
  return stable;
}

// The identity of the process that evaluated this module.
export const PROCESS_CODE_IDENTITY = computeCodeIdentity();
export const PROCESS_CODE_IDENTITY_SHA256 = PROCESS_CODE_IDENTITY.codeIdentitySha256;
