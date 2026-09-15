// User-launched live signer for one approved Sepolia run. It unlocks the two
// named test keystores inside this process, reads the Brickken sandbox API key
// from standard input, and serves a loopback-only interface to the owner
// workspace and the integration MCP server. Keys and the API key never leave
// this process. Callers receive signed bytes only for steps that the
// hash-bound run approval names, and each role token reaches only its own steps.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
// The code identity module is imported first so the process identity is the
// disk state at startup, before the application modules below are evaluated.
import { PROCESS_CODE_IDENTITY_SHA256 } from '../src/code-identity.mjs';
import { ROOT, boundedPath } from '../src/store.mjs';
import { loadLiveProposal } from '../src/brickken-live-plan.mjs';
import { LiveSigner, LiveSignerError } from '../src/brickken-live-signer.mjs';
import { createRoleResolver, createSignerRequestHandler } from '../src/live-signer-http.mjs';

const require = createRequire(import.meta.url);
const ethers = require('../vendor/ethers-6.17.0/ethers.umd.min.cjs');
const WALLET_FILES = Object.freeze({
  owner: 'principal.keystore.json',
  agent: 'agent.keystore.json',
  unlock: 'avaussalaisuus.bin'
});
const MAX_KEYSTORE_BYTES = 64 * 1024;

function stop(message) {
  console.error(`Live signer stopped: ${message}`);
  process.exit(1);
}

function parseArguments(args) {
  const allowed = new Set(['--approval', '--approval-sha256', '--code-identity-sha256', '--wallet-dir', '--data']);
  const settings = {};
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = args[index + 1];
    if (!allowed.has(name) || typeof value !== 'string' || !value || Object.hasOwn(settings, name)) stop('invalid arguments.');
    settings[name] = value;
  }
  if (Object.keys(settings).length !== allowed.size) stop('all five arguments are required.');
  if (!/^[a-f0-9]{64}$/.test(settings['--approval-sha256'])) stop('the approval hash must be 64 lowercase hexadecimal characters.');
  if (!/^[a-f0-9]{64}$/.test(settings['--code-identity-sha256'])) stop('the code identity hash must be 64 lowercase hexadecimal characters.');
  return {
    approvalFile: boundedPath(path.resolve(ROOT, settings['--approval'])),
    approvalSha256: settings['--approval-sha256'],
    codeIdentitySha256: settings['--code-identity-sha256'],
    walletDirectory: path.resolve(settings['--wallet-dir']),
    dataDirectory: boundedPath(path.resolve(ROOT, settings['--data']))
  };
}

// Reads one fixed file name from the wallet directory without following links.
function readWalletFile(directory, name, maximum) {
  const target = path.join(directory, name);
  const entry = fs.lstatSync(target, { throwIfNoEntry: false });
  if (!entry || !entry.isFile() || entry.isSymbolicLink() || entry.size > maximum) stop(`wallet file ${name} is unavailable.`);
  if (fs.realpathSync.native(target).toLowerCase() !== target.toLowerCase()) stop(`wallet file ${name} is linked.`);
  return fs.readFileSync(target);
}

async function readStandardInput() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 8192) stop('standard input is too large.');
    chunks.push(chunk);
  }
  let parsed;
  try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { stop('standard input must be one JSON object.'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.keys(parsed).length !== 1 ||
      typeof parsed.apiKey !== 'string' || !parsed.apiKey || parsed.apiKey.length > 4096 || /[^\x21-\x7e]/.test(parsed.apiKey)) {
    stop('standard input must contain only the API key field.');
  }
  return parsed.apiKey;
}

function writeFileAtomic(file, text) {
  const temporary = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, text, { flag: 'w' });
  fs.renameSync(temporary, file);
}

async function main() {
  const settings = parseArguments(process.argv.slice(2));
  // The signer serves only the code identity the run was approved for. A
  // different identity on disk at startup stops here, before any key is read.
  if (settings.codeIdentitySha256 !== PROCESS_CODE_IDENTITY_SHA256) {
    stop(`the code identity on disk (${PROCESS_CODE_IDENTITY_SHA256}) is not the approved one (${settings.codeIdentitySha256}).`);
  }
  const proposal = loadLiveProposal();
  let approval;
  try {
    const stat = fs.statSync(settings.approvalFile);
    if (!stat.isFile() || stat.size > 1024 * 1024) throw new Error('size');
    approval = JSON.parse(fs.readFileSync(settings.approvalFile, 'utf8'));
  } catch { stop('the run approval file could not be read.'); }
  const apiKey = await readStandardInput();

  const unlock = readWalletFile(settings.walletDirectory, WALLET_FILES.unlock, 32);
  if (unlock.length !== 32) stop('the unlock file must contain exactly 32 bytes.');
  const keys = {};
  try {
    for (const role of ['owner', 'agent']) {
      const encrypted = readWalletFile(settings.walletDirectory, WALLET_FILES[role], MAX_KEYSTORE_BYTES).toString('utf8');
      let wallet;
      try { wallet = await ethers.Wallet.fromEncryptedJson(encrypted, unlock); }
      catch { stop(`the ${role} keystore could not be decrypted.`); }
      keys[role] = new ethers.SigningKey(wallet.privateKey);
    }
  } finally {
    unlock.fill(0);
  }

  const liveDirectory = path.join(settings.dataDirectory, 'live');
  fs.mkdirSync(liveDirectory, { recursive: true });
  let signer;
  try {
    signer = new LiveSigner({
      proposal, approval, approvalSha256: settings.approvalSha256, codeIdentitySha256: settings.codeIdentitySha256, keys,
      stateDirectory: path.join(liveDirectory, 'signer'), credential: apiKey
    });
  } catch (error) {
    stop(error instanceof LiveSignerError ? `configuration rejected with ${error.code}.` : 'configuration rejected.');
  }

  const tokens = { owner: randomBytes(32).toString('hex'), agent: randomBytes(32).toString('hex') };
  // The request handler lives in src/live-signer-http.mjs so it can be tested
  // with an injected signer and no key. Inside its serialized queue, right
  // before every prepare, sign and send, it compares the approved code identity
  // with this process and with the files on disk at that moment (R2-F05).
  const server = http.createServer(createSignerRequestHandler({
    signer, roleFor: createRoleResolver(tokens), port: () => server.address().port,
    identity: { approved: settings.codeIdentitySha256, process: PROCESS_CODE_IDENTITY_SHA256 }
  }));
  server.requestTimeout = 120_000;
  server.headersTimeout = 10_000;

  const endpointFile = path.join(liveDirectory, 'signer-endpoint.json');
  const tokenFiles = { owner: path.join(liveDirectory, 'signer-owner.token'), agent: path.join(liveDirectory, 'signer-agent.token') };
  const cleanup = () => {
    for (const file of [endpointFile, tokenFiles.owner, tokenFiles.agent]) {
      try { fs.unlinkSync(file); } catch { /* already absent */ }
    }
  };
  server.listen(0, '127.0.0.1', () => {
    const port = server.address().port;
    writeFileAtomic(tokenFiles.owner, tokens.owner);
    writeFileAtomic(tokenFiles.agent, tokens.agent);
    writeFileAtomic(endpointFile, JSON.stringify({
      schemaVersion: 1, kind: 'mandate-desk-live-signer-endpoint', port, pid: process.pid,
      approvalSha256: signer.approval.approvalSha256, codeIdentitySha256: signer.codeIdentitySha256, notAfter: signer.approval.notAfter,
      startedAt: new Date().toISOString()
    }, null, 2));
    console.log('Mandate Desk live signer is ready.');
    console.log(`Run approval: ${signer.approval.approvalSha256}`);
    console.log(`Code identity: ${signer.codeIdentitySha256}`);
    console.log(`Approval valid until: ${signer.approval.notAfter}`);
    console.log(`Owner address: ${proposal.principal}`);
    console.log(`Agent address: ${proposal.agent}`);
    console.log('Keep this window open during the run. Press Ctrl+C to stop the signer.');
  });
  for (const event of ['SIGINT', 'SIGTERM']) {
    process.on(event, () => {
      cleanup();
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 2000).unref();
    });
  }
  process.on('exit', cleanup);
}

main().catch(() => stop('an unexpected startup error occurred.'));
