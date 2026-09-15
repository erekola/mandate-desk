// Deterministic in-memory Ethereum Sepolia stand-in for the live adapter and
// workspace tests. It models only what a Mandate Desk run touches: the
// dedicated executor's action table, the RAMS mandate registry, one ERC-20
// token, account nonces and balances, blocks with a state snapshot per block
// hash, a mempool, receipts with event logs and reorganisations. The signer
// gateway applies the real signer policy (authorize*) and signs with public
// Hardhat test keys; the test verifier keeps every decoded field of the real
// bytes and only substitutes the intended sender, because a synthetic key can
// never produce the pinned principal or agent address.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as plan from '../src/brickken-live-plan.mjs';
import { TRANSFER_FROM_ACTION } from '../src/brickken-intent.mjs';
import { EVENT_TOPICS } from '../src/brickken-postcheck.mjs';
import { SepoliaRpcError } from '../src/brickken-rpc.mjs';
import { LiveAdapterError } from '../src/brickken-live-adapter.mjs';
import { parseRamsPrepareResponse } from '../src/brickken-prepare.mjs';
import { PROCESS_CODE_IDENTITY_SHA256 } from '../src/code-identity.mjs';
import {
  LiveSignerError,
  authorizePrepare,
  authorizeSend,
  authorizeSign,
  decodeSignedLiveTransaction,
  signLiveTransaction
} from '../src/brickken-live-signer.mjs';

const require = createRequire(import.meta.url);
const ethers = require('../vendor/ethers-6.17.0/ethers.umd.min.cjs');
const HERE = path.dirname(fileURLToPath(import.meta.url));
const CODE = JSON.parse(fs.readFileSync(path.join(HERE, 'fixtures', 'sepolia-live-code.json'), 'utf8'));

// Public Hardhat development keys. They hold nothing on Sepolia for this project.
export const TEST_KEYS = Object.freeze({
  owner: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
  agent: '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d'
});
export const GWEI = 1_000_000_000n;
const ZERO = '0x' + '0'.repeat(40);
const GAS = Object.freeze({ a4a22854: 47_178n, '095ea7b3': 56_228n, c6a4ad00: 281_611n, '1cff79cd': 150_000n, '5e20639e': 40_000n });

const word = value => BigInt(value).toString(16).padStart(64, '0');
const addressWord = value => '0'.repeat(24) + value.slice(2).toLowerCase();
const argument = (data, index) => data.slice(10 + index * 64, 10 + (index + 1) * 64);
const argumentAddress = (data, index) => '0x' + argument(data, index).slice(24);
const argumentUint = (data, index) => BigInt('0x' + argument(data, index));
const fakeHash = (...parts) => '0x' + createHash('sha256').update(parts.join(':')).digest('hex');

class Revert {
  constructor(data) { this.data = data; }
}
const revert = (selector, words = []) => { throw new Revert(selector + words.join('')); };

export function createClock(start = '2026-09-15T08:00:00.000Z') {
  return { ms: Date.parse(start) };
}

export class FakeSepolia {
  constructor({
    proposal, clock, startBlock = 11_704_475, baseFeePerGas = 1_200_000_000n,
    principalWei = 50_000_000_000_000_000n, agentWei = 20_000_000_000_000_000n,
    principalToken = 20_000_000n, recipientToken = 3_100n, actionConfigured = false
  }) {
    this.p = proposal;
    this.clock = clock;
    this.baseFeePerGas = baseFeePerGas;
    this.state = {
      eth: { [proposal.principal]: principalWei, [proposal.agent]: agentWei },
      nonce: { [proposal.principal]: 0, [proposal.agent]: 0 },
      token: { [proposal.principal]: principalToken, [proposal.recipient.address]: recipientToken },
      allowance: 0n,
      action: actionConfigured ? { supported: true, hasAmount: true, amountIndex: 2 } : { supported: false, hasAmount: false, amountIndex: 0 },
      mandate: null,
      actionEnabled: false,
      frozen: false
    };
    this.generation = 0;
    this.logIndex = 0;
    this.mempool = [];
    this.transactions = new Map();
    this.signed = new Map();
    this.blocks = [{
      number: startBlock, hash: fakeHash('block', startBlock, 0), parentHash: fakeHash('block', startBlock - 1, 0),
      timestamp: Math.floor(clock.ms / 1000), baseFeePerGas, state: structuredClone(this.state), txHashes: []
    }];
  }

  latest() { return this.blocks.at(-1); }

  advanceTo(milliseconds) {
    while (Math.floor(milliseconds / 1000) >= this.latest().timestamp + 12) this.mine();
  }

  // Moves the chain clock far ahead with a single block, for approval-expiry
  // tests that would otherwise mine tens of thousands of blocks.
  jumpTo(milliseconds) {
    const seconds = Math.floor(milliseconds / 1000);
    if (seconds <= this.latest().timestamp + 12) return this.advanceTo(milliseconds);
    this.latest().timestamp = seconds - 12;
    this.mine();
  }

  register(bytes, tx, hash) { this.signed.set(bytes, { tx, hash }); }

  accept(bytes) {
    const entry = this.signed.get(bytes);
    if (!entry) throw new SepoliaRpcError('RPC_REJECTED', 'eth_sendRawTransaction');
    if (this.transactions.has(entry.hash) || this.mempool.some(item => item.hash === entry.hash)) {
      throw new SepoliaRpcError('ALREADY_KNOWN', 'eth_sendRawTransaction');
    }
    if (BigInt(entry.tx.nonce) < BigInt(this.state.nonce[entry.tx.from] ?? 0)) {
      throw new SepoliaRpcError('NONCE_TOO_LOW', 'eth_sendRawTransaction');
    }
    this.mempool.push({ hash: entry.hash, bytes, tx: entry.tx });
    return entry.hash;
  }

  // Mines one block, including mempool transactions in nonce order.
  mine() {
    const parent = this.latest();
    const number = parent.number + 1;
    const timestamp = parent.timestamp + 12;
    const hash = fakeHash('block', number, this.generation);
    const txHashes = [];
    let progressed = true;
    while (progressed) {
      progressed = false;
      for (const entry of [...this.mempool]) {
        if (entry.tx.nonce !== String(this.state.nonce[entry.tx.from] ?? 0)) continue;
        this.mempool.splice(this.mempool.indexOf(entry), 1);
        const before = structuredClone(this.state);
        let logs = [];
        let status = 1;
        try { logs = this.#execute(entry.tx, timestamp); }
        catch (error) {
          if (!(error instanceof Revert)) throw error;
          this.state = before;
          status = 0;
        }
        const selector = entry.tx.data.slice(2, 10);
        const gasUsed = GAS[selector] ?? 50_000n;
        const effectiveGasPrice = this.baseFeePerGas + BigInt(entry.tx.maxPriorityFeePerGas);
        this.state.nonce[entry.tx.from] = (this.state.nonce[entry.tx.from] ?? 0) + 1;
        this.state.eth[entry.tx.from] = (this.state.eth[entry.tx.from] ?? 0n) - gasUsed * effectiveGasPrice;
        const receipt = {
          transactionHash: entry.hash, status, from: entry.tx.from, to: entry.tx.to,
          blockNumber: String(number), blockHash: hash, gasUsed: gasUsed.toString(), effectiveGasPrice: effectiveGasPrice.toString(),
          logs: logs.map(log => ({
            address: log.address, topics: log.topics, data: log.data, transactionHash: entry.hash,
            blockNumber: String(number), blockHash: hash, logIndex: String(this.logIndex++), removed: false
          }))
        };
        this.transactions.set(entry.hash, { tx: entry.tx, bytes: entry.bytes, blockNumber: number, blockHash: hash, receipt });
        txHashes.push(entry.hash);
        progressed = true;
      }
    }
    this.blocks.push({ number, hash, parentHash: parent.hash, timestamp, baseFeePerGas: this.baseFeePerGas, state: structuredClone(this.state), txHashes });
  }

  // Replaces the last `depth` blocks with new hashes; their transactions return
  // to the mempool and are mined again in the replacement blocks.
  reorg(depth = 1) {
    const removed = this.blocks.splice(this.blocks.length - depth, depth);
    this.state = structuredClone(this.latest().state);
    this.generation += 1;
    for (const block of removed) {
      for (const hash of block.txHashes) {
        const entry = this.transactions.get(hash);
        this.transactions.delete(hash);
        this.mempool.push({ hash, bytes: entry.bytes, tx: entry.tx });
      }
    }
    for (let index = 0; index < depth; index++) this.mine();
  }

  canExecute(state, agent, principal, asset, action, amount, timestamp) {
    const m = state.mandate;
    return Boolean(m) && m.agent === agent && m.principal === principal && m.asset === asset && m.revoked === false &&
      BigInt(m.validFrom) <= BigInt(timestamp) && BigInt(timestamp) < BigInt(m.validUntil) &&
      state.actionEnabled === true && action === TRANSFER_FROM_ACTION && state.frozen === false &&
      amount <= BigInt(m.maxTransactionValue) && BigInt(m.cumulativeUsed) + amount <= BigInt(m.maxCumulativeValue);
  }

  #execute(tx, timestamp) {
    const p = this.p;
    const selector = tx.data.slice(0, 10);
    const logs = [];
    if (tx.to === p.executor && selector === '0xa4a22854') {
      if (tx.from !== p.principal) revert('0x118cdaa7', [addressWord(tx.from)]);
      if (argument(tx.data, 0) !== '23b872dd' + '0'.repeat(56)) revert('0x');
      this.state.action = { supported: argumentUint(tx.data, 1) === 1n, hasAmount: argumentUint(tx.data, 2) === 1n, amountIndex: Number(argumentUint(tx.data, 3)) };
      return logs;
    }
    if (tx.to === p.token.address && selector === '0x095ea7b3') {
      if (argumentAddress(tx.data, 0) !== p.executor || tx.from !== p.principal) revert('0x');
      const amount = argumentUint(tx.data, 1);
      this.state.allowance = amount;
      logs.push({ address: p.token.address, topics: [EVENT_TOPICS.Approval, '0x' + addressWord(tx.from), '0x' + addressWord(p.executor)], data: '0x' + word(amount) });
      return logs;
    }
    if (tx.to === p.registry && selector === '0xc6a4ad00') {
      const d = tx.data;
      const m = {
        agent: argumentAddress(d, 2), validFrom: argumentUint(d, 3).toString(), validUntil: argumentUint(d, 4).toString(),
        principal: argumentAddress(d, 5), revoked: false, complianceProvider: argumentAddress(d, 6), identityRef: '0x' + argument(d, 7),
        asset: argumentAddress(d, 8), maxTransactionValue: argumentUint(d, 9).toString(), maxCumulativeValue: argumentUint(d, 10).toString(),
        cumulativeUsed: '0', metadata: '0x' + argument(d, 11)
      };
      if (tx.from !== m.principal) revert('0x789a70b0');
      const current = this.state.mandate;
      if (current && !current.revoked && BigInt(timestamp) < BigInt(current.validUntil)) revert('0x8f2d3ce4');
      if (BigInt(m.validUntil) <= BigInt(timestamp)) revert('0xd36c8500');
      this.state.mandate = m;
      this.state.actionEnabled = '0x' + argument(d, 15) === TRANSFER_FROM_ACTION;
      logs.push({
        address: p.registry, topics: [EVENT_TOPICS.MandateGranted, '0x' + addressWord(m.agent), '0x' + addressWord(m.principal)],
        data: '0x' + addressWord(m.complianceProvider) + addressWord(m.asset) + word(m.validFrom) + word(m.validUntil) + m.metadata.slice(2)
      });
      logs.push({ address: p.registry, topics: [EVENT_TOPICS.ActionEnabled, '0x' + addressWord(m.agent), '0x' + addressWord(m.principal), TRANSFER_FROM_ACTION], data: '0x' });
      return logs;
    }
    if (tx.to === p.registry && selector === '0x5e20639e') {
      const m = this.state.mandate;
      if (tx.from !== p.principal) revert('0xea8e4eb5');
      if (!m || m.revoked) revert('0xfc316461');
      m.revoked = true;
      logs.push({ address: p.registry, topics: [EVENT_TOPICS.MandateRevoked, '0x' + addressWord(m.agent), '0x' + addressWord(m.principal)], data: '0x' + addressWord(tx.from) });
      return logs;
    }
    if (tx.to === p.executor && selector === '0x1cff79cd') {
      const target = argumentAddress(tx.data, 0);
      const length = Number(argumentUint(tx.data, 2));
      const inner = tx.data.slice(10 + 64 * 3, 10 + 64 * 3 + length * 2);
      const innerSelector = inner.slice(0, 8);
      if (innerSelector !== '23b872dd' || !this.state.action.supported) revert('0x8c91850f', [innerSelector + '0'.repeat(56)]);
      const amount = this.state.action.hasAmount ? BigInt('0x' + inner.slice(8 + this.state.action.amountIndex * 64, 8 + (this.state.action.amountIndex + 1) * 64)) : 0n;
      if (!this.canExecute(this.state, tx.from, p.principal, target, TRANSFER_FROM_ACTION, amount, timestamp)) {
        revert('0x0aae0b09', [addressWord(tx.from), addressWord(target), innerSelector + '0'.repeat(56), word(amount)]);
      }
      const m = this.state.mandate;
      m.cumulativeUsed = (BigInt(m.cumulativeUsed) + amount).toString();
      logs.push({
        address: p.registry, topics: [EVENT_TOPICS.ExecutionRecorded, '0x' + addressWord(tx.from), '0x' + addressWord(p.principal), TRANSFER_FROM_ACTION],
        data: '0x' + word(amount) + word(m.cumulativeUsed)
      });
      const from = '0x' + inner.slice(8 + 24, 8 + 64);
      const to = '0x' + inner.slice(8 + 64 + 24, 8 + 128);
      const value = BigInt('0x' + inner.slice(8 + 128, 8 + 192));
      if (target !== p.token.address || this.state.allowance < value || (this.state.token[from] ?? 0n) < value) revert('0xa5fa8d2b', [word(32), word(0)]);
      this.state.allowance -= value;
      this.state.token[from] -= value;
      this.state.token[to] = (this.state.token[to] ?? 0n) + value;
      logs.push({ address: p.token.address, topics: [EVENT_TOPICS.Transfer, '0x' + addressWord(from), '0x' + addressWord(to)], data: '0x' + word(value) });
      return logs;
    }
    return revert('0x');
  }

  view(block, { from, to, data }) {
    const p = this.p;
    const s = block.state;
    const selector = data.slice(0, 10);
    const bool = value => '0x' + word(value ? 1 : 0);
    if (to === p.registry) {
      if (selector === '0xf80ba00f') {
        return bool(this.canExecute(s, argumentAddress(data, 0), argumentAddress(data, 1), argumentAddress(data, 2), '0x' + argument(data, 3), argumentUint(data, 4), block.timestamp));
      }
      if (selector === '0xc5e98345') {
        const m = s.mandate;
        if (!m) return '0x' + '0'.repeat(64 * 12);
        return '0x' + addressWord(m.agent) + word(m.validFrom) + word(m.validUntil) + addressWord(m.principal) + word(m.revoked ? 1 : 0) +
          addressWord(m.complianceProvider) + m.identityRef.slice(2) + addressWord(m.asset) + word(m.maxTransactionValue) +
          word(m.maxCumulativeValue) + word(m.cumulativeUsed) + m.metadata.slice(2);
      }
      if (selector === '0x0c53b010') return bool(Boolean(s.mandate) && s.actionEnabled && argumentAddress(data, 0) === s.mandate.agent);
      if (selector === '0xe5839836') return bool(s.frozen);
      if (selector === '0x91d14854') return bool('0x' + argument(data, 0) === plan.RECORDER_ROLE && argumentAddress(data, 1) === p.executor);
    }
    if (to === p.executor) {
      if (selector === '0x7b37e5f4') return '0x' + word(s.action.supported ? 1 : 0) + word(s.action.hasAmount ? 1 : 0) + word(s.action.amountIndex);
      if (selector === '0xd47cf1ac') return '0x' + addressWord(p.registry);
      if (selector === '0xba5d3078' || selector === '0x8da5cb5b') return '0x' + addressWord(p.principal);
    }
    if (to === p.token.address) {
      if (selector === '0x70a08231') return '0x' + word(s.token[argumentAddress(data, 0)] ?? 0n);
      if (selector === '0xdd62ed3e') return '0x' + word(argumentAddress(data, 0) === p.principal && argumentAddress(data, 1) === p.executor ? s.allowance : 0n);
      if (selector === '0x313ce567') return '0x' + word(6);
    }
    // Anything else is simulated as a transaction on a copy of the block state.
    const saved = this.state;
    this.state = structuredClone(s);
    try {
      this.#execute({ from: from ?? ZERO, to, data }, block.timestamp);
      return '0x' + word(32) + word(32) + word(1);
    } finally {
      this.state = saved;
    }
  }
}

export class FakeRpc {
  // faults.viewOverride(block, input, returnData) may replace one eth_call
  // result on this source only; faults.hideBlock(block) makes this source
  // answer null for that block, as a refusing or lagging endpoint would;
  // faults.tipBlock freezes this source's tip at that block number, as a
  // stalled endpoint would, so its depth readings stop growing.
  constructor(chain, endpointName, faults = {}) {
    this.chain = chain;
    this.endpointName = endpointName;
    this.faults = { lagBlocks: 0, sendErrors: [], forgeReceipt: null, viewOverride: null, hideBlock: null, tipBlock: null, logsError: null, ...faults };
  }

  #visible() {
    let blocks = this.chain.blocks.slice(0, this.chain.blocks.length - this.faults.lagBlocks);
    if (this.faults.tipBlock !== null) blocks = blocks.filter(block => block.number <= this.faults.tipBlock);
    return this.faults.hideBlock ? blocks.filter(block => !this.faults.hideBlock(block)) : blocks;
  }

  #block(ref) {
    const blocks = this.#visible();
    if (ref === 'latest') return blocks.at(-1);
    if (ref === 'finalized' || ref === 'safe') return blocks.find(block => block.number === blocks.at(-1).number - 32) ?? blocks[0];
    if (ref && typeof ref === 'object' && ref.blockNumber !== undefined) return blocks.find(block => String(block.number) === ref.blockNumber) ?? null;
    if (ref && typeof ref === 'object' && ref.blockHash !== undefined) return blocks.find(block => block.hash === ref.blockHash) ?? null;
    return null;
  }

  #state(ref) {
    const block = this.#block(ref);
    if (!block) throw new SepoliaRpcError('RPC_ERROR', 'block');
    return block;
  }

  async chainId() { return '11155111'; }
  async blockNumber() { return String(this.#visible().at(-1).number); }
  async maxPriorityFeePerGas() { return '1000000'; }

  async getBlock(ref) {
    const block = this.#block(ref);
    return block ? { number: String(block.number), hash: block.hash, parentHash: block.parentHash, timestamp: String(block.timestamp), baseFeePerGas: block.baseFeePerGas.toString() } : null;
  }

  async getTransactionCount(address, ref) {
    if (ref === 'pending') {
      return String((this.chain.state.nonce[address] ?? 0) + this.chain.mempool.filter(item => item.tx.from === address).length);
    }
    return String(this.#state(ref).state.nonce[address] ?? 0);
  }

  async getBalance(address, ref) { return (this.#state(ref).state.eth[address] ?? 0n).toString(); }

  async getCode(address, ref) {
    this.#state(ref);
    const entry = Object.values(CODE.code).find(item => item.address === address);
    return entry ? entry.hex : '0x';
  }

  async call(input, ref) {
    const block = this.#state(ref);
    try {
      const returnData = this.chain.view(block, input);
      return { ok: true, returnData: this.faults.viewOverride ? this.faults.viewOverride(block, input, returnData) : returnData };
    } catch (error) {
      if (error instanceof Revert) return { ok: false, revertData: error.data.length > 2 ? error.data : null };
      throw error;
    }
  }

  async estimateGas(input) {
    const latest = this.#visible().at(-1);
    const next = { ...latest, timestamp: latest.timestamp + 12 };
    try { this.chain.view(next, input); }
    catch (error) {
      if (error instanceof Revert) throw new SepoliaRpcError('ESTIMATE_REVERTED', 'eth_estimateGas');
      throw error;
    }
    return (GAS[input.data.slice(2, 10)] ?? 50_000n).toString();
  }

  async getTransactionByHash(hash) {
    const pending = this.chain.mempool.find(item => item.hash === hash);
    const mined = this.chain.transactions.get(hash);
    const entry = pending ?? mined;
    if (!entry) return null;
    const visible = mined && this.#visible().some(block => block.hash === mined.blockHash);
    const tx = entry.tx;
    return {
      hash, from: tx.from, to: tx.to, nonce: tx.nonce, value: tx.value, data: tx.data, type: 2, chainId: tx.chainId,
      gasLimit: tx.gasLimit, maxFeePerGas: tx.maxFeePerGas, maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
      blockNumber: visible ? String(mined.blockNumber) : null, blockHash: visible ? mined.blockHash : null
    };
  }

  async getTransactionReceipt(hash) {
    const mined = this.chain.transactions.get(hash);
    if (!mined || !this.#visible().some(block => block.hash === mined.blockHash)) return null;
    const receipt = structuredClone(mined.receipt);
    return this.faults.forgeReceipt ? this.faults.forgeReceipt(receipt) : receipt;
  }

  // Event query over this source's visible blocks, the same filter shape as
  // SepoliaRpc.getLogs: one address, exact topics with null wildcards, an
  // inclusive block range. faults.logsError makes the query fail as a source
  // without the method would.
  async getLogs({ address, topics, fromBlock, toBlock }) {
    if (this.faults.logsError) throw new SepoliaRpcError(this.faults.logsError, 'eth_getLogs');
    const logs = [];
    for (const block of this.#visible()) {
      if (BigInt(block.number) < BigInt(fromBlock) || BigInt(block.number) > BigInt(toBlock)) continue;
      for (const hash of block.txHashes) {
        const mined = this.chain.transactions.get(hash);
        if (!mined) continue;
        for (const log of mined.receipt.logs) {
          if (log.address !== address) continue;
          if (topics.some((topic, index) => topic !== null && log.topics[index] !== topic)) continue;
          logs.push(structuredClone(log));
        }
      }
    }
    return logs;
  }

  async sendRawTransaction(bytes) {
    const fault = this.faults.sendErrors.shift();
    if (fault === 'TIMEOUT_ACCEPTED') {
      this.chain.accept(bytes);
      throw new SepoliaRpcError('RPC_TIMEOUT', 'eth_sendRawTransaction');
    }
    if (fault) throw new SepoliaRpcError(fault, 'eth_sendRawTransaction');
    return this.chain.accept(bytes);
  }
}

const BRICKKEN_CODES = new Set(['PAYMENT_REQUIRED', 'AUTHORIZATION_DENIED', 'RATE_LIMITED', 'HTTP_REJECTED', 'HTTP_TIMEOUT', 'NETWORK_FAILED', 'PREPARATION_REJECTED']);

// A Brickken-like gateway with the real signer policy. Faults are queued per
// method: prepare accepts PAYMENT_REQUIRED, SIGNER_NOT_WHITELISTED, WRONG_RECIPIENT
// and HIGH_FEE; send accepts TIMEOUT_ACCEPTED, TIMEOUT_DROPPED, REJECT_400 and
// WRONG_RELAY_HASH.
export class FakeSignerGateway {
  constructor({ chain, proposal, clock }) {
    this.chain = chain;
    this.proposal = proposal;
    this.clock = clock;
    this.approval = null;
    this.entries = [];
    this.faults = { prepare: [], send: [] };
    this.keys = { owner: new ethers.SigningKey(TEST_KEYS.owner), agent: new ethers.SigningKey(TEST_KEYS.agent) };
    this.counter = 0;
    // The identity the fake signer reports: this process's by default, as a real
    // signer started from the same tree would; a test may set another value.
    this.codeIdentitySha256 = PROCESS_CODE_IDENTITY_SHA256;
    this.verify = bytes => {
      const entry = this.chain.signed.get(bytes);
      if (!entry) throw new Error('unknown bytes');
      const decoded = decodeSignedLiveTransaction(bytes);
      return { transactionHash: decoded.transactionHash, transaction: { ...decoded.transaction, from: entry.tx.from } };
    };
  }

  setApproval(approval) { this.approval = approval; }

  #wrap(work) {
    try { return work(); }
    catch (error) {
      if (error instanceof LiveSignerError) {
        throw new LiveAdapterError(error.code, { layer: BRICKKEN_CODES.has(error.code) ? 'brickken-api' : 'signer', ...(error.details ?? {}) });
      }
      throw error;
    }
  }

  client(role) {
    const gateway = this;
    const context = request => ({ proposal: gateway.proposal, approval: gateway.approval, entries: gateway.entries, request, nowMs: gateway.clock.ms });
    const record = entry => gateway.entries.push({ at: new Date(gateway.clock.ms).toISOString(), role, ...entry });
    return {
      role,
      approvalSha256: () => gateway.approval?.approvalSha256 ?? null,
      async status() {
        if (!gateway.approval) throw new LiveAdapterError('SIGNER_UNAVAILABLE', { layer: 'signer' });
        return {
          role, approvalSha256: gateway.approval.approvalSha256, codeIdentitySha256: gateway.codeIdentitySha256, notAfter: gateway.approval.notAfter,
          active: gateway.clock.ms >= Date.parse(gateway.approval.createdAt) && gateway.clock.ms < Date.parse(gateway.approval.notAfter),
          signed: gateway.entries.filter(entry => entry.type === 'signed').map(entry => ({ step: entry.step }))
        };
      },
      async prepare(step, body) {
        const normalized = gateway.#wrap(() => authorizePrepare(context({ role, step, body })));
        record({ type: 'prepare-attempt', step });
        const fault = gateway.faults.prepare.shift();
        if (fault === 'PAYMENT_REQUIRED') throw new LiveAdapterError('PAYMENT_REQUIRED', { layer: 'brickken-api', status: 402 });
        if (fault === 'SIGNER_NOT_WHITELISTED') throw new LiveAdapterError('HTTP_REJECTED', { layer: 'brickken-api', status: 400, apiErrorCode: 'SIGNER_NOT_WHITELISTED' });
        const p = gateway.proposal;
        let data = plan.expectedCalldata(p, step, step === 'grant' ? { validFrom: normalized.validFrom } : {});
        if (fault === 'WRONG_RECIPIENT') data = data.replace(p.recipient.address.slice(2), '9'.repeat(40));
        const base = gateway.chain.latest().baseFeePerGas;
        const big = value => ({ type: 'BigNumber', hex: '0x' + BigInt(value).toString(16) });
        const transaction = {
          from: plan.stepSignerAddress(p, step), to: plan.stepTarget(p, step), data, value: big(0), nonce: normalized.nonce,
          chainId: 11155111, gasLimit: big(normalized.gasLimit), maxPriorityFeePerGas: big(GWEI),
          maxFeePerGas: big(fault === 'HIGH_FEE' ? 31n * GWEI : 2n * base + GWEI), type: 2
        };
        const txId = `fake_prepare_${++gateway.counter}`;
        // The documented response carries an x402Requirements quote beside the transaction; the fake sends one so every live test reads it as data.
        const x402Requirements = { scheme: 'exact', network: 'eip155:84532', asset: 'USDC', maxAmountRequired: '250000', payTo: '0x' + '55'.repeat(20), note: 'fake quote, never paid' };
        const responseText = JSON.stringify({ data: { transactions: transaction, txId, info: { contractAddress: transaction.to, mode: 'direct' }, x402Requirements } });
        try {
          const parsed = parseRamsPrepareResponse(responseText);
          plan.checkLiveTransaction(p, step, parsed.transaction, { nonce: String(normalized.nonce) });
          record({ type: 'prepared', step, txId, transaction: parsed.transaction });
        } catch (error) {
          record({ type: 'prepare-rejected', step, code: String(error.code) });
          throw new LiveAdapterError(String(error.code), { layer: 'signer' });
        }
        return responseText;
      },
      async sign(step, transaction) {
        const { transaction: tx, repeated } = gateway.#wrap(() => authorizeSign(context({ role, step, transaction })));
        if (repeated) return { signedTransaction: repeated.signedTransaction, transactionHash: repeated.transactionHash, repeated: true };
        const signed = signLiveTransaction(tx, gateway.keys[role]);
        gateway.chain.register(signed.signedTransaction, tx, signed.transactionHash);
        record({ type: 'signed', step, transaction: tx, signedTransaction: signed.signedTransaction, transactionHash: signed.transactionHash });
        return { signedTransaction: signed.signedTransaction, transactionHash: signed.transactionHash, repeated: false };
      },
      async send(step, txId, signedTransaction) {
        const signed = gateway.#wrap(() => authorizeSend({ approval: gateway.approval, entries: gateway.entries, request: { role, step, txId, signedTransaction }, nowMs: gateway.clock.ms }));
        record({ type: 'send-attempt', step });
        const fault = gateway.faults.send.shift();
        if (fault === 'TIMEOUT_DROPPED') throw new LiveAdapterError('SIGNER_TIMEOUT', { layer: 'signer' });
        if (fault === 'REJECT_400') throw new LiveAdapterError('HTTP_REJECTED', { layer: 'brickken-api', status: 400, apiErrorCode: 'INVALID_SIGNATURE' });
        let hash;
        try { hash = gateway.chain.accept(signed.signedTransaction); }
        catch (error) {
          if (error?.code !== 'ALREADY_KNOWN') throw new LiveAdapterError('HTTP_REJECTED', { layer: 'brickken-api', status: 400, apiErrorCode: null });
          hash = signed.transactionHash;
        }
        if (fault === 'TIMEOUT_ACCEPTED') throw new LiveAdapterError('SIGNER_TIMEOUT', { layer: 'signer' });
        record({ type: 'send-accepted', step, relayTransactionHash: hash });
        return { relayTransactionHash: fault === 'WRONG_RELAY_HASH' ? '0x' + 'e'.repeat(64) : hash, status: 'pending', transactionHash: hash };
      },
      async transactionStatus() { return { status: 'pending', transactionHash: null, errorReported: false }; }
    };
  }
}
