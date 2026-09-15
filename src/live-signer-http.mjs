// The loopback HTTP surface of the live signer (tools/live-signer.mjs), kept
// apart from the process that holds the keys so it can be exercised with an
// injected signer and no key. The three write-capable routes (prepare, sign,
// send) run in one serialized queue. Inside that queue, after any wait, and
// right before the signer is asked, the handler compares the code identity the
// signer was started for with the identity of this process and with the files
// on disk at that moment; a difference refuses the request with
// CODE_IDENTITY_MISMATCH and nothing is prepared, signed or sent (R2-F05). The
// status and transaction-status routes are reads and stay available. A disk
// hash is not an attestation of the bytes this process has loaded; the process
// identity covers those as read at startup (src/code-identity.mjs).
import { timingSafeEqual } from 'node:crypto';
import { LiveSignerError } from './brickken-live-signer.mjs';
import { PROCESS_CODE_IDENTITY_SHA256, computeCodeIdentity } from './code-identity.mjs';

export const MAX_SIGNER_REQUEST_BYTES = 64 * 1024;
export const SIGNER_WRITE_ROUTES = Object.freeze({ '/v1/prepare': 'prepare', '/v1/sign': 'sign', '/v1/send': 'send' });
const ROLES = Object.freeze(['owner', 'agent']);

function fail(code, details) { throw new LiveSignerError(code, details); }

// Maps a bearer header to the role whose token it carries, in constant time
// per token, or to null.
export function createRoleResolver(tokens) {
  for (const role of ROLES) {
    if (typeof tokens?.[role] !== 'string' || !/^[a-f0-9]{64}$/.test(tokens[role])) fail('CONFIGURATION');
  }
  return header => {
    const match = /^Bearer ([a-f0-9]{64})$/.exec(header ?? '');
    if (!match) return null;
    const presented = Buffer.from(match[1]);
    for (const role of ROLES) {
      const expected = Buffer.from(tokens[role]);
      if (presented.length === expected.length && timingSafeEqual(presented, expected)) return role;
    }
    return null;
  };
}

// signer: an object with status(), prepare(), sign(), send() and
// transactionStatus(); roleFor: the resolver above; port: a function returning
// the listening port; identity.approved: the code identity the signer was
// started for; identity.process and identity.disk default to this process's
// identity and a fresh reading of the covered files.
export function createSignerRequestHandler({ signer, roleFor, port, identity, maxRequestBytes = MAX_SIGNER_REQUEST_BYTES }) {
  for (const method of ['status', 'prepare', 'sign', 'send', 'transactionStatus']) {
    if (typeof signer?.[method] !== 'function') fail('CONFIGURATION', { method });
  }
  if (typeof roleFor !== 'function' || typeof port !== 'function') fail('CONFIGURATION');
  const approved = identity?.approved;
  if (typeof approved !== 'string' || !/^[a-f0-9]{64}$/.test(approved)) fail('CONFIGURATION', { field: 'approved' });
  const processIdentity = identity.process ?? PROCESS_CODE_IDENTITY_SHA256;
  const disk = identity.disk ?? (() => computeCodeIdentity().codeIdentitySha256);
  if (typeof disk !== 'function') fail('CONFIGURATION', { field: 'disk' });
  if (!Number.isSafeInteger(maxRequestBytes) || maxRequestBytes <= 0) fail('CONFIGURATION', { field: 'maxRequestBytes' });

  let queue = Promise.resolve();
  const serialized = work => {
    const run = queue.then(work, work);
    queue = run.catch(() => undefined);
    return run;
  };
  const requireCodeIdentity = route => {
    let current;
    try { current = disk(); }
    catch (error) {
      fail('CODE_IDENTITY_MISMATCH', { route, reason: error?.code ?? 'CODE_IDENTITY_UNREADABLE', codeIdentitySha256: approved });
    }
    if (current !== approved || processIdentity !== approved) {
      fail('CODE_IDENTITY_MISMATCH', { route, codeIdentitySha256: approved, processCodeIdentitySha256: processIdentity, diskCodeIdentitySha256: current });
    }
  };

  return async (req, res) => {
    const reply = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
      res.end(JSON.stringify(body));
    };
    try {
      if (req.headers.host !== `127.0.0.1:${port()}` || req.headers.origin !== undefined) return reply(403, { error: 'ORIGIN_DENIED' });
      const role = roleFor(req.headers.authorization);
      if (!role) return reply(401, { error: 'TOKEN_DENIED' });
      if (req.method === 'GET' && req.url === '/v1/status') return reply(200, { role, ...signer.status() });
      if (req.method !== 'POST' || !/^application\/json(?:;|$)/i.test(req.headers['content-type'] ?? '')) {
        return reply(405, { error: 'METHOD_DENIED' });
      }
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > maxRequestBytes) return reply(413, { error: 'REQUEST_TOO_LARGE' });
        chunks.push(chunk);
      }
      let input;
      try { input = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return reply(400, { error: 'REQUEST_INVALID' }); }
      if (!input || typeof input !== 'object' || Array.isArray(input)) return reply(400, { error: 'REQUEST_INVALID' });
      const result = await serialized(async () => {
        // The identity is read here, after the queue wait, so a byte that
        // changed while this request waited still refuses it.
        const write = SIGNER_WRITE_ROUTES[req.url];
        if (write) requireCodeIdentity(write);
        switch (req.url) {
          case '/v1/prepare': return signer.prepare({ role, step: input.step, body: input.body });
          case '/v1/sign': return signer.sign({ role, step: input.step, transaction: input.transaction });
          case '/v1/send': return signer.send({ role, step: input.step, txId: input.txId, signedTransaction: input.signedTransaction });
          case '/v1/transaction-status': return signer.transactionStatus({ role, step: input.step });
          default: throw new LiveSignerError('NOT_FOUND');
        }
      });
      return reply(200, result);
    } catch (error) {
      if (error instanceof LiveSignerError) {
        return reply(error.code === 'NOT_FOUND' ? 404 : 409, { error: error.code, ...(error.details === undefined ? {} : { details: error.details }) });
      }
      return reply(500, { error: 'INTERNAL' });
    }
  };
}
