import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { Store, ROOT, boundedPath } from './store.mjs';
import * as domain from './domain.mjs';
import { BrickkenLiveWorkspace, BrickkenWorkspace, BrickkenWorkspaceError } from './brickken-workspace.mjs';
import { saveDemoRecording } from './demo-recording.mjs';

const files = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/app.mjs', ['app.mjs', 'text/javascript; charset=utf-8']],
  ['/style.css', ['style.css', 'text/css; charset=utf-8']],
  ['/copy.json', ['copy.json', 'application/json; charset=utf-8']],
  ['/integration', ['integration.html', 'text/html; charset=utf-8']],
  ['/integration.html', ['integration.html', 'text/html; charset=utf-8']],
  ['/integration.mjs', ['integration.mjs', 'text/javascript; charset=utf-8']],
  ['/integration-copy.json', ['integration-copy.json', 'application/json; charset=utf-8']]
  ,['/demo', ['demo.html', 'text/html; charset=utf-8']]
  ,['/demo.mjs', ['demo.mjs', 'text/javascript; charset=utf-8']]
  ,['/demo-copy.json', ['demo-copy.json', 'application/json; charset=utf-8']]
  ,['/live-demo', ['live-demo.html', 'text/html; charset=utf-8']]
  ,['/live-demo.mjs', ['live-demo.mjs', 'text/javascript; charset=utf-8']]
  ,['/live-demo-copy.json', ['live-demo-copy.json', 'application/json; charset=utf-8']]
]);
export function createApp({ store = new Store(), integrationWorkspace, liveWorkspace = null } = {}) {
  const workspace = integrationWorkspace ?? new BrickkenWorkspace(store.directory);
  // The live Sepolia run exists only when the owner starts the app with --live.
  const live = liveWorkspace;
  const liveState = async () => ({ ...live.view(), signer: await live.signerStatus() });
  const csrf = randomBytes(32).toString('hex');
  const server = http.createServer(async (req, res) => {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const json = (status, body) => {
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(body));
    };
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    if (req.headers.host !== `127.0.0.1:${server.address().port}` ||
        (req.headers.origin && req.headers.origin !== origin) ||
        (req.headers['sec-fetch-site'] && !['same-origin', 'none'].includes(req.headers['sec-fetch-site']))) {
      return json(403, { error: 'ORIGIN_DENIED', message: 'Requests are allowed only from this local app.' });
    }
    try {
      if (req.method === 'GET') {
        if (req.url === '/api/health') return json(200, { app: 'mandate-desk', version: '0.3.0-preview.1', mode: 'simulation', live: live !== null, pid: process.pid, root: ROOT, dataDirectory: store.directory });
        if (req.url === '/api/session') return json(200, { csrf });
        if (req.url === '/api/state') return json(200, store.read());
        if (req.url === '/api/integration/state') return json(200, workspace.read());
        if (req.url === '/api/live/state' || req.url.startsWith('/api/live/approval/')) {
          if (!live) return json(404, { error: 'LIVE_DISABLED', message: 'Start the app with --live to use the Sepolia live run.' });
          if (req.url === '/api/live/state') return json(200, await liveState());
          return json(200, live.approvalDocument(req.url.slice('/api/live/approval/'.length)));
        }
        if (req.url === '/api/export') {
          res.setHeader('Content-Disposition', 'attachment; filename="mandate-desk-demo.json"');
          return json(200, store.read());
        }
        const asset = files.get(req.url);
        if (!asset) return json(404, { error: 'NOT_FOUND', message: 'The page was not found.' });
        const bytes = fs.readFileSync(boundedPath(path.join(ROOT, 'public', asset[0])));
        res.writeHead(200, { 'Content-Type': asset[1] }); return res.end(bytes);
      }
      if (req.method !== 'POST') return json(405, { error: 'METHOD', message: 'The request method is not supported.' });
      if (req.url === '/api/demo-recording') {
        if (req.headers['x-mandate-csrf'] !== csrf || req.headers['content-type'] !== 'video/webm') {
          return json(403, { error: 'SESSION', message: 'Refresh the page before the next action.' });
        }
        return json(200, await saveDemoRecording(req, store.directory));
      }
      if (req.url === '/api/live-recording') {
        if (req.headers['x-mandate-csrf'] !== csrf || req.headers['content-type'] !== 'video/webm') {
          return json(403, { error: 'SESSION', message: 'Refresh the page before the next action.' });
        }
        if (!live) return json(404, { error: 'LIVE_DISABLED', message: 'Start the app with --live to use the Sepolia live run.' });
        // The page names the run; the server binds the recording only to a run whose evidence is complete now.
        const runId = req.headers['x-mandate-live-run'];
        if (typeof runId !== 'string' || !/^live_[a-f0-9]{32}$/.test(runId)) {
          req.resume();
          return json(400, { error: 'RECORDING_RUN_REQUIRED', message: 'Choose the completed live run the recording shows.' });
        }
        let binding;
        try { binding = live.recordingBinding(runId); }
        catch (error) {
          if (!(error instanceof BrickkenWorkspaceError)) throw error;
          req.resume();
          return json(409, { error: error.code, message: error.message, ...(error.details === undefined ? {} : { details: error.details }) });
        }
        return json(200, await saveDemoRecording(req, store.directory, 'live-run-evidence', binding));
      }
      if (req.headers['x-mandate-csrf'] !== csrf || !/^application\/json(?:;|$)/i.test(req.headers['content-type'] ?? '')) {
        return json(403, { error: 'SESSION', message: 'Refresh the page before the next action.' });
      }
      let bytes = 0; const chunks = [];
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 65536) return json(413, { error: 'TOO_LARGE', message: 'The request is too large.' });
        chunks.push(chunk);
      }
      let input;
      try { input = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
      catch { return json(400, { error: 'JSON', message: 'The request structure could not be read.' }); }
      if (req.url.startsWith('/api/integration/')) {
        let result;
        switch (req.url) {
          case '/api/integration/plan':
            domain.strictObject(input, ['operationId']);
            result = workspace.planExecute(input);
            break;
          case '/api/integration/approve':
            domain.strictObject(input, ['operationId', 'previewHash']);
            result = workspace.approve(input);
            break;
          case '/api/integration/preflight':
            domain.strictObject(input, ['operationId']);
            result = workspace.preflight(input);
            break;
          case '/api/integration/execute':
            domain.strictObject(input, ['operationId']);
            result = workspace.executeApproved(input);
            break;
          case '/api/integration/receipt':
            domain.strictObject(input, ['operationId']);
            result = workspace.getReceipt(input);
            break;
          default:
            domain.fail('NOT_FOUND', 'The action was not found.');
        }
        return json(200, { result, state: workspace.read() });
      }
      if (req.url.startsWith('/api/live/')) {
        if (!live) return json(404, { error: 'LIVE_DISABLED', message: 'Start the app with --live to use the Sepolia live run.' });
        let result;
        switch (req.url) {
          case '/api/live/prepare': domain.strictObject(input, []); result = await live.prepareRun(); break;
          case '/api/live/approve': domain.strictObject(input, ['runId', 'approvalSha256']); result = live.approveRun(input); break;
          case '/api/live/start-setup': domain.strictObject(input, ['runId']); result = await live.startOwnerSetup(input); break;
          case '/api/live/start-revocation': domain.strictObject(input, ['runId']); result = await live.startOwnerRevocation(input); break;
          case '/api/live/cleanup': domain.strictObject(input, ['runId']); result = await live.startCleanup(input); break;
          case '/api/live/resume': domain.strictObject(input, ['runId']); result = await live.resumeRun(input); break;
          case '/api/live/finality': domain.strictObject(input, ['runId']); result = await live.refreshFinality(input); break;
          default: domain.fail('NOT_FOUND', 'The action was not found.');
        }
        return json(200, { result, state: await liveState() });
      }
      const result = store.transact(state => {
        switch (req.url) {
          case '/api/plan': return domain.plan(state, input);
          case '/api/preflight': domain.strictObject(input, ['operationId']); return domain.preflight(state, input.operationId);
          case '/api/approve': domain.strictObject(input, ['operationId', 'planHash']); return domain.approve(state, input.operationId, input.planHash);
          case '/api/execute': domain.strictObject(input, ['operationId', 'planHash']); return domain.execute(state, input.operationId, input.planHash);
          case '/api/grant': return domain.grant(state, input);
          case '/api/revoke': domain.strictObject(input, []); return domain.revoke(state);
          case '/api/scenario': domain.strictObject(input, []); return domain.scenario(state);
          default: domain.fail('NOT_FOUND', 'The action was not found.');
        }
      });
      return json(200, { result, state: store.read() });
    } catch (error) {
      if (error instanceof domain.DomainError) return json(error.code === 'STORE_BUSY' ? 409 : 400, { error: error.code, message: error.message });
      if (error instanceof BrickkenWorkspaceError) {
        const liveRoute = req.url.startsWith('/api/live/');
        let integrationState;
        try { integrationState = liveRoute && live ? await liveState() : workspace.read(); } catch { /* Preserve the original bounded error. */ }
        const liveStatus = ['INVALID_INPUT', 'INVALID_OPERATION_ID', 'RUN_NOT_FOUND', 'OPERATION_NOT_FOUND'].includes(error.code) ? 400 : 409;
        return json(liveRoute ? liveStatus : [
          'WORKSPACE_BUSY', 'STALE_APPROVAL', 'STALE_PREVIEW', 'PLAN_EXPIRED',
          'SIGNING_ROUTE_UNAVAILABLE', 'OPERATION_FINAL', 'WORKSPACE_TOO_LARGE'
        ].includes(error.code) ? 409 : 400, {
          error: error.code,
          message: error.message,
          ...(error.details === undefined ? {} : { receipt: error.details }),
          ...(integrationState === undefined ? {} : { state: integrationState })
        });
      }
      console.error('Mandate Desk: internal request failure. Stored files were not reset.');
      return json(500, { error: 'INTERNAL', message: 'The action stopped. Saved history was preserved.' });
    }
  });
  server.requestTimeout = live ? 180000 : 15000;
  server.headersTimeout = 10000;
  return server;
}
export function argumentsFor(args) {
  const settings = { port: 4317, directory: path.join(ROOT, 'data') };
  for (let i = 0; i < args.length; i += 2) {
    if (args[i] === '--live' && settings.live === undefined) { settings.live = true; i -= 1; }
    else if (args[i] === '--port' && /^\d+$/.test(args[i + 1] ?? '')) settings.port = Number(args[i + 1]);
    else if (args[i] === '--data' && args[i + 1]) settings.directory = boundedPath(path.resolve(ROOT, args[i + 1]));
    else throw new Error('Unknown or incomplete argument');
  }
  if (settings.port < 1024 || settings.port > 65535) throw new Error('Invalid local port');
  return settings;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    const settings = argumentsFor(process.argv.slice(2));
    const server = createApp({
      store: new Store(settings.directory),
      liveWorkspace: settings.live ? new BrickkenLiveWorkspace(settings.directory, { role: 'owner' }) : null
    });
    server.on('error', () => { console.error('Mandate Desk: local server could not start.'); process.exitCode = 1; });
    server.listen(settings.port, '127.0.0.1', () => {
      console.log(`Mandate Desk simulation: http://127.0.0.1:${settings.port}`);
      if (settings.live) console.log('Sepolia live run enabled in the integration workspace.');
    });
  } catch { console.error('Mandate Desk: startup failed. Existing data preserved.'); process.exitCode = 1; }
}
