// Renders a finished Sepolia live run from the app's own saved state onto a
// canvas and records that rendering. It sends no transaction itself: every
// value drawn comes from GET /api/live/state, which reads the run's saved
// live workspace document and journal from disk.
const canvas = document.getElementById('live-canvas'), ctx = canvas.getContext('2d');
const runSelect = document.getElementById('run-select');
const button = document.getElementById('record-live'), status = document.getElementById('live-status');
const copy = await (await fetch('/live-demo-copy.json')).json();
document.getElementById('live-title').textContent = copy.title;
document.getElementById('live-help').textContent = copy.help;
document.getElementById('run-select-label').textContent = copy.runSelectLabel;
button.textContent = copy.start;

let csrf, liveState = null, stage = 0, scenes = null;

function pretty(n) {
  const x = BigInt(n);
  return (x / 1000000n).toString() + (x % 1000000n ? ',' + (x % 1000000n).toString().padStart(6, '0').replace(/0+$/, '') : '');
}
function short(runId) { return runId.replace(/^live_/, '').slice(0, 12); }
function stepInfo(run, name) { return run.steps.find(item => item.step === name); }
function controlInfo(run, id) { return run.controls.find(item => item.id === id); }

function lines(text, x, y, width, size = 28, color = '#1b322b', font = 'Arial') {
  ctx.font = `${size}px ${font}`; ctx.fillStyle = color; let line = '';
  for (const word of text.split(' ')) {
    const next = line ? line + ' ' + word : word;
    if (ctx.measureText(next).width > width && line) { ctx.fillText(line, x, y); y += size * 1.4; line = word; }
    else line = next;
  }
  ctx.fillText(line, x, y);
  return y + size * 1.4;
}

function drawBlocks(blocks, x, y, width) {
  for (const block of blocks) {
    for (const row of block.rows) {
      if (row.label) { ctx.font = '18px Arial'; ctx.fillStyle = '#52665b'; ctx.fillText(row.label, x, y); y += 24; }
      y = lines(row.value, x, y, width, row.mono ? 20 : 22, row.mono ? '#183f30' : '#1b322b', row.mono ? 'monospace' : 'Arial') + 4;
      if (row.sub) y = lines(row.sub, x, y, width, 15, '#68776e');
      y += 10;
    }
    y += 14;
  }
  return y;
}

function drawIdle() {
  ctx.fillStyle = '#f4f5ee'; ctx.fillRect(0, 0, 1600, 900);
  ctx.fillStyle = '#214e40'; ctx.fillRect(0, 0, 1600, 16);
  ctx.font = 'bold 34px Arial'; ctx.fillStyle = '#214e40'; ctx.fillText(copy.brand, 72, 84);
  ctx.font = 'bold 22px Arial'; ctx.fillText(copy.mode, 1180, 80);
  lines(copy.idlePrompt, 72, 240, 1430, 40, '#52665b');
}
drawIdle();

function draw() {
  const scene = scenes[stage];
  ctx.fillStyle = '#f4f5ee'; ctx.fillRect(0, 0, 1600, 900);
  ctx.fillStyle = '#214e40'; ctx.fillRect(0, 0, 1600, 16);
  ctx.font = 'bold 34px Arial'; ctx.fillStyle = '#214e40'; ctx.fillText(copy.brand, 72, 84);
  ctx.font = 'bold 22px Arial'; ctx.fillText(copy.mode, 1180, 80);
  ctx.font = '20px Arial'; ctx.fillStyle = '#68776e'; ctx.fillText(`${stage + 1} / ${scenes.length}`, 72, 143);
  let y = lines(scene.title, 72, 208, 1430, 46);
  if (scene.body) y = lines(scene.body, 72, y + 20, 1410, 26, '#52665b');
  y = drawBlocks(scene.blocks, 72, y + 26, 1400);
  ctx.font = '19px Arial'; ctx.fillStyle = '#68776e'; ctx.fillText(copy.footer, 72, 860);
}

// Every value drawn in a scene is read here from the state the server
// already saved for this run; nothing is computed or guessed at render time.
function buildScenes(run, proposal) {
  const missing = [];
  const need = (ok, label) => { if (!ok) missing.push(label); };
  need(run.status === 'completed', copy.missing.runNotCompleted);
  need(!!run.ownerApproval?.approvedAt, copy.missing.ownerApproval);
  const stepChecks = {};
  for (const name of ['setAction', 'approve', 'grant', 'execute', 'revoke', 'approveReset']) {
    const info = stepInfo(run, name);
    stepChecks[name] = info;
    if (!info) { need(false, copy.missing.stepEvidence.replace('{step}', name)); continue; }
    if (info.planned) need(!!(info.transactionHash && info.blockNumber && info.semanticallyVerified), copy.missing.stepEvidence.replace('{step}', name));
    else need(!!info.skipReason, copy.missing.stepSkip.replace('{step}', name));
  }
  need(!!stepChecks.execute?.apiTxId, copy.missing.apiTxId);
  const controlChecks = {};
  for (const [id, key] of [['control-transaction-cap', 'controlTransactionCap'], ['control-cumulative-cap', 'controlCumulativeCap'], ['control-after-revoke', 'controlAfterRevoke']]) {
    const info = controlInfo(run, id);
    controlChecks[id] = info;
    need(!!(info && info.observed && info.passed), copy.missing[key]);
  }
  const lastReplay = run.replays[run.replays.length - 1];
  need(!!(lastReplay && lastReplay.passed), copy.missing.replay);
  need(!!(run.finality && run.finality.allFinalized && Array.isArray(run.finality.entries) && run.finality.entries.length), copy.missing.finality);
  if (missing.length) return { missing };

  const limits = proposal.limits, s = copy.steps, L = copy.labels;
  const stepRow = name => {
    const info = stepChecks[name];
    if (info.planned) return { label: copy.stepNames[name], value: info.transactionHash, mono: true, sub: `${L.route}: ${info.route} · ${L.blockNumber} ${info.blockNumber} · ${L.verified}: ${copy.yes}` };
    return { label: copy.stepNames[name], value: `${L.skipped}: ${info.skipReason}` };
  };
  const scenes = [
    { title: s[0].title, body: s[0].body, blocks: [{ rows: [
      { label: L.network, value: proposal.network },
      { label: L.chainId, value: proposal.chainId },
      { label: L.runId, value: run.runId, mono: true },
      { label: L.approvalHash, value: run.approvalSha256, mono: true }
    ] }] },
    { title: s[1].title, body: s[1].body, blocks: [{ rows: [
      { label: L.ownerApprovedAt, value: run.ownerApproval.approvedAt },
      { label: L.perTransferLimit, value: `${pretty(limits.maxTransactionValue)} ${copy.unit}` },
      { label: L.cumulativeLimit, value: `${pretty(limits.maxCumulativeValue)} ${copy.unit}` },
      { label: L.allowanceLimit, value: `${pretty(limits.allowance)} ${copy.unit}` },
      { label: L.recipient, value: proposal.recipient, mono: true },
      { label: L.mandateValidity, value: `${proposal.mandateValiditySeconds} ${copy.secondsUnit}` }
    ] }] },
    { title: s[2].title, body: s[2].body, blocks: [{ rows: ['setAction', 'approve', 'grant'].map(stepRow) }] },
    { title: s[3].title, body: s[3].body, blocks: [{ rows: [
      { label: L.controlBlock, value: `${controlChecks['control-transaction-cap'].blockNumber}` },
      { value: controlChecks['control-transaction-cap'].interpretation }
    ] }] },
    { title: s[4].title, body: s[4].body, blocks: [{ rows: [
      { label: L.transactionHash, value: stepChecks.execute.transactionHash, mono: true, sub: `${L.blockNumber} ${stepChecks.execute.blockNumber} · ${L.verified}: ${copy.yes}` },
      { label: L.apiTxId, value: stepChecks.execute.apiTxId, mono: true, sub: copy.apiTxIdNote }
    ] }] },
    { title: s[5].title, body: s[5].body, blocks: [{ rows: [
      { label: L.operationId, value: stepChecks.execute.operationId, mono: true },
      { label: L.transactionHash, value: lastReplay.transactionHash, mono: true },
      { label: L.replayResult, value: `${lastReplay.newAgentTransaction ? copy.replayNew : copy.replayNone} ${L.blockNumber} ${lastReplay.blockNumber}.` }
    ] }] },
    { title: s[6].title, body: s[6].body, blocks: [{ rows: [
      { label: L.controlBlock, value: `${controlChecks['control-cumulative-cap'].blockNumber}` },
      { value: controlChecks['control-cumulative-cap'].interpretation }
    ] }] },
    { title: s[7].title, body: s[7].body, blocks: [{ rows: [
      stepRow('revoke'),
      { label: L.controlBlock, value: `${controlChecks['control-after-revoke'].blockNumber}` },
      { value: controlChecks['control-after-revoke'].interpretation }
    ] }] },
    { title: s[8].title, body: s[8].body, blocks: [{ rows: [
      stepRow('approveReset'),
      { label: L.allFinalized, value: run.finality.allFinalized ? copy.yes : copy.no },
      { label: L.finalityEntries, value: `${run.finality.entries.length} / ${run.finality.entries.length}`, sub: `${L.finalityCheckedAt}: ${run.finality.checkedAt}` }
    ] }] },
    { title: s[9].title, body: s[9].body, blocks: [{ rows: [
      { label: L.evidence, value: copy.evidencePrefix + short(run.runId) },
      { value: copy.closing }
    ] }] }
  ];
  return { scenes };
}

function populateRuns() {
  while (runSelect.firstChild) runSelect.removeChild(runSelect.firstChild);
  const byNewest = [...liveState.runs].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
  for (const run of byNewest) {
    const opt = document.createElement('option');
    opt.value = run.runId;
    opt.textContent = `${short(run.runId)} — ${run.status} — ${run.createdAt}`;
    runSelect.appendChild(opt);
  }
  const completed = liveState.runs.filter(run => run.status === 'completed').sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
  if (completed[0]) runSelect.value = completed[0].runId;
}

try {
  ({ csrf } = await (await fetch('/api/session')).json());
  const response = await fetch('/api/live/state');
  if (response.ok) liveState = await response.json();
} catch { /* liveState stays null; handled below */ }
if (!liveState) { status.textContent = copy.liveUnavailable; button.disabled = true; runSelect.disabled = true; }
else if (!liveState.runs.length) { status.textContent = copy.noRuns; button.disabled = true; runSelect.disabled = true; }
else populateRuns();

const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

button.addEventListener('click', async () => {
  if (button.disabled || !liveState) return;
  const run = liveState.runs.find(item => item.runId === runSelect.value);
  if (!run) { status.textContent = copy.noRuns; return; }
  const built = buildScenes(run, liveState.proposal);
  if (built.missing) { status.textContent = copy.missingValue.replace('{value}', built.missing.join('; ')); return; }
  scenes = built.scenes;
  button.disabled = true; runSelect.disabled = true;
  let recorder, stream, captureTick; const chunks = [];
  try {
    const mime = ['video/webm;codecs=vp9', 'video/webm;codecs=vp8', 'video/webm'].find(x => typeof MediaRecorder !== 'undefined' && MediaRecorder.isTypeSupported(x));
    if (!mime || typeof canvas.captureStream !== 'function') { status.textContent = copy.unsupported; return; }
    status.textContent = copy.recording;
    stream = canvas.captureStream(10);
    recorder = new MediaRecorder(stream, { mimeType: mime, videoBitsPerSecond: 12000000 });
    recorder.addEventListener('dataavailable', e => { if (e.data.size) chunks.push(e.data); });
    captureTick = setInterval(() => stream.getVideoTracks()[0]?.requestFrame?.(), 100);
    const stopped = new Promise(resolve => recorder.addEventListener('stop', resolve, { once: true }));
    recorder.start(1000);
    for (stage = 0; stage < scenes.length; stage++) {
      draw();
      await delay(copy.steps[stage].seconds * 1000);
    }
    clearInterval(captureTick); recorder.stop(); await stopped;
    stream.getTracks().forEach(track => track.stop());
    const blob = new Blob(chunks, { type: 'video/webm' });
    // The server binds the saved file to this run only if the run's evidence is complete right now.
    const saveResponse = await fetch('/api/live-recording', { method: 'POST', headers: { 'content-type': 'video/webm', 'x-mandate-csrf': csrf, 'x-mandate-live-run': run.runId }, body: blob });
    if (!saveResponse.ok) {
      let body = null;
      try { body = await saveResponse.json(); } catch { /* the code below covers a non-JSON failure */ }
      throw Object.assign(Error('SAVE_FAILED'), { refused: body?.error ?? null, missing: body?.details?.missing ?? null });
    }
    const saved = await saveResponse.json();
    status.textContent = `${copy.saved} ${saved.name} · sha256 ${saved.sha256} · ${copy.boundTo} ${short(saved.binding.runId)}`;
  } catch (error) {
    if (recorder?.state === 'recording') recorder.stop();
    stream?.getTracks().forEach(track => track.stop());
    status.textContent = error?.refused
      ? copy.bindingRefused.replace('{code}', error.refused).replace('{missing}', (error.missing ?? []).join(', ') || copy.none)
      : copy.failed;
  } finally {
    clearInterval(captureTick); button.disabled = false; runSelect.disabled = false;
    stage = Math.min(stage, (scenes?.length ?? 1) - 1);
  }
});
