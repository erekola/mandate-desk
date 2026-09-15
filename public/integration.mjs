const $ = id => document.getElementById(id);
let copy;
let csrf;
let state;
let operation;
let busy = false;
let liveMode = 'unknown';
let liveState = null;
const text = (element, value) => { element.textContent = String(value); return element; };
const make = (tag, className, value) => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (value !== undefined) text(element, value);
  return element;
};

function notify(message, error = false) {
  const element = $('notification');
  text(element, message);
  element.className = 'notification' + (error ? ' error' : '');
  element.hidden = false;
}
async function request(url, body) {
  const response = await fetch(url, body === undefined ? {} : {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Mandate-CSRF': csrf },
    body: JSON.stringify(body)
  });
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.message ?? copy?.networkError ?? 'The local app request failed.');
    error.payload = result;
    throw error;
  }
  return result;
}
async function action(work) {
  if (busy) return;
  busy = true;
  document.querySelectorAll('button').forEach(button => { button.disabled = true; });
  try { await work(); }
  catch (error) {
    if (error.payload?.state) state = error.payload.state;
    render();
    notify(error.message === 'Failed to fetch' ? copy.networkError : error.message, true);
  } finally {
    busy = false;
    syncButtons();
  }
}
function latestOperation() {
  return state?.operations?.at(-1) ?? null;
}
function approvalStatus() {
  const approval = operation?.approval;
  if (!approval) return { current: false, message: copy.approvalMissing, className: 'pending' };
  if (state.revision !== approval.stateRevision) {
    return { current: false, message: copy.approvalStale, className: 'pending' };
  }
  const now = Math.floor(Date.now() / 1000);
  if (now < approval.approvedAt || now >= approval.expiresAt) {
    return { current: false, message: copy.approvalExpired, className: 'pending' };
  }
  return { current: true, message: copy.approvalCurrent, className: 'approved' };
}
function renderApproval() {
  const approval = approvalStatus();
  text($('approval-status'), approval.message);
  $('approval-status').className = 'badge ' + approval.className;
  return approval;
}
function setButtons() {
  operation = latestOperation();
  const approval = approvalStatus();
  $('approve').disabled = busy || !operation || operation.status !== 'planned';
  $('preflight').disabled = busy || !approval.current;
  $('execute').disabled = busy || !approval.current || Boolean(operation?.receipt);
  $('prepare').disabled = busy;
  $('refresh').disabled = busy;
}
function addTerm(root, label, value) {
  root.append(make('dt', '', label), make('dd', '', value));
}
function renderProposal() {
  const root = $('proposal');
  root.replaceChildren();
  if (!operation) {
    root.className = 'empty';
    root.append(make('strong', '', copy.empty));
    return;
  }
  root.className = '';
  const proposal = operation.preview.proposal;
  const details = make('dl', 'technical');
  addTerm(details, copy.network, `Ethereum Sepolia (${proposal.chainId})`);
  addTerm(details, copy.amount, `${proposal.amount} raw units (0.01 test USDC)`);
  addTerm(details, copy.limits, `${proposal.maxTransactionValue} / ${proposal.maxCumulativeValue} / ${proposal.allowance} raw units`);
  addTerm(details, copy.validity, `${proposal.mandateValiditySeconds / 60} ${copy.minutes}`);
  for (const [label, value] of [
    [copy.principal, proposal.principal], [copy.agent, proposal.agent],
    [copy.executor, proposal.executor], [copy.registry, proposal.registry],
    [copy.token, proposal.token], [copy.recipient, proposal.recipient],
    [copy.identity, proposal.identityRef]
  ]) addTerm(details, label, value);
  addTerm(details, copy.provenance, copy.provenanceHelp);
  root.append(details);
}
function renderActions() {
  const root = $('actions');
  root.replaceChildren();
  if (!operation) return root.append(make('div', 'empty', copy.empty));
  const envelopes = operation.envelopes;
  const entries = envelopes ?? operation.preview.actions;
  text($('envelope-count'), `${envelopes?.length ?? 0} / 5`);
  const wrap = make('div', 'table-wrap');
  const table = make('table');
  const head = make('thead');
  const header = make('tr');
  for (const label of [copy.action, copy.signer, copy.nonce, copy.target, copy.hash, copy.fullDetails]) {
    const cell = make('th', '', label); cell.scope = 'col'; header.append(cell);
  }
  head.append(header);
  const body = make('tbody');
  for (const entry of entries) {
    const tx = envelopes ? entry.transaction : entry.transaction;
    const row = make('tr');
    const artifact = make('details');
    artifact.append(make('summary', '', copy.fullDetails));
    const full = make('textarea');
    full.readOnly = true;
    full.rows = 12;
    full.value = JSON.stringify(entry, null, 2);
    full.setAttribute('aria-label', `${entry.action} ${copy.fullDetails}`);
    artifact.append(full);
    row.append(
      make('td', '', entry.action),
      make('td', '', entry.action === 'execute' ? copy.agent : copy.principal),
      make('td', '', tx.nonce),
      make('td', '', tx.to),
      make('td', '', envelopes ? entry.envelopeHash : copy.draft),
      make('td', '', '')
    );
    row.lastElementChild.append(artifact);
    body.append(row);
  }
  table.append(head, body); wrap.append(table); root.append(wrap);
}
function renderReceipt() {
  const root = $('receipt');
  root.replaceChildren(make('h3', '', copy.receipt));
  const receipt = operation?.receipt;
  if (!receipt) return root.append(make('p', '', copy.noReceipt));
  root.append(make('pre', '', JSON.stringify(receipt, null, 2)));
}
function render() {
  operation = latestOperation();
  renderProposal();
  text($('preview-hash'), operation?.previewHash ?? '-');
  renderApproval();
  renderActions();
  renderReceipt();
  text($('prepare'), operation ? copy.prepareAgain : copy.prepare);
  setButtons();
}

function syncButtons() {
  setButtons();
  setLiveButtons();
}
function currentLiveRun() {
  if (!liveState || !Array.isArray(liveState.runs) || liveState.runs.length === 0) return null;
  return liveState.runs.find(run => run.runId === liveState.activeRunId) ?? liveState.runs.at(-1);
}
function setLiveButtons() {
  const enabled = liveMode === 'enabled';
  const run = currentLiveRun();
  const disabledBase = busy || !enabled;
  $('live-prepare').disabled = disabledBase || Boolean(liveState?.activeRunId);
  $('live-approve').disabled = disabledBase || !run || run.status !== 'awaiting-owner-approval';
  $('live-start-setup').disabled = disabledBase || !run || run.status !== 'owner-approved';
  $('live-start-revocation').disabled = disabledBase || !run || run.status !== 'awaiting-owner-revocation';
  $('live-resume').disabled = disabledBase || !run || !(
    (run.status === 'stopped' && ['owner-setup', 'owner-revocation', 'cleanup'].includes(run.phase)) ||
    (run.status.endsWith('-running') && run.jobRunning === false)
  );
  $('live-cleanup').disabled = disabledBase || !run || !(
    ['stopped', 'awaiting-agent', 'awaiting-owner-revocation', 'agent-executing'].includes(run.status) && run.ownerApproved
  );
  $('live-finality').disabled = disabledBase || !run || !run.steps.some(step => step.semanticallyVerified);
  $('live-refresh').disabled = disabledBase;
}
function formatUnits(raw, decimals) {
  const value = BigInt(raw);
  const base = 10n ** BigInt(decimals);
  const whole = value / base;
  const fraction = (value % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : `${whole}`;
}
function renderLiveProposal() {
  const root = $('live-proposal');
  const proposal = liveState.proposal;
  const decimals = proposal.tokenDecimals;
  const dl = make('dl', 'technical');
  addTerm(dl, copy.network, `${proposal.network} (${copy.liveChainIdLabel} ${proposal.chainId})`);
  addTerm(dl, copy.principal, proposal.principal);
  addTerm(dl, copy.agent, proposal.agent);
  addTerm(dl, copy.executor, proposal.executor);
  addTerm(dl, copy.registry, proposal.registry);
  addTerm(dl, copy.token, `${proposal.token} (${decimals} ${copy.liveDecimalsLabel})`);
  addTerm(dl, copy.recipient, proposal.recipient);
  addTerm(dl, copy.liveLimitsLabel,
    `${formatUnits(proposal.limits.maxTransactionValue, decimals)} / ${formatUnits(proposal.limits.maxCumulativeValue, decimals)} / ${formatUnits(proposal.limits.allowance, decimals)} test USDC ` +
    `(${copy.liveRawLabel}: ${proposal.limits.maxTransactionValue} / ${proposal.limits.maxCumulativeValue} / ${proposal.limits.allowance})`);
  addTerm(dl, copy.liveMinBalanceLabel, `${formatUnits(proposal.limits.minimumPrincipalTokenBalance, decimals)} test USDC (${proposal.limits.minimumPrincipalTokenBalance} ${copy.liveRawLabel})`);
  addTerm(dl, copy.liveExecuteAmountLabel, `${formatUnits(proposal.amounts.execute, decimals)} test USDC (${proposal.amounts.execute} ${copy.liveRawLabel})`);
  addTerm(dl, copy.liveOverCapAmountLabel, `${formatUnits(proposal.amounts.overTransactionCapProbe, decimals)} test USDC (${proposal.amounts.overTransactionCapProbe} ${copy.liveRawLabel})`);
  addTerm(dl, copy.liveCumulativeAllowedAmountLabel, `${formatUnits(proposal.amounts.cumulativeAllowedProbe, decimals)} test USDC (${proposal.amounts.cumulativeAllowedProbe} ${copy.liveRawLabel})`);
  addTerm(dl, copy.liveCumulativeDeniedAmountLabel, `${formatUnits(proposal.amounts.cumulativeDeniedProbe, decimals)} test USDC (${proposal.amounts.cumulativeDeniedProbe} ${copy.liveRawLabel})`);
  addTerm(dl, copy.liveRevocationAmountLabel, `${formatUnits(proposal.amounts.revocationProbe, decimals)} test USDC (${proposal.amounts.revocationProbe} ${copy.liveRawLabel})`);
  addTerm(dl, copy.validity, `${proposal.mandateValiditySeconds / 60} ${copy.minutes}`);
  addTerm(dl, copy.liveFeesLabel, `${formatUnits(proposal.fees.maxFeePerGas, 9)} / ${formatUnits(proposal.fees.maxPriorityFeePerGas, 9)} gwei`);
  addTerm(dl, copy.liveConfigLabel, proposal.persistentConfiguration);
  addTerm(dl, copy.liveRecipientEnforcementLabel, proposal.recipientEnforcement);
  root.replaceChildren(dl);
}
function renderLiveSigner() {
  const root = $('live-signer');
  const signer = liveState.signer;
  const dl = make('dl', 'technical');
  addTerm(dl, copy.liveSignerAvailableLabel, signer.available ? copy.liveYes : copy.liveNo);
  if (signer.available) {
    addTerm(dl, copy.liveSignerRoleLabel, signer.role ?? copy.liveNone);
    dl.append(make('dt', '', copy.liveSignerApprovalHashLabel));
    const hashDd = make('dd');
    hashDd.append(make('code', '', signer.approvalSha256 ?? copy.liveNone));
    dl.append(hashDd);
    addTerm(dl, copy.liveSignerActiveLabel, signer.active ? copy.liveYes : copy.liveNo);
    addTerm(dl, copy.liveSignerSignedStepsLabel, signer.signedSteps?.length ? signer.signedSteps.join(', ') : copy.liveNone);
  } else {
    addTerm(dl, copy.liveSignerCodeLabel, signer.code ?? copy.liveNone);
  }
  root.replaceChildren(dl);
}
function renderLiveRun() {
  const root = $('live-run');
  const run = currentLiveRun();
  if (!run) { root.replaceChildren(make('p', 'support', copy.liveNoRun)); return; }
  const dl = make('dl', 'technical');
  addTerm(dl, copy.liveStatusLabel, run.status);
  addTerm(dl, copy.livePhaseLabel, run.phase ?? copy.liveNone);
  addTerm(dl, copy.liveRunIdLabel, run.runId);
  dl.append(make('dt', '', copy.liveApprovalHashLabel));
  const hashDd = make('dd');
  hashDd.append(make('code', '', run.approvalSha256));
  dl.append(hashDd);
  addTerm(dl, copy.liveApprovalValidUntilLabel, run.notAfter);
  if (run.codeIdentitySha256) {
    dl.append(make('dt', '', copy.liveCodeIdentityLabel));
    const codeDd = make('dd', '');
    codeDd.append(make('code', '', run.codeIdentitySha256));
    dl.append(codeDd);
  }
  addTerm(dl, copy.liveOwnerApprovalLabel, run.ownerApproval ? run.ownerApproval.approvedAt : copy.liveNotApproved);
  const parts = [dl];
  if (run.preflightBlockers?.length) {
    const list = make('ul');
    for (const blocker of run.preflightBlockers) {
      list.append(make('li', '', blocker.detail === undefined ? blocker.code : `${blocker.code}: ${JSON.stringify(blocker.detail)}`));
    }
    parts.push(make('h3', '', copy.livePreflightBlockersLabel), list);
  }
  if (run.stop) {
    const stopDl = make('dl', 'technical');
    addTerm(stopDl, copy.liveStopCodeLabel, run.stop.code);
    addTerm(stopDl, copy.liveStopMessageLabel, run.stop.message);
    addTerm(stopDl, copy.liveStopLayerLabel, run.stop.details?.layer ?? copy.liveNone);
    addTerm(stopDl, copy.liveStopStepLabel, run.stop.details?.step ?? copy.liveNone);
    parts.push(make('h3', '', copy.liveStopLabel), stopDl);
  }
  if (run.cleanup) {
    parts.push(make('h3', '', copy.liveCleanupLabel), make('pre', '', JSON.stringify(run.cleanup, null, 2)));
  }
  if (run.finality) {
    const finalityDl = make('dl', 'technical');
    addTerm(finalityDl, copy.liveAllFinalizedLabel, run.finality.allFinalized ? copy.liveYes : copy.liveNo);
    const list = make('ul');
    for (const entry of run.finality.entries) {
      list.append(make('li', '', `${entry.operationId ?? entry.controlId}: ${entry.finalized ? copy.liveYes : copy.liveNo}${entry.reason ? ` (${entry.reason})` : ''}`));
    }
    parts.push(make('h3', '', copy.liveFinalityLabel), finalityDl, list);
  }
  const details = make('details');
  details.append(make('summary', '', copy.liveLoadApprovalLabel));
  const textarea = make('textarea');
  textarea.readOnly = true;
  textarea.rows = 12;
  textarea.value = copy.liveApprovalNotLoaded;
  textarea.setAttribute('aria-label', copy.liveLoadApprovalLabel);
  details.addEventListener('toggle', () => {
    if (!details.open || textarea.dataset.loaded) return;
    request(`/api/live/approval/${run.runId}`).then(document_ => {
      textarea.value = JSON.stringify(document_, null, 2);
      textarea.dataset.loaded = 'true';
    }).catch(error => { textarea.value = error.message; });
  });
  details.append(textarea);
  parts.push(details);
  root.replaceChildren(...parts);
}
const LIVE_STEP_STATUS_KEYS = Object.freeze({
  waiting: 'liveStatusWaiting', prepared: 'liveStatusPrepared', signed: 'liveStatusSigned', sent: 'liveStatusSent',
  uncertain: 'liveStatusUncertain', confirmed: 'liveStatusConfirmed', verified: 'liveStatusVerified',
  failed: 'liveStatusFailed', skipped: 'liveStatusSkipped'
});
function renderLiveSteps() {
  const root = $('live-steps');
  const run = currentLiveRun();
  if (!run) { root.replaceChildren(); return; }
  const wrap = make('div', 'table-wrap');
  const table = make('table');
  const headerRow = make('tr');
  for (const label of [copy.action, copy.signer, copy.liveRoute, copy.liveStatusLabel, copy.liveApiTxId, copy.liveTxHash, copy.liveExplorer, copy.liveBlockNumber, copy.liveConfirmations]) {
    const cell = make('th', '', label); cell.scope = 'col'; headerRow.append(cell);
  }
  const thead = make('thead'); thead.append(headerRow);
  const tbody = make('tbody');
  for (const step of run.steps) {
    const row = make('tr');
    const signerLabel = step.signer === 'owner' ? copy.liveSignerOwner : copy.liveSignerAgent;
    const routeLabel = step.route === 'brickken-api' ? copy.liveRouteBrickken : copy.liveRouteSepolia;
    const statusLabel = copy[LIVE_STEP_STATUS_KEYS[step.status]] ?? step.status;
    const statusText = step.status === 'skipped' && step.skipReason ? `${statusLabel} (${step.skipReason})` : statusLabel;
    row.append(make('td', '', step.step), make('td', '', signerLabel), make('td', '', routeLabel), make('td', '', statusText), make('td', '', step.apiTxId ?? '-'));
    const hashCell = make('td');
    hashCell.append(make('code', '', step.transactionHash ?? '-'));
    row.append(hashCell);
    const explorerCell = make('td');
    if (step.explorerUrl) {
      const link = document.createElement('a');
      link.href = step.explorerUrl;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      text(link, copy.liveExplorerLink);
      explorerCell.append(link);
    } else {
      text(explorerCell, '-');
    }
    row.append(explorerCell, make('td', '', step.blockNumber ?? '-'), make('td', '', step.confirmations ?? '-'));
    tbody.append(row);
  }
  table.append(thead, tbody); wrap.append(table);
  const execStep = run.steps.find(item => item.step === 'execute');
  root.replaceChildren(make('h3', '', copy.liveStepsLabel), wrap, make('p', 'field-help', `${copy.liveExecuteNote} ${execStep.operationId}`));
}
function renderLiveControls() {
  const root = $('live-controls');
  const run = currentLiveRun();
  if (!run) { root.replaceChildren(); return; }
  const wrap = make('div', 'table-wrap');
  const table = make('table');
  const headerRow = make('tr');
  for (const label of [copy.liveControlId, copy.liveObserved, copy.livePassed, copy.liveBlockNumber, copy.liveInterpretation]) {
    const cell = make('th', '', label); cell.scope = 'col'; headerRow.append(cell);
  }
  const thead = make('thead'); thead.append(headerRow);
  const tbody = make('tbody');
  for (const control of run.controls) {
    const row = make('tr');
    row.append(
      make('td', '', control.id),
      make('td', '', control.observed ? copy.liveYes : copy.liveNo),
      make('td', '', control.observed ? (control.passed ? copy.liveYes : copy.liveNo) : '-'),
      make('td', '', control.blockNumber ?? '-'),
      make('td', 'reason', control.interpretation ?? '-')
    );
    tbody.append(row);
  }
  table.append(thead, tbody); wrap.append(table);
  const replayList = make('ul');
  if (run.replays.length) {
    for (const replay of run.replays) {
      replayList.append(make('li', '',
        `${replay.observedAt} - ${copy.liveBlockNumber} ${replay.blockNumber} - ${copy.livePassed} ${replay.passed ? copy.liveYes : copy.liveNo} - ${copy.liveNewAgentTx} ${replay.newAgentTransaction ? copy.liveYes : copy.liveNo}`));
    }
  }
  root.replaceChildren(
    make('h3', '', copy.liveControlsHeading), wrap,
    make('h3', '', copy.liveReplaysLabel),
    run.replays.length ? replayList : make('p', 'support', copy.liveNoReplays)
  );
}
function renderLive() {
  const disabled = $('live-disabled');
  const body = $('live-body');
  if (liveMode !== 'enabled' || !liveState) {
    disabled.hidden = false;
    body.hidden = true;
    return;
  }
  disabled.hidden = true;
  body.hidden = false;
  renderLiveProposal();
  renderLiveSigner();
  renderLiveRun();
  renderLiveSteps();
  renderLiveControls();
}
async function liveAction(work) {
  if (busy) return;
  busy = true;
  document.querySelectorAll('button').forEach(button => { button.disabled = true; });
  try { await work(); }
  catch (error) {
    if (error.payload?.state) liveState = error.payload.state;
    renderLive();
    notify(error.message === 'Failed to fetch' ? copy.networkError : error.message, true);
  } finally {
    busy = false;
    syncButtons();
  }
}
async function pollLive() {
  if (liveMode !== 'enabled' || !liveState) return;
  const shouldPoll = liveState.runs.some(run => run.jobRunning || run.status.endsWith('-running') || run.status === 'agent-executing');
  if (!shouldPoll) return;
  try {
    liveState = await request('/api/live/state');
    renderLive();
    setLiveButtons();
  } catch { /* A poll failure is silent; the next tick or a manual refresh retries. */ }
}

try {
  copy = await request('/integration-copy.json');
  document.querySelectorAll('[data-copy]').forEach(element => text(element, copy[element.dataset.copy]));
  ({ csrf } = await request('/api/session'));
  state = await request('/api/integration/state');
  render();
  try {
    liveState = await request('/api/live/state');
    liveMode = 'enabled';
  } catch (error) {
    liveMode = 'disabled';
    liveState = null;
    if (error.payload?.error !== 'LIVE_DISABLED') notify(error.message, true);
  }
  renderLive();
  $('prepare').addEventListener('click', () => action(async () => {
    const response = await request('/api/integration/plan', { operationId: `sepolia_${crypto.randomUUID()}` });
    state = response.state; render(); notify(copy.saved);
  }));
  $('approve').addEventListener('click', () => action(async () => {
    const response = await request('/api/integration/approve', { operationId: operation.operationId, previewHash: operation.previewHash });
    state = response.state; render(); notify(copy.approvalCurrent);
  }));
  $('preflight').addEventListener('click', () => action(async () => {
    const response = await request('/api/integration/preflight', { operationId: operation.operationId });
    state = response.state; render(); notify(JSON.stringify(response.result));
  }));
  $('execute').addEventListener('click', () => action(async () => {
    const response = await request('/api/integration/execute', { operationId: operation.operationId });
    state = response.state; render(); notify(JSON.stringify(response.result));
  }));
  $('refresh').addEventListener('click', () => action(async () => {
    state = await request('/api/integration/state'); render(); notify(copy.saved);
  }));
  $('live-refresh').addEventListener('click', () => liveAction(async () => {
    liveState = await request('/api/live/state'); renderLive(); notify(copy.saved);
  }));
  $('live-prepare').addEventListener('click', () => liveAction(async () => {
    const response = await request('/api/live/prepare', {});
    liveState = response.state; renderLive(); notify(copy.liveSaved);
  }));
  $('live-approve').addEventListener('click', () => liveAction(async () => {
    const run = currentLiveRun();
    const response = await request('/api/live/approve', { runId: run.runId, approvalSha256: run.approvalSha256 });
    liveState = response.state; renderLive(); notify(copy.liveSaved);
  }));
  $('live-start-setup').addEventListener('click', () => liveAction(async () => {
    const run = currentLiveRun();
    const response = await request('/api/live/start-setup', { runId: run.runId });
    liveState = response.state; renderLive(); notify(copy.liveSaved);
  }));
  $('live-start-revocation').addEventListener('click', () => liveAction(async () => {
    const run = currentLiveRun();
    const response = await request('/api/live/start-revocation', { runId: run.runId });
    liveState = response.state; renderLive(); notify(copy.liveSaved);
  }));
  $('live-resume').addEventListener('click', () => liveAction(async () => {
    const run = currentLiveRun();
    const response = await request('/api/live/resume', { runId: run.runId });
    liveState = response.state; renderLive(); notify(copy.liveSaved);
  }));
  $('live-cleanup').addEventListener('click', () => liveAction(async () => {
    const run = currentLiveRun();
    const response = await request('/api/live/cleanup', { runId: run.runId });
    liveState = response.state; renderLive(); notify(copy.liveSaved);
  }));
  $('live-finality').addEventListener('click', () => liveAction(async () => {
    const run = currentLiveRun();
    const response = await request('/api/live/finality', { runId: run.runId });
    liveState = response.state; renderLive(); notify(copy.liveSaved);
  }));
  syncButtons();
  setInterval(() => {
    if (!busy && operation?.approval) {
      renderApproval();
      setButtons();
    }
  }, 1000);
  setInterval(pollLive, 4000);
} catch (error) {
  notify(error.message === 'Failed to fetch' ? copy?.networkError ?? 'The local app could not be opened.' : error.message, true);
}
