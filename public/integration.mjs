const $ = id => document.getElementById(id);
let copy;
let csrf;
let state;
let operation;
let busy = false;
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
    setButtons();
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

try {
  copy = await request('/integration-copy.json');
  document.querySelectorAll('[data-copy]').forEach(element => text(element, copy[element.dataset.copy]));
  ({ csrf } = await request('/api/session'));
  state = await request('/api/integration/state');
  render();
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
  setInterval(() => {
    if (!busy && operation?.approval) {
      renderApproval();
      setButtons();
    }
  }, 1000);
} catch (error) {
  notify(error.message === 'Failed to fetch' ? copy?.networkError ?? 'The local app could not be opened.' : error.message, true);
}
