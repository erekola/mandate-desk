const $ = id => document.getElementById(id);
let copy, state, csrf, selectedId, busy = false;
const text = (element, value) => { element.textContent = value; return element; };
const make = (tag, className, value) => { const element = document.createElement(tag); if (className) element.className = className; if (value !== undefined) text(element, value); return element; };
const short = value => value.slice(0, 8) + '...' + value.slice(-6);
function amount(value) {
  const n = BigInt(value); const scale = 1000000n;
  const fraction = (n % scale).toString().padStart(6, '0').replace(/0+$/, '');
  return (n / scale).toString() + (fraction ? ',' + fraction : '');
}
function notify(message, error = false) {
  const element = $('notification'); text(element, message); element.className = 'notification' + (error ? ' error' : ''); element.hidden = false;
}
async function request(url, body) {
  const response = await fetch(url, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Mandate-CSRF': csrf }, body: JSON.stringify(body) });
  const result = await response.json();
  if (!response.ok) throw Object.assign(new Error(result.message ?? copy?.networkError), { serverMessage: typeof result.message === 'string' ? result.message : undefined });
  return result;
}
async function action(work) {
  if (busy) return;
  busy = true;
  document.querySelectorAll('button').forEach(button => { button.disabled = true; });
  try { await work(); }
  catch (error) { notify(error.message === 'Failed to fetch' ? copy.networkError : error.message, true); }
  finally { busy = false; document.querySelectorAll('button').forEach(button => { button.disabled = false; }); $('revoke').disabled = !state?.policy.active; }
}
async function post(url, body) {
  const response = await request(url, body); state = response.state; render(); return response.result;
}
function badge(status) { return make('span', 'badge ' + status, copy[status]); }
function reason(op) { return op.receipt?.outcome === 'blocked' ? copy.blockedReasons[op.receipt.reason] ?? copy.blocked : copy[op.status]; }
function render({ forms = false } = {}) {
  const policy = state.policy;
  text($('remaining'), amount((BigInt(policy.maxCumulative) - BigInt(policy.used)).toString()));
  text($('used'), amount(policy.used)); text($('total'), amount(policy.maxCumulative)); text($('single'), amount(policy.maxTransaction));
  text($('balance'), amount(state.ledger.principalBalance));
  $('budget-progress').value = Number(BigInt(policy.used) * 10000n / BigInt(policy.maxCumulative)) / 100;
  text($('policy-status'), copy[policy.active ? 'active' : 'revoked']); $('policy-status').className = 'badge ' + (policy.active ? 'active' : 'revoked');
  text($('principal'), state.principal); text($('agent'), state.agent); $('revoke').disabled = !policy.active;
  if (forms) {
    $('max-transaction').value = amount(policy.maxTransaction); $('max-cumulative').value = amount(policy.maxCumulative);
    $('allowed-recipients').value = policy.recipients.join('\n'); $('recipient').value = policy.recipients[0];
  }
  const activity = $('activity'); activity.replaceChildren();
  if (!state.operations.length) {
    const empty = make('div', 'empty'); empty.append(make('strong', '', copy.emptyTitle), make('p', '', copy.emptyHelp)); activity.append(empty);
  } else {
    const wrap = make('div', 'table-wrap'); const table = make('table'); const head = make('thead'); const row = make('tr');
    for (const key of ['time', 'amount', 'status', 'reason']) { const cell = make('th', '', copy[key]); cell.scope = 'col'; row.append(cell); }
    head.append(row); const body = make('tbody');
    for (const op of [...state.operations].reverse()) {
      const tr = make('tr');
      const date = new Date(op.createdAt); const timeCell = make('td', '', date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })); timeCell.title = date.toLocaleString('en-GB');
      const total = op.plan.transfers.reduce((sum, transfer) => sum + BigInt(transfer.amount), 0n);
      const statusCell = make('td'); statusCell.append(badge(op.status));
      const detail = make('td', 'activity-details'); detail.colSpan = 4; const button = make('button', 'quiet', copy.details); button.addEventListener('click', () => showReview(op.id, true)); detail.append(button);
      const detailRow = make('tr'); detailRow.append(detail);
      tr.append(timeCell, make('td', 'amount', amount(total.toString()) + ' MDT'), statusCell, make('td', 'reason', reason(op))); body.append(tr, detailRow);
    }
    table.append(head, body); wrap.append(table); activity.append(wrap);
  }
  const lastScenario = state.scenarios.at(-1); $('scenario-result').hidden = !lastScenario;
  if (lastScenario) text($('scenario-result'), copy[lastScenario.passed ? 'scenarioPassed' : 'scenarioFailed']);
  if (selectedId) showReview(selectedId);
}
function showReview(id, focus = false) {
  selectedId = id; const op = state.operations.find(item => item.id === id); if (!op) return;
  $('review-panel').hidden = false; const root = $('review-content'); root.replaceChildren();
  const summary = make('div', 'review-summary');
  for (const transfer of op.plan.transfers) {
    const item = make('div'); item.append(make('div', 'review-amount', amount(transfer.amount) + ' MDT'), make('code', '', transfer.to)); summary.append(item);
  }
  summary.append(badge(op.status)); root.append(summary);
  const list = make('ul', 'check-grid');
  for (const check of op.checks) {
    const item = make('li', check.ok ? '' : 'failed'); const mark = make('span', 'check-state', check.ok ? '+' : '!'); mark.setAttribute('aria-label', copy[check.ok ? 'passed' : 'failed']);
    item.append(mark, document.createTextNode(copy.checks[check.code] ?? check.code)); list.append(item);
  }
  root.append(list);
  if (op.receipt) {
    const receipt = make('div', 'receipt'); receipt.append(make('h3', '', copy.evidence), make('p', '', copy.evidenceHelp));
    if (op.receipt.outcome === 'blocked') receipt.append(make('p', '', reason(op)));
    else {
      const balances = make('dl');
      balances.append(make('dt', '', copy.demoBalance + ': ' + copy.before.toLowerCase()), make('dd', '', amount(op.receipt.before.principalBalance) + ' MDT'), make('dt', '', copy.demoBalance + ': ' + copy.after.toLowerCase()), make('dd', '', amount(op.receipt.after.principalBalance) + ' MDT'));
      receipt.append(balances);
    }
    root.append(receipt);
  }
  const buttons = make('div', 'review-actions');
  if (op.status === 'checked') {
    const approve = make('button', 'primary', copy.approve);
    approve.addEventListener('click', () => action(async () => { await post('/api/approve', { operationId: id, planHash: op.planHash }); notify(reason(state.operations.find(item => item.id === id))); })); buttons.append(approve);
  }
  if (op.status === 'approved') {
    const execute = make('button', 'primary', copy.execute);
    execute.addEventListener('click', () => action(async () => { await post('/api/execute', { operationId: id, planHash: op.planHash }); notify(reason(state.operations.find(item => item.id === id))); })); buttons.append(execute);
  }
  if (op.status === 'planned') {
    const check = make('button', 'primary', copy.prepare);
    check.addEventListener('click', () => action(async () => { await post('/api/preflight', { operationId: id }); notify(copy.saved); })); buttons.append(check);
  }
  root.append(buttons);
  const technical = make('dl', 'technical'); technical.append(make('dt', '', copy.operationId), make('dd', '', id), make('dt', '', copy.planHash));
  const hash = make('dd'); hash.append(make('code', '', op.planHash)); technical.append(hash); root.append(technical);
  if (focus) $('review-panel').focus({ preventScroll: false });
}
try {
  copy = await request('/copy.json');
  document.querySelectorAll('[data-copy]').forEach(element => text(element, copy[element.dataset.copy]));
  ({ csrf } = await request('/api/session')); state = await request('/api/state'); render({ forms: true });
  $('transfer-form').addEventListener('submit', event => {
    event.preventDefault(); action(async () => {
      const op = await post('/api/plan', { operationId: crypto.randomUUID(), transfers: [{ to: $('recipient').value.trim(), amount: $('amount').value.trim() }] });
      await post('/api/preflight', { operationId: op.id }); showReview(op.id, true); notify(reason(state.operations.find(item => item.id === op.id)));
    });
  });
  $('policy-form').addEventListener('submit', event => {
    event.preventDefault(); action(async () => {
      await post('/api/grant', { maxTransaction: $('max-transaction').value.trim(), maxCumulative: $('max-cumulative').value.trim(), recipients: $('allowed-recipients').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean) });
      render({ forms: true }); notify(copy.grantDone);
    });
  });
  $('revoke').addEventListener('click', () => action(async () => { await post('/api/revoke', {}); notify(copy.revokeDone); }));
  $('scenario').addEventListener('click', () => action(async () => { const result = await post('/api/scenario', {}); render({ forms: true }); notify(copy[result.passed ? 'scenarioPassed' : 'scenarioFailed']); }));
  $('refresh').addEventListener('click', () => action(async () => { state = await request('/api/state'); render(); notify(copy.saved); }));
  $('close-review').addEventListener('click', () => { selectedId = null; $('review-panel').hidden = true; $('amount').focus(); });
} catch (error) { notify(error.serverMessage ?? copy?.networkError ?? 'The local app could not be opened.', true); }
