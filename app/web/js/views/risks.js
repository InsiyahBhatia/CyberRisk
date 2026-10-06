import { ai, api, el, clear, qs, formField, fmt, fmtDate, dataTable, levelBadge, statusBadge, badge, monoText, scoreBar, openDrawer, kv, section, simpleTable, skeleton, errorBox, notice, toast, chart, chartBox, gridOpts, title } from '../core.js';
import { runAI } from '../ai.js';

const LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUSES = ['IDENTIFIED', 'ASSESSMENT', 'TREATMENT', 'MITIGATION', 'VALIDATION', 'ACCEPTED', 'CLOSED'];

export async function risks(root, params = {}) {
  const table = dataTable({
    caption: 'Risk register',
    initialFilters: { level: params.level || '' }, initialSort: { sort: 'residual_score', order: 'desc' },
    filters: [{ key: 'q', label: 'Search risks…', type: 'search' }, { key: 'level', label: 'All levels', type: 'select', options: LEVELS }, { key: 'status', label: 'All statuses', type: 'select', options: STATUSES },
      { key: 'business_unit', label: 'All business units', type: 'select', options: ['Engineering', 'Finance', 'Human Resources', 'Sales', 'Operations', 'IT Infrastructure', 'Customer Support', 'Legal'] }],
    load: (p) => api('/api/risks' + qs(p)),
    columns: [
      { key: 'risk_code', label: 'ID', sort: 'risk_code', mono: true },
      { key: 'title', label: 'Risk', sort: 'title', render: (r) => el('span', {}, r.title, r.approval_status === 'PENDING' ? [' ', badge('Approval pending', 'med')] : null) },
      { key: 'asset_tag', label: 'Asset', mono: true, render: (r) => monoText(r.asset_tag) },
      { key: 'inherent_score', label: 'Inherent', sort: 'inherent_score', num: true, render: (r) => fmt(r.inherent_score, 0) },
      { key: 'residual_score', label: 'Residual', sort: 'residual_score', num: true, render: (r) => scoreBar(r.residual_score, 25, fmt(r.residual_score, 1)) },
      { key: 'risk_level', label: 'Level', sort: 'risk_level', render: (r) => levelBadge(r.risk_level) },
      { key: 'status', label: 'Status', sort: 'status', render: (r) => statusBadge(r.status) },
      { key: 'owner', label: 'Owner', sort: 'owner' }],
    onRow: (r) => openRiskDrawer(r.id, () => table.refresh()),
  });
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Risks'), el('p', {}, 'Scores are calculated deterministically from likelihood, impact and linked control effectiveness.')),
    el('div', { class: 'actions' }, el('button', { class: 'btn', onclick: () => suggestions(() => table.refresh()) }, 'Suggest from vulnerabilities'),
      el('button', { class: 'btn primary', onclick: () => newRiskForm(() => table.refresh()) }, 'Add risk'))), table);
}

function newRiskForm(done) {
  const d = openDrawer({ heading: 'Add risk', subtitle: 'Scores are calculated on save' });
  const f = { title: el('input', { type: 'text', maxlength: '200', required: true }), likelihood: el('select', {}, [1, 2, 3, 4, 5].map((n) => el('option', { value: n }, n))),
    impact: el('select', {}, [1, 2, 3, 4, 5].map((n) => el('option', { value: n }, n))), owner: el('input', { type: 'text', maxlength: '80' }), category: el('input', { type: 'text', maxlength: '80' }),
    asset: el('select', { 'aria-label': 'Asset' }, el('option', { value: '' }, 'No specific asset')) };
  api('/api/assets?page_size=200').then((a) => a.items.forEach((x) => f.asset.append(el('option', { value: x.id }, `${x.asset_tag} (${title(x.criticality)})`)))).catch(() => {});
  const preview = el('div', { class: 'formula' });
  const upd = () => { const i = f.likelihood.value * f.impact.value; preview.textContent = `inherent = ${f.likelihood.value} × ${f.impact.value} = ${i} → ${i >= 17 ? 'CRITICAL' : i >= 10 ? 'HIGH' : i >= 5 ? 'MEDIUM' : 'LOW'} (before controls)`; };
  f.likelihood.onchange = f.impact.onchange = upd; upd();
  const field = (label, node) => el('label', { class: 'field mb' }, label, node);
  d.body.append(field('Title', f.title), el('div', { class: 'grid g2' }, field('Likelihood (1–5)', f.likelihood), field('Impact (1–5)', f.impact)), preview,
    el('div', { class: 'grid g2', style: 'margin-top:12px' }, field('Owner', f.owner), field('Category', f.category)), field('Affected asset', f.asset),
    el('div', { class: 'actions', style: 'margin-top:16px' }, el('button', { class: 'btn primary', onclick: async () => {
      try {
        const r = await api('/api/risks', { method: 'POST', body: { title: f.title.value, likelihood: +f.likelihood.value, impact: +f.impact.value, owner: f.owner.value || null, category: f.category.value || null, asset_id: f.asset.value ? +f.asset.value : null } });
        toast(`Created ${r.risk_code}`); d.close(); done();
      } catch (e) { toast(e.body?.error?.details?.map((x) => x.message).join('; ') || e.message, 'err'); }
    } }, 'Create risk')));
}

export async function openRiskDrawer(id, onChange) {
  const d = openDrawer({ heading: 'Risk', subtitle: 'Loading…' });
  d.body.append(skeleton(8));
  let r;
  try { r = await api(`/api/risks/${id}`); } catch (e) { clear(d.body).append(errorBox(e, () => openRiskDrawer(id, onChange))); return; }
  d.setTitle(`${r.risk_code} · ${r.title}`, `${r.category || 'Uncategorised'} · owner ${r.owner || 'unassigned'}`);
  clear(d.body);

  d.body.append(el('div', { class: 'actions mb' }, levelBadge(r.risk_level), statusBadge(r.status), r.treatment ? badge(`Treatment: ${title(r.treatment)}`, 'outline') : null,
    r.asset ? badge(r.asset.asset_tag, 'outline') : null));

  // pending acceptance approval (human only)
  if (r.approval_status === 'PENDING') d.body.append(approvalBox(r, () => { openRiskDrawer(id, onChange); onChange?.(); }));

  d.body.append(section('How this score is calculated',
    el('div', { class: 'formula' }, `inherent  = likelihood × impact = ${r.likelihood} × ${r.impact} = ${fmt(r.inherent_score, 0)}\n`,
      `effective control strength = ${fmt(r.control_effectiveness * 100, 0)}%\nresidual = ${fmt(r.inherent_score, 0)} × (1 − ${fmt(r.control_effectiveness, 2)}) = `, el('strong', {}, fmt(r.residual_score, 2)), ` → ${r.risk_level}`)));

  // AI (contextual)
  const aiOut = el('div', { style: 'margin-top:10px' });
  d.body.append(section('AI assistance', el('div', { class: 'actions' },
    el('button', { class: 'btn primary', onclick: () => runAI(aiOut, '/api/ai/investigate', { risk_id: id }) }, `Investigate with ${ai.name}`),
    el('button', { class: 'btn', onclick: () => runAI(aiOut, '/api/ai/remediation', { risk_id: id }) }, 'Generate remediation'),
    el('button', { class: 'btn', onclick: () => runAI(aiOut, '/api/ai/suggest-mappings', { risk_id: id }, { onDecision: () => openRiskDrawer(id, onChange) }) }, 'Suggest mappings')), aiOut));

  // controls + mappings
  d.body.append(section('Linked controls', el('div', { class: 'actions', style: 'margin-bottom:8px' }, el('button', { class: 'btn sm', onclick: () => editControls(r, () => { openRiskDrawer(id, onChange); onChange?.(); }) }, 'Edit linked controls')), simpleTable([
    { label: 'Control', render: (c) => el('span', {}, monoText(c.control_code), ' ', c.title) }, { label: 'Framework', key: 'framework' },
    { label: 'Status', render: (c) => statusBadge(c.implementation_status) }, { label: 'Strength', num: true, render: (c) => fmt(c.effectiveness * 100, 0) + '%' }], r.controls, { empty: 'No controls linked: residual risk currently assumes zero mitigation.' })));
  d.body.append(section('Framework mappings', el('p', { class: 'small muted' }, r.mapping_note),
    simpleTable([{ label: 'Framework', render: (m) => `${m.framework} ${m.framework_version || ''}` }, { label: 'Reference', render: (m) => monoText(m.reference) }, { label: 'Title', key: 'title' },
      { label: 'Origin', render: (m) => badge(m.origin === 'AI_SUGGESTED' ? 'AI-suggested' : 'Curated', m.origin === 'AI_SUGGESTED' ? 'med' : 'info') },
      { label: 'Review', render: (m) => statusBadge(m.review_state) }], r.mappings, { empty: 'No mappings.' })));

  // remediation + simulation
  const simOut = el('div', { style: 'margin-top:10px' });
  const checks = [];
  const open = r.remediation.filter((a) => a.status !== 'COMPLETED');
  const actionRows = r.remediation.map((a) => {
    const cb = el('input', { type: 'checkbox', disabled: a.status === 'COMPLETED', 'aria-label': `Include ${a.action} in simulation` });
    checks.push([a.id, cb]);
    return el('tr', {}, el('td', {}, cb), el('td', {}, a.action), el('td', {}, statusBadge(a.status)), el('td', { class: 'num' }, `+${fmt(a.effectiveness_gain * 100, 0)}%`), el('td', {}, fmtDate(a.due_date)));
  });
  d.body.append(section('Remediation and what-if simulation',
    r.remediation.length ? el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['Sim', 'Action', 'Status', 'Assumed gain', 'Due'].map((h) => el('th', { scope: 'col' }, h)))), el('tbody', {}, actionRows))) : el('div', { class: 'muted small' }, 'No remediation actions recorded.'),
    open.length ? el('div', { class: 'actions', style: 'margin-top:8px' }, el('button', { class: 'btn', onclick: async () => {
      const ids = checks.filter(([, cb]) => cb.checked).map(([i]) => i);
      clear(simOut).append(skeleton(2));
      try {
        const s = await api(`/api/risks/${id}/simulate`, { method: 'POST', body: { action_ids: ids } });
        clear(simOut).append(el('div', { class: 'notice' },
          el('div', { style: 'font-weight:600' }, 'Projection (not a guarantee)'),
          el('div', {}, `Residual ${fmt(s.current_residual, 2)} → ${fmt(s.projected_residual, 2)} (Δ ${fmt(s.delta, 2)}) · ${s.current_level} → ${s.projected_level}`),
          el('div', { class: 'small muted' }, `Enterprise score ${fmt(s.enterprise_current, 1)} → ${fmt(s.enterprise_projected, 1)}. Calculated deterministically; the simulation does not change stored data.`)));
      } catch (e) { clear(simOut).append(notice(e.message, 'err')); }
    } }, 'Run simulation')) : null, simOut));

  // history
  const hb = chartBox('sm');
  d.body.append(section('Residual score history', hb.box, el('div', { class: 'legend-note' }, 'Earlier points are a synthetic baseline; the latest reflects the current calculation.')));
  api(`/api/risks/${id}/history`).then((h) => chart(hb.canvas, { type: 'line', data: { labels: h.items.map((x) => fmtDate(x.recorded_at)), datasets: [{ label: 'Residual score', data: h.items.map((x) => x.score), borderColor: '#3a5a78', tension: .2, pointRadius: 3 }] },
    options: { plugins: { legend: { display: false } }, scales: { y: { ...gridOpts, beginAtZero: true }, x: { grid: { display: false } } } } })).catch(() => {});

  if (r.related_vulnerabilities.length) d.body.append(section('Open vulnerabilities on this asset', simpleTable([
    { label: 'CVE', render: (v) => monoText(v.cve_id) }, { label: 'Severity', render: (v) => levelBadge(v.severity) }, { label: 'CVSS', num: true, render: (v) => fmt(v.cvss_score) },
    { label: 'KEV', render: (v) => v.known_exploited ? badge('KEV', 'crit') : '—' }, { label: 'Due', render: (v) => fmtDate(v.due_date) }], r.related_vulnerabilities)));

  d.body.append(section('Details', kv([['Asset', r.asset ? `${r.asset.asset_tag} (${r.asset.business_unit}, ${title(r.asset.criticality)})` : '—'], ['Due', fmtDate(r.due_date)], ['Approval', title(r.approval_status)]])));
}

function approvalBox(r, done) {
  const name = el('input', { type: 'text', placeholder: 'Reviewer name', 'aria-label': 'Reviewer name' });
  const note = el('input', { type: 'text', placeholder: 'Rationale', 'aria-label': 'Rationale' });
  const act = async (decision) => {
    try { await api(`/api/risks/${r.id}/approval`, { method: 'POST', body: { decision, reviewer: name.value.trim(), comments: note.value.trim() || null } }); toast(`Acceptance ${decision.toLowerCase()}`); done(); }
    catch (e) { toast(e.body?.error?.details?.map((x) => x.message).join('; ') || e.message, 'err'); }
  };
  return el('div', { class: 'notice warn mb' }, el('div', { style: 'font-weight:600' }, `Acceptance of a ${r.risk_level} risk needs human approval`),
    el('div', { class: 'small muted', style: 'margin:4px 0 8px' }, 'Neither the system nor AI can accept a high or critical risk.'),
    el('div', { class: 'actions' }, name, note, el('button', { class: 'btn sm primary', onclick: () => act('APPROVED') }, 'Approve acceptance'), el('button', { class: 'btn sm danger', onclick: () => act('REJECTED') }, 'Reject')));
}


async function editControls(r, done) {
  const d = openDrawer({ heading: 'Linked controls', subtitle: `${r.risk_code} · only controls you link reduce this risk` });
  d.body.append(skeleton(5));
  let data;
  try { data = await api('/api/controls?page_size=200'); } catch (e) { clear(d.body).append(errorBox(e)); return; }
  const have = new Set(r.controls.map((c) => `${c.framework}/${c.control_code}`));
  const boxes = [];
  const q = el('input', { type: 'search', placeholder: 'Filter controls…', 'aria-label': 'Filter controls' });
  const list = el('div', { style: 'max-height:56vh;overflow:auto;border:1px solid var(--border);border-radius:4px' });
  data.items.forEach((c) => {
    const cb = el('input', { type: 'checkbox', checked: have.has(`${c.framework}/${c.control_code}`), 'aria-label': `${c.framework} ${c.control_code}` });
    boxes.push([c.id, cb]);
    list.append(el('label', { style: 'display:flex;gap:8px;padding:6px 10px;border-bottom:1px solid var(--border)', dataset: { text: `${c.framework} ${c.control_code} ${c.title}`.toLowerCase() } }, cb,
      el('span', {}, monoText(c.control_code), ' ', c.title, el('span', { class: 'small faint' }, ` · ${c.framework} · ${title(c.implementation_status)}`))));
  });
  q.addEventListener('input', () => list.querySelectorAll('label').forEach((l) => { l.style.display = l.dataset.text.includes(q.value.toLowerCase()) ? 'flex' : 'none'; }));
  clear(d.body).append(el('p', { class: 'small muted' }, 'Residual risk uses the average effectiveness of the linked controls you have assessed.'), q, list,
    el('div', { class: 'actions', style: 'margin-top:12px' }, el('button', { class: 'btn primary', onclick: async () => {
      try { const out = await api(`/api/risks/${r.id}/controls`, { method: 'PUT', body: { control_ids: boxes.filter(([, cb]) => cb.checked).map(([i]) => i) } });
        toast(`Residual risk now ${fmt(out.residual, 1)} (${out.level})`); d.close(); done(); } catch (e) { toast(e.message, 'err'); }
    } }, 'Save links')));
}

async function suggestions(done) {
  const d = openDrawer({ heading: 'Suggested risks', subtitle: 'Proposed from your vulnerability data. Nothing is created until you accept.' });
  d.body.append(skeleton(4));
  let data;
  try { data = await api('/api/risks-suggestions'); } catch (e) { clear(d.body).append(errorBox(e)); return; }
  clear(d.body);
  if (!data.items.length) { d.body.append(notice('No suggestions: either there are no open critical or known-exploited vulnerabilities on assets without a vulnerability risk, or no vulnerability data has been imported yet.')); return; }
  const boxes = [];
  data.items.forEach((s) => {
    const cb = el('input', { type: 'checkbox', 'aria-label': `Accept ${s.title}` });
    boxes.push([s.asset_id, cb]);
    d.body.append(el('div', { class: 'card mb' }, el('label', { class: 'card-b', style: 'display:flex;gap:10px;align-items:flex-start' }, cb,
      el('div', {}, el('strong', {}, s.title), ' ', levelBadge(s.inherent_score >= 17 ? 'CRITICAL' : s.inherent_score >= 10 ? 'HIGH' : 'MEDIUM'), el('div', { class: 'small muted' }, s.rationale), el('div', { class: 'small faint' }, `Likelihood ${s.likelihood} × impact ${s.impact} = ${s.inherent_score}`)))));
  });
  d.body.append(el('button', { class: 'btn primary', onclick: async () => {
    const ids = boxes.filter(([, cb]) => cb.checked).map(([i]) => i);
    if (!ids.length) { toast('Tick at least one suggestion', 'err'); return; }
    try { const r = await api('/api/risks-suggestions/accept', { method: 'POST', body: { asset_ids: ids } }); toast(`Created ${r.created.length} risk(s)`); d.close(); done(); } catch (e) { toast(e.message, 'err'); }
  } }, 'Create selected risks'));
}
