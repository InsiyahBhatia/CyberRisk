import { api, el, clear, qs, fmt, fmtDate, dataTable, levelBadge, statusBadge, badge, monoText, scoreBar, openDrawer, kv, section, skeleton, errorBox, simpleTable, notice, tabs, toast, formField, title } from '../core.js';

export async function controls(root, params = {}) {
  const table = dataTable({
    caption: 'Controls', pageSize: 20, initialFilters: { framework: params.framework || '' },
    filters: [{ key: 'q', label: 'Search controls…', type: 'search' }, { key: 'framework', label: 'All frameworks', type: 'select', options: ['NIST CSF', 'ISO/IEC 27001', 'SOC 2'] },
      { key: 'status', label: 'All statuses', type: 'select', options: ['IMPLEMENTED', 'PARTIAL', 'NOT_IMPLEMENTED', 'NOT_APPLICABLE'] }, { key: 'evidence', label: 'Any evidence', type: 'select', options: ['PRESENT', 'MISSING', 'EXPIRED', 'NEEDS_REVIEW'] }],
    load: (p) => api('/api/controls' + qs(p)),
    columns: [{ key: 'control_code', label: 'Control ID', mono: true }, { key: 'framework', label: 'Framework', render: (c) => `${c.framework} ${c.framework_version}` }, { key: 'title', label: 'Title' },
      { key: 'implementation_status', label: 'Status', render: (c) => statusBadge(c.implementation_status) }, { key: 'evidence_status', label: 'Evidence', render: (c) => statusBadge(c.evidence_status) },
      { key: 'owner', label: 'Owner' }, { key: 'effectiveness', label: 'Effectiveness', render: (c) => scoreBar(c.effectiveness * 100, 100, fmt(c.effectiveness * 100, 0) + '%') }],
    onRow: (c) => openControl(c.id),
  });
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Controls'), el('p', {}, 'Curated framework controls with synthetic implementation status and evidence. Mappings are curated or human-approved.'))), table);
}

async function openControl(id) {
  const d = openDrawer({ heading: 'Control', subtitle: 'Loading…' });
  d.body.append(skeleton(5));
  let c, ev;
  try { [c, ev] = await Promise.all([api(`/api/controls/${id}`), api(`/api/controls/${id}/evidence`)]); } catch (e) { clear(d.body).append(errorBox(e, () => openControl(id))); return; }
  d.setTitle(`${c.control_code} · ${c.title}`, `${c.framework} ${c.framework_version}`);
  clear(d.body).append(el('div', { class: 'actions mb' }, statusBadge(c.implementation_status), statusBadge(c.evidence_status)), section('Description', el('p', {}, c.description)),
    section('Evidence', simpleTable([{ label: 'ID', render: (e) => monoText(e.title) }, { label: 'Type', key: 'evidence_type' }, { label: 'Status', render: (e) => statusBadge(e.status) }, { label: 'Collected', render: (e) => fmtDate(e.collected_at) }, { label: 'Expires', render: (e) => fmtDate(e.expiry_date) }], ev.items, { empty: 'No evidence recorded: treated as MISSING.' })),
    section('Linked risks', simpleTable([{ label: 'Risk', render: (r) => `${r.risk_code} ${r.title}` }, { label: 'Level', render: (r) => levelBadge(r.risk_level) }], c.linked_risks, { empty: 'No risks reference this control.' })),
    section('Record', kv([['Owner', c.owner], ['Effectiveness', fmt(c.effectiveness * 100, 0) + '%'], ['Category', c.category]])),
    assessForm(c, () => openControl(id)), evidenceForm(c, () => openControl(id)));
}

function assessForm(c, reload) {
  const st = el('select', { 'aria-label': 'Implementation status' }, ['IMPLEMENTED', 'PARTIAL', 'NOT_IMPLEMENTED', 'NOT_APPLICABLE'].map((s) => el('option', { value: s, selected: s === c.implementation_status }, title(s))));
  const eff = el('input', { type: 'range', min: '0', max: '100', step: '5', value: Math.round(c.effectiveness * 100), 'aria-label': 'Effectiveness' });
  const effOut = el('output', { class: 'mono' }, `${Math.round(c.effectiveness * 100)}%`);
  eff.addEventListener('input', () => { effOut.textContent = `${eff.value}%`; });
  const owner = el('input', { type: 'text', maxlength: '80', value: c.owner || '', placeholder: 'Control owner', 'aria-label': 'Owner' });
  return section('Assess this control', el('div', { class: 'card' }, el('div', { class: 'card-b' },
    el('p', { class: 'small muted' }, 'Your assessment drives residual risk for every risk linked to this control. Effectiveness is how much of the risk it removes when working (0–100%).'),
    formField('Implementation status', st), formField('Effectiveness', el('div', { class: 'actions' }, eff, effOut)), formField('Owner', owner),
    el('button', { class: 'btn primary', onclick: async () => {
      try { const r = await api(`/api/controls/${c.id}`, { method: 'PATCH', body: { implementation_status: st.value, effectiveness: +eff.value / 100, owner: owner.value || null } }); toast(`Saved. ${r.risks_recalculated} risks recalculated.`); reload(); }
      catch (e) { toast(e.message, 'err'); }
    } }, 'Save assessment'))));
}

function evidenceForm(c, reload) {
  const t = el('input', { type: 'text', maxlength: '160', placeholder: 'e.g. Q3 access review sign-off', 'aria-label': 'Evidence title' });
  const type = el('select', { 'aria-label': 'Evidence type' }, ['Policy', 'Configuration Screenshot', 'Audit Report', 'Access Review', 'Log Extract', 'Document'].map((x) => el('option', { value: x }, x)));
  const loc = el('input', { type: 'text', maxlength: '300', placeholder: 'Link or file location (optional)', 'aria-label': 'Location' });
  const col = el('input', { type: 'date', 'aria-label': 'Collected on' });
  const exp = el('input', { type: 'date', 'aria-label': 'Expires on' });
  return section('Add evidence', el('div', { class: 'card' }, el('div', { class: 'card-b' }, formField('Title', t), el('div', { class: 'grid g2' }, formField('Type', type), formField('Location', loc)),
    el('div', { class: 'grid g2' }, formField('Collected', col), formField('Expires', exp, 'Past-expiry evidence is stored as EXPIRED')),
    el('button', { class: 'btn', onclick: async () => {
      try { await api(`/api/controls/${c.id}/evidence`, { method: 'POST', body: { title: t.value.trim(), evidence_type: type.value, location: loc.value || null, collected_at: col.value || null, expiry_date: exp.value || null } }); toast('Evidence added'); reload(); }
      catch (e) { toast(e.body?.error?.details?.map((x) => x.message).join('; ') || e.message, 'err'); }
    } }, 'Add evidence'))));
}

export async function compliance(root) {
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Compliance'),
    el('p', {}, 'Readiness metrics computed from control status and evidence. This is not a certification or audit opinion.'))));
  const host = el('div', {}, skeleton(6));
  root.append(host);
  let data;
  try { data = await api('/api/compliance/summary'); } catch (e) { clear(host).append(errorBox(e, () => { root.replaceChildren(); compliance(root); })); return; }
  clear(host);
  host.append(el('div', { class: 'grid g3 mb' }, data.frameworks.map((f) => el('div', { class: 'card kpi' },
    el('div', { class: 'label' }, el('span', {}, `${f.name} ${f.version}`), el('button', { class: 'btn ghost sm', onclick: () => show(f.id) }, 'Breakdown')),
    el('div', { class: 'value' }, fmt(f.control_coverage, 1), el('small', {}, '% controls implemented')),
    el('div', { class: 'bar', 'aria-hidden': 'true' }, el('i', { style: `width:${f.control_coverage}%` })),
    el('div', { class: 'sub', style: 'margin-top:8px' }, `Evidence coverage ${fmt(f.evidence_coverage, 1)}% (${f.controls_with_valid_evidence}/${f.applicable_controls} applicable controls with valid evidence)`),
    el('div', { class: 'small faint' }, Object.entries(f.evidence_breakdown).map(([k, n]) => `${n} ${k.toLowerCase().replace('_', ' ')}`).join(' · '))))));
  const detail = el('div', {});
  host.append(el('div', { class: 'notice mb' }, 'Control coverage = implemented ÷ applicable controls. Evidence coverage = controls with valid (PRESENT, unexpired) evidence ÷ applicable controls. Expired evidence counts as missing.'), detail);
  async function show(fid) {
    clear(detail).append(skeleton(4));
    try {
      const f = await api(`/api/compliance/${fid}`);
      clear(detail).append(el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, `${f.name} ${f.version}: by category`), el('a', { href: `#/controls?framework=${encodeURIComponent(f.name)}` }, 'View controls')),
        simpleTable([{ label: 'Category', key: 'category' }, { label: 'Applicable', num: true, key: 'applicable_controls' }, { label: 'Implemented', num: true, key: 'implemented_controls' },
          { label: 'Control coverage', render: (c) => scoreBar(c.control_coverage, 100, fmt(c.control_coverage, 0) + '%') }, { label: 'Evidence coverage', render: (c) => scoreBar(c.evidence_coverage, 100, fmt(c.evidence_coverage, 0) + '%') }], f.categories)));
      detail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (e) { clear(detail).append(errorBox(e)); }
  }
  if (data.frameworks[0]) show(data.frameworks[0].id);
}
