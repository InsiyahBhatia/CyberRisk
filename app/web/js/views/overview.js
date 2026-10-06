import { ai, api, el, clear, fmt, levelBadge, statusBadge, relTime, skeleton, errorBox, chart, chartBox, gridOpts, LEVEL_COLORS, simpleTable, monoText, scoreBar, badge, openDrawer } from '../core.js';
import { runAI, openAskPanel } from '../ai.js';
import { openRiskDrawer } from './risks.js';
import { openVulnDrawer } from './vulns.js';

function kpi(label, value, { unit = '', sub = '', hero = false, bar = null, note = '' } = {}) {
  return el('div', { class: `card kpi ${hero ? 'hero' : ''}` },
    el('div', { class: 'label' }, el('span', {}, label), note ? el('span', { class: 'faint', title: note }, 'ⓘ') : null),
    el('div', { class: 'value' }, value === null || value === undefined ? '—' : value, value !== null && value !== undefined && unit ? el('small', {}, unit) : null),
    el('div', { class: 'sub' }, sub),
    bar !== null ? el('div', { class: 'bar', 'aria-hidden': 'true' }, el('i', { style: `width:${Math.min(100, bar)}%` })) : null);
}

function heatmap(cells) {
  const m = {};
  cells.forEach((c) => { m[`${c.likelihood}-${c.impact}`] = c.count; });
  const colorFor = (l, i) => { const s = l * i; return s >= 17 ? 'var(--crit-bg)' : s >= 10 ? 'var(--high-bg)' : s >= 5 ? 'var(--med-bg)' : 'var(--low-bg)'; };
  const g = el('div', { class: 'heat', role: 'table', 'aria-label': 'Open risks by likelihood and impact' });
  for (let l = 5; l >= 1; l--) {
    g.append(el('div', { class: 'axis' }, `L${l}`));
    for (let i = 1; i <= 5; i++) {
      const n = m[`${l}-${i}`] || 0;
      g.append(el('div', { class: 'cell', style: `background:${colorFor(l, i)}`, title: `Likelihood ${l} × Impact ${i} = ${l * i}: ${n} open risk(s)`, role: 'cell' }, n || ''));
    }
  }
  g.append(el('div', { class: 'axis' }, ''), ...[1, 2, 3, 4, 5].map((i) => el('div', { class: 'axis' }, `I${i}`)));
  return g;
}

export async function overview(root) {
  const head = el('div', { class: 'page-head' },
    el('div', {}, el('h1', {}, 'Overview'), el('p', {}, 'Enterprise cyber risk, calculated from your data. AI explains; it never scores.')),
    el('div', { class: 'actions' }, el('button', { class: 'btn', onclick: () => openAskPanel() }, 'Ask about data'),
      el('button', { class: 'btn primary', onclick: summarize }, 'Summarize for executives')));
  const body = el('div', {}, skeleton(8));
  root.append(head, body);

  function summarize() {
    const d = openDrawer({ heading: 'Executive summary', subtitle: 'Generated from calculated KPIs and retrieved policy text' });
    runAI(d.body, '/api/ai/executive-summary');
  }

  let s, trend, bu, heat, sources;
  try {
    [s, trend, bu, heat, sources] = await Promise.all([api('/api/dashboard/summary'), api('/api/dashboard/risk-trend'), api('/api/dashboard/business-units'),
      api('/api/dashboard/heatmap'), api('/api/data-sources')]);
  } catch (e) { clear(body).append(errorBox(e, () => { root.replaceChildren(); overview(root); })); return; }
  const k = s.kpis;
  clear(body);
  if (!s.top_risks.length && !k.open_vulnerabilities) body.append(el('div', { class: 'notice warn mb' }, 'This workspace has no risks or vulnerability findings yet, so the figures below are zero. ', el('a', { href: '#/setup' }, 'Follow the setup checklist'), ' to import data and assess controls.'));

  const pub = sources.items.filter((x) => x.source_type === 'PUBLIC');
  body.append(el('div', { class: 'small muted mb', style: 'display:flex;gap:14px;flex-wrap:wrap' },
    pub.map((p) => el('span', {}, el('span', { class: `dot`, style: `color:${p.status === 'HEALTHY' ? 'var(--low)' : p.status === 'CACHED' ? 'var(--med)' : 'var(--crit)'}`, 'aria-hidden': 'true' }), ' ',
      `${p.source_name}: ${p.status === 'CACHED' ? 'cached snapshot from ' : 'synced '}${relTime(p.retrieval_timestamp)}`, p.status === 'FAILED' ? ' (failed)' : '')),
    el('span', { class: 'faint' }, '· Organisational data (assets, people, vendors, evidence) is synthetic.')));

  body.append(el('div', { class: 'grid g4 mb' },
    kpi('Enterprise risk score', fmt(k.enterprise_risk_score, 1), { unit: '/100', hero: true, bar: k.enterprise_risk_score, sub: `${k.critical_risks} critical, ${k.high_risks} high open risks`, note: 'Weighted mean of normalised residual risk and share of HIGH/CRITICAL risks. Deterministic.' }),
    kpi('Critical findings', fmt(k.critical_findings, 0), { hero: true, sub: 'Open CRITICAL-severity vulnerabilities' }),
    kpi('Open vulnerabilities', fmt(k.open_vulnerabilities, 0), { hero: true, sub: `${fmt(k.overdue_vulnerabilities, 0)} overdue · ${fmt(k.known_exploited_open, 0)} in CISA KEV` }),
    kpi('Control coverage', fmt(k.control_coverage, 1), { unit: '%', hero: true, bar: k.control_coverage, sub: 'Implemented / applicable controls', note: 'Internal readiness metric; not a certification.' })));
  body.append(el('div', { class: 'grid g4 mb' },
    kpi('MFA adoption', k.mfa_adoption === null ? null : fmt(k.mfa_adoption, 1), { unit: '%', bar: k.mfa_adoption, sub: 'Active accounts with MFA' }),
    kpi('High-risk vendors', fmt(k.high_risk_vendors, 0), { sub: 'Residual vendor risk ≥ 7 / 10' }),
    kpi('Open incidents', fmt(k.open_incidents, 0), { sub: 'Not yet closed' }),
    kpi('Mean time to remediate', k.mean_time_to_remediate_days === null ? null : fmt(k.mean_time_to_remediate_days, 1), { unit: ' days', sub: 'Resolved vulnerabilities, discovery to fix' })));
  const aiNote = k.ai_eval_measured ? `Measured by ${k.ai_eval_mode === 'live' ? `live ${ai.name}` : 'guardrails-only'} eval run` : 'Not measured yet. Run evals.';
  body.append(el('div', { class: 'grid g2 mb' },
    kpi('AI grounding score', k.ai_grounding_score === null ? null : fmt(k.ai_grounding_score, 1), { unit: '%', sub: k.ai_grounding_score === null ? `Needs a live ${ai.name} eval run` : aiNote, note: 'Share of findings with valid supporting evidence in the eval set.' }),
    kpi('AI security pass rate', k.ai_security_pass_rate === null ? null : fmt(k.ai_security_pass_rate, 1), { unit: '%', sub: aiNote, note: 'Prompt injection, RAG poisoning and PII cases.' })));

  // charts
  const t = chartBox(), lv = chartBox('sm'), bc = chartBox(), rem = chartBox('sm');
  body.append(el('div', { class: 'grid g-main mb' },
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Risk trend'), el('span', { class: 'small faint' }, 'Mean residual risk, 0–100')), el('div', { class: 'card-b' }, t.box, el('div', { class: 'legend-note' }, trend.note))),
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Open risks by level')), el('div', { class: 'card-b' }, lv.box))));
  chart(t.canvas, { type: 'line', data: { labels: trend.points.map((p) => p.month), datasets: [{ label: 'Mean residual risk (0–100)', data: trend.points.map((p) => p.score), borderColor: '#3a5a78', backgroundColor: '#3a5a78', tension: .25, pointRadius: 3 }] },
    options: { plugins: { legend: { display: false } }, scales: { y: { ...gridOpts, beginAtZero: true, suggestedMax: 60 }, x: { ...gridOpts, grid: { display: false } } } } });
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const lvData = order.map((l) => (s.risk_levels.find((x) => x.label === l) || {}).count || 0);
  chart(lv.canvas, { type: 'doughnut', data: { labels: order, datasets: [{ data: lvData, backgroundColor: order.map((l) => LEVEL_COLORS[l]), borderWidth: 2, borderColor: '#fff' }] },
    options: { cutout: '62%', plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, generateLabels: (c) => c.data.labels.map((l, i) => ({ text: `${l} (${c.data.datasets[0].data[i]})`, fillStyle: c.data.datasets[0].backgroundColor[i], index: i })) } } } } });

  body.append(el('div', { class: 'grid g-main mb' },
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Business-unit risk'), el('span', { class: 'small faint' }, 'Average residual score (0–25) and open vulnerabilities')), el('div', { class: 'card-b' }, bc.box)),
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Risk heatmap'), el('span', { class: 'small faint' }, 'Open risks')), el('div', { class: 'card-b' }, heatmap(heat.cells)))));
  const buRows = bu.items.filter((b) => b.business_unit);
  chart(bc.canvas, { type: 'bar', data: { labels: buRows.map((b) => b.business_unit), datasets: [
    { label: 'Avg residual risk', data: buRows.map((b) => b.avg_residual_risk), backgroundColor: '#3a5a78', yAxisID: 'y' },
    { label: 'Open vulnerabilities', data: buRows.map((b) => b.open_vulns), backgroundColor: '#b9b6ab', yAxisID: 'y1' }] },
    options: { plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } }, scales: { x: { grid: { display: false } }, y: { ...gridOpts, beginAtZero: true, title: { display: true, text: 'Risk' } }, y1: { position: 'right', grid: { display: false }, beginAtZero: true, title: { display: true, text: 'Vulns' } } } } });

  body.append(el('div', { class: 'grid g2 mb' },
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Highest-priority risks'), el('a', { href: '#/risks' }, 'View all')),
      simpleTable([{ label: 'Risk', render: (r) => el('a', { href: '#', onclick: (e) => { e.preventDefault(); openRiskDrawer(r.id); } }, `${r.risk_code} ${r.title}`) },
        { label: 'Residual', num: true, render: (r) => fmt(r.residual_score, 1) }, { label: 'Level', render: (r) => levelBadge(r.risk_level) }], s.top_risks)),
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Highest-priority vulnerabilities'), el('a', { href: '#/vulnerabilities' }, 'View all')),
      simpleTable([{ label: 'CVE', render: (v) => el('a', { href: '#', onclick: (e) => { e.preventDefault(); openVulnDrawer(v.id); } }, v.cve_id) }, { label: 'Asset', key: 'asset_tag', mono: true },
        { label: 'Severity', render: (v) => levelBadge(v.severity) }, { label: 'KEV', render: (v) => v.known_exploited ? badge('KEV', 'crit') : '—' },
        { label: 'Priority', render: (v) => scoreBar(v.risk_score, 100, fmt(v.risk_score, 0)) }], s.top_vulnerabilities))));

  const cb = chartBox('sm');
  body.append(el('div', { class: 'grid g2' },
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Control and evidence coverage'), el('a', { href: '#/compliance' }, 'Details')), el('div', { class: 'card-b' }, cb.box,
      el('div', { class: 'legend-note' }, 'Internal readiness metrics from synthetic control data; not a certification.'))),
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Remediation actions')),
      simpleTable([{ label: 'Status', render: (r) => statusBadge(r.label) }, { label: 'Actions', num: true, key: 'count' }], s.remediation))));
  chart(cb.canvas, { type: 'bar', data: { labels: s.compliance.map((c) => c.name), datasets: [
    { label: 'Control coverage %', data: s.compliance.map((c) => c.control_coverage), backgroundColor: '#3a5a78' },
    { label: 'Evidence coverage %', data: s.compliance.map((c) => c.evidence_coverage), backgroundColor: '#b9b6ab' }] },
    options: { plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } }, scales: { y: { ...gridOpts, beginAtZero: true, max: 100 }, x: { grid: { display: false } } } } });
}
