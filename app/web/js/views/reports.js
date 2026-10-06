import { api, el, clear, fmt, levelBadge, badge, skeleton, errorBox, simpleTable, openReport, notice, toast, openDrawer } from '../core.js';
import { runAI } from '../ai.js';

export async function reports(root) {
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Reports'), el('p', {}, 'A risk assessment you can hand to a client or executive. Every figure is calculated; recommendations cite their evidence.')),
    el('div', { class: 'actions' },
      el('button', { class: 'btn', onclick: () => openReport('/api/reports/risk-register.csv', { download: true, filename: 'risk-register.csv' }).catch((e) => toast(e.message, 'err')) }, 'Export risk register (CSV)'),
      el('button', { class: 'btn', onclick: () => { const d = openDrawer({ heading: 'Executive summary', subtitle: 'Written from the calculated figures' }); runAI(d.body, '/api/ai/executive-summary'); } }, 'Summarize for executives'),
      el('button', { class: 'btn primary', onclick: () => openReport('/api/reports/assessment.html', { download: true, filename: 'risk-assessment.html' }).catch((e) => toast(e.message, 'err')) }, 'Download assessment report'))));
  const host = el('div', {}, skeleton(8));
  root.append(host);
  let d;
  try { d = await api('/api/reports/assessment'); } catch (e) { clear(host).append(errorBox(e, () => { root.replaceChildren(); reports(root); })); return; }
  clear(host);
  if (!d.open_risks) { host.append(el('div', { class: 'card' }, el('div', { class: 'state' }, el('strong', {}, 'Nothing to report yet'), 'Register risks and assess controls first.', el('div', { style: 'margin-top:10px' }, el('a', { class: 'btn', href: '#/setup' }, 'Open the setup checklist'))))); return; }
  host.append(el('div', { class: 'grid g4 mb' },
    el('div', { class: 'card kpi hero' }, el('div', { class: 'label' }, 'Enterprise risk score'), el('div', { class: 'value' }, fmt(d.enterprise_score, 1), el('small', {}, '/100')), el('div', { class: 'sub' }, `${d.open_risks} open risks`)),
    ...['CRITICAL', 'HIGH', 'MEDIUM'].map((l) => el('div', { class: 'card kpi' }, el('div', { class: 'label' }, `${l[0]}${l.slice(1).toLowerCase()} risks`), el('div', { class: 'value' }, d.risk_counts[l])))));
  host.append(el('div', { class: 'card mb' }, el('div', { class: 'card-h' }, el('h2', {}, 'Recommendations'), el('span', { class: 'small faint' }, 'Rule-based, each with its evidence')),
    d.recommendations.length ? simpleTable([{ label: 'Priority', render: (r) => badge(r.priority, r.priority === 'High' ? 'high' : 'med') }, { label: 'Recommendation', render: (r) => el('strong', {}, r.title) }, { label: 'Why (evidence)', key: 'why' }, { label: 'Action', key: 'action' }], d.recommendations)
      : el('div', { class: 'state' }, 'No recommendations triggered by the current data.')));
  host.append(el('div', { class: 'grid g2 mb' },
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Control gaps behind high risks')), simpleTable([{ label: 'Control', render: (g) => `${g.framework} ${g.control_code}` }, { label: 'Status', render: (g) => g.implementation_status.toLowerCase().replace('_', ' ') }, { label: 'Drives', key: 'drives_risks' }], d.control_gaps, { empty: 'No gaps linked to HIGH/CRITICAL risks.' })),
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Top risks')), simpleTable([{ label: 'Risk', render: (r) => `${r.risk_code} ${r.title}` }, { label: 'Residual', num: true, render: (r) => fmt(r.residual_score, 1) }, { label: 'Level', render: (r) => levelBadge(r.risk_level) }], d.top_risks.slice(0, 8)))));
  host.append(el('div', { class: 'notice' }, el('strong', {}, 'Limitations. '), d.limitations.join(' ')));
}
