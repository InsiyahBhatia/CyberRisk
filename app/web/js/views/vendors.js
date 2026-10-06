import { api, el, clear, qs, fmt, fmtDate, dataTable, levelBadge, statusBadge, badge, monoText, scoreBar, openDrawer, kv, section, skeleton, errorBox, simpleTable, chart, chartBox } from '../core.js';

export async function vendors(root) {
  const dist = chartBox('sm');
  const table = dataTable({
    caption: 'Vendors', initialSort: { sort: 'residual_risk', order: 'desc' },
    filters: [{ key: 'criticality', label: 'All criticalities', type: 'select', options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] }, { key: 'assessment_status', label: 'All assessments', type: 'select', options: ['COMPLETED', 'IN_PROGRESS', 'OVERDUE', 'NOT_STARTED'] },
      { key: 'high_risk', label: 'Any residual risk', type: 'select', options: [['true', 'High risk (≥ 7)']] }],
    load: (p) => api('/api/vendors' + qs(p)),
    columns: [{ key: 'vendor_code', label: 'ID', mono: true }, { key: 'vendor_name', label: 'Vendor', sort: 'vendor_name' }, { key: 'criticality', label: 'Criticality', sort: 'criticality', render: (v) => levelBadge(v.criticality) },
      { key: 'data_access', label: 'Data access' }, { key: 'inherent_risk', label: 'Inherent', sort: 'inherent_risk', num: true, render: (v) => fmt(v.inherent_risk) },
      { key: 'residual_risk', label: 'Residual', sort: 'residual_risk', render: (v) => scoreBar(v.residual_risk, 10, fmt(v.residual_risk)) },
      { key: 'assessment_status', label: 'Assessment', sort: 'assessment_status', render: (v) => statusBadge(v.assessment_status) }, { key: 'open_findings', label: 'Open findings', num: true },
      { key: 'next_review', label: 'Next review', sort: 'next_review', render: (v) => v.review_overdue ? el('span', { class: 'overdue' }, `${fmtDate(v.next_review)} · overdue`) : fmtDate(v.next_review) }],
    onRow: (v) => openVendor(v.id),
  });
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Vendors'), el('p', {}, 'Residual vendor risk = inherent risk reduced by assessment status, plus penalties for open findings.'))),
    el('div', { class: 'card mb' }, el('div', { class: 'card-h' }, el('h2', {}, 'Residual risk distribution')), el('div', { class: 'card-b' }, dist.box)), table);
  api('/api/vendors-summary/distribution').then((r) => {
    const order = ['High (7-10)', 'Medium (4-7)', 'Low (0-4)']; const colors = ['#9a2e2e', '#c9a93f', '#6a9a76'];
    chart(dist.canvas, { type: 'bar', data: { labels: order, datasets: [{ data: order.map((l) => (r.items.find((x) => x.label === l) || {}).count || 0), backgroundColor: colors }] },
      options: { indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false } } } } });
  }).catch(() => {});
}

async function openVendor(id) {
  const d = openDrawer({ heading: 'Vendor', subtitle: 'Loading…' });
  d.body.append(skeleton(5));
  let v;
  try { v = await api(`/api/vendors/${id}`); } catch (e) { clear(d.body).append(errorBox(e, () => openVendor(id))); return; }
  d.setTitle(v.vendor_name, `${v.vendor_code} · ${v.service_category}`);
  clear(d.body).append(el('div', { class: 'actions mb' }, levelBadge(v.criticality), statusBadge(v.assessment_status)),
    section('Risk', kv([['Inherent', fmt(v.inherent_risk)], ['Residual', fmt(v.residual_risk)], ['Data access', v.data_access], ['Last assessed', fmtDate(v.last_assessed)], ['Next review', fmtDate(v.next_review)]])),
    section('Findings', simpleTable([{ label: 'Finding', key: 'finding' }, { label: 'Severity', render: (f) => levelBadge((f.severity || '').toUpperCase()) }, { label: 'Status', render: (f) => statusBadge((f.status || '').toUpperCase()) }, { label: 'Due', render: (f) => fmtDate(f.due_date) }], v.findings, { empty: 'No findings.' })));
}
