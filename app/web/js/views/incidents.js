import { api, el, clear, qs, fmtDate, dataTable, levelBadge, statusBadge, badge, monoText, openDrawer, kv, section, skeleton, errorBox, simpleTable } from '../core.js';

export async function incidents(root) {
  const table = dataTable({
    caption: 'Incidents', initialSort: { sort: 'detected_at', order: 'desc' },
    filters: [{ key: 'severity', label: 'All severities', type: 'select', options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] }, { key: 'status', label: 'All statuses', type: 'select', options: ['OPEN', 'INVESTIGATING', 'CONTAINED', 'CLOSED'] },
      { key: 'category', label: 'All categories', type: 'select', options: ['Phishing', 'Malware', 'Unauthorized Access', 'Data Exposure', 'Ransomware', 'Denial of Service', 'Insider Misuse'] }],
    load: (p) => api('/api/incidents' + qs(p)),
    columns: [{ key: 'incident_code', label: 'ID', sort: 'incident_code', mono: true }, { key: 'title', label: 'Incident' }, { key: 'category', label: 'Category', sort: 'category' },
      { key: 'severity', label: 'Severity', sort: 'severity', render: (i) => levelBadge(i.severity) }, { key: 'status', label: 'Status', sort: 'status', render: (i) => statusBadge(i.status) },
      { key: 'asset_tag', label: 'Asset', mono: true, render: (i) => monoText(i.asset_tag) }, { key: 'technique_ids', label: 'ATT&CK', render: (i) => el('span', {}, (i.technique_ids || '').split(',').filter(Boolean).map((t) => el('span', { class: 'chip' }, t))) },
      { key: 'detected_at', label: 'Detected', sort: 'detected_at', render: (i) => fmtDate(i.detected_at) }],
    onRow: (i) => openIncident(i.id),
  });
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Incidents'), el('p', {}, 'Synthetic incidents enriched with MITRE ATT&CK technique context from the official dataset.'))), table);
}

async function openIncident(id) {
  const d = openDrawer({ heading: 'Incident', subtitle: 'Loading…' });
  d.body.append(skeleton(5));
  let i;
  try { i = await api(`/api/incidents/${id}`); } catch (e) { clear(d.body).append(errorBox(e, () => openIncident(id))); return; }
  d.setTitle(`${i.incident_code} · ${i.title}`, `${i.category} · ${i.asset_tag || 'no asset'}`);
  clear(d.body).append(el('div', { class: 'actions mb' }, levelBadge(i.severity), statusBadge(i.status)),
    section('Description', el('p', {}, i.description)),
    section('MITRE ATT&CK context', i.techniques.length ? simpleTable([{ label: 'ID', render: (t) => monoText(t.technique_id) }, { label: 'Technique', key: 'name' }, { label: 'Tactics', render: (t) => (t.tactics || '').replace(/,/g, ', ') }], i.techniques) : el('div', { class: 'muted small' }, 'No technique identifiers recorded.'),
      el('p', { class: 'small faint', style: 'margin-top:6px' }, 'ATT&CK describes adversary behaviour; it is threat context, not a control framework.')),
    section('Timeline', kv([['Detected', fmtDate(i.detected_at)], ['Resolved', fmtDate(i.resolved_at)], ['Business unit', i.business_unit]])));
}
