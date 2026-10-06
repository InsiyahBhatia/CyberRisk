import { api, el, clear, qs, fmt, fmtDate, dataTable, levelBadge, statusBadge, badge, monoText, scoreBar, openDrawer, kv, section, skeleton, errorBox } from '../core.js';

const BUS = ['Engineering', 'Finance', 'Human Resources', 'Sales', 'Operations', 'IT Infrastructure', 'Customer Support', 'Legal'];

export async function vulnerabilities(root, params = {}) {
  const table = dataTable({
    caption: 'Vulnerabilities',
    initialFilters: { severity: params.severity || '', overdue: params.overdue || '', known_exploited: params.known_exploited || '' },
    initialSort: { sort: 'risk_score', order: 'desc' },
    filters: [{ key: 'q', label: 'Search CVE or asset…', type: 'search' }, { key: 'severity', label: 'All severities', type: 'select', options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
      { key: 'status', label: 'All statuses', type: 'select', options: ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'ACCEPTED'] },
      { key: 'known_exploited', label: 'Any exploitation', type: 'select', options: [['true', 'In CISA KEV'], ['false', 'Not in KEV']] },
      { key: 'overdue', label: 'Any due date', type: 'select', options: [['true', 'Overdue only']] }, { key: 'business_unit', label: 'All business units', type: 'select', options: BUS }],
    load: (p) => api('/api/vulnerabilities' + qs(p)),
    columns: [
      { key: 'cve_id', label: 'CVE', sort: 'cve_id', mono: true },
      { key: 'asset_tag', label: 'Asset', sort: 'asset_tag', mono: true },
      { key: 'severity', label: 'Severity', sort: 'severity', render: (v) => levelBadge(v.severity) },
      { key: 'cvss_score', label: 'CVSS', sort: 'cvss_score', num: true, render: (v) => fmt(v.cvss_score) },
      { key: 'known_exploited', label: 'KEV', render: (v) => v.known_exploited ? badge('In KEV', 'crit') : '—' },
      { key: 'risk_score', label: 'Priority score', sort: 'risk_score', render: (v) => scoreBar(v.risk_score, 100, fmt(v.risk_score, 0)) },
      { key: 'status', label: 'Status', sort: 'status', render: (v) => statusBadge(v.status) },
      { key: 'due_date', label: 'Due', sort: 'due_date', render: (v) => v.overdue ? el('span', { class: 'overdue' }, `${fmtDate(v.due_date)} · overdue`) : fmtDate(v.due_date) },
      { key: 'business_unit', label: 'Business unit' }],
    onRow: (v) => openVulnDrawer(v.id),
  });
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Vulnerabilities'),
    el('p', {}, 'CVE data from NVD, exploitation status from CISA KEV; findings on synthetic assets. Priority score ≠ CVSS.'))), table);
}

export async function openVulnDrawer(id) {
  const d = openDrawer({ heading: 'Vulnerability', subtitle: 'Loading…' });
  d.body.append(skeleton(6));
  let v;
  try { v = await api(`/api/vulnerabilities/${id}`); } catch (e) { clear(d.body).append(errorBox(e, () => openVulnDrawer(id))); return; }
  d.setTitle(v.cve_id, `${v.asset_tag} · ${v.business_unit}`);
  clear(d.body).append(
    el('div', { class: 'actions mb' }, levelBadge(v.severity), statusBadge(v.status), v.known_exploited ? badge('CISA KEV', 'crit') : null, v.overdue ? badge('Overdue', 'crit') : null),
    section('Description', el('p', {}, v.catalog?.description || v.title || 'No NVD description loaded for this CVE.'),
      v.catalog ? el('div', { class: 'small faint' }, `Source: NVD, published ${fmtDate(v.catalog.published_at)}, CVSS ${v.catalog.cvss_version || ''} ${v.catalog.cvss_vector || ''}`) : el('div', { class: 'small faint' }, 'Source: scanner report only (CVE not in the loaded NVD window).')),
    section('Scoring', el('div', { class: 'formula' }, `CVSS (severity)        ${fmt(v.cvss_score)}\npriority score (0–100) ${fmt(v.risk_score, 1)}\n= weighted CVSS + asset criticality (${v.asset_criticality}) + exploitability (${v.exploitability})\n  + internet exposure (${v.internet_exposed ? 'yes' : 'no'}) + CISA KEV (${v.known_exploited ? 'yes' : 'no'})`),
      el('p', { class: 'small muted', style: 'margin-top:6px' }, v.scoring_note)),
    v.kev ? section('CISA Known Exploited Vulnerabilities entry', kv([['Name', v.kev.vulnerability_name], ['Vendor / product', `${v.kev.vendor_project} / ${v.kev.product}`], ['Added', fmtDate(v.kev.date_added)], ['KEV due date', fmtDate(v.kev.due_date)],
      ['Ransomware use', v.kev.known_ransomware_use], ['Required action', v.kev.required_action]]), el('p', { class: 'small muted' }, 'KEV membership is a prioritisation signal, not proof of compromise.')) : null,
    section('Record', kv([['Discovered', fmtDate(v.discovered_at)], ['Due', fmtDate(v.due_date)], ['Resolved', fmtDate(v.resolved_at)], ['Source', v.source], ['CWE', v.catalog?.cwe || '—']])));
}
