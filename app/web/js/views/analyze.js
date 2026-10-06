import { ai, api, el, clear, qs, fmt, fmtDate, relTime, badge, levelBadge, monoText, skeleton, errorBox, notice, toast, tabs, simpleTable, section, kv, openReport, chart, chartBox, openDrawer, getWorkspace, formField, title } from '../core.js';
import { runAI } from '../ai.js';

const SAMPLE_LOG = `Oct  6 02:00:01 srv sshd[1]: Failed password for root from 203.0.113.9 port 40001 ssh2
Oct  6 02:00:03 srv sshd[1]: Failed password for root from 203.0.113.9 port 40002 ssh2
Oct  6 02:00:05 srv sshd[1]: Failed password for admin from 203.0.113.9 port 40003 ssh2
Oct  6 02:00:07 srv sshd[1]: Failed password for admin from 203.0.113.9 port 40004 ssh2
Oct  6 02:00:09 srv sshd[1]: Failed password for ubuntu from 203.0.113.9 port 40005 ssh2
Oct  6 02:00:11 srv sshd[1]: Failed password for root from 203.0.113.9 port 40006 ssh2
Oct  6 02:03:00 srv sshd[2]: Accepted password for root from 203.0.113.9 port 40007 ssh2
Oct  6 02:03:30 srv bash: powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA`;

export async function analyze(root, params = {}) {
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Analyze'),
    el('p', {}, 'Upload a log or paste an incident report. Detections are rule-based and mapped to MITRE ATT&CK; CVEs are enriched from NVD and CISA KEV. No organisation required.'))));
  const host = el('div', {});
  const show = (k) => { clear(host); ({ new: newAnalysis, history: historyView })[k](host); };
  root.append(tabs([{ key: 'new', label: 'New analysis' }, { key: 'history', label: 'Saved analyses' }], params.tab || 'new', show), host);
  show(params.tab || 'new');
  if (params.id) openAnalysis(params.id);
}

function newAnalysis(host) {
  const out = el('div', { style: 'margin-top:16px' });
  const file = el('input', { type: 'file', accept: '.log,.txt,.csv,.json,.jsonl,.ndjson', 'aria-label': 'Log file' });
  const lname = el('input', { type: 'text', maxlength: '120', placeholder: 'Name (optional)', 'aria-label': 'Analysis name' });
  const text = el('textarea', { rows: '9', maxlength: '50000', placeholder: 'Paste an incident report, ticket or analyst notes. Include timestamps, hostnames, commands, IPs, CVEs, whatever you have.', 'aria-label': 'Incident description' });
  const iname = el('input', { type: 'text', maxlength: '120', placeholder: 'Name (optional)', 'aria-label': 'Incident name' });
  const run = async (fn, btn) => {
    btn.disabled = true; const old = btn.textContent; btn.textContent = 'Analyzing…'; clear(out).append(skeleton(5));
    try { const a = await fn(); clear(out); renderAnalysis(out, a); }
    catch (e) { clear(out).append(notice(e.body?.error?.details?.map((x) => x.message).join('; ') || e.message, 'err')); }
    finally { btn.disabled = false; btn.textContent = old; }
  };
  const lbtn = el('button', { class: 'btn primary', onclick: (e) => run(() => {
    if (!file.files[0]) throw new Error('Choose a log file first (.log, .txt, .csv, .json or .jsonl, up to 10 MB).');
    const form = new FormData(); form.append('file', file.files[0]); if (lname.value) form.append('name', lname.value);
    return api('/api/analysis/logs', { method: 'POST', form });
  }, e.target) }, 'Analyze log file');
  const ibtn = el('button', { class: 'btn primary', onclick: (e) => run(() => api('/api/analysis/incident', { method: 'POST', body: { text: text.value, name: iname.value || null } }), e.target) }, 'Analyze incident');
  const sample = el('button', { class: 'btn ghost sm', onclick: async (e) => {
    const f = new File([SAMPLE_LOG], 'sample-auth.log', { type: 'text/plain' }); const form = new FormData(); form.append('file', f); form.append('name', 'Sample: SSH brute force + takeover');
    run(() => api('/api/analysis/logs', { method: 'POST', form }), e.target);
  } }, 'Try a sample log');
  host.append(el('div', { class: 'grid g2' },
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Logs and events'), sample), el('div', { class: 'card-b' },
      el('p', { class: 'small muted' }, 'Syslog / auth.log, web access logs, Windows events (CSV), JSON or JSON-lines.'), formField('File', file), formField('Name', lname), lbtn)),
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Incident report')), el('div', { class: 'card-b' }, formField('Description', text), formField('Name', iname), ibtn))),
    el('div', { class: 'small faint', style: 'margin-top:8px' }, `Files are parsed on the server and stored only as analysis results in this workspace. Nothing is sent to an AI unless you click "Explain with ${ai.name}".`), out);
}

async function historyView(host) {
  host.append(skeleton(4));
  try {
    const d = await api('/api/analysis');
    clear(host).append(el('div', { class: 'card' }, d.items.length ? simpleTable([
      { label: 'Name', render: (r) => el('a', { href: '#', onclick: (e) => { e.preventDefault(); openAnalysis(r.id); } }, r.name) }, { label: 'Type', render: (r) => badge(r.kind === 'logs' ? 'Logs' : 'Incident', 'outline') },
      { label: 'Severity', render: (r) => levelBadge(r.severity) }, { label: 'Score', num: true, render: (r) => fmt(r.score, 0) }, { label: 'Events', num: true, key: 'event_count' }, { label: 'Findings', num: true, key: 'finding_count' },
      { label: 'When', render: (r) => relTime(r.created_at) }], d.items) : el('div', { class: 'state' }, el('strong', {}, 'No analyses yet'), 'Run one from the New analysis tab.')));
  } catch (e) { clear(host).append(errorBox(e)); }
}

async function openAnalysis(id) {
  const d = openDrawer({ heading: 'Analysis', subtitle: 'Loading…' });
  d.body.append(skeleton(6));
  try { const a = await api(`/api/analysis/${id}`); d.setTitle(a.name, `${a.kind === 'logs' ? 'Log analysis' : 'Incident analysis'} · ${relTime(a.created_at)}`); clear(d.body); renderAnalysis(d.body, a, { drawer: d }); }
  catch (e) { clear(d.body).append(errorBox(e, () => openAnalysis(id))); }
}

function renderAnalysis(host, a, { drawer } = {}) {
  host.append(el('div', { class: 'grid g4 mb' },
    el('div', { class: 'card kpi hero' }, el('div', { class: 'label' }, 'Severity'), el('div', { class: 'value', style: 'font-size:22px' }, levelBadge(a.severity)), el('div', { class: 'sub' }, `Score ${fmt(a.score, 0)}/100`)),
    el('div', { class: 'card kpi' }, el('div', { class: 'label' }, a.kind === 'logs' ? 'Events analysed' : 'Category'), el('div', { class: 'value', style: 'font-size:22px' }, a.kind === 'logs' ? fmt(a.meta.events, 0) : a.category), el('div', { class: 'sub' }, a.kind === 'logs' ? `${a.meta.format} · ${a.meta.with_timestamp} with timestamps` : (a.secondary_categories || []).join(', '))),
    el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Findings'), el('div', { class: 'value' }, a.findings.length), el('div', { class: 'sub' }, `${a.techniques.length} ATT&CK techniques`)),
    el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Indicators'), el('div', { class: 'value' }, a.iocs.ips.length + a.iocs.domains.length + a.iocs.hashes.length), el('div', { class: 'sub' }, `${a.cves.length} CVE(s)${a.cves.some((c) => c.in_kev) ? ' · in CISA KEV' : ''}`))));
  host.append(el('div', { class: 'actions mb' },
    el('button', { class: 'btn', onclick: () => openReport(`/api/analysis/${a.id}/report`, { download: true, filename: `analysis-${a.id}.html` }) }, 'Download report'),
    el('button', { class: 'btn primary', onclick: () => { const d2 = openDrawer({ heading: `Explain with ${ai.name}`, subtitle: a.name }); runAI(d2.body, `/api/analysis/${a.id}/explain`, {}); } }, `Explain with ${ai.name}`),
    el('a', { class: 'small', href: '#/analyze?tab=history' }, 'All analyses')));
  if (a.severity_rationale) host.append(el('div', { class: 'notice mb' }, el('strong', {}, 'Why this severity: '), a.severity_rationale.join(' ')));

  host.append(section('Findings', a.findings.length ? el('div', {}, ...a.findings.map((f) => el('div', { class: 'card mb' }, el('div', { class: 'card-h' },
    el('div', {}, el('strong', {}, f.title), ' ', levelBadge(f.severity), ' ', f.techniques.map((t) => el('span', { class: 'chip' }, t))), el('span', { class: 'small faint' }, `${f.id} · ${f.count} event(s)`)),
    el('div', { class: 'card-b small' }, el('div', {}, f.description), f.sample.length ? el('pre', { class: 'formula', style: 'margin-top:8px;font-size:11.5px' }, f.sample.join('\n')) : null,
      el('div', { style: 'margin-top:8px' }, el('strong', {}, 'Do next: '), f.recommendation), f.evidence_lines.length ? el('div', { class: 'faint', style: 'margin-top:4px' }, `Evidence lines: ${f.evidence_lines.slice(0, 12).join(', ')}${f.evidence_lines.length > 12 ? '…' : ''}`) : null,
      el('div', { class: 'actions', style: 'margin-top:8px' }, el('button', { class: 'btn sm', onclick: () => promote(a, f) }, 'Add to risk register…'))))))
    : el('div', { class: 'notice ok' }, 'No known attack patterns were detected in the supplied data. That does not prove the data is clean: detections are rule-based and only as complete as the logs provided.')));

  if (a.techniques.length) host.append(section('MITRE ATT&CK', simpleTable([{ label: 'ID', render: (t) => el('a', { href: t.url, target: '_blank', rel: 'noopener' }, t.id) }, { label: 'Technique', render: (t) => t.name || el('span', { class: 'faint' }, 'not in loaded dataset') },
    { label: 'Tactics', render: (t) => t.tactics.join(', ') }, { label: 'Findings', render: (t) => t.findings.join(', ') || '—' }], a.techniques)));
  if (a.cves.length) host.append(section('Referenced CVEs (NVD + CISA KEV)', simpleTable([{ label: 'CVE', render: (c) => monoText(c.id) }, { label: 'CVSS', num: true, render: (c) => fmt(c.cvss) }, { label: 'Exploited (KEV)', render: (c) => c.in_kev ? badge('In KEV', 'crit') : badge('Not in KEV', 'outline') },
    { label: 'Details', render: (c) => c.kev ? `${c.kev.vulnerability_name}. Required action: ${c.kev.required_action}` : c.description }], a.cves)));
  const ioc = a.iocs;
  if (ioc.ips.length || ioc.domains.length || ioc.hashes.length || ioc.emails.length) host.append(section('Indicators of compromise', simpleTable([{ label: 'Type', key: 't' }, { label: 'Value', render: (r) => monoText(r.v) }, { label: 'Notes', key: 'n' }],
    [...ioc.ips.slice(0, 25).map((i) => ({ t: 'IP', v: i.value, n: `${i.scope}${i.flagged ? ', involved in a finding' : ''} · ${i.count}×` })), ...ioc.domains.slice(0, 15).map((d) => ({ t: 'Domain', v: d.value, n: `${d.count}×` })),
      ...ioc.urls.slice(0, 10).map((u) => ({ t: 'URL', v: u.value, n: '' })), ...ioc.hashes.slice(0, 10).map((h) => ({ t: h.type, v: h.value, n: '' })), ...ioc.emails.slice(0, 10).map((m) => ({ t: 'Email', v: m.value, n: '' }))]),
    el('p', { class: 'small faint' }, 'Defanged indicators (hxxp, [.]) are normalised. Check IOCs against your own telemetry before blocking.')));
  if (a.timeline.length) host.append(section('Timeline', simpleTable([{ label: 'Time (UTC)', render: (t) => t.ts ? t.ts.replace('T', ' ') : '—' }, { label: 'Line', num: true, key: 'line' }, { label: 'Finding', render: (t) => t.finding || '' }, { label: 'Event', render: (t) => el('span', { class: 'small' }, t.event) }], a.timeline)));
  host.append(section('Recommended next steps', el('ol', { style: 'margin:0;padding-left:20px' }, a.next_steps.map((s) => el('li', {}, s)))));
  host.append(el('div', { class: 'notice' }, el('strong', {}, 'Limitations. '), a.limitations.join(' ')));
}

async function promote(a, f) {
  const d = openDrawer({ heading: 'Add to risk register', subtitle: f.title });
  const assets = await api('/api/assets?page_size=200').catch(() => ({ items: [] }));
  const sel = el('select', {}, el('option', { value: '' }, assets.items.length ? 'No specific asset (impact 3)' : 'No assets in this workspace'), assets.items.map((x) => el('option', { value: x.id }, `${x.asset_tag} · ${title(x.criticality)} criticality`)));
  const owner = el('input', { type: 'text', maxlength: '80', placeholder: 'Risk owner' });
  d.body.append(el('p', { class: 'muted' }, 'This creates a new risk in the current workspace. Likelihood comes from the finding severity; impact from the asset’s criticality. You can edit it afterwards.'),
    formField('Affected asset', sel), formField('Owner', owner), el('div', { class: 'actions' }, el('button', { class: 'btn primary', onclick: async () => {
      try { const r = await api(`/api/analysis/${a.id}/promote`, { method: 'POST', body: { finding_id: f.id, asset_id: sel.value ? +sel.value : null, owner: owner.value || null } });
        clear(d.body).append(notice(`Created ${r.risk_code}: likelihood ${r.likelihood} × impact ${r.impact} = ${r.inherent_score}.`, 'ok'), el('p', {}, el('a', { href: '#/risks' }, 'Open the risk register')));
      } catch (e) { toast(e.message, 'err'); }
    } }, 'Create risk')));
}
