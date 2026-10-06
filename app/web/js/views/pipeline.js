import { api, el, clear, qs, fmt, openReport, fmtDate, relTime, dataTable, statusBadge, badge, monoText, scoreBar, openDrawer, kv, section, skeleton, errorBox, simpleTable, notice, tabs, toast } from '../core.js';

const ACQ_KEY = { 'NVD': 'nvd', 'CISA KEV': 'cisa-kev', 'MITRE ATT&CK': 'mitre', 'GRC Frameworks': 'nist' };
const DATASETS = ['assets', 'employees', 'vendors', 'vendor_findings', 'control_status', 'compliance_evidence', 'vulnerability_scan', 'incidents', 'audit_findings', 'risk_register', 'remediation_actions'];

export async function pipeline(root, params = {}) {
  const host = el('div', {});
  const show = (key) => { clear(host); ({ sources, history, run })[key](host); };
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Data Pipeline'),
    el('p', {}, 'Official public sources and synthetic organisational data flow through validation, normalisation, de-duplication and enrichment into SQLite. Rejected rows are logged, never dropped silently.'))),
    tabs([{ key: 'sources', label: 'Data sources' }, { key: 'history', label: 'Ingestion history' }, { key: 'run', label: 'Run / upload' }], params.tab || 'sources', show), host);
  show(params.tab || 'sources');
}

async function sources(host) {
  host.append(skeleton(6));
  let data;
  try { data = await api('/api/data-sources'); } catch (e) { clear(host).append(errorBox(e, () => { clear(host); sources(host); })); return; }
  clear(host);
  const statusText = (s) => s.status === 'CACHED' ? 'Cached snapshot' : s.status === 'HEALTHY' ? 'Healthy' : s.status === 'FAILED' ? 'Failed (stale)' : s.status.replace('_', ' ');
  const refresh = async (s, btn) => {
    btn.disabled = true; btn.textContent = 'Refreshing…';
    try {
      const r = await api('/api/etl/acquire', { method: 'POST', body: { source: ACQ_KEY[s.source_name], limit: s.source_name === 'NVD' ? 150 : undefined } });
      toast(`${s.source_name}: ${r.status} (${r.records} records)`, r.status === 'FAILED' ? 'err' : '');
    } catch (e) { toast(e.message, 'err'); }
    clear(host); sources(host);
  };
  host.append(el('div', { class: 'card' }, el('div', { class: 'table-wrap' }, el('table', {}, el('caption', { class: 'sr-only' }, 'Data sources'),
    el('thead', {}, el('tr', {}, ['Source', 'Type', 'Last sync', 'Records', 'Version', 'Status', ''].map((h) => el('th', { scope: 'col' }, h)))),
    el('tbody', {}, data.items.map((s) => el('tr', { class: 'clickable', tabindex: '0', onclick: () => detail(s), onkeydown: (e) => { if (e.key === 'Enter') detail(s); } },
      el('td', {}, s.source_name), el('td', {}, badge(s.source_type === 'PUBLIC' ? 'Public' : 'Synthetic', s.source_type)),
      el('td', {}, s.last_successful_run ? `${relTime(s.last_successful_run)}${s.from_cache ? ' (cached data)' : ''}` : 'never'),
      el('td', { class: 'num' }, fmt(s.record_count, 0)), el('td', {}, s.dataset_version || '—'),
      el('td', {}, statusBadge(s.status), s.status === 'FAILED' ? el('div', { class: 'small overdue' }, 'Previous data preserved') : null),
      el('td', {}, ACQ_KEY[s.source_name] ? el('button', { class: 'btn sm', onclick: (e) => { e.stopPropagation(); refresh(s, e.target); } }, 'Refresh') : null))))))),
    el('div', { class: 'notice', style: 'margin-top:16px' }, 'Freshness is the time of the last successful acquisition, not a real-time claim. If a public source fails, previous valid data is kept and flagged; it is never replaced with synthetic records.'));
}

function detail(s) {
  const d = openDrawer({ heading: s.source_name, subtitle: s.source_type === 'PUBLIC' ? 'Public source' : 'Synthetic data' });
  d.body.append(kv([['Publisher', s.publisher], ['Official URL', s.official_url], ['Method', s.acquisition_method], ['Retrieved', s.retrieval_timestamp || '—'], ['Version', s.dataset_version || '—'],
    ['Checksum (SHA-256)', s.checksum ? monoText(s.checksum) : '—'], ['Records', fmt(s.record_count, 0)], ['Status', statusBadge(s.status)], ['Served from cache', s.from_cache ? 'Yes: live acquisition was unavailable' : 'No']]),
    section('License and usage', el('p', {}, s.license_notes || '—')), s.last_error ? section('Last error', notice(s.last_error, 'err')) : null);
}

async function history(host) {
  const t = dataTable({
    caption: 'Ingestion history', initialSort: { sort: 'id', order: 'desc' },
    filters: [{ key: 'status', label: 'All statuses', type: 'select', options: ['SUCCESS', 'FAILED', 'RUNNING'] }],
    load: (p) => api('/api/etl/runs' + qs({ status: p.status, page: p.page, page_size: p.page_size })),
    columns: [{ key: 'id', label: 'Run', mono: true }, { key: 'source_name', label: 'Source' }, { key: 'started_at', label: 'Started', render: (r) => relTime(r.started_at) },
      { key: 'duration_seconds', label: 'Duration', num: true, render: (r) => r.duration_seconds === null ? '—' : fmt(r.duration_seconds, 1) + ' s' },
      { key: 'records_read', label: 'Read', num: true }, { key: 'records_valid', label: 'Valid', num: true }, { key: 'records_rejected', label: 'Rejected', num: true, render: (r) => r.records_rejected ? el('span', { class: 'overdue' }, r.records_rejected) : 0 },
      { key: 'duplicates_removed', label: 'Duplicates', num: true }, { key: 'records_loaded', label: 'Loaded', num: true },
      { key: 'quality_score', label: 'Quality', num: true, render: (r) => r.quality_score === null ? '—' : fmt(r.quality_score, 1) }, { key: 'status', label: 'Status', render: (r) => statusBadge(r.status) }],
    onRow: (r) => runDetail(r),
  });
  host.append(el('p', { class: 'small muted' }, 'quality score = 100 − missing-required − invalid-value − 0.5 × duplicate − referential-integrity penalties (each as % of rows read).'), t);
}

async function runDetail(r) {
  const d = openDrawer({ heading: `ETL run ${r.id}`, subtitle: r.source_name });
  d.body.append(kv([['Started', r.started_at], ['Completed', r.completed_at || '—'], ['Source version', r.source_version || '—'], ['Source checksum', r.source_checksum ? monoText(r.source_checksum.slice(0, 24) + '…') : '—'],
    ['Read / valid / rejected', `${r.records_read} / ${r.records_valid} / ${r.records_rejected}`], ['Duplicates removed', r.duplicates_removed], ['Loaded', r.records_loaded], ['Quality score', fmt(r.quality_score, 1)], ['Error', r.error_message]]));
  const rej = el('div', {});
  d.body.append(section('Rejected rows', rej));
  rej.append(skeleton(3));
  try {
    const x = await api(`/api/etl/runs/${r.id}/rejections?page_size=100`);
    clear(rej).append(x.items.length ? simpleTable([{ label: 'Row', num: true, key: 'source_row' }, { label: 'Reason', key: 'reason' }, { label: 'Raw payload', render: (i) => el('code', { class: 'small' }, (i.raw_payload || '').slice(0, 140)) }], x.items)
      : el('div', { class: 'muted small' }, 'No rows were rejected in this run.'), x.total > 100 ? el('div', { class: 'small faint' }, `Showing first 100 of ${x.total}.`) : null);
  } catch (e) { clear(rej).append(errorBox(e)); }
}

function run(host) {
  const area = el('div', {});
  host.append(el('div', { class: 'notice mb' }, 'Bring your own data: upload any CSV or JSON, check the suggested column mapping, and import. The same validation, normalisation, de-duplication and rejection logging apply. Need a starting point? Download a template.'), area);
  step1(area);
}

function step1(area) {
  clear(area);
  const file = el('input', { type: 'file', accept: '.csv,.json', 'aria-label': 'CSV or JSON file' });
  const out = el('div', {});
  const tplSel = el('select', { 'aria-label': 'Template dataset' }, DATASETS.map((n) => el('option', { value: n }, n)));
  area.append(el('div', { class: 'grid g2' },
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, '1 · Upload a file')), el('div', { class: 'card-b' },
      el('p', { class: 'small muted' }, 'CSV or JSON records, up to 10 MB. The file is stored in this workspace only.'), el('div', { class: 'actions' }, file,
        el('button', { class: 'btn primary', onclick: async (e) => {
          if (!file.files[0]) { toast('Choose a file first', 'err'); return; }
          e.target.disabled = true; clear(out).append(skeleton(3));
          try { const form = new FormData(); form.append('file', file.files[0]); step2(area, await api('/api/etl/profile', { method: 'POST', form })); }
          catch (err) { clear(out).append(notice(err.message, 'err')); e.target.disabled = false; }
        } }, 'Profile file')), out)),
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Or start from a template')), el('div', { class: 'card-b' },
      el('p', { class: 'small muted' }, 'Header and one example row in the exact format each dataset expects.'), el('div', { class: 'actions' }, tplSel,
        el('button', { class: 'btn', onclick: () => openReport(`/api/etl/templates/${tplSel.value}`, { download: true, filename: `${tplSel.value}_template.csv` }).catch((e) => toast(e.message, 'err')) }, 'Download template'))))));
}

async function step2(area, prof) {
  clear(area);
  const guess = prof.dataset_guesses[0];
  const ds = el('select', { 'aria-label': 'Dataset type' }, DATASETS.map((n) => el('option', { value: n, selected: n === guess.dataset }, n)));
  const mapHost = el('div', {});
  const out = el('div', { style: 'margin-top:16px' });
  area.append(el('div', { class: 'card mb' }, el('div', { class: 'card-h' }, el('h2', {}, `2 · Check your data (${fmt(prof.rows, 0)} rows, ${prof.columns.length} columns)`), el('button', { class: 'btn sm', onclick: () => step1(area) }, 'Start over')),
    simpleTable([{ label: 'Column', render: (c) => monoText(c.name) }, { label: 'Type', key: 'type' }, { label: 'Empty', num: true, render: (c) => c.null_pct + '%' }, { label: 'Unique', num: true, key: 'unique' },
      { label: 'Examples', render: (c) => el('span', { class: 'small muted' }, c.sample.slice(0, 3).join(' · ')) }], prof.columns)),
    el('div', { class: 'card mb' }, el('div', { class: 'card-h' }, el('h2', {}, '3 · Map columns'), el('div', { class: 'actions' }, el('span', { class: 'small muted' }, `Looks like: ${guess.dataset} (${guess.matched_required}/${guess.required} required fields matched)`), ds)), mapHost), out);
  let selects = {};
  async function loadMap() {
    clear(mapHost).append(skeleton(4));
    try {
      const sug = await api('/api/etl/mapping/suggest', { method: 'POST', body: { upload_id: prof.upload_id, dataset: ds.value } });
      selects = {};
      const cols = prof.columns.map((c) => c.name);
      clear(mapHost).append(el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['Target field', 'Required', 'Source column', 'Match', 'If unmapped'].map((h) => el('th', { scope: 'col' }, h)))),
        el('tbody', {}, sug.fields.map((f) => {
          const sel = el('select', { 'aria-label': `Source for ${f.field}` }, el('option', { value: '' }, '— not mapped —'), cols.map((c) => el('option', { value: c, selected: c === f.mapped_from }, c)));
          selects[f.field] = sel;
          return el('tr', {}, el('td', {}, monoText(f.field), f.example ? el('div', { class: 'small faint' }, `e.g. ${f.example}`) : null), el('td', {}, f.required ? badge('Required', 'high') : badge('Optional', 'outline')), el('td', {}, sel),
            el('td', {}, f.mapped_from ? badge(`${Math.round(f.confidence * 100)}%`, f.confidence >= 0.8 ? 'low' : 'med') : '—'),
            el('td', { class: 'small muted' }, f.default ? (f.default === 'TODAY' ? "today's date" : `"${f.default}"`) : (f.required ? el('span', { class: 'overdue' }, 'blocks import') : 'left empty')));
        })))),
        sug.missing_required.length ? el('div', { class: 'notice warn', style: 'margin-top:12px' }, `No column matched: ${sug.missing_required.join(', ')}. Pick one above, or the import will be blocked.`) : null,
        el('div', { class: 'actions', style: 'margin-top:12px' }, el('button', { class: 'btn primary', onclick: runImport }, 'Import data')));
    } catch (e) { clear(mapHost).append(errorBox(e, loadMap)); }
  }
  async function runImport(e) {
    const mapping = Object.fromEntries(Object.entries(selects).map(([k, v]) => [k, v.value || null]));
    e.target.disabled = true; clear(out).append(skeleton(3));
    try {
      const r = await api('/api/etl/run-mapped', { method: 'POST', body: { upload_id: prof.upload_id, dataset: ds.value, mapping } });
      clear(out).append(el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, `Imported into ${r.dataset}`), badge(`Quality ${fmt(r.quality_score, 1)}`, r.quality_score >= 95 ? 'low' : r.quality_score >= 85 ? 'med' : 'high')),
        el('div', { class: 'card-b' }, kv([['Rows read', r.read], ['Loaded', r.loaded], ['Rejected (with reasons)', r.rejected], ['Duplicates removed', r.duplicates], ['Defaults applied to', r.defaults_applied.join(', ') || '—']]),
          r.rejected ? el('div', { class: 'notice warn', style: 'margin-top:10px' }, `${r.rejected} row(s) were rejected, not silently dropped. See Ingestion history, run ${r.run_id}, for each row and reason.`) : null,
          el('div', { class: 'actions', style: 'margin-top:10px' }, el('a', { class: 'btn sm', href: '#/pipeline?tab=history' }, 'Ingestion history'), el('a', { class: 'btn sm', href: '#/setup' }, 'Setup checklist')))));
      toast(`Imported ${r.loaded} rows`);
    } catch (err) { clear(out).append(notice(err.body?.error?.message || err.message, 'err')); }
    finally { e.target.disabled = false; }
  }
  ds.addEventListener('change', loadMap);
  loadMap();
}
