import { api, el, clear, fmt, relTime, badge, levelBadge, statusBadge, monoText, skeleton, errorBox, notice, toast, openDrawer, kv, section, simpleTable, chart, chartBox, gridOpts, onLeave, formField, title, ai } from '../core.js';

const SOURCE_COLORS = { SIEM: '#3a5a78', EDR: '#9a2e2e', ITSM: '#8a6d12', Scanner: '#6a9a76', IAM: '#7d6a99', Cloud: '#4f8f9c', Email: '#b9b6ab' };
const SOURCES = Object.keys(SOURCE_COLORS);
const fmtTime = (ts) => (ts || '').slice(11, 19);

export async function live(root) {
  let scenarios, st;
  try { [scenarios, st] = await Promise.all([api('/api/sim/scenarios'), api('/api/sim/status')]); } catch (e) { root.append(errorBox(e, () => { root.replaceChildren(); live(root); })); return; }

  // ---- state shared by the polling callbacks
  const state = { feed: [], latest: 0, paused: false, source: '', minSev: 'INFO', running: st.running };
  const ui = {};
  const timers = [];
  onLeave(() => timers.forEach(clearInterval));

  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Live operations'),
    el('p', {}, 'Realistic alerts, tickets and findings from seven integrations flow through the same validated pipeline, correlate into incidents, and update risk data. Everything here is simulated.')),
    el('div', { class: 'actions', id: 'live-actions' })));
  ui.banner = el('div', { class: 'notice warn mb', style: 'display:none', role: 'status' });
  ui.control = el('div', { class: 'card mb' });
  ui.kpis = el('div', { class: 'grid g4 mb' });
  ui.integrations = el('div', { class: 'grid mb', style: 'grid-template-columns:repeat(auto-fit,minmax(128px,1fr))' });
  const chartB = chartBox();
  ui.feedHost = el('div', {});
  ui.incHost = el('div', {});
  root.append(ui.banner, ui.control, ui.kpis, ui.integrations,
    el('div', { class: 'card mb' }, el('div', { class: 'card-h' }, el('h2', {}, 'Events per second by source'), el('span', { class: 'small faint' }, 'Last ~90 ingestion batches')), el('div', { class: 'card-b' }, chartB.box)),
    el('div', { class: 'grid', style: 'grid-template-columns:minmax(0,3fr) minmax(0,2fr)' }, ui.feedHost, ui.incHost));

  // ---- chart
  const lineChart = chart(chartB.canvas, { type: 'bar', data: { labels: [], datasets: SOURCES.map((s) => ({ label: s, data: [], backgroundColor: SOURCE_COLORS[s], stack: 'a' })) },
    options: { animation: false, plugins: { legend: { position: 'bottom', labels: { boxWidth: 10 } } }, scales: { x: { stacked: true, grid: { display: false }, ticks: { maxTicksLimit: 8 } }, y: { stacked: true, ...gridOpts, beginAtZero: true, title: { display: true, text: 'events / batch' } } } } });

  // ---- controls
  function renderControl() {
    clear(ui.control);
    const acts = document.getElementById('live-actions');
    clear(acts);
    if (state.running) {
      const sim = state.status?.simulator;
      ui.control.append(el('div', { class: 'card-h' }, el('h2', {}, 'Inject an attack storyline'), el('span', { class: 'small faint' }, 'Runs across several integrations over ~1 minute')),
        el('div', { class: 'card-b' }, el('div', { class: 'actions' }, scenarios.items.map((s) => el('button', { class: 'btn sm', title: s.description, onclick: () => inject(s.name) }, title(s.name)))),
          el('p', { class: 'small muted', style: 'margin-top:8px' }, sim ? `Rate ${sim.rate_per_min}/min · speed ×${sim.speed} · auto-stops after ${sim.duration_min} min.` : '')));
      acts.append(el('button', { class: 'btn danger', onclick: stop }, 'Stop simulation'));
    } else {
      const rate = el('input', { type: 'range', min: '5', max: '300', step: '5', value: '40', 'aria-label': 'Events per minute' });
      const rateOut = el('output', { class: 'mono' }, '40 / min');
      rate.addEventListener('input', () => { rateOut.textContent = `${rate.value} / min`; });
      const speed = el('select', { 'aria-label': 'Storyline speed' }, [['1', '×1 (realistic pacing)'], ['2', '×2'], ['5', '×5'], ['10', '×10 (fast demo)']].map(([v, l]) => el('option', { value: v, selected: v === '2' }, l)));
      const dur = el('select', { 'aria-label': 'Duration' }, [['5', '5 minutes'], ['15', '15 minutes'], ['30', '30 minutes'], ['60', '1 hour']].map(([v, l]) => el('option', { value: v, selected: v === '15' }, l)));
      const boxes = scenarios.items.map((s) => { const cb = el('input', { type: 'checkbox', checked: true, 'aria-label': s.name }); return [s.name, cb, el('label', { style: 'display:flex;gap:6px;align-items:flex-start', title: s.description }, cb, el('span', {}, title(s.name), el('span', { class: 'small faint', style: 'display:block' }, s.description)))]; });
      ui.control.append(el('div', { class: 'card-h' }, el('h2', {}, 'Start a simulation')), el('div', { class: 'card-b' },
        el('div', { class: 'grid g3' }, formField('Background event rate', el('div', { class: 'actions' }, rate, rateOut)), formField('Storyline speed', speed), formField('Auto-stop after', dur)),
        el('div', { class: 'section' }, el('h3', {}, 'Attack storylines to play at random'), el('div', { class: 'grid g2' }, boxes.map((b) => b[2]))),
        el('div', { class: 'small muted mb' }, 'Empty workspaces first receive a small simulated asset inventory so events map to real assets. Vulnerability findings use real CVEs and CISA KEV data from this workspace.'),
        el('button', { class: 'btn primary', onclick: () => start({ rate_per_min: +rate.value, speed: +speed.value, duration_min: +dur.value, scenarios: boxes.filter((b) => b[1].checked).map((b) => b[0]) }) }, 'Start simulation')));
    }
  }
  async function start(cfg) {
    try { await api('/api/sim/start', { method: 'POST', body: cfg }); state.running = true; toast('Simulation started'); await refreshStatus(); renderControl(); }
    catch (e) { toast(e.body?.error?.details?.map((d) => d.message).join('; ') || e.message, 'err'); }
  }
  async function stop() { try { await api('/api/sim/stop', { method: 'POST' }); state.running = false; toast('Simulation stopped'); await refreshStatus(); renderControl(); } catch (e) { toast(e.message, 'err'); } }
  async function inject(name) { try { const r = await api('/api/sim/inject', { method: 'POST', body: { scenario: name } }); toast(`${title(name)} started on ${r.target} (${r.steps} steps, ~${r.completes_in_s}s)`); } catch (e) { toast(e.message, 'err'); } }

  // ---- status, kpis, integrations
  async function refreshStatus() {
    state.status = await api('/api/sim/status');
    const wasRunning = state.running;
    state.running = state.status.running;
    if (wasRunning !== state.running) renderControl();
    ui.banner.style.display = state.running ? '' : 'none';
    clear(ui.banner).append(el('strong', {}, 'SIMULATION RUNNING. '), 'All events below are synthetic and labelled as such. Auto-stops; real systems are never contacted.');
    if (!state.running && state.status.finished && state.status.stop_reason) {
      clear(ui.banner).append(`Simulation ended: ${state.status.stop_reason}.`); ui.banner.style.display = '';
    }
    const conns = state.status.simulator?.connectors || {};
    clear(ui.integrations).append(...SOURCES.map((s) => {
      const c = conns[s] || { events: 0, rejected: 0, health: 'idle' };
      const colour = c.health === 'healthy' ? 'var(--low)' : c.health === 'degraded' ? 'var(--med)' : 'var(--text-3)';
      const rejPct = c.events ? Math.round(100 * c.rejected / c.events) : 0;
      return el('div', { class: 'card kpi', style: 'padding:10px 12px' }, el('div', { class: 'label' }, el('strong', {}, s), el('span', { style: `color:${colour};font-size:12px` }, el('span', { class: 'dot', 'aria-hidden': 'true' }), ' ', title(c.health))),
        el('div', { class: 'value', style: 'font-size:20px' }, fmt(c.events, 0)), el('div', { class: 'sub' }, `${rejPct}% rejected${c.avg_batch_ms ? ` · ${c.avg_batch_ms} ms/batch` : ''}`),
        el('div', { class: 'small faint' }, c.last_ts ? `last ${fmtTime(c.last_ts)} UTC` : 'no events yet'));
    }));
  }
  async function refreshMetrics() {
    const m = await api('/api/sim/metrics?points=90');
    const last = m.series[m.series.length - 1] || {};
    const total = m.series.reduce((a, p) => a + p.events, 0);
    const rej = m.series.reduce((a, p) => a + p.rejected, 0);
    clear(ui.kpis).append(
      kpi('Events ingested', fmt(total, 0), `${fmt(rej, 0)} rejected (logged with reasons)`), kpi('Open incidents', fmt(m.incidents.open, 0), `${fmt(m.incidents.closed, 0)} closed`),
      kpi('Scenario detection', m.detection.rate === null ? '—' : `${m.detection.detected}/${m.detection.scenarios}`, m.detection.mean_time_to_detect_s !== null ? `mean time to detect ${m.detection.mean_time_to_detect_s}s` : 'inject a storyline to measure'),
      kpi('Open KEV vulnerabilities', fmt(last.kev_open ?? 0, 0), `${fmt(last.open_vulns ?? 0, 0)} open vulnerabilities in total`));
    if (lineChart) {
      lineChart.data.labels = m.series.map((p) => fmtTime(p.ts));
      SOURCES.forEach((s, i) => { lineChart.data.datasets[i].data = m.series.map((p) => p.by_source[s] || 0); });
      lineChart.update('none');
    }
    state.unmanaged = m.unmanaged_hosts;
  }
  const kpi = (label, value, sub) => el('div', { class: 'card kpi' }, el('div', { class: 'label' }, label), el('div', { class: 'value' }, value), el('div', { class: 'sub' }, sub));

  // ---- feed
  const filters = {
    source: el('select', { 'aria-label': 'Source filter', onchange: (e) => { state.source = e.target.value; state.feed = []; state.latest = 0; loadFeed(true); } }, el('option', { value: '' }, 'All sources'), SOURCES.map((s) => el('option', { value: s }, s))),
    sev: el('select', { 'aria-label': 'Minimum severity', onchange: (e) => { state.minSev = e.target.value; state.feed = []; state.latest = 0; loadFeed(true); } }, ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((s) => el('option', { value: s }, s === 'INFO' ? 'All severities' : `≥ ${title(s)}`))),
    pause: el('button', { class: 'btn sm', onclick: (e) => { state.paused = !state.paused; e.target.textContent = state.paused ? 'Resume' : 'Pause'; } }, 'Pause'),
  };
  ui.feedBody = el('div', { class: 'table-wrap', style: 'max-height:560px;overflow:auto' });
  clear(ui.feedHost).append(el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Live event feed'), el('div', { class: 'actions' }, filters.source, filters.sev, filters.pause)), ui.feedBody));
  async function loadFeed(reset = false) {
    if (state.paused && !reset) return;
    const q = new URLSearchParams({ after_id: reset ? 0 : state.latest, limit: reset ? 60 : 100, min_severity: state.minSev });
    if (state.source) q.set('source', state.source);
    const f = await api(`/api/sim/feed?${q}`);
    if (f.items.length) { state.feed = [...f.items, ...state.feed].slice(0, 200); state.latest = Math.max(state.latest, f.items[0].id); }
    renderFeed();
  }
  function renderFeed() {
    clear(ui.feedBody);
    if (!state.feed.length) { ui.feedBody.append(el('div', { class: 'state' }, el('strong', {}, state.running ? 'Waiting for events…' : 'No events yet'), state.running ? 'The first batch arrives within a second or two.' : 'Start a simulation to see events from every integration.')); return; }
    ui.feedBody.append(el('table', {}, el('caption', { class: 'sr-only' }, 'Live events'), el('thead', {}, el('tr', {}, ['Time', 'Source', 'Severity', 'Event', 'Host', 'ATT&CK', 'Incident'].map((h) => el('th', { scope: 'col' }, h)))),
      el('tbody', {}, state.feed.map((s) => el('tr', { class: 'clickable', tabindex: '0', onclick: () => openSignal(s.id), onkeydown: (e) => { if (e.key === 'Enter') openSignal(s.id); } },
        el('td', { class: 'mono' }, fmtTime(s.ts)), el('td', {}, badge(s.source, 'outline')), el('td', {}, s.severity === 'INFO' ? badge('INFO') : levelBadge(s.severity)),
        el('td', {}, s.title.length > 70 ? s.title.slice(0, 70) + '…' : s.title), el('td', {}, monoText(s.host || '—'), s.unmanaged ? [' ', badge('not in inventory', 'med')] : null),
        el('td', {}, (s.technique_ids || '').split(',').filter(Boolean).map((t) => el('span', { class: 'chip' }, t))), el('td', {}, s.incident_code ? badge(s.incident_code, 'info') : ''))))));
  }
  async function openSignal(id) {
    const d = openDrawer({ heading: 'Signal', subtitle: 'Simulated event' });
    try {
      const s = await api(`/api/sim/signals/${id}`);
      d.setTitle(s.title, `${s.source} · ${s.ts}`);
      d.body.append(el('div', { class: 'actions mb' }, s.severity === 'INFO' ? badge('INFO') : levelBadge(s.severity), badge(s.kind, 'outline'), badge('SIMULATED', 'SYNTHETIC')),
        section('Normalised', kv([['Host', s.host || '—'], ['User', s.user || '—'], ['Source IP', s.src_ip || '—'], ['ATT&CK', s.technique_ids || '—'], ['CVE', s.cve_id || '—'], ['Asset in inventory', s.asset_id ? 'yes' : 'no'], ['Status', s.status]])),
        section('Description', el('p', {}, s.description || '—')), section('Raw evidence line', el('pre', { class: 'formula' }, s.raw || '—')), el('p', { class: 'small faint' }, s.simulated_notice));
    } catch (e) { d.body.append(errorBox(e)); }
  }

  // ---- incidents
  async function loadIncidents() {
    const d = await api('/api/sim/incidents');
    clear(ui.incHost).append(el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Correlated incidents'), el('span', { class: 'small faint' }, `${d.items.filter((i) => i.status !== 'CLOSED').length} open`)),
      d.items.length ? el('div', { style: 'max-height:560px;overflow:auto' }, d.items.map((i) => el('div', { class: 'card-b', style: 'border-bottom:1px solid var(--border);cursor:pointer', tabindex: '0', role: 'button', onclick: () => openIncident(i.id), onkeydown: (e) => { if (e.key === 'Enter') openIncident(i.id); } },
        el('div', { style: 'display:flex;justify-content:space-between;gap:8px' }, el('strong', {}, i.title), levelBadge(i.severity)),
        el('div', { class: 'small muted' }, `${i.incident_code} · ${i.signal_count} signals · ${i.source_count || 1} source(s) · `, statusBadge(i.status)),
        el('div', { style: 'margin-top:4px' }, (i.technique_ids || '').split(',').filter(Boolean).slice(0, 6).map((t) => el('span', { class: 'chip' }, t))))))
        : el('div', { class: 'state' }, el('strong', {}, 'No incidents yet'), 'Related alerts from different sources are correlated automatically. Inject a storyline to see one form.')));
  }
  async function openIncident(id) {
    const d = openDrawer({ heading: 'Incident', subtitle: 'Loading…' });
    d.body.append(skeleton(5));
    let inc;
    try { inc = await api(`/api/sim/incidents/${id}`); } catch (e) { clear(d.body).append(errorBox(e)); return; }
    d.setTitle(`${inc.incident_code} · ${inc.title}`, `${inc.category || ''} · detected ${inc.detected_at}`);
    const analyst = el('input', { type: 'text', placeholder: 'Your name', maxlength: '80', 'aria-label': 'Analyst name', value: 'analyst' });
    const triage = async (status) => { try { await api(`/api/sim/incidents/${id}/triage`, { method: 'POST', body: { status, analyst: analyst.value.trim() || 'analyst' } }); toast(`Incident ${status.toLowerCase()}`); d.close(); loadIncidents(); } catch (e) { toast(e.message, 'err'); } };
    const deep = async (btn) => { btn.disabled = true; try { const r = await api(`/api/sim/incidents/${id}/analyze`, { method: 'POST' }); toast(`Analysis created (${r.findings} findings)`); location.hash = `#/analyze?tab=history&id=${r.analysis_id}`; } catch (e) { toast(e.message, 'err'); btn.disabled = false; } };
    clear(d.body).append(el('div', { class: 'actions mb' }, levelBadge(inc.severity), statusBadge(inc.status), badge(`${inc.signal_count} signals`, 'outline')),
      el('p', {}, inc.description),
      section('Analyst actions', el('div', { class: 'actions' }, analyst, el('button', { class: 'btn sm', onclick: () => triage('INVESTIGATING') }, 'Acknowledge'), el('button', { class: 'btn sm', onclick: () => triage('CONTAINED') }, 'Mark contained'),
        el('button', { class: 'btn sm danger', onclick: () => triage('CLOSED') }, 'Close'), el('button', { class: 'btn sm primary', onclick: (e) => deep(e.target) }, 'Deep analyze evidence')),
        el('p', { class: 'small faint', style: 'margin-top:6px' }, 'Containment here is a record of a human decision; nothing is executed on any system.')),
      section('ATT&CK techniques', simpleTable([{ label: 'ID', render: (t) => monoText(t.technique_id) }, { label: 'Technique', render: (t) => t.name || '—' }, { label: 'Tactics', render: (t) => (t.tactics || '').replace(/,/g, ', ') }], inc.techniques)),
      section('Evidence timeline', simpleTable([{ label: 'Time', render: (s) => fmtTime(s.ts) }, { label: 'Source', key: 'source' }, { label: 'Sev', render: (s) => s.severity === 'INFO' ? 'INFO' : levelBadge(s.severity) }, { label: 'Event', render: (s) => el('span', { class: 'small' }, s.title) }, { label: 'Host', render: (s) => monoText(s.host || '—') }], inc.signals)));
  }

  // ---- go
  renderControl();
  await Promise.all([refreshStatus(), refreshMetrics(), loadFeed(true), loadIncidents()]).catch((e) => toast(e.message, 'err'));
  renderControl();
  // one in-flight guard per poller: a shared guard would let the 2s poller starve the 4s one (4s is a multiple of 2s)
  const poller = (fn) => { let busy = false; return async () => { if (busy) return; busy = true; try { await fn(); } catch (e) { console.warn('live poll failed:', e && e.message); } finally { busy = false; } }; };
  timers.push(setInterval(poller(async () => { await loadFeed(); await refreshStatus(); }), 2000));
  timers.push(setInterval(poller(async () => { await refreshMetrics(); await loadIncidents(); }), 4000));
}
