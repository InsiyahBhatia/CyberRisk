// Shared UI primitives. All DOM is built with textContent/createElement: API data is never injected as HTML.

// Make Element.append tolerant: null/false are skipped and nested arrays flattened (a native append would print "null" / "[object ...]").
const nativeAppend = Element.prototype.append;
Element.prototype.append = function (...kids) { return nativeAppend.apply(this, kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false)); };

/** Active LLM provider label ("Gemini", "Groq" or generic "AI"), set at boot from /api/ai/status. */
export const ai = { name: 'AI', warning: null };

export const $ = (sel, root = document) => root.querySelector(sel);

export function el(tag, attrs = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k === 'dataset') Object.assign(node.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === 'text') node.textContent = v;
    else node.setAttribute(k, v === true ? '' : v);
  }
  append(node, kids);
  return node;
}
export function append(node, kids) {
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}
export const clear = (node) => { node.replaceChildren(); return node; };

// ---- API ---------------------------------------------------------------------------------------
export class ApiError extends Error {
  constructor(status, message, body) { super(message); this.status = status; this.body = body; }
}
// ---- workspace + role (per-browser preferences; the server enforces tenant isolation) ---------------
const store = { get: (k, d) => { try { return localStorage.getItem(k) || d; } catch { return d; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } } };
export const getWorkspace = () => store.get('cr.workspace', 'demo');
export const setWorkspace = (slug) => store.set('cr.workspace', slug);
export const getRole = () => store.get('cr.role', 'advisor');
export const setRole = (r) => store.set('cr.role', r);

export async function api(path, { method = 'GET', body, form, raw } = {}) {
  const opts = { method, headers: { 'X-Workspace': getWorkspace() } };
  if (form) opts.body = form;
  else if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(path, opts); }
  catch { throw new ApiError(0, 'Cannot reach the CyberRisk server. Is it running?', null); }
  if (raw && res.ok) return res;
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) throw new ApiError(res.status, data?.error?.message || data?.detail || `Request failed (${res.status})`, data);
  return data;
}
export const qs = (obj) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) if (v !== '' && v !== null && v !== undefined) p.set(k, v);
  const s = p.toString();
  return s ? `?${s}` : '';
};

// ---- formatting --------------------------------------------------------------------------------
export const fmt = (n, d = 1) => (n === null || n === undefined || Number.isNaN(n)) ? '—' : Number(n).toLocaleString(undefined, { maximumFractionDigits: d, minimumFractionDigits: 0 });
export const fmtDate = (s) => s ? String(s).slice(0, 10) : '—';
export function relTime(iso) {
  if (!iso) return 'never';
  const t = new Date(iso.length === 10 ? iso + 'T00:00:00Z' : iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 90) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  const d = Math.round(s / 86400);
  return d === 1 ? 'yesterday' : `${d} days ago`;
}
export const title = (s) => (s || '').toLowerCase().replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());

// ---- small components --------------------------------------------------------------------------
export const badge = (text, cls = '') => el('span', { class: `badge ${cls}` }, text);
export const levelBadge = (lvl) => lvl ? badge(lvl, lvl) : badge('—');
const STATUS_CLS = { OPEN: 'high', IN_PROGRESS: 'med', RESOLVED: 'low', ACCEPTED: 'info', CLOSED: 'low', HEALTHY: 'low', CACHED: 'med', FAILED: 'crit', PRESENT: 'low', MISSING: 'crit',
  EXPIRED: 'high', NEEDS_REVIEW: 'med', IMPLEMENTED: 'low', PARTIAL: 'med', NOT_IMPLEMENTED: 'crit', PENDING: 'med', APPROVED: 'low', REJECTED: 'crit', ACTIVE: 'low', QUARANTINED: 'crit',
  SUCCESS: 'low', RUNNING: 'info', COMPLETED: 'low', OVERDUE: 'crit', NOT_STARTED: 'med' };
export const statusBadge = (s) => badge(title(s) || '—', STATUS_CLS[s] || '');
export const monoText = (s) => el('span', { class: 'mono' }, s ?? '—');
export function scoreBar(value, max = 100, label) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  return el('span', { class: 'score-bar', title: `${fmt(value)} / ${max}` },
    el('span', { class: 'track' }, el('i', { style: `width:${pct}%` })), el('span', { class: 'mono' }, label ?? fmt(value)));
}
export function skeleton(rows = 5) { return el('div', { 'aria-busy': 'true', 'aria-label': 'Loading' }, Array.from({ length: rows }, () => el('div', { class: 'skeleton' }))); }
export function stateBox(heading, message, ...actions) {
  return el('div', { class: 'state', role: 'status' }, el('strong', {}, heading), el('div', {}, message), actions.length ? el('div', { style: 'margin-top:10px' }, actions) : null);
}
export function errorBox(err, retry) {
  return el('div', { class: 'state', role: 'alert' }, el('strong', {}, 'Something went wrong'), el('div', {}, err.message || String(err)),
    retry ? el('div', { style: 'margin-top:10px' }, el('button', { class: 'btn', onclick: retry }, 'Retry')) : null);
}
export function notice(text, kind = '') { return el('div', { class: `notice ${kind}`, role: kind === 'err' ? 'alert' : 'note' }, text); }

export function toast(message, kind = '') {
  let stack = $('.toast-stack');
  if (!stack) { stack = el('div', { class: 'toast-stack', role: 'status', 'aria-live': 'polite' }); document.body.append(stack); }
  const t = el('div', { class: `toast ${kind}` }, message);
  stack.append(t);
  setTimeout(() => t.remove(), kind === 'err' ? 7000 : 3500);
}

// ---- drawer (compact right-side panel; also used for contextual AI) ------------------------------
let activeDrawer = null;
export function openDrawer({ heading, subtitle, onClose } = {}) {
  closeDrawer();
  const prevFocus = document.activeElement;
  const scrim = el('div', { class: 'scrim', onclick: () => closeDrawer() });
  const body = el('div', { class: 'drawer-b' });
  const h = el('h2', {}, heading || '');
  const sub = el('div', { class: 'muted small' }, subtitle || '');
  const closeBtn = el('button', { class: 'btn sm', 'aria-label': 'Close panel', onclick: () => closeDrawer() }, 'Close');
  const panel = el('aside', { class: 'drawer', role: 'dialog', 'aria-modal': 'true', 'aria-label': heading || 'Details', tabindex: '-1' },
    el('div', { class: 'drawer-h' }, el('div', {}, h, sub), closeBtn), body);
  document.body.append(scrim, panel);
  const onKey = (e) => { if (e.key === 'Escape') closeDrawer(); };
  document.addEventListener('keydown', onKey);
  panel.focus();
  activeDrawer = { scrim, panel, onKey, prevFocus, onClose };
  return { body, setTitle: (t, s) => { h.textContent = t; sub.textContent = s || ''; panel.setAttribute('aria-label', t); }, close: closeDrawer };
}
export function closeDrawer() {
  if (!activeDrawer) return;
  const { scrim, panel, onKey, prevFocus, onClose } = activeDrawer;
  scrim.remove(); panel.remove(); document.removeEventListener('keydown', onKey);
  activeDrawer = null;
  if (onClose) onClose();
  if (prevFocus && prevFocus.focus) prevFocus.focus();
}

// ---- page lifecycle: views register cleanup (timers, listeners) that runs when the route changes ------------------
const leaveHooks = [];
export const onLeave = (fn) => { leaveHooks.push(fn); };
export function runLeave() { while (leaveHooks.length) { try { leaveHooks.pop()(); } catch { /* ignore */ } } }

// ---- charts (Chart.js, vendored) -------------------------------------------------------------------
const charts = [];
export function destroyCharts() { while (charts.length) charts.pop().destroy(); }
const PALETTE = { text: '#62625d', grid: '#e9e7e0', accent: '#3a5a78', accent2: '#8aa3b8', neutral: '#b9b6ab' };
export const LEVEL_COLORS = { CRITICAL: '#9a2e2e', HIGH: '#c0703f', MEDIUM: '#c9a93f', LOW: '#6a9a76' };
export function chart(canvas, config) {
  if (!window.Chart) { canvas.replaceWith(stateBox('Chart unavailable', 'Chart.js did not load.')); return null; }
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.color = PALETTE.text;
  Chart.defaults.animation = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? false : { duration: 250 };
  config.options = { maintainAspectRatio: false, responsive: true, ...config.options };
  const c = new Chart(canvas, config);
  charts.push(c);
  return c;
}
export const gridOpts = { grid: { color: PALETTE.grid }, border: { display: false } };
export const chartBox = (cls = '') => { const canvas = el('canvas', { role: 'img' }); return { box: el('div', { class: `chart-box ${cls}` }, canvas), canvas }; };

// ---- tabs ---------------------------------------------------------------------------------------------
export function tabs(items, initial, onSelect) {
  const bar = el('div', { class: 'tabs', role: 'tablist' });
  const render = (sel) => items.forEach((it, i) => {
    const btn = bar.children[i];
    btn.setAttribute('aria-selected', String(it.key === sel));
    btn.tabIndex = it.key === sel ? 0 : -1;
  });
  items.forEach((it, i) => bar.append(el('button', {
    role: 'tab', id: `tab-${it.key}`, onclick: () => { render(it.key); onSelect(it.key); },
    onkeydown: (e) => {
      const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (!d) return;
      const next = items[(i + d + items.length) % items.length];
      render(next.key); onSelect(next.key); bar.children[items.indexOf(next)].focus();
    } }, it.label)));
  render(initial);
  return bar;
}

// ---- data table: server-side sort / filter / pagination, loading + empty + error states ---------------------
export function dataTable({ columns, load, filters = [], pageSize = 15, onRow, empty = 'No records match these filters.', initialFilters = {}, initialSort = {}, caption }) {
  const state = { page: 1, sort: initialSort.sort || '', order: initialSort.order || 'desc', filters: { ...initialFilters } };
  const root = el('div', { class: 'card' });
  const toolbar = el('div', { class: 'toolbar', role: 'search' });
  const tableHost = el('div', { class: 'table-wrap' });
  const pager = el('div', { class: 'pager' });
  root.append(toolbar, tableHost, pager);
  let timer;

  for (const f of filters) {
    let input;
    if (f.type === 'select') {
      input = el('select', { 'aria-label': f.label, onchange: (e) => { state.filters[f.key] = e.target.value; state.page = 1; refresh(); } },
        el('option', { value: '' }, f.label), f.options.map((o) => { const [v, l] = Array.isArray(o) ? o : [o, title(o)]; return el('option', { value: v, selected: String(state.filters[f.key] ?? '') === String(v) }, l); }));
    } else {
      input = el('input', { type: 'search', placeholder: f.label, 'aria-label': f.label, value: state.filters[f.key] || '',
        oninput: (e) => { clearTimeout(timer); timer = setTimeout(() => { state.filters[f.key] = e.target.value; state.page = 1; refresh(); }, 250); } });
    }
    toolbar.append(input);
  }
  if (!filters.length) toolbar.remove();

  async function refresh() {
    clear(tableHost).append(skeleton(6));
    try {
      const params = { ...state.filters, sort: state.sort, order: state.order, page: state.page, page_size: pageSize };
      const data = await load(params);
      render(data);
    } catch (e) { clear(tableHost).append(errorBox(e, refresh)); clear(pager); }
  }
  function render(data) {
    clear(tableHost);
    if (!data.items.length) { tableHost.append(stateBox('Nothing to show', empty)); clear(pager); return; }
    const thead = el('thead', {}, el('tr', {}, columns.map((c) => {
      const th = el('th', { scope: 'col', class: c.num ? 'num' : '' });
      if (c.sort) {
        const active = state.sort === c.sort;
        th.setAttribute('aria-sort', active ? (state.order === 'asc' ? 'ascending' : 'descending') : 'none');
        th.append(el('button', { onclick: () => { state.order = active && state.order === 'desc' ? 'asc' : 'desc'; state.sort = c.sort; state.page = 1; refresh(); } },
          c.label, el('span', { 'aria-hidden': 'true' }, active ? (state.order === 'asc' ? '▲' : '▼') : '')));
      } else th.append(c.label);
      return th;
    })));
    const tbody = el('tbody', {}, data.items.map((row) => {
      const tr = el('tr', { class: onRow ? 'clickable' : '', tabindex: onRow ? '0' : null,
        onclick: onRow ? () => onRow(row) : null, onkeydown: onRow ? (e) => { if (e.key === 'Enter') onRow(row); } : null },
        columns.map((c) => el('td', { class: c.num ? 'num' : '' }, c.render ? c.render(row) : (c.mono ? monoText(row[c.key]) : (row[c.key] ?? '—')))));
      return tr;
    }));
    tableHost.append(el('table', {}, caption ? el('caption', { class: 'sr-only' }, caption) : null, thead, tbody));
    const pages = Math.max(1, Math.ceil(data.total / data.page_size));
    const from = (data.page - 1) * data.page_size + 1;
    clear(pager).append(el('span', {}, `${from}–${Math.min(data.total, data.page * data.page_size)} of ${fmt(data.total, 0)}`),
      el('span', { class: 'pages' },
        el('button', { class: 'btn sm', disabled: data.page <= 1, onclick: () => { state.page--; refresh(); } }, 'Previous'),
        el('span', {}, `Page ${data.page} of ${pages}`),
        el('button', { class: 'btn sm', disabled: data.page >= pages, onclick: () => { state.page++; refresh(); } }, 'Next')));
  }
  refresh();
  root.refresh = refresh;
  return root;
}

export function kv(pairs) {
  const dl = el('dl', { class: 'kv' });
  for (const [k, v] of pairs) dl.append(el('dt', {}, k), el('dd', {}, v ?? '—'));
  return dl;
}
export function section(heading, ...content) { return el('div', { class: 'section' }, el('h3', {}, heading), content); }
export function simpleTable(columns, items, { empty = 'No data.' } = {}) {
  if (!items.length) return el('div', { class: 'muted small' }, empty);
  return el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, columns.map((c) => el('th', { scope: 'col', class: c.num ? 'num' : '' }, c.label)))),
    el('tbody', {}, items.map((r) => el('tr', {}, columns.map((c) => el('td', { class: c.num ? 'num' : '' }, c.render ? c.render(r) : (c.mono ? monoText(r[c.key]) : (r[c.key] ?? '—')))))))));
}

/** Fetch a file/report with the workspace header and open or save it (a plain link cannot send headers). */
export async function openReport(path, { download = false, filename = 'report.html' } = {}) {
  const res = await api(path, { raw: true });
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  if (download) { const a = el('a', { href: url, download: filename }); document.body.append(a); a.click(); a.remove(); }
  else window.open(url, '_blank', 'noopener');
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}
export function formField(label, node, hint) { return el('label', { class: 'field', style: 'margin-bottom:12px' }, label, node, hint ? el('span', { class: 'faint small' }, hint) : null); }
