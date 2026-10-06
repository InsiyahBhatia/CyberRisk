import { ai, $, el, clear, closeDrawer, destroyCharts, runLeave, errorBox, api, badge, getWorkspace, setWorkspace, getRole, setRole } from './core.js';
import { openAskPanel } from './ai.js';
import { openWorkspaceManager } from './views/workspaces.js';
import { overview } from './views/overview.js';
import { risks } from './views/risks.js';
import { controls, compliance } from './views/grc.js';
import { vulnerabilities } from './views/vulns.js';
import { incidents } from './views/incidents.js';
import { vendors } from './views/vendors.js';
import { governance } from './views/governance.js';
import { evals } from './views/evals.js';
import { pipeline } from './views/pipeline.js';
import { settings } from './views/settings.js';
import { setup } from './views/setup.js';
import { analyze } from './views/analyze.js';
import { assets } from './views/assets.js';
import { reports } from './views/reports.js';
import { live } from './views/live.js';

const ORG = ['organization', 'demo'];
const ALL = ['organization', 'demo', 'sandbox'];
const ROUTES = [
  { path: 'setup', label: 'Getting started', view: setup, kinds: ['organization'] },
  { path: 'overview', label: 'Overview', view: overview, kinds: ORG },
  { path: 'analyze', label: 'Analyze', view: analyze, kinds: ALL },
  { path: 'live', label: 'Live operations', view: live, kinds: ORG },
  { path: 'risks', label: 'Risks', view: risks, kinds: ORG },
  { path: 'controls', label: 'Controls', view: controls, kinds: ORG },
  { path: 'compliance', label: 'Compliance', view: compliance, kinds: ORG },
  { path: 'assets', label: 'Assets', view: assets, kinds: ORG },
  { path: 'vulnerabilities', label: 'Vulnerabilities', view: vulnerabilities, kinds: ORG },
  { path: 'incidents', label: 'Incidents', view: incidents, kinds: ORG },
  { path: 'vendors', label: 'Vendors', view: vendors, kinds: ORG },
  { path: 'reports', label: 'Reports', view: reports, kinds: ORG },
  { path: 'ai-governance', label: 'AI Governance', view: governance, kinds: ALL },
  { path: 'evals', label: 'Evals', view: evals, kinds: ALL },
  { path: 'pipeline', label: 'Data Pipeline', view: pipeline, kinds: ALL },
  { path: 'settings', label: 'Settings', view: settings, kinds: ALL },
];
// What each job focuses on first. Everything else stays reachable under "More".
const ROLES = {
  advisor: { label: 'Risk advisor / GRC', focus: ['setup', 'overview', 'risks', 'controls', 'compliance', 'assets', 'reports', 'vendors'] },
  analyst: { label: 'Security analyst', focus: ['analyze', 'live', 'vulnerabilities', 'incidents', 'assets', 'pipeline', 'risks'] },
  executive: { label: 'Executive', focus: ['overview', 'risks', 'compliance', 'reports', 'vendors'] },
};

let workspace = null; // {slug, name, kind}

async function loadWorkspace() {
  const data = await api('/api/workspaces');
  workspace = data.items.find((w) => w.slug === getWorkspace());
  if (!workspace) { setWorkspace('demo'); workspace = data.items.find((w) => w.slug === 'demo'); }
}

const visible = () => ROUTES.filter((r) => r.kinds.includes(workspace.kind));

function buildNav() {
  const nav = $('#nav');
  clear(nav);
  const role = ROLES[getRole()] || ROLES.advisor;
  const vis = visible();
  const focus = role.focus.map((p) => vis.find((r) => r.path === p)).filter(Boolean);
  const rest = vis.filter((r) => !focus.includes(r));
  const link = (r) => el('a', { href: `#/${r.path}`, 'data-path': r.path }, r.label);
  if (focus.length) nav.append(el('div', { class: 'group', 'aria-hidden': 'true' }, role.label), ...focus.map(link));
  if (rest.length) nav.append(el('div', { class: 'group', 'aria-hidden': 'true' }, focus.length ? 'More' : 'Tools'), ...rest.map(link));
}

function buildChrome() {
  $('#ws-name').textContent = workspace.name;
  const kind = $('#ws-kind');
  kind.textContent = { demo: 'Demo', organization: 'Organization', sandbox: 'Sandbox' }[workspace.kind];
  kind.className = `badge ${workspace.kind === 'organization' ? 'info' : 'outline'}`;
  const sel = $('#role');
  if (!sel.options.length) Object.entries(ROLES).forEach(([k, v]) => sel.append(el('option', { value: k }, v.label)));
  sel.value = getRole();
  document.querySelector('.topbar .tagline').textContent = workspace.kind === 'sandbox' ? 'No organisation: analyse logs and incidents on their own' : workspace.kind === 'demo' ? 'Demo: synthetic organisation, real public threat data' : `Workspace: ${workspace.name}`;
}

function parseHash() {
  const [path, query = ''] = location.hash.replace(/^#\/?/, '').split('?');
  return { path, params: Object.fromEntries(new URLSearchParams(query)) };
}

async function landing() {
  const vis = visible();
  if (workspace.kind === 'sandbox') return 'analyze';
  if (workspace.kind === 'organization' && getRole() === 'advisor') {
    try { const s = await api('/api/workspace/status'); if (s.progress < 100) return 'setup'; } catch { /* fall through */ }
  }
  const first = (ROLES[getRole()] || ROLES.advisor).focus.find((p) => vis.some((r) => r.path === p));
  return first || vis[0].path;
}

let seq = 0;
async function renderNow() {
  const { path, params } = parseHash();
  const route = visible().find((r) => r.path === path);
  if (!route) { location.replace(`#/${await landing()}`); return; }
  const mine = ++seq;
  runLeave(); closeDrawer(); destroyCharts();
  for (const a of $('#nav').querySelectorAll('a')) { if (a.dataset.path === route.path) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); }
  document.title = `${route.label} · ${workspace.name} · CyberRisk`;
  $('#sidebar').classList.remove('open');
  // each render fills its own container; a newer render detaches it, so a slow stale view can never write into the page
  const root = el('div');
  $('#view').replaceChildren(root);
  try { await route.view(root, params); } catch (e) { if (mine === seq) clear(root).append(errorBox(e, renderNow)); }
  if (mine === seq) { $('#main').focus({ preventScroll: true }); window.scrollTo(0, 0); }
}

let ready = Promise.resolve(true);
function boot(forceLanding = false) {
  ready = (async () => {
    try { await loadWorkspace(); } catch (e) { clear($('#view')).append(errorBox(e, () => boot())); return false; }
    buildNav(); buildChrome(); status();
    const current = parseHash().path;
    if (forceLanding || !visible().some((r) => r.path === current)) {
      const want = await landing();
      if (want !== current) { location.hash = `#/${want}`; return false; } // the hashchange handler renders
    }
    return true;
  })();
  return ready.then((ok) => ok && renderNow());
}

window.addEventListener('hashchange', () => { ready.then(() => renderNow()); });
$('#menu-btn').addEventListener('click', () => { const sb = $('#sidebar'); const open = sb.classList.toggle('open'); $('#menu-btn').setAttribute('aria-expanded', String(open)); });
$('#ask-btn').addEventListener('click', openAskPanel);
$('#ws-btn').addEventListener('click', () => openWorkspaceManager(() => boot(true)));
$('#role').addEventListener('change', async (e) => { setRole(e.target.value); buildNav(); const want = await landing(); if (parseHash().path === want) renderNow(); else location.hash = `#/${want}`; });

async function status() {
  try {
    const st = await api('/api/ai/status');
    ai.name = st.provider_id === 'groq' ? 'Groq' : st.provider_id === 'gemini' ? 'Gemini' : 'AI';
    ai.warning = st.warning;
    clear($('#status')).append(badge(st.configured ? `${ai.name}: ${st.model}` : 'AI not configured', st.configured ? 'low' : 'outline'));
    if (st.warning) $('#status').append(el('span', { class: 'small', style: 'color:var(--med);margin-left:8px', title: st.warning }, '⚠ key check'));
  } catch { clear($('#status')).append(badge('Server unreachable', 'crit')); }
}
boot();
