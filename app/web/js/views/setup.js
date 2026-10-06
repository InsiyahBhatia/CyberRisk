import { api, el, clear, badge, skeleton, errorBox, fmt, notice, openReport, toast } from '../core.js';

/** Guided onboarding for a new organization: what to do next, computed from what is really in the database. */
export async function setup(root) {
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Getting started'), el('p', {}, 'Build a defensible risk picture step by step. Each step completes automatically when its data exists.'))));
  const host = el('div', {}, skeleton(6));
  root.append(host);
  let s;
  try { s = await api('/api/workspace/status'); } catch (e) { clear(host).append(errorBox(e, () => { root.replaceChildren(); setup(root); })); return; }
  clear(host);
  const w = s.workspace || {};
  host.append(el('div', { class: 'card mb' }, el('div', { class: 'card-b' }, el('div', { class: 'actions', style: 'justify-content:space-between' },
    el('div', {}, el('h2', {}, w.name || 'Workspace'), el('div', { class: 'small muted' }, [w.industry, w.size].filter(Boolean).join(' · ') || 'Organization workspace')),
    el('div', { style: 'min-width:220px' }, el('div', { class: 'small muted' }, `${s.progress}% complete`), el('div', { class: 'kpi' }, el('div', { class: 'bar', style: 'margin:4px 0 0' }, el('i', { style: `width:${s.progress}%` }))))))));
  host.append(el('div', { class: 'card' }, ...s.steps.map((st, i) => el('div', { class: 'card-b', style: 'border-bottom:1px solid var(--border);display:flex;gap:14px;align-items:flex-start' },
    el('div', { 'aria-hidden': 'true', style: `width:26px;height:26px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;font-weight:600;font-size:13px;${st.done ? 'background:var(--low);color:#fff' : 'background:var(--neutral-bg);color:var(--text-2)'}` }, st.done ? '✓' : String(i + 1)),
    el('div', { style: 'flex:1' }, el('div', { style: 'font-weight:600' }, st.title, ' ', badge(st.done ? 'Done' : 'To do', st.done ? 'low' : 'outline'), el('span', { class: 'sr-only' }, st.done ? ' completed' : ' not completed')),
      el('div', { class: 'small muted' }, st.hint), el('div', { class: 'small faint' }, st.detail)),
    el('a', { class: 'btn sm', href: st.link }, st.done ? 'Review' : 'Do this')))));
  host.append(el('div', { class: 'grid g2', style: 'margin-top:16px' },
    el('div', { class: 'notice' }, el('strong', {}, 'No data yet? '), 'Download a CSV template for any dataset from Data Pipeline → Run / upload, or analyse a log or incident right now with ', el('a', { href: '#/analyze' }, 'Analyze'), ' (no organisation data needed).'),
    el('div', { class: 'notice' }, el('strong', {}, 'Public threat data '), `${s.counts.public_sources} of 4 sources loaded in this workspace. `, el('a', { href: '#/pipeline' }, 'Refresh or inspect'), '.')));
}
