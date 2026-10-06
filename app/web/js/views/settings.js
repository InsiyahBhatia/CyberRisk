import { api, el, clear, fmt, relTime, dataTable, badge, monoText, section, kv, skeleton, errorBox, notice, toast, qs } from '../core.js';

export async function settings(root) {
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Settings'), el('p', {}, 'Risk model weights, AI configuration and the audit log. Secrets are never shown here.'))));
  const host = el('div', {}, skeleton(6));
  root.append(host);
  let s;
  try { s = await api('/api/settings'); } catch (e) { clear(host).append(errorBox(e, () => { root.replaceChildren(); settings(root); })); return; }
  clear(host);
  const inputs = {};
  const rows = s.risk_config.map((c) => {
    inputs[c.key] = el('input', { type: 'number', min: '0', max: '1', step: '0.05', value: c.value, 'aria-label': c.key, style: 'width:90px' });
    return el('tr', {}, el('td', {}, monoText(c.key)), el('td', {}, c.description), el('td', {}, inputs[c.key]));
  });
  const save = async () => {
    try {
      const values = Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, parseFloat(i.value)]));
      const r = await api('/api/settings/risk-config', { method: 'PUT', body: { values } });
      toast(`Saved. Recalculated ${r.recalculated.risks} risks and ${r.recalculated.vulnerabilities} vulnerabilities.`);
    } catch (e) { toast(e.body?.error?.message || e.message, 'err'); }
  };
  host.append(el('div', { class: 'grid g2 mb' },
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'AI configuration')), el('div', { class: 'card-b' }, kv([['Provider', s.ai.provider], ['Model', s.ai.model], ['API key', s.ai.configured ? badge('Configured', 'low') : badge('Not configured', 'med')],
      ['Prompt version', s.ai.prompt_version], ['Max input length', `${s.application.max_input_chars} characters`]]), el('p', { class: 'small muted', style: 'margin-top:8px' }, 'Set GEMINI_API_KEY and GEMINI_MODEL in .env, then restart. The key is never returned by any endpoint.'))),
    el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'Public data')), el('div', { class: 'card-b' }, kv([['NVD API key', s.nvd.api_key_configured ? badge('Configured (higher rate limit)', 'low') : badge('Not set (public rate limit)', 'outline')],
      ['Default NVD window', `${s.nvd.default_window_days} days`], ['Max NVD records', s.nvd.max_records], ['Database', s.application.database]])))),
    el('div', { class: 'card mb' }, el('div', { class: 'card-h' }, el('h2', {}, 'Risk model weights'), el('button', { class: 'btn primary', onclick: save }, 'Save and recalculate')),
      el('div', { class: 'card-b' }, el('p', { class: 'small muted' }, 'Weights live in the risk_config table, not in prompts. Within each group they are normalised, so only their ratios matter. Saving recalculates every score.'),
        el('div', { class: 'table-wrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['Key', 'Meaning', 'Weight (0–1)'].map((h) => el('th', { scope: 'col' }, h)))), el('tbody', {}, rows))))),
    el('div', { class: 'card mb' }, el('div', { class: 'card-h' }, el('h2', {}, 'Formulas')), el('div', { class: 'card-b' }, kv(Object.entries(s.formulas).map(([k, v]) => [k.replace(/_/g, ' '), v])))),
    el('h2', { style: 'margin:0 0 8px' }, 'Audit log'),
    dataTable({ caption: 'Audit log', pageSize: 10, load: (p) => api('/api/audit-log' + qs({ page: p.page, page_size: p.page_size })), empty: 'No audited actions yet.',
      columns: [{ key: 'ts', label: 'Time', render: (r) => relTime(r.ts) }, { key: 'actor', label: 'Actor' }, { key: 'action', label: 'Action', mono: true }, { key: 'entity', label: 'Entity' }, { key: 'entity_id', label: 'ID', mono: true }, { key: 'detail', label: 'Detail', render: (r) => (r.detail || '').slice(0, 80) }] }));
}
