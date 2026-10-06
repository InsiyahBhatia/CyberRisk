import { api, el, clear, badge, openDrawer, closeDrawer, toast, skeleton, errorBox, notice, getWorkspace, setWorkspace, formField, fmt, relTime } from '../core.js';

const KIND = { demo: 'Demo', organization: 'Organization', sandbox: 'Sandbox' };

export async function openWorkspaceManager(onChange) {
  const d = openDrawer({ heading: 'Workspaces', subtitle: 'Each workspace has its own isolated data' });
  const list = el('div', {}, skeleton(4));
  d.body.append(list);
  const load = async () => {
    let data;
    try { data = await api('/api/workspaces'); } catch (e) { clear(list).append(errorBox(e, load)); return; }
    const cur = getWorkspace();
    clear(list).append(...data.items.map((w) => el('div', { class: 'card mb', style: w.slug === cur ? 'border-color:var(--accent)' : '' },
      el('div', { class: 'card-b' }, el('div', { class: 'actions', style: 'justify-content:space-between' },
        el('div', {}, el('strong', {}, w.name), ' ', badge(KIND[w.kind], w.kind === 'organization' ? 'info' : 'outline'), w.slug === cur ? [' ', badge('Current', 'low')] : null,
          el('div', { class: 'small muted' }, [w.industry, w.size].filter(Boolean).join(' · ') || w.description || '')),
        el('div', { class: 'actions' },
          w.slug !== cur ? el('button', { class: 'btn sm primary', onclick: () => { setWorkspace(w.slug); closeDrawer(); onChange(); } }, 'Open') : null,
          w.kind === 'organization' ? el('button', { class: 'btn sm danger', onclick: () => remove(w) }, 'Delete') : null)),
        el('div', { class: 'small faint', style: 'margin-top:6px' }, w.kind === 'sandbox' ? `${w.stats.analyses ?? 0} saved analyses · no organisation data`
          : `${fmt(w.stats.assets, 0)} assets · ${fmt(w.stats.risks, 0)} open risks · ${fmt(w.stats.open_vulnerabilities, 0)} open vulnerabilities`)))));
    list.append(createForm());
  };
  async function remove(w) {
    const typed = prompt(`This permanently deletes "${w.name}" and all its data.\nType the workspace id to confirm: ${w.slug}`);
    if (typed !== w.slug) return;
    try { await api(`/api/workspaces/${w.slug}?confirm=${encodeURIComponent(typed)}`, { method: 'DELETE' }); toast('Workspace deleted'); if (getWorkspace() === w.slug) { setWorkspace('demo'); closeDrawer(); onChange(); } else load(); }
    catch (e) { toast(e.message, 'err'); }
  }
  function createForm() {
    const name = el('input', { type: 'text', maxlength: '60', placeholder: 'e.g. Globex Corporation', required: true });
    const industry = el('select', {}, ['', 'Technology', 'Financial services', 'Healthcare', 'Retail', 'Manufacturing', 'Government', 'Education', 'Energy', 'Other'].map((x) => el('option', { value: x }, x || 'Industry (optional)')));
    const size = el('select', {}, ['', '1-50', '51-250', '251-1000', '1000+'].map((x) => el('option', { value: x }, x || 'Size (optional)')));
    const tpl = el('select', {}, el('option', { value: 'empty' }, 'Start empty (I will import my own data)'), el('option', { value: 'demo' }, 'Pre-load synthetic demo data'));
    const btn = el('button', { class: 'btn primary', onclick: async () => {
      if (name.value.trim().length < 2) { toast('Enter an organization name', 'err'); return; }
      btn.disabled = true; btn.textContent = 'Creating…';
      try { const w = await api('/api/workspaces', { method: 'POST', body: { name: name.value.trim(), industry: industry.value || null, size: size.value || null, template: tpl.value } });
        setWorkspace(w.slug); toast(`Created ${w.name}`); closeDrawer(); onChange(); }
      catch (e) { toast(e.body?.error?.details?.map((x) => x.message).join('; ') || e.message, 'err'); btn.disabled = false; btn.textContent = 'Create workspace'; }
    } }, 'Create workspace');
    return el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, 'New organization')), el('div', { class: 'card-b' },
      formField('Name', name), el('div', { class: 'grid g2' }, formField('Industry', industry), formField('Size', size)), formField('Starting point', tpl),
      el('p', { class: 'small muted' }, 'New workspaces include the public threat data (NVD, CISA KEV, ATT&CK), framework controls and the knowledge base. Your assets, risks, control status and evidence start empty and stay private to the workspace.'), btn));
  }
  load();
}
