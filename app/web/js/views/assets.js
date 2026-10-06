import { api, el, qs, dataTable, levelBadge, badge, monoText, openDrawer, toast, formField, title } from '../core.js';

export async function assets(root) {
  const table = dataTable({
    caption: 'Assets', pageSize: 20, initialSort: { sort: 'asset_tag', order: 'asc' },
    filters: [{ key: 'q', label: 'Search assets…', type: 'search' }, { key: 'criticality', label: 'All criticalities', type: 'select', options: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] }],
    load: (p) => api('/api/assets' + qs(p)),
    empty: 'No assets yet. Import an inventory from Data Pipeline → Run / upload, or add one.',
    columns: [{ key: 'asset_tag', label: 'Tag', sort: 'asset_tag', mono: true }, { key: 'name', label: 'Name' }, { key: 'asset_type', label: 'Type' }, { key: 'business_unit', label: 'Business unit' },
      { key: 'owner', label: 'Owner' }, { key: 'criticality', label: 'Criticality', sort: 'criticality', render: (a) => levelBadge(a.criticality) },
      { key: 'internet_exposed', label: 'Exposure', render: (a) => a.internet_exposed ? badge('Internet-facing', 'high') : badge('Internal', 'outline') },
      { key: 'open_vulns', label: 'Open vulns', sort: 'open_vulns', num: true }, { key: 'open_risks', label: 'Open risks', num: true }],
  });
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Assets'), el('p', {}, 'The inventory risk is attached to. Criticality and exposure feed vulnerability priority and risk impact.')),
    el('div', { class: 'actions' }, el('a', { class: 'btn', href: '#/pipeline?tab=run' }, 'Import inventory'), el('button', { class: 'btn primary', onclick: () => form(() => table.refresh()) }, 'Add asset'))), table);
}

function form(done) {
  const d = openDrawer({ heading: 'Add asset' });
  const f = { tag: el('input', { type: 'text', maxlength: '40', placeholder: 'e.g. SRV-0001' }), name: el('input', { type: 'text', maxlength: '120' }), type: el('input', { type: 'text', maxlength: '60', placeholder: 'Server, Database, Laptop…' }),
    bu: el('input', { type: 'text', maxlength: '80' }), owner: el('input', { type: 'text', maxlength: '80' }), crit: el('select', {}, ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((c) => el('option', { value: c, selected: c === 'MEDIUM' }, title(c)))),
    exp: el('input', { type: 'checkbox' }), cls: el('input', { type: 'text', maxlength: '40', placeholder: 'Public, Internal, Confidential, Restricted' }) };
  d.body.append(formField('Asset tag', f.tag, 'Unique identifier used by scanner data and risks'), formField('Name', f.name), el('div', { class: 'grid g2' }, formField('Type', f.type), formField('Criticality', f.crit)),
    el('div', { class: 'grid g2' }, formField('Business unit', f.bu), formField('Owner', f.owner)), formField('Data classification', f.cls),
    el('label', { style: 'display:flex;gap:8px;align-items:center;margin-bottom:16px' }, f.exp, 'Internet-facing'),
    el('button', { class: 'btn primary', onclick: async () => {
      try { await api('/api/assets', { method: 'POST', body: { asset_tag: f.tag.value.trim(), name: f.name.value.trim() || f.tag.value.trim(), asset_type: f.type.value || null, business_unit: f.bu.value || null, owner: f.owner.value || null,
        criticality: f.crit.value, internet_exposed: f.exp.checked, data_classification: f.cls.value || null } }); toast('Asset added'); d.close(); done(); }
      catch (e) { toast(e.body?.error?.details?.map((x) => `${x.field}: ${x.message}`).join('; ') || e.message, 'err'); }
    } }, 'Add asset'));
}
