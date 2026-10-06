import { ai, api, el, clear, qs, fmt, fmtDate, relTime, dataTable, statusBadge, badge, monoText, scoreBar, openDrawer, kv, section, skeleton, errorBox, simpleTable, notice, toast, tabs, title } from '../core.js';
import { renderAIResult } from '../ai.js';

function metricTile(label, m, { unit = '', invert = false } = {}) {
  const measured = m.basis === 'measured' && m.value !== null && m.value !== undefined;
  return el('div', { class: 'card kpi' },
    el('div', { class: 'label' }, el('span', {}, label), badge(measured ? 'Measured' : 'Not measured yet', measured ? 'low' : 'outline')),
    el('div', { class: 'value' }, measured ? fmt(m.value, 1) : '—', measured && unit ? el('small', {}, unit) : null), el('div', { class: 'sub' }, m.source));
}

export async function governance(root, params = {}) {
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'AI Governance'), el('p', {}, 'What model ran, with which prompt and sources, what the guardrails did, and what humans approved.'))));
  const host = el('div', {}, skeleton(8));
  root.append(host);
  let g;
  try { g = await api('/api/ai-governance/summary'); } catch (e) { clear(host).append(errorBox(e, () => { root.replaceChildren(); governance(root, params); })); return; }
  clear(host);
  const m = g.metrics, i = g.interactions;
  host.append(
    !g.model.configured ? el('div', { class: 'notice warn mb' }, 'Gemini is not configured (set GROQ_API_KEY or GEMINI_API_KEY in .env). AI actions will report that clearly; nothing is simulated. Deterministic features are unaffected.') : null,
    el('div', { class: 'grid g4 mb' },
      el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Model'), el('div', { class: 'value', style: 'font-size:18px' }, g.model.name), el('div', { class: 'sub' }, `${g.model.provider} · ${g.model.configured ? 'configured' : 'not configured'}`)),
      el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Prompt version'), el('div', { class: 'value', style: 'font-size:18px' }, g.versions.prompt), el('div', { class: 'sub' }, `guardrails ${g.versions.guardrails}`)),
      el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Retrieval index'), el('div', { class: 'value mono', style: 'font-size:18px' }, g.versions.retrieval_index), el('div', { class: 'sub' }, g.versions.retrieval_method)),
      el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Knowledge base'), el('div', { class: 'value', style: 'font-size:18px' }, `${g.knowledge_base.active_documents} docs`), el('div', { class: 'sub' }, `${g.knowledge_base.chunks} chunks · ${g.knowledge_base.quarantined_documents} quarantined`))),
    el('div', { class: 'grid g3 mb' }, metricTile('Evidence traceability (runtime)', m.grounding_score, { unit: '%' }), metricTile('Injection resistance (evals)', m.injection_resistance, { unit: '%' }),
      metricTile('PII leakage failures (evals)', m.pii_leakage_failures), metricTile('Hallucination rate (evals)', m.hallucination_rate, { unit: '%' }),
      metricTile('Schema validity (live evals)', m.schema_validity, { unit: '%' }), metricTile('Latest eval score', m.eval_score, { unit: '%' })),
    el('div', { class: 'grid g4 mb' },
      el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Interactions'), el('div', { class: 'value' }, i.total), el('div', { class: 'sub' }, `${i.answered} answered`)),
      el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Blocked by input guardrail'), el('div', { class: 'value' }, i.blocked_by_input_guardrail), el('div', { class: 'sub' }, 'Injection, exfiltration, out of scope')),
      el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Withheld by output guardrail'), el('div', { class: 'value' }, i.withheld_by_output_guardrail), el('div', { class: 'sub' }, 'Ungrounded or unsupported claims')),
      el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Pending human review'), el('div', { class: 'value' }, i.pending_human_review), el('div', { class: 'sub' }, `${i.approvals.APPROVED || 0} approved · ${i.approvals.REJECTED || 0} rejected`))),
    el('div', { class: 'notice mb' }, g.notes.map((n) => el('div', {}, n))));

  const tabHost = el('div', {});
  const views = { interactions: () => interactionsView(tabHost), knowledge: () => knowledgeView(tabHost) };
  const sel = (k) => { clear(tabHost); views[k](); };
  host.append(tabs([{ key: 'interactions', label: 'Interaction log' }, { key: 'knowledge', label: 'Knowledge base' }], params.tab || 'interactions', sel), tabHost);
  sel(params.tab || 'interactions');
}

function interactionsView(host) {
  const t = dataTable({
    caption: 'AI interactions', filters: [{ key: 'task', label: 'All tasks', type: 'select', options: ['investigate', 'remediation', 'executive_summary', 'analytics', 'rag_answer', 'mapping'] },
      { key: 'guardrail_status', label: 'All guardrail results', type: 'select', options: ['PASSED', 'REDACTED', 'BLOCKED'] }],
    load: (p) => api('/api/ai-governance/interactions' + qs({ task: p.task, guardrail_status: p.guardrail_status, page: p.page, page_size: p.page_size })),
    columns: [{ key: 'id', label: 'ID', mono: true }, { key: 'created_at', label: 'When', render: (r) => relTime(r.created_at + 'Z') }, { key: 'task', label: 'Task', render: (r) => title(r.task) },
      { key: 'sanitized_query', label: 'Query (sanitised)', render: (r) => (r.sanitized_query || '—').slice(0, 70) }, { key: 'model', label: 'Model', render: (r) => r.model || '—' },
      { key: 'guardrail_status', label: 'Input guardrail', render: (r) => badge(r.guardrail_status, r.guardrail_status === 'BLOCKED' ? 'crit' : r.guardrail_status === 'REDACTED' ? 'med' : 'low') },
      { key: 'grounding_score', label: 'Traceability', num: true, render: (r) => r.grounding_score === null ? '—' : fmt(r.grounding_score * 100, 0) + '%' },
      { key: 'requires_approval', label: 'Review', render: (r) => r.approval_decision ? statusBadge(r.approval_decision) : r.requires_approval && r.response ? badge('Pending', 'med') : '—' }],
    onRow: (r) => openInteraction(r, () => t.refresh()),
    empty: `No AI interactions yet. Use "Investigate with ${ai.name}" on a risk, or ask a question from the Overview.`,
  });
  host.append(t);
}

function openInteraction(r, done) {
  const d = openDrawer({ heading: `Interaction ${r.id}`, subtitle: `${title(r.task)} · ${r.created_at}` });
  const out = JSON.parse(r.output_validation || '{}');
  d.body.append(kv([['Model', r.model], ['Prompt version', r.prompt_version], ['Retrieval', `${r.retrieval_count} passage(s)`], ['Retrieved ids', monoText((JSON.parse(r.retrieval_ids || '[]')).join(', ') || '—')], ['Input guardrail', r.guardrail_status],
    ['Output validation', out.valid === undefined ? (out.abstained ? 'Abstained (no evidence)' : out.blocked ? `Blocked: ${out.blocked.join(', ')}` : '—') : (out.valid ? 'Valid' : `Rejected: ${(out.errors || []).join('; ')}`)]]));
  if (r.response) {
    const res = { status: 'OK', answer: JSON.parse(r.response), deterministic: {}, citations: [], evidence: [], guardrails: {}, validation: out, requires_approval: !!r.requires_approval && !r.approval_decision, interaction_id: r.id, model: r.model, prompt_version: r.prompt_version };
    d.body.append(section('Stored response', renderAIResult(res, { onDecision: () => { done(); } })));
    if (r.approval_decision) d.body.append(notice(`Decision recorded: ${r.approval_decision}.`, 'ok'));
  } else d.body.append(notice('No response was stored for this interaction (blocked, withheld or failed validation).', 'warn'));
}

async function knowledgeView(host) {
  const search = el('input', { type: 'search', placeholder: 'Search the knowledge base (retrieval only, no AI)…', 'aria-label': 'Knowledge search', style: 'flex:1;min-width:240px' });
  const results = el('div', { style: 'margin-top:12px' });
  const doSearch = async () => {
    if (!search.value.trim()) return;
    clear(results).append(skeleton(3));
    try {
      const r = await api('/api/rag/query', { method: 'POST', body: { query: search.value.trim(), k: 5 } });
      clear(results);
      if (!r.confident) results.append(notice(r.message || 'Low-confidence retrieval.', 'warn'));
      r.results.forEach((c) => results.append(el('div', { class: 'card mb' }, el('div', { class: 'card-h' }, el('strong', {}, `${c.title} — ${c.section}`), el('span', {}, badge(`relevance ${fmt(c.score, 2)}`, 'outline'), ' ', el('span', { class: 'chip' }, c.source_id))), el('div', { class: 'card-b small' }, c.content))));
      if (r.dropped_as_unsafe.length) results.append(notice(`${r.dropped_as_unsafe.length} passage(s) were removed because they contained instruction-like content.`, 'warn'));
    } catch (e) { clear(results).append(notice(e.status === 400 ? `Blocked by guardrails: ${e.message}` : e.message, e.status === 400 ? 'err' : 'warn')); }
  };
  search.addEventListener('keydown', (e) => { if (e.key === 'Enter') doSearch(); });
  const file = el('input', { type: 'file', accept: '.md,.txt', 'aria-label': 'Document to ingest' });
  const docs = el('div', {});
  const loadDocs = async () => {
    clear(docs).append(skeleton(4));
    try {
      const d = await api('/api/rag/documents');
      clear(docs).append(el('div', { class: 'card' }, simpleTable([{ label: 'Document', key: 'title' }, { label: 'Source type', key: 'source_type' }, { label: 'Framework', key: 'framework' }, { label: 'Version', key: 'version' },
        { label: 'Chunks', num: true, key: 'chunks' }, { label: 'Status', render: (x) => statusBadge(x.status) }, { label: 'Checksum', render: (x) => monoText((x.checksum || '').slice(0, 10)) }], d.items)));
    } catch (e) { clear(docs).append(errorBox(e, loadDocs)); }
  };
  host.append(el('div', { class: 'actions' }, search, el('button', { class: 'btn', onclick: doSearch }, 'Search')), results,
    el('div', { class: 'card mb', style: 'margin-top:16px' }, el('div', { class: 'card-h' }, el('h2', {}, 'Add a source document')),
      el('div', { class: 'card-b' }, el('div', { class: 'actions' }, file, el('button', { class: 'btn', onclick: async () => {
        if (!file.files[0]) { toast('Choose a .md or .txt file', 'err'); return; }
        const form = new FormData(); form.append('file', file.files[0]);
        try { const r = await api('/api/rag/documents/ingest', { method: 'POST', form }); toast(r.status === 'QUARANTINED' ? r.message : `Ingested ${r.chunks} chunks`, r.status === 'QUARANTINED' ? 'err' : ''); loadDocs(); } catch (e) { toast(e.message, 'err'); }
      } }, 'Ingest')), el('p', { class: 'small muted', style: 'margin-top:8px' }, 'Documents with instruction-like content are quarantined at ingestion and never retrieved. The adversarial test document is quarantined by design.'))), docs);
  loadDocs();
}
