import { ai, api, el, clear, qs, fmt, relTime, statusBadge, badge, monoText, scoreBar, skeleton, errorBox, simpleTable, notice, toast, dataTable, title } from '../core.js';

export async function evals(root) {
  const status = await api('/api/ai/status').catch(() => ({ configured: false }));
  const baseline = el('input', { type: 'checkbox', id: 'baseline' });
  const detail = el('div', {}, skeleton(6));
  const list = el('div', {});
  const run = async (mode, btn) => {
    btn.disabled = true; const old = btn.textContent; btn.textContent = 'Running…';
    try { const r = await api('/api/evals/run', { method: 'POST', body: { mode, set_baseline: baseline.checked } }); toast(`Eval complete: ${fmt(r.score, 1)}%`); await loadList(); showRun(r.id); }
    catch (e) { toast(e.message, 'err'); } finally { btn.disabled = false; btn.textContent = old; }
  };
  const gbtn = el('button', { class: 'btn primary', onclick: (e) => run('guardrails', e.target) }, 'Run guardrail evals');
  const lbtn = el('button', { class: 'btn', disabled: !status.configured, title: status.configured ? '' : 'Set GROQ_API_KEY or GEMINI_API_KEY to run live evals', onclick: (e) => run('live', e.target) }, `Run live ${ai.name} evals`);
  root.append(el('div', { class: 'page-head' }, el('div', {}, el('h1', {}, 'Evals'), el('p', {}, 'Deterministic checks for grounding, citations, risk reasoning, hallucination, prompt injection, RAG poisoning and PII. No judge model; results are stored and compared to a baseline.')),
    el('div', { class: 'actions' }, el('label', { class: 'small', style: 'display:flex;gap:6px;align-items:center' }, baseline, 'Save as baseline'), gbtn, lbtn)),
    !status.configured ? el('div', { class: 'notice warn mb' }, 'Gemini is not configured, so live evals are disabled. Guardrail evals exercise the deterministic layers only (input, RAG, output) and do not measure Gemini itself; cases that need the model are skipped, never faked.') : null,
    detail, el('h2', { style: 'margin:24px 0 8px' }, 'Run history'), list);

  async function loadList() {
    clear(list).append(skeleton(3));
    try {
      const d = await api('/api/evals/runs?page_size=20');
      clear(list).append(el('div', { class: 'card' }, d.items.length ? simpleTable([{ label: 'Run', render: (r) => el('a', { href: '#', onclick: (e) => { e.preventDefault(); showRun(r.id); } }, `#${r.id}`) },
        { label: 'When', render: (r) => relTime(r.completed_at) }, { label: 'Mode', render: (r) => badge(r.mode === 'live' ? `Live ${ai.name}` : 'Guardrails only', r.mode === 'live' ? 'info' : 'outline') },
        { label: 'Model', key: 'model' }, { label: 'Prompt', key: 'prompt_version' }, { label: 'Score', num: true, render: (r) => `${fmt(r.score, 1)}%` }, { label: 'Passed', num: true, render: (r) => `${r.passed_cases}/${r.total_cases}` },
        { label: 'Skipped', num: true, key: 'skipped_cases' }, { label: 'Baseline', render: (r) => r.is_baseline ? badge('Baseline', 'info') : '' }], d.items) : el('div', { class: 'state' }, 'No runs yet.')));
      return d.items;
    } catch (e) { clear(list).append(errorBox(e, loadList)); return []; }
  }
  async function showRun(id) {
    clear(detail).append(skeleton(6));
    try { renderRun(detail, await api(`/api/evals/runs/${id}`)); } catch (e) { clear(detail).append(errorBox(e, () => showRun(id))); }
  }
  const items = await loadList();
  if (items.length) showRun(items[0].id);
  else clear(detail).append(el('div', { class: 'card' }, el('div', { class: 'state' }, el('strong', {}, 'No eval runs yet'), 'Run the guardrail evals to measure the deterministic security layers.')));
}

function renderRun(host, r) {
  clear(host);
  const cmp = r.comparison;
  host.append(el('div', { class: 'grid g4 mb' },
    el('div', { class: 'card kpi hero' }, el('div', { class: 'label' }, 'Overall score'), el('div', { class: 'value' }, fmt(r.score, 1), el('small', {}, '%')), el('div', { class: 'sub' }, `${r.passed_cases}/${r.total_cases} cases passed`)),
    el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Mode'), el('div', { class: 'value', style: 'font-size:18px' }, r.mode === 'live' ? `Live ${ai.name}` : 'Guardrails only'), el('div', { class: 'sub' }, `${r.model} · prompt ${r.prompt_version}`)),
    el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Security pass rate'), el('div', { class: 'value' }, r.security_pass_rate === null ? '—' : fmt(r.security_pass_rate, 1), el('small', {}, '%')), el('div', { class: 'sub' }, `PII leak failures: ${r.pii_leak_failures}`)),
    el('div', { class: 'card kpi' }, el('div', { class: 'label' }, 'Run'), el('div', { class: 'value', style: 'font-size:18px' }, `#${r.id}`), el('div', { class: 'sub' }, `${r.completed_at} · index ${r.retrieval_index_version}`))));
  if (r.errored_cases) host.append(el('div', { class: 'notice err mb' }, `${r.errored_cases} case(s) could not be evaluated because ${ai.name} was unavailable (overloaded or unreachable). They are not counted as passes or failures, so this run is incomplete. Run it again.`));
  if (r.models_used && Object.keys(r.models_used).length) host.append(el('div', { class: 'small muted mb' }, 'Models that answered: ' + Object.entries(r.models_used).map(([m, n]) => `${m} (${n})`).join(', ')));
  if (r.skipped_cases) host.append(el('div', { class: 'notice warn mb' }, `${r.skipped_cases} case(s) were skipped because they need a live ${ai.name} response. They are excluded from scores, not counted as passes.`));
  if (cmp) host.append(el('div', { class: `notice mb ${cmp.regressed ? 'err' : 'ok'}` }, cmp.regressed
    ? el('div', {}, el('strong', {}, `Regression vs baseline #${cmp.baseline_run_id}: `), cmp.regressions.map((x) => `${title(x.category)} ${x.baseline}% → ${x.current}%`).join('; '))
    : `No regression vs baseline #${cmp.baseline_run_id} (overall ${cmp.overall_delta >= 0 ? '+' : ''}${cmp.overall_delta} pts).`));
  else host.append(el('div', { class: 'notice mb' }, r.is_baseline ? 'This run is the baseline for its mode.' : 'No baseline saved for this mode yet. Tick "Save as baseline" on a run to enable comparison.'));
  host.append(el('div', { class: 'card mb' }, el('div', { class: 'card-h' }, el('h2', {}, 'Categories')), simpleTable([
    { label: 'Category', render: (c) => title(c.category) }, { label: 'Score', render: (c) => c.score === null ? el('span', { class: 'faint' }, 'not evaluated') : scoreBar(c.score, 100, fmt(c.score, 1) + '%') },
    { label: 'Threshold', num: true, render: (c) => `${c.threshold}%` }, { label: 'Result', render: (c) => c.meets_threshold === null ? badge('n/a') : badge(c.meets_threshold ? 'Pass' : 'Fail', c.meets_threshold ? 'low' : 'crit') },
    { label: 'vs baseline', num: true, render: (c) => cmp && cmp.category_deltas[c.category] !== undefined ? `${cmp.category_deltas[c.category] > 0 ? '+' : ''}${cmp.category_deltas[c.category]}` : '—' }], r.category_results)));
  const failed = r.failed_cases || [];
  host.append(el('div', { class: 'card' }, el('div', { class: 'card-h' }, el('h2', {}, `Failed cases (${failed.length})`)),
    failed.length ? simpleTable([{ label: 'Case', render: (c) => monoText(c.case_code) }, { label: 'Category', render: (c) => title(c.category) }, { label: 'Input', render: (c) => (c.input || '').slice(0, 70) },
      { label: 'Why', key: 'failure_reason' }], failed) : el('div', { class: 'state' }, 'No failed cases in this run.')));
  host.append(el('details', { style: 'margin-top:16px' }, el('summary', { class: 'small muted', style: 'cursor:pointer' }, `All ${r.cases.length} cases`),
    el('div', { class: 'card', style: 'margin-top:8px' }, simpleTable([{ label: 'Case', render: (c) => monoText(c.case_code) }, { label: 'Category', render: (c) => title(c.category) }, { label: 'Expected', key: 'expected_behavior' },
      { label: 'Result', render: (c) => c.passed === null ? badge('Skipped', 'outline') : badge(c.passed ? 'Pass' : 'Fail', c.passed ? 'low' : 'crit') }], r.cases))));
}
