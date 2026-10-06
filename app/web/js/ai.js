// Contextual AI: results rendered with evidence, citations, validation status and human-approval controls.
import { ai, api, el, clear, badge, levelBadge, notice, skeleton, toast, openDrawer, simpleTable, monoText, fmt, statusBadge } from './core.js';

export function renderAIResult(res, { onDecision } = {}) {
  const wrap = el('div', { class: 'ai-block' });
  const a = res.answer;
  const head = el('header', {}, el('span', {}, res.status === 'ABSTAINED' ? 'Insufficient evidence' : 'AI analysis'),
    el('span', { class: 'actions' }, res.requires_approval ? badge('Human review required', 'med') : null, res.model ? badge(res.model, 'outline') : null));
  const body = el('div', { class: 'body' });
  wrap.append(head, body);
  if (!a) { body.append(notice(res.message || 'No answer produced.', 'warn')); return wrap; }

  if (res.status === 'ABSTAINED' || a.insufficient_evidence) {
    body.append(notice(a.clarification || a.summary || 'The available evidence is not sufficient to answer reliably.', 'warn'));
  } else body.append(el('p', {}, a.summary));

  const det = res.deterministic || {};
  if (Object.keys(det).length) {
    body.append(el('div', { class: 'small muted', style: 'margin:8px 0' }, 'Calculated by CyberRisk (not AI): ',
      Object.entries(det).map(([k, v]) => el('span', { class: 'chip' }, `${k.replace(/_/g, ' ')}: ${typeof v === 'number' ? fmt(v, 2) : v}`))));
  }
  if (a.findings?.length) {
    body.append(el('h3', { class: 'small muted', style: 'margin:12px 0 4px' }, 'FINDINGS'));
    a.findings.forEach((f) => body.append(el('div', { class: 'finding' },
      el('div', {}, f.statement, ' ', badge(f.type === 'framework' ? 'Framework' : 'Our data', 'outline')),
      el('div', { class: 'chips' }, (f.evidence_ids || []).map((id) => el('span', { class: 'chip', title: (res.evidence.find((e) => e.id === id) || {}).summary || '' }, id))))));
  }
  if (a.recommended_actions?.length) {
    body.append(el('h3', { class: 'small muted', style: 'margin:12px 0 4px' }, 'RECOMMENDED ACTIONS (NOT EXECUTED)'));
    a.recommended_actions.forEach((r) => body.append(el('div', { class: 'finding' }, el('div', {}, r.action, ' ', r.requires_human_approval ? badge('Needs human approval', 'med') : null),
      r.rationale ? el('div', { class: 'small muted' }, r.rationale) : null)));
  }
  if (res.citations?.length) {
    body.append(el('h3', { class: 'small muted', style: 'margin:12px 0 4px' }, 'SOURCES'));
    res.citations.forEach((c) => body.append(el('div', { class: 'small' }, `${c.title} — ${c.section} `, el('span', { class: 'chip' }, c.source_id), c.score !== null && c.score !== undefined ? el('span', { class: 'faint' }, ` relevance ${fmt(c.score, 2)}`) : null)));
  }
  const v = res.validation || {}, g = res.guardrails || {};
  body.append(el('div', { class: 'small faint', style: 'margin-top:12px' },
    `Guardrails: input ${g.input_status || '—'}`, g.pii_redacted?.length ? ` (redacted ${g.pii_redacted.join(', ')})` : '',
    g.rag_chunks_dropped ? `; ${g.rag_chunks_dropped} unsafe retrieved passage(s) removed` : '',
    `; output ${v.valid ? 'validated' : 'not validated'}`, v.grounding_score !== undefined ? `; evidence traceability ${fmt(v.grounding_score * 100, 0)}%` : '',
    v.attempts > 1 ? `; repaired after ${v.attempts} attempts` : '', `; prompt ${res.prompt_version}. AI output is advisory.`));

  if (res.requires_approval && res.interaction_id) body.append(approvalControls(res.interaction_id, onDecision));
  return wrap;
}

function approvalControls(id, onDecision) {
  const reviewer = el('input', { type: 'text', placeholder: 'Reviewer name', 'aria-label': 'Reviewer name', maxlength: '80' });
  const comment = el('input', { type: 'text', placeholder: 'Comment (optional)', 'aria-label': 'Review comment', maxlength: '500' });
  const box = el('div', { class: 'notice', style: 'margin-top:12px' });
  const decide = async (decision) => {
    if (reviewer.value.trim().length < 2) { toast('Enter the reviewer name', 'err'); return; }
    try {
      const r = await api(`/api/ai-governance/${id}/approve`, { method: 'POST', body: { decision, reviewer: reviewer.value.trim(), comments: comment.value.trim() || null } });
      clear(box).append(`Recorded: ${decision.toLowerCase()} by ${r.reviewer}.`, r.mappings_updated ? ` ${r.mappings_updated} suggested mapping(s) updated.` : '');
      if (onDecision) onDecision(r);
    } catch (e) { toast(e.message, 'err'); }
  };
  box.append(el('div', { style: 'font-weight:600;margin-bottom:6px' }, 'Human review'),
    el('div', { class: 'small muted', style: 'margin-bottom:8px' }, 'This output can affect compliance status or be shared externally, so it needs a documented human decision.'),
    el('div', { class: 'actions' }, reviewer, comment, el('button', { class: 'btn sm primary', onclick: () => decide('APPROVED') }, 'Approve'), el('button', { class: 'btn sm danger', onclick: () => decide('REJECTED') }, 'Reject')));
  return box;
}

/** Call an AI endpoint and render success or a clear, specific failure state into `host`. */
export async function runAI(host, path, body, opts = {}) {
  clear(host).append(skeleton(4), el('div', { class: 'small muted', style: 'padding:0 16px 12px' }, 'Gathering evidence, retrieving sources and validating the response…'));
  try {
    const res = await api(path, { method: 'POST', body: body || {} });
    clear(host).append(renderAIResult(res, opts));
    return res;
  } catch (e) {
    const b = e.body || {};
    clear(host);
    if (e.status === 503) host.append(notice(`${e.message} Calculated data on this page is unaffected.`, 'warn'));
    else if (e.status === 400) host.append(notice(`Request blocked by guardrails: ${e.message}`, 'err'));
    else if (e.status === 502) host.append(notice('The model response failed validation (unsupported claims or ungrounded evidence) and was withheld. Details are in AI Governance.', 'err'));
    else if (e.status === 429) host.append(notice('Too many AI requests. Please wait a moment.', 'warn'));
    else host.append(notice(e.message, 'err'));
    if (b.validation?.errors?.length) host.append(el('div', { class: 'small faint', style: 'margin-top:6px' }, 'Validation: ' + b.validation.errors.join('; ')));
    return null;
  }
}

export function aiButton(label, onClick) { return el('button', { class: 'btn', onclick: onClick }, label); }

/** Header "Ask about data": safe-intent natural-language analytics in a compact side panel. */
export function openAskPanel() {
  const d = openDrawer({ heading: 'Ask about your data', subtitle: `Answers come from fixed, parameterized queries; ${ai.name} only explains the result.` });
  const input = el('input', { type: 'text', placeholder: 'e.g. Which business unit has the most overdue vulnerabilities?', 'aria-label': 'Question', maxlength: '500', style: 'flex:1' });
  const out = el('div', { style: 'margin-top:16px' });
  const ask = async () => {
    if (!input.value.trim()) return;
    clear(out).append(skeleton(3));
    try {
      const r = await api('/api/ai/natural-language-analytics', { method: 'POST', body: { question: input.value.trim() } });
      clear(out);
      if (!r.analytics) { out.append(notice(r.message || 'No matching analysis.', 'warn')); return; }
      out.append(el('h3', { style: 'margin-bottom:6px' }, r.analytics.title));
      const cols = Object.keys(r.analytics.rows[0] || {}).map((k) => ({ key: k, label: k.replace(/_/g, ' '), num: typeof r.analytics.rows[0][k] === 'number' }));
      out.append(simpleTable(cols, r.analytics.rows, { empty: 'The query returned no rows.' }), el('div', { class: 'small faint', style: 'margin:6px 0 12px' }, r.analytics.note));
      if (r.explanation_unavailable) out.append(notice(`${r.explanation_unavailable} The table above is still computed from your data.`, 'warn'));
      else if (r.answer) out.append(renderAIResult(r));
    } catch (e) { clear(out).append(notice(e.status === 400 ? `Blocked by guardrails: ${e.message}` : e.message, e.status === 400 ? 'err' : 'warn')); }
  };
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') ask(); });
  d.body.append(el('div', { class: 'actions', style: 'flex-wrap:nowrap' }, input, el('button', { class: 'btn primary', onclick: ask }, 'Ask')), out);
  input.focus();
}
