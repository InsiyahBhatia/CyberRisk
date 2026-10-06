"""python -m app.evals.run [--mode guardrails|live] [--baseline]"""
from __future__ import annotations

import argparse
import sys

from app.ai.llm import LLMUnavailable, make_llm
from app.db.session import connect, get_engine, init_schema
from app.evals.runner import run_suite


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["guardrails", "live"], default=None, help="default: live when GEMINI_API_KEY is set, else guardrails")
    p.add_argument("--baseline", action="store_true", help="store this run as the baseline for its mode")
    a = p.parse_args(argv)
    init_schema(get_engine())
    llm = make_llm()
    mode = a.mode or ("live" if llm.configured else "guardrails")
    if mode == "live" and not llm.configured:
        print("No LLM API key is configured (GROQ_API_KEY or GEMINI_API_KEY); cannot run live evals.", file=sys.stderr)
        return 2
    with connect() as conn:
        try:
            run = run_suite(conn, mode, llm if mode == "live" else None, set_baseline=a.baseline)
        except LLMUnavailable as exc:
            print(exc, file=sys.stderr)
            return 2
    print(f"Eval run {run['id']} mode={run['mode']} model={run['model']} score={run['score']}% ({run['passed_cases']}/{run['total_cases']}, {run['skipped_cases']} skipped, {run.get('errored_cases', 0)} not evaluated)")
    for r in run["category_results"]:
        flag = "n/a" if r["meets_threshold"] is None else ("PASS" if r["meets_threshold"] else "FAIL")
        print(f"  {r['category']:<20} {str(r['score']):>6}  threshold {r['threshold']:>3}  {flag}")
    if run.get("errored_cases"):
        print(f"  WARNING: {run['errored_cases']} case(s) could not be evaluated because the model was unavailable; they are NOT counted. Re-run for a complete result.")
    if run.get("models_used"):
        print("  models that answered:", run["models_used"])
    if run["comparison"]:
        print("  vs baseline:", "REGRESSION " + str(run["comparison"]["regressions"]) if run["comparison"]["regressed"] else "no regression")
    return 0 if all(r["meets_threshold"] in (True, None) for r in run["category_results"]) else 1


if __name__ == "__main__":
    sys.exit(main())
