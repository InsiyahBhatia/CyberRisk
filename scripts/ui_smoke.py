import sys, json
from pathlib import Path
from playwright.sync_api import sync_playwright

OUT = Path(sys.argv[1]); OUT.mkdir(exist_ok=True, parents=True)
BASE = "http://localhost:8000"
pages = ["overview", "risks", "vulnerabilities", "incidents", "vendors", "controls", "compliance", "ai-governance", "evals", "pipeline", "settings"]
errors = []
with sync_playwright() as p:
    b = p.chromium.launch(channel="msedge", headless=True)
    ctx = b.new_context(viewport={"width": 1400, "height": 900})
    page = ctx.new_page()
    page.on("console", lambda m: errors.append(("console." + m.type, m.text)) if m.type in ("error", "warning") else None)
    page.on("pageerror", lambda e: errors.append(("pageerror", str(e))))
    page.on("requestfailed", lambda r: errors.append(("requestfailed", r.url)))
    page.on("response", lambda r: errors.append(("http%d" % r.status, r.url)) if r.status >= 400 and "/api/ai" not in r.url else None)
    for name in pages:
        page.goto(f"{BASE}/#/{name}")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(700)
        page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)
        h1 = page.locator("h1").first.inner_text()
        print(f"{name:16} h1={h1!r} aria-current={page.locator('nav a[aria-current=page]').inner_text()!r}")
    b.close()
print("ERRORS:", json.dumps(errors, indent=1))
