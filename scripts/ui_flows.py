"""Browser flows for the multi-workspace features (needs a running server and Edge/Chromium).
python scripts/ui_flows.py <screenshot-dir> [base-url]"""
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)
BASE = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8000"
errors = []


def cleanup():
    """Remove workspaces left by previous runs so the flow starts from a known state."""
    import json
    import urllib.request
    for w in json.load(urllib.request.urlopen(BASE + "/api/workspaces"))["items"]:
        if w["name"].startswith("Playwright"):
            urllib.request.urlopen(urllib.request.Request(f"{BASE}/api/workspaces/{w['slug']}?confirm={w['slug']}", method="DELETE"))


cleanup()
CSV = "Hostname,Dept,Owner,Tier,Public Facing,Device Type\nweb-01,Engineering,Alice Ops,Tier 1,yes,Server\ndb-01,Finance,Bob DBA,Moderate,no,Database\nlaptop-9,Sales,Carol,Low,no,Laptop\n"


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        errors.append(msg)


with sync_playwright() as p:
    b = p.chromium.launch(channel="msedge", headless=True)
    page = b.new_context(viewport={"width": 1400, "height": 900}).new_page()
    page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    page.on("console", lambda m: errors.append(f"console: {m.text}") if m.type == "error" and "404" not in m.text else None)

    page.goto(BASE + "/")
    page.wait_for_selector("h1")
    check(page.locator("#ws-name").inner_text().startswith("Acme"), "starts in the demo workspace")

    # --- create an organization from the UI
    page.click("#ws-btn")
    page.wait_for_selector("text=New organization")
    page.screenshot(path=str(OUT / "workspaces.png"))
    page.fill("input[placeholder='e.g. Globex Corporation']", "Playwright Org")
    page.click("button:has-text('Create workspace')")
    page.wait_for_selector("h1:has-text('Getting started')", timeout=60000)
    check(page.locator("#ws-name").inner_text() == "Playwright Org", "switched into the new organization")
    check("0% complete" in page.inner_text("#view"), "setup checklist starts at 0%")
    page.screenshot(path=str(OUT / "setup_empty.png"), full_page=True)

    # --- import wizard
    page.goto(BASE + "/#/pipeline?tab=run")
    page.wait_for_selector("text=Upload a file")
    f = Path(tempfile.mkdtemp()) / "my_inventory.csv"
    f.write_text(CSV)
    page.set_input_files("input[type=file]", str(f))
    page.click("button:has-text('Profile file')")
    page.wait_for_selector("text=Map columns")
    page.wait_for_selector("select[aria-label='Source for hostname']")
    check(page.locator("select[aria-label='Source for business_unit']").input_value() == "Dept", "wizard auto-maps Dept -> business_unit")
    check(page.locator("select[aria-label='Source for criticality']").input_value() == "Tier", "wizard auto-maps Tier -> criticality")
    page.select_option("select[aria-label='Source for asset_tag']", "Hostname")
    page.screenshot(path=str(OUT / "wizard.png"), full_page=True)
    page.click("button:has-text('Import data')")
    page.wait_for_selector("text=Imported into assets")
    check("Loaded" in page.inner_text("#view"), "import reports a result")
    page.goto(BASE + "/#/assets")
    page.wait_for_selector("text=WEB-01")
    check(page.locator("text=DB-01").count() >= 1, "imported assets appear in the Assets page")
    page.screenshot(path=str(OUT / "assets.png"), full_page=True)

    # --- role lens (inside an organization, where role-focused pages exist)
    page.select_option("#role", "executive")
    page.wait_for_selector("h1:has-text('Overview')", timeout=15000)
    check("executive" in page.inner_text("#nav").lower() and "Reports" in page.inner_text("#nav"), "role switch re-labels navigation and lands on the role's home page")
    page.select_option("#role", "advisor")
    page.wait_for_timeout(500)

    # --- sandbox: analyze without an organisation
    page.click("#ws-btn")
    page.wait_for_selector("text=Personal sandbox")
    page.locator(".card", has_text="Personal sandbox").get_by_role("button", name="Open").click()
    page.wait_for_selector("h1:has-text('Analyze')", timeout=30000)
    nav = page.inner_text("#nav")
    check("Risks" not in nav and "Analyze" in nav, "sandbox navigation hides organisation pages")
    page.click("button:has-text('Try a sample log')")
    page.wait_for_selector("text=Brute-force", timeout=30000)
    check(page.locator("text=Successful login from an IP that was brute-forcing").count() >= 1, "sample log detects takeover after brute force")
    check(page.locator("text=T1110").count() >= 1, "ATT&CK technique shown")
    page.screenshot(path=str(OUT / "analyze.png"), full_page=True)

    # --- incident text
    page.click("button[role=tab]:has-text('New analysis')")
    page.fill("textarea[aria-label='Incident description']", "A phishing email with a malicious link led to stolen credential use and lateral movement to multiple systems. vssadmin delete shadows /all was run and files were encrypted; ransom note demands bitcoin.")
    page.click("button:has-text('Analyze incident')")
    page.wait_for_selector("text=Why this severity", timeout=30000)
    check(page.locator("text=Ransomware").count() >= 1, "incident classified as ransomware")
    page.screenshot(path=str(OUT / "incident.png"), full_page=True)

    b.close()
print("\nFAILURES:" if errors else "\nALL FLOWS OK", errors or "")
sys.exit(1 if errors else 0)
