"""Browser flow for the live simulation page (needs a running server and Edge/Chromium).
python scripts/ui_live.py <screenshot-dir> [base-url]"""
import json
import sys
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)
BASE = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8000"
errors = []


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        errors.append(msg)


def api(path, method="GET", body=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None, headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req))


api("/api/sim/stop", "POST")
api("/api/sim/data", "DELETE")

with sync_playwright() as p:
    b = p.chromium.launch(channel="msedge", headless=True)
    page = b.new_context(viewport={"width": 1400, "height": 1000}).new_page()
    page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
    page.on("console", lambda m: errors.append(f"console: {m.text}") if m.type == "error" and "404" not in m.text else None)

    page.goto(BASE + "/#/live")
    page.wait_for_selector("h1:has-text('Live operations')")
    page.screenshot(path=str(OUT / "live_idle.png"), full_page=True)
    check(page.locator("button:has-text('Start simulation')").count() == 1, "idle page offers Start")
    page.select_option("select[aria-label='Storyline speed']", "10")
    page.click("button:has-text('Start simulation')")
    page.wait_for_selector("text=SIMULATION RUNNING", timeout=15000)
    check(True, "banner shows the simulation is running")
    page.wait_for_selector("tbody tr", timeout=20000)
    check(page.locator("tbody tr").count() > 0, "live feed receives events")
    page.click("button:has-text('Phishing To Ransomware')")
    page.wait_for_selector("text=Ransomware activity", timeout=60000)
    check(True, "ransomware storyline is correlated into an incident")
    page.wait_for_timeout(2500)
    page.screenshot(path=str(OUT / "live_running.png"), full_page=True)
    check(page.locator("text=EDR").count() > 0 and page.locator("text=SIEM").count() > 0, "multiple integrations visible")
    page.locator("div[role=button]:has-text('Ransomware activity')").first.click()
    page.wait_for_selector("text=Evidence timeline")
    page.screenshot(path=str(OUT / "live_incident.png"), full_page=True)
    page.click("button:has-text('Acknowledge')")
    page.wait_for_selector("text=Incident investigating", timeout=10000)
    check(True, "analyst can acknowledge")
    page.click("button:has-text('Stop simulation')")
    page.wait_for_selector("button:has-text('Start simulation')", timeout=15000)
    check(True, "stop returns to idle")
    check(api("/api/sim/status")["running"] is False, "server confirms stopped")
    page.goto(BASE + "/#/pipeline?tab=history")
    page.wait_for_selector("text=Sim ·", timeout=15000)
    check(True, "simulated batches appear in ingestion history")
    b.close()
api("/api/sim/data", "DELETE")
print("\nFAILURES:" if errors else "\nALL LIVE FLOWS OK", errors or "")
sys.exit(1 if errors else 0)
