"""Generate complete screenshots of the CyberRisk platform for README and documentation.
Run: python scripts/generate_all_screenshots.py
"""
import json
import os
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path("docs/screenshots")
OUT.mkdir(parents=True, exist_ok=True)
BASE = "http://127.0.0.1:8000"


def cleanup():
    try:
        req = urllib.request.urlopen(f"{BASE}/api/workspaces")
        data = json.load(req)
        for w in data.get("items", []):
            if w["name"].startswith("Playwright Screenshot") or w["name"].startswith("New Client Org"):
                del_req = urllib.request.Request(f"{BASE}/api/workspaces/{w['slug']}?confirm={w['slug']}", method="DELETE")
                urllib.request.urlopen(del_req)
    except Exception as e:
        print(f"Cleanup note: {e}")


def capture_all():
    cleanup()
    print("Starting screenshot capture...")

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        # 1440x920 viewport gives a crisp, modern web dashboard aspect ratio
        context = browser.new_context(viewport={"width": 1440, "height": 920})
        page = context.new_page()

        # Helper to navigate to demo workspace page
        def go_demo(route):
            # Ensure workspace is demo
            page.goto(f"{BASE}/#/{route}")
            page.wait_for_load_state("networkidle")
            page.wait_for_timeout(1000)

        # Ensure we start in Demo workspace
        page.goto(f"{BASE}/#/overview")
        page.wait_for_selector("#ws-name")
        if not page.locator("#ws-name").inner_text().startswith("Acme"):
            page.click("#ws-btn")
            page.wait_for_selector(".card")
            page.locator(".card", has_text="Acme Corp").get_by_role("button", name="Open").click()
            page.wait_for_selector("#ws-name:has-text('Acme')")

        # 01. Overview Dashboard
        print("Capturing 01_overview.png...")
        go_demo("overview")
        page.wait_for_selector(".kpi")
        page.wait_for_timeout(1200)
        page.screenshot(path=str(OUT / "01_overview.png"), full_page=True)

        # 02. Risks Register
        print("Capturing 02_risks.png...")
        go_demo("risks")
        page.wait_for_selector("table")
        page.wait_for_timeout(800)
        page.screenshot(path=str(OUT / "02_risks.png"), full_page=True)

        # 03. Risk Detail Drawer
        print("Capturing 03_risk_detail.png...")
        # Click the first row in the risks table
        page.locator("table tbody tr").first.click()
        page.wait_for_selector(".drawer.open, .drawer")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "03_risk_detail.png"), full_page=True)
        # Close drawer
        page.click("button:has-text('Close')")
        page.wait_for_timeout(500)

        # 04. Vulnerabilities
        print("Capturing 04_vulnerabilities.png...")
        go_demo("vulnerabilities")
        page.wait_for_selector("table")
        page.wait_for_timeout(800)
        page.screenshot(path=str(OUT / "04_vulnerabilities.png"), full_page=True)

        # 05. Incidents
        print("Capturing 05_incidents.png...")
        go_demo("incidents")
        page.wait_for_selector("table")
        page.wait_for_timeout(800)
        page.screenshot(path=str(OUT / "05_incidents.png"), full_page=True)

        # 06. Assets
        print("Capturing 06_assets.png...")
        go_demo("assets")
        page.wait_for_selector("table")
        page.wait_for_timeout(800)
        page.screenshot(path=str(OUT / "06_assets.png"), full_page=True)

        # 07. Vendors
        print("Capturing 07_vendors.png...")
        go_demo("vendors")
        page.wait_for_selector("table")
        page.wait_for_timeout(800)
        page.screenshot(path=str(OUT / "07_vendors.png"), full_page=True)

        # 08. Controls Catalogue
        print("Capturing 08_controls.png...")
        go_demo("controls")
        page.wait_for_selector("table")
        page.wait_for_timeout(800)
        page.screenshot(path=str(OUT / "08_controls.png"), full_page=True)

        # 09. Compliance Matrix
        print("Capturing 09_compliance.png...")
        go_demo("compliance")
        page.wait_for_selector(".card")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "09_compliance.png"), full_page=True)

        # 10. Reports
        print("Capturing 10_reports.png...")
        go_demo("reports")
        page.wait_for_selector(".kpi")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "10_reports.png"), full_page=True)

        # 11. Analyze - Log Analyzer (Sample SSH Brute Force)
        print("Capturing 11_analyze_log.png...")
        go_demo("analyze")
        page.wait_for_selector("button:has-text('Try a sample log')")
        page.click("button:has-text('Try a sample log')")
        page.wait_for_selector("text=Brute-force", timeout=20000)
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "11_analyze_log.png"), full_page=True)

        # 12. Analyze - Incident Text Classifier
        print("Capturing 12_analyze_incident.png...")
        go_demo("analyze")
        page.click("button[role=tab]:has-text('New analysis')")
        page.fill(
            "textarea[aria-label='Incident description']",
            "A high-priority phishing alert triggered on work email. Stolen corporate credentials were used to access VPN. Threat actor performed lateral movement across servers, ran 'vssadmin delete shadows /all', and executed ransomware encrypting database volumes. Ransom note was left in C:\\README.txt demanding 5 BTC.",
        )
        page.click("button:has-text('Analyze incident')")
        page.wait_for_selector("text=Why this severity", timeout=25000)
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "12_analyze_incident.png"), full_page=True)

        # 13. Live Operations Simulation (Running state)
        print("Capturing 13_live_operations.png...")
        # Reset sim state
        try:
            req = urllib.request.Request(f"{BASE}/api/sim/stop", method="POST", data=b"{}", headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req)
        except Exception:
            pass
        go_demo("live")
        page.wait_for_selector("h1:has-text('Live operations')")
        page.select_option("select[aria-label='Storyline speed']", "10")
        page.click("button:has-text('Start simulation')")
        page.wait_for_selector("text=SIMULATION RUNNING", timeout=15000)
        page.wait_for_selector("tbody tr", timeout=20000)
        page.click("button:has-text('Phishing To Ransomware')")
        page.wait_for_selector("text=Ransomware activity", timeout=40000)
        page.wait_for_timeout(2000)
        page.screenshot(path=str(OUT / "13_live_operations.png"), full_page=True)

        # 14. Live Operations Incident Drawer
        print("Capturing 14_live_incident_drawer.png...")
        page.locator("div[role=button]:has-text('Ransomware activity')").first.click()
        page.wait_for_selector("text=Evidence timeline", timeout=10000)
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "14_live_incident_drawer.png"), full_page=True)
        # Stop sim
        page.click("button:has-text('Close')")
        page.wait_for_timeout(500)
        page.click("button:has-text('Stop simulation')")
        page.wait_for_selector("button:has-text('Start simulation')", timeout=10000)

        # 15. AI Governance
        print("Capturing 15_ai_governance.png...")
        go_demo("ai-governance")
        page.wait_for_selector(".card")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "15_ai_governance.png"), full_page=True)

        # 16. AI Evals
        print("Capturing 16_ai_evals.png...")
        go_demo("evals")
        page.wait_for_selector(".card")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "16_ai_evals.png"), full_page=True)

        # 17. Data Pipeline
        print("Capturing 17_data_pipeline.png...")
        go_demo("pipeline")
        page.wait_for_selector(".card")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "17_data_pipeline.png"), full_page=True)

        # 18. Universal CSV Import Wizard
        print("Capturing 18_import_wizard.png...")
        page.goto(f"{BASE}/#/pipeline?tab=run")
        page.wait_for_selector("text=Upload a file")
        csv_file = Path(tempfile.mkdtemp()) / "asset_inventory.csv"
        csv_file.write_text("Hostname,Dept,Owner,Tier,Public Facing,Device Type\nweb-01,Engineering,Alice Ops,Tier 1,yes,Server\ndb-01,Finance,Bob DBA,Moderate,no,Database\nlaptop-9,Sales,Carol,Low,no,Laptop\n")
        page.set_input_files("input[type=file]", str(csv_file))
        page.click("button:has-text('Profile file')")
        page.wait_for_selector("text=Map columns")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "18_import_wizard.png"), full_page=True)

        # 19. Multi-Tenant Workspaces Manager
        print("Capturing 19_workspaces.png...")
        go_demo("overview")
        page.click("#ws-btn")
        page.wait_for_selector(".card")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "19_workspaces.png"), full_page=True)

        # 20. Getting Started Checklist (in a fresh organization)
        print("Capturing 20_setup_checklist.png...")
        page.fill("input[placeholder='e.g. Globex Corporation']", "Playwright Screenshot Org")
        page.click("button:has-text('Create workspace')")
        page.wait_for_selector("h1:has-text('Getting started')", timeout=45000)
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "20_setup_checklist.png"), full_page=True)

        # 21. Governed AI Assistant Drawer
        print("Capturing 21_ai_assistant.png...")
        # Switch back to Demo workspace
        page.click("#ws-btn")
        page.wait_for_selector(".card")
        page.locator(".card", has_text="Acme Corp").get_by_role("button", name="Open").click()
        page.wait_for_selector("#ws-name:has-text('Acme')")
        page.goto(f"{BASE}/#/overview")
        page.wait_for_selector("#ask-btn")
        page.click("#ask-btn")
        page.fill("input[aria-label='Question']", "Which business unit has the most overdue vulnerabilities?")
        page.press("input[aria-label='Question']", "Enter")
        page.wait_for_selector(".drawer table, .drawer .notice, .drawer .ai-block", timeout=30000)
        page.wait_for_timeout(1500)
        page.screenshot(path=str(OUT / "21_ai_assistant.png"), full_page=True)
        page.locator(".drawer button:has-text('Close')").click()
        page.wait_for_timeout(500)

        # 22. System Settings
        print("Capturing 22_settings.png...")
        go_demo("settings")
        page.wait_for_selector(".card")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "22_settings.png"), full_page=True)

        browser.close()

    cleanup()
    print("All screenshots captured successfully!")


if __name__ == "__main__":
    capture_all()
