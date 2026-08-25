#!/usr/bin/env python3
"""Generate README screenshots from a synthetic Active Directory report.

Builds fake directory objects and risks, renders English and Turkish HTML
reports, then captures Dashboard, Domain Admin Map, and Critical Risks views
with headless Chromium (Selenium + system chromedriver).

Usage (from repository root):

    python3 scripts/generate_demo_screenshots.py
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analysis.domain_admin_takeover_analyzer import DomainAdminTakeoverAnalyzer
from reporting.compliance_reporter import ComplianceReporter
from reporting.html_report import HTMLReportGenerator

DOMAIN = "contoso.lab"
DC_IP = "10.50.1.10"
SHOT_DIR = ROOT / "img" / "screenshots"
DEMO_DIR = SHOT_DIR / ".demo"
VIEWPORT = (1440, 900)

SHOTS = (
    ("dashboard", "dashboard"),
    ("domain-admin-map", "domain-admin-takeover"),
    ("critical-risks", "critical-risks"),
)


def _user(
    sam: str,
    *,
    display: str | None = None,
    groups: list[str] | None = None,
    spn: list[str] | None = None,
    uac: int = 512,
    admin_count: int | None = None,
) -> dict[str, Any]:
    return {
        "sAMAccountName": sam,
        "displayName": display or sam,
        "distinguishedName": f"CN={sam},OU=Users,DC=contoso,DC=lab",
        "memberOf": groups or [],
        "servicePrincipalName": spn or [],
        "userAccountControl": uac,
        "adminCount": admin_count,
        "isDisabled": False,
        "isLocked": False,
    }


def build_demo_inventory() -> dict[str, Any]:
    """Return synthetic users, computers, groups, and scored risks."""
    da = "CN=Domain Admins,CN=Users,DC=contoso,DC=lab"
    users = [
        _user(
            "helper",
            display="Sync Helper",
            groups=["CN=Helpdesk,OU=Groups,DC=contoso,DC=lab"],
        ),
        _user(
            "svc_sql",
            display="SQL Service",
            groups=["CN=Service Accounts,OU=Groups,DC=contoso,DC=lab"],
            spn=["MSSQLSvc/sql01.contoso.lab:1433"],
        ),
        _user(
            "alice",
            display="Alice Admin",
            groups=[da],
            admin_count=1,
            uac=0x10000 | 512,  # password never expires
        ),
        _user(
            "bob.asrep",
            display="Bob NoPreauth",
            groups=["CN=Domain Users,CN=Users,DC=contoso,DC=lab"],
            uac=0x400000 | 512,  # DONT_REQUIRE_PREAUTH
        ),
        _user(
            "krbtgt",
            display="krbtgt",
            groups=[],
            admin_count=1,
        ),
    ]
    computers = [
        {
            "name": "DC01",
            "sAMAccountName": "DC01$",
            "operatingSystem": "Windows Server 2022 Datacenter",
            "distinguishedName": "CN=DC01,OU=Domain Controllers,DC=contoso,DC=lab",
            "userAccountControl": 532480,
            "primaryGroupID": 516,
        },
        {
            "name": "APP01",
            "sAMAccountName": "APP01$",
            "operatingSystem": "Windows Server 2019 Standard",
            "distinguishedName": "CN=APP01,OU=Servers,DC=contoso,DC=lab",
            "userAccountControl": 4096 | 524288,  # TRUSTED_FOR_DELEGATION
            "primaryGroupID": 515,
        },
        {
            "name": "WS10",
            "sAMAccountName": "WS10$",
            "operatingSystem": "Windows 10 Pro",
            "distinguishedName": "CN=WS10,OU=Workstations,DC=contoso,DC=lab",
            "userAccountControl": 4096,
            "primaryGroupID": 515,
        },
    ]
    groups = [
        {
            "name": "Domain Admins",
            "sAMAccountName": "Domain Admins",
            "distinguishedName": da,
            "member": ["CN=alice,OU=Users,DC=contoso,DC=lab"],
            "objectSid": "S-1-5-21-1000-2000-3000-512",
        },
        {
            "name": "Helpdesk",
            "sAMAccountName": "Helpdesk",
            "distinguishedName": "CN=Helpdesk,OU=Groups,DC=contoso,DC=lab",
            "member": ["CN=helper,OU=Users,DC=contoso,DC=lab"],
        },
    ]
    risks = [
        {
            "type": "dcsync_rights",
            "title": "DCSync rights on helper",
            "description": (
                "Account 'helper' has DS-Replication-Get-Changes-All on the domain NC."
            ),
            "affected_object": "helper",
            "object_type": "user",
            "severity": "critical",
            "impact": "Domain Admin equivalent via directory replication.",
            "attack_scenario": "Request KRBTGT and Domain Admin password hashes.",
            "mitigation": "Remove the replication ACE; rotate KRBTGT twice.",
            "mitre_attack": "T1003.006",
            "final_score": 95.0,
            "severity_level": "Critical",
        },
        {
            "type": "kerberoasting_target",
            "title": "Kerberoasting target: svc_sql",
            "description": "User account with SPN and a long-lived password.",
            "affected_object": "svc_sql",
            "object_type": "user",
            "severity": "high",
            "impact": "Offline cracking of the service account secret.",
            "attack_scenario": "Request a TGS and crack offline.",
            "mitigation": "Move the service to a gMSA with AES-only encryption.",
            "mitre_attack": "T1558.003",
            "spns": ["MSSQLSvc/sql01.contoso.lab:1433"],
            "is_privileged": False,
            "final_score": 78.0,
            "severity_level": "High",
            "export_format": {
                "impacket_command": (
                    f"GetUserSPNs.py -dc-ip {DC_IP} {DOMAIN}/svc_sql"
                ),
                "rubeus_command": "Rubeus.exe kerberoast /user:svc_sql",
                "cme_command": (
                    f"netexec ldap {DC_IP} -u USER -p PASS --kerberoasting hashes.txt"
                ),
            },
        },
        {
            "type": "asrep_roasting_target",
            "title": "AS-REP roasting target: bob.asrep",
            "description": "Kerberos pre-authentication is disabled.",
            "affected_object": "bob.asrep",
            "object_type": "user",
            "severity": "high",
            "impact": "Unauthenticated AS-REP hash retrieval.",
            "attack_scenario": "Request an AS-REP without credentials and crack offline.",
            "mitigation": "Clear DONT_REQUIRE_PREAUTH and rotate the password.",
            "mitre_attack": "T1558.004",
            "final_score": 74.0,
            "severity_level": "High",
        },
        {
            "type": "unconstrained_delegation",
            "title": "Unconstrained delegation on APP01",
            "description": "Non-DC computer is trusted for unconstrained Kerberos delegation.",
            "affected_object": "APP01",
            "object_type": "computer",
            "severity": "critical",
            "impact": "Privileged TGTs can be cached on APP01.",
            "attack_scenario": "Coerce or wait for a Domain Admin authentication.",
            "mitigation": "Disable unconstrained delegation; use constrained or RBCD.",
            "mitre_attack": "T1558.002",
            "final_score": 90.0,
            "severity_level": "Critical",
        },
        {
            "type": "user_password_never_expires",
            "title": "Password never expires: alice",
            "description": "Privileged account password is set to never expire.",
            "affected_object": "alice",
            "object_type": "user",
            "severity": "high",
            "impact": "Stale privileged credentials remain valid indefinitely.",
            "attack_scenario": "Compromise and reuse a long-lived Domain Admin password.",
            "mitigation": "Enforce password expiry or smart-card for privileged users.",
            "mitre_attack": "T1078.002",
            "final_score": 70.0,
            "severity_level": "High",
        },
        {
            "type": "ldap_signing_disabled",
            "title": "LDAP signing not required",
            "description": "Domain Controllers do not require LDAP signing.",
            "affected_object": "DC01",
            "object_type": "computer",
            "severity": "critical",
            "impact": "NTLM relay to LDAP can grant DCSync or RBCD.",
            "attack_scenario": "Coerce DC authentication and relay to LDAP.",
            "mitigation": "Require LDAP signing and channel binding on all DCs.",
            "mitre_attack": "T1557.001",
            "final_score": 88.0,
            "severity_level": "Critical",
        },
    ]
    return {
        "users": users,
        "computers": computers,
        "groups": groups,
        "gpos": [],
        "risks": risks,
        "misconfig_findings": [
            {
                "type": "misconfig_machine_account_quota",
                "title": "MachineAccountQuota is non-zero",
                "description": "Authenticated users can create computer accounts.",
                "severity": "medium",
                "recommendation": "Set ms-DS-MachineAccountQuota to 0.",
            }
        ],
    }


def render_reports(inventory: dict[str, Any]) -> dict[str, Path]:
    """Write English and Turkish demo HTML reports under .demo/."""
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    takeover = DomainAdminTakeoverAnalyzer().analyze(
        inventory["risks"],
        users=inventory["users"],
        groups=inventory["groups"],
        computers=inventory["computers"],
        domain=DOMAIN,
        dc_ip=DC_IP,
    )
    compliance = ComplianceReporter().generate_compliance_report(
        inventory["risks"],
        users=inventory["users"],
        groups=inventory["groups"],
        computers=inventory["computers"],
    )
    executive = {
        "summary": (
            "Synthetic contoso.lab assessment for README screenshots. "
            f"{len(inventory['risks'])} scored findings; "
            f"{takeover['summary']['open_path_count']} Domain Admin paths open."
        ),
        "top_critical_risks": [
            {"title": r["title"], "severity": r["severity"]}
            for r in inventory["risks"]
            if r["severity"] == "critical"
        ][:5],
    }
    analysis_counts = {
        "user_risks": 2,
        "computer_risks": 1,
        "kerberoasting_risks": 1,
        "asrep_risks": 1,
        "dcsync_risks": 1,
        "domain_security_risks": 1,
        "domain_admin_takeover": int(takeover["summary"]["open_path_count"]),
    }
    outputs: dict[str, Path] = {}
    for lang in ("en", "tr"):
        path = DEMO_DIR / f"demo-report-{lang}.html"
        HTMLReportGenerator(language=lang).generate(
            users=inventory["users"],
            computers=inventory["computers"],
            groups=inventory["groups"],
            gpos=inventory["gpos"],
            risks=list(inventory["risks"]),
            misconfig_findings=inventory["misconfig_findings"],
            domain_score=32.0,
            executive_summary=executive,
            output_file=str(path),
            compliance_data=compliance,
            domain=DOMAIN,
            dc_ip=DC_IP,
            kerberoasting_targets=[{"sAMAccountName": "svc_sql"}],
            asrep_targets=[{"sAMAccountName": "bob.asrep"}],
            analysis_summary_counts=analysis_counts,
            domain_admin_takeover=takeover,
            inline_assets=True,
        )
        outputs[lang] = path
        print(f"[+] Wrote {path}")
    return outputs


def _file_url(path: Path) -> str:
    return "file://" + quote(str(path.resolve()))


def capture_screenshots(reports: dict[str, Path]) -> list[Path]:
    """Open each report and save PNGs for the configured panes."""
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait

    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    options = Options()
    options.binary_location = "/usr/bin/chromium"
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(f"--window-size={VIEWPORT[0]},{VIEWPORT[1]}")
    options.add_argument("--force-device-scale-factor=1")
    service = Service("/usr/bin/chromedriver")
    driver = webdriver.Chrome(service=service, options=options)
    driver.set_window_size(*VIEWPORT)
    written: list[Path] = []
    try:
        for lang, html_path in reports.items():
            driver.get(_file_url(html_path))
            WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "#dashboard.tab-pane"))
            )
            # Allow charts / Lucide icons to settle.
            time.sleep(1.2)
            for slug, pane_id in SHOTS:
                driver.execute_script(
                    "if (typeof window.showTab === 'function') { window.showTab(arguments[0]); }",
                    pane_id,
                )
                WebDriverWait(driver, 10).until(
                    lambda d, pid=pane_id: "active"
                    in (d.find_element(By.ID, pid).get_attribute("class") or "")
                )
                time.sleep(0.6)
                if pane_id == "domain-admin-takeover":
                    # Prefer the hero + first open path (includes PoC roadmap).
                    driver.execute_script(
                        """
                        var hero = document.querySelector('#domain-admin-takeover .da-hero');
                        var card = document.querySelector('#da-open-paths .da-path');
                        var target = hero || card;
                        if (target) { target.scrollIntoView({block: 'start'}); }
                        window.scrollBy(0, -8);
                        """
                    )
                    time.sleep(0.5)
                else:
                    driver.execute_script(
                        "var pane = document.getElementById(arguments[0]);"
                        "if (pane) { pane.scrollIntoView({block: 'start'}); }",
                        pane_id,
                    )
                    time.sleep(0.3)
                out = SHOT_DIR / f"{lang}-{slug}.png"
                driver.save_screenshot(str(out))
                written.append(out)
                print(f"[+] Screenshot {out.name} ({out.stat().st_size} bytes)")
    finally:
        driver.quit()
    return written


def main() -> int:
    print("[*] Building synthetic contoso.lab inventory...")
    inventory = build_demo_inventory()
    print("[*] Rendering English and Turkish demo reports...")
    reports = render_reports(inventory)
    print("[*] Capturing Chromium screenshots...")
    paths = capture_screenshots(reports)
    missing = [
        SHOT_DIR / f"{lang}-{slug}.png"
        for lang in ("en", "tr")
        for slug, _ in SHOTS
        if not (SHOT_DIR / f"{lang}-{slug}.png").is_file()
    ]
    if missing:
        print("[-] Missing screenshots:", ", ".join(p.name for p in missing))
        return 1
    print(f"[+] Done. {len(paths)} screenshots in {SHOT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
