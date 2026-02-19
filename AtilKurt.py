#!/usr/bin/env python3
"""
AtilKurt - Active Directory Security Health Check Tool
Main execution file
"""

import argparse
import json
import os
import re
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

from core.ldap_connection import LDAPConnection
from core.validators import validate_output_file
from core.exceptions import ValidationError, LDAPConnectionError, LDAPSearchError
from core.collectors.user_collector import UserCollector
from core.collectors.computer_collector import ComputerCollector
from core.collectors.group_collector import GroupCollector
from core.collectors.gpo_collector import GPOCollector
from core.collectors.acl_collector import ACLCollector
from core.stealth_mode import create_stealth_mode
from analysis.registry import (
    run_all_analyses,
    get_consolidated_risk_lists,
    build_export_analysis_slice,
    CONSOLIDATION_RISK_KEYS,
)
from analysis.exploitability_scorer import ExploitabilityScorer
from analysis.privilege_calculator import PrivilegeCalculator
from analysis.password_policy_analyzer import PasswordPolicyAnalyzer
from analysis.baseline_comparator import BaselineComparator
from scoring.risk_scorer import RiskScorer
from reporting.html_report import HTMLReportGenerator
from reporting.export_formats import ExportFormats
from reporting.compliance_reporter import ComplianceReporter
from core.secure_password import SecurePasswordManager
from core.parallel_ldap import ParallelLDAPExecutor
from core.progress_persistence import ProgressPersistence, IncrementalScanner
from risk.risk_manager import RiskManager


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description='AtilKurt - Active Directory Security Health Check Tool'
    )
    parser.add_argument('-d', '--domain', required=True,
                        help='Domain name (e.g., example.com)')
    parser.add_argument('-u', '--username', required=True,
                        help='LDAP username (without domain prefix)')
    parser.add_argument('-p', '--password',
                        help='[DEPRECATED] LDAP password via CLI — use env var '
                             'ATILKURT_PASS or interactive prompt instead')
    parser.add_argument('--dc-ip', required=True,
                        help='Domain Controller IP address')
    parser.add_argument('--output', default='report.html',
                        help='Output HTML report file')
    parser.add_argument('--json-export',
                        help='Optional JSON export file path')
    parser.add_argument('--ssl', action='store_true',
                        help='Enable SSL/TLS (default: disabled, will auto-detect)')
    parser.add_argument('--stealth', action='store_true',
                        help='Enable stealth mode (enhanced rate limiting)')
    parser.add_argument('--rate-limit', type=float, default=0.5,
                        help='Rate limit in seconds between queries (default: 0.5)')
    parser.add_argument('--random-delay', type=float, nargs=2,
                        metavar=('MIN', 'MAX'),
                        help='Random delay range in seconds (e.g., --random-delay 1 5)')
    parser.add_argument('--page-size', type=int, default=5000,
                        help='LDAP page size for large result sets (default: 5000)')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Base LDAP timeout in seconds (default: 30)')
    parser.add_argument('--max-retries', type=int, default=3,
                        help='Maximum retry attempts for failed queries (default: 3)')
    parser.add_argument('--no-progress', action='store_true',
                        help='Disable progress tracking output')
    parser.add_argument('--kerberoasting-export',
                        help='Export Kerberoasting targets to JSON')
    parser.add_argument('--check-user',
                        help='Check if specific user can become Domain Admin')

    # Performance optimization arguments
    parser.add_argument('--parallel', action='store_true',
                        help='Enable parallel LDAP queries')
    parser.add_argument('--max-workers', type=int, default=5,
                        help='Maximum parallel workers (default: 5)')

    # Progress persistence arguments
    parser.add_argument('--resume',
                        help='Resume from checkpoint ID')
    parser.add_argument('--checkpoint',
                        help='Save checkpoint with specified ID')
    parser.add_argument('--incremental', action='store_true',
                        help='Enable incremental scanning')

    # Risk management arguments
    parser.add_argument('--hourly-rate', type=float, default=100.0,
                        help='Hourly rate for cost calculations (default: 100.0)')

    # Certificate validation — default is now True in LDAPConnection,
    # so we only need a flag to *disable* it.
    parser.add_argument('--no-validate-cert', action='store_true',
                        help='Disable SSL/TLS certificate validation '
                             '(NOT recommended; use only in lab environments)')
    # Keep --validate-cert for backward compat (now a no-op)
    parser.add_argument('--validate-cert', action='store_true',
                        help='(Default — kept for backward compatibility)')

    parser.add_argument('--baseline',
                        help='Baseline JSON file for drift comparison '
                             '(from previous --json-export)')

    # Logging
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output (INFO level)')
    parser.add_argument('--debug', action='store_true',
                        help='Debug output (DEBUG level)')
    parser.add_argument('--log-file',
                        help='Optional log file path')

    return parser


def setup_logging(args: argparse.Namespace) -> None:
    """Configure logging level and optional log file from CLI args."""
    level = logging.WARNING
    if getattr(args, "debug", False):
        level = logging.DEBUG
    elif getattr(args, "verbose", False):
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    log_file = getattr(args, "log_file", None)
    if log_file:
        try:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setLevel(level)
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
            logging.getLogger().addHandler(fh)
        except OSError as e:
            logging.warning("Could not open log file %s: %s", log_file, e)


def validate_output_paths(args: argparse.Namespace) -> None:
    """Validate all output file paths to prevent path traversal.

    Raises:
        SystemExit: If any path is invalid.
    """
    try:
        args.output = validate_output_file(args.output)
        if args.json_export:
            args.json_export = validate_output_file(args.json_export)
        if args.kerberoasting_export:
            args.kerberoasting_export = validate_output_file(args.kerberoasting_export)
    except ValidationError as e:
        print(f"[-] Invalid output path: {e}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Password resolution
# ---------------------------------------------------------------------------

def resolve_password(args: argparse.Namespace) -> Tuple[str, SecurePasswordManager]:
    """Resolve password from env var, CLI arg (deprecated), or interactive prompt.

    Returns:
        Tuple of (password, password_manager).
    """
    password_manager = SecurePasswordManager()

    # 1. Prefer environment variable
    env_pass = os.environ.get('ATILKURT_PASS')
    if env_pass:
        password_manager._password = env_pass
        password_manager._password_set = True
        return env_pass, password_manager

    # 2. CLI argument (deprecated)
    if args.password:
        password = password_manager.get_password_from_arg(args.password)
        return password, password_manager

    # 3. Interactive prompt (most secure)
    password = password_manager.get_password_from_prompt(
        f"Password for {args.username}@{args.domain}: "
    )
    return password, password_manager


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def collect_data(
    ldap_conn: LDAPConnection,
    show_progress: bool,
) -> Dict[str, Any]:
    """Collect all AD objects via LDAP.

    Returns:
        Dictionary with keys: users, computers, groups, gpos.
    """
    print("[*] Collecting Active Directory data...")

    user_collector = UserCollector(ldap_conn, show_progress=show_progress)
    users = user_collector.collect()
    print(f"[+] Collected {len(users)} users")

    computer_collector = ComputerCollector(ldap_conn, show_progress=show_progress)
    computers = computer_collector.collect()
    print(f"[+] Collected {len(computers)} computers")

    group_collector = GroupCollector(ldap_conn, show_progress=show_progress)
    groups = group_collector.collect()
    print(f"[+] Collected {len(groups)} groups")

    gpo_collector = GPOCollector(ldap_conn, show_progress=show_progress)
    gpos = gpo_collector.collect()
    print(f"[+] Collected {len(gpos)} GPOs")

    return {
        'users': users,
        'computers': computers,
        'groups': groups,
        'gpos': gpos,
    }


# ---------------------------------------------------------------------------
# Security analysis
# ---------------------------------------------------------------------------

def run_security_analysis(
    ldap_conn: LDAPConnection,
    data: Dict[str, Any],
) -> Dict[str, Any]:
    """Run all security analyzers and return consolidated results.

    Args:
        ldap_conn: Active LDAP connection.
        data: Collected AD data (users, computers, groups, gpos).

    Returns:
        Dictionary with all analysis results.
    """
    def progress_callback(description: str, step_result: Dict[str, Any]) -> None:
        counts = [len(v) for v in step_result.values() if isinstance(v, list)]
        if counts:
            print(f"[+] {description}: {counts[0]} items")
        else:
            for key, value in step_result.items():
                if isinstance(value, dict):
                    if key == "legacy_os_results":
                        print(f"[+] Legacy OS: {value.get('total_count', 0)} computers, {value.get('eol_count', 0)} EOL")
                        return
                    if key == "tier_data":
                        td = value
                        print(f"[+] TIER: T0={td.get('tier_0', {}).get('count', 0)}, "
                              f"T1={td.get('tier_1', {}).get('count', 0)}, T2={td.get('tier_2', {}).get('count', 0)}")
                        return
                    if key == "acl_security_results":
                        print(f"[+] ACL: {len(value.get('acl_risks', []))} risks, {len(value.get('shadow_admins', []))} Shadow Admins")
                        return
        if not counts:
            print(f"[+] {description}: done")

    print("[*] Performing security analysis...")
    results = run_all_analyses(ldap_conn, data, progress_callback=progress_callback)

    # Exploitability scoring (mutates risk dicts in-place)
    print("[*] Calculating exploitability scores...")
    exploitability_scorer = ExploitabilityScorer()
    scored_categories = (
        results.get("user_risks", [])
        + results.get("computer_risks", [])
        + results.get("group_risks", [])
        + results.get("kerberos_risks", [])
    )
    for risk in scored_categories:
        risk["exploitability"] = exploitability_scorer.score_risk(risk)

    return results


# ---------------------------------------------------------------------------
# Risk scoring & consolidation
# ---------------------------------------------------------------------------

def score_and_consolidate(
    analysis: Dict[str, Any],
    data: Dict[str, Any],
) -> Dict[str, Any]:
    """Score risks, generate executive summary, and produce consolidated risk list.

    Args:
        analysis: Output of ``run_security_analysis``.
        data: Collected AD data.

    Returns:
        Dictionary with scored_risks, domain_score, executive_summary, and
        converted shadow admin / ACL escalation risks.
    """
    print("[*] Calculating risk scores...")
    scorer = RiskScorer()

    users = data['users']
    computers = data['computers']
    groups = data['groups']

    # Convert shadow admins to risk format
    shadow_admin_risks: List[Dict[str, Any]] = []
    for sa in analysis.get('shadow_admins', []):
        shadow_admin_risks.append({
            'type': 'shadow_admin',
            'severity': sa.get('risk_level', 'high'),
            'title': f"Shadow Admin: {sa.get('user')}",
            'description': (
                f"User '{sa.get('user')}' has dangerous ACL permissions "
                "without being Domain/Enterprise Admin"
            ),
            'affected_object': sa.get('user'),
            'object_type': 'user',
            'why_risky': sa.get('why_risky'),
            'attack_scenario': sa.get('attack_scenario'),
            'dangerous_permissions': sa.get('dangerous_permissions', []),
        })

    acl_escalation_risks: List[Dict[str, Any]] = []
    for path in analysis.get('acl_escalation_paths', []):
        acl_escalation_risks.append({
            'type': 'acl_privilege_escalation_path',
            'severity': 'high',
            'title': f"ACL Privilege Escalation Path: {path.get('source_user')}",
            'description': (
                f"User '{path.get('source_user')}' can escalate to Domain Admin "
                f"through {path.get('hops')} hops"
            ),
            'affected_object': path.get('source_user'),
            'object_type': 'user',
            'path': path.get('path', []),
            'hops': path.get('hops', 0),
            'attack_scenario': path.get('attack_scenario'),
        })

    import itertools
    risk_lists = get_consolidated_risk_lists(analysis)
    all_risks_iter = itertools.chain(
        *risk_lists,
        shadow_admin_risks,
        acl_escalation_risks,
    )
    all_risks = list(all_risks_iter)

    scored_risks = scorer.score_risks(all_risks, users=users, groups=groups,
                                       computers=computers)
    domain_score = scorer.calculate_domain_score(scored_risks)
    print(f"[+] Domain security score: {domain_score:.1f}/100")

    executive_summary = scorer.generate_executive_summary(scored_risks, users,
                                                          computers, groups)
    top = executive_summary['top_critical_risks']
    print(f"[+] Top critical risk: {top[0]['title'] if top else 'None'}")

    return {
        'scored_risks': scored_risks,
        'domain_score': domain_score,
        'executive_summary': executive_summary,
        'shadow_admin_risks': shadow_admin_risks,
        'acl_escalation_risks': acl_escalation_risks,
    }


# ---------------------------------------------------------------------------
# Compliance & risk management
# ---------------------------------------------------------------------------

def generate_compliance_and_risk(
    ldap_conn: LDAPConnection,
    scored_risks: List[Dict[str, Any]],
    data: Dict[str, Any],
    hourly_rate: float,
) -> Dict[str, Any]:
    """Generate compliance reports and risk management data.

    Returns:
        Dictionary with compliance_data and risk_management_data.
    """
    users = data['users']
    computers = data['computers']
    groups = data['groups']

    print("[*] Generating compliance reports with advanced LDAP analysis...")
    compliance_reporter = ComplianceReporter(ldap_conn)

    # Get password policy data
    password_policy_data = None
    try:
        password_policy_analyzer = PasswordPolicyAnalyzer(ldap_conn)
        password_policy_analyzer.analyze_password_policy()
        domain_results = ldap_conn.search(
            search_base=ldap_conn.base_dn,
            search_filter="(objectClass=domainDNS)",
            attributes=[
                "minPwdLength", "maxPwdAge", "minPwdAge",
                "pwdHistoryLength", "pwdProperties",
                "lockoutThreshold", "lockoutDuration",
                "lockoutObservationWindow",
            ],
        )
        if domain_results and len(domain_results) > 0:
            password_policy_data = domain_results[0]
    except (LDAPSearchError, LDAPConnectionError) as e:
        logger.debug("Could not retrieve password policy data for compliance: %s", e)
    except Exception as e:
        logger.warning("Unexpected error retrieving password policy data: %s", e)

    compliance_data = compliance_reporter.generate_compliance_report(
        scored_risks,
        users=users,
        groups=groups,
        computers=computers,
        password_policy_data=password_policy_data,
    )
    print(f"[+] CIS Benchmark compliance: {compliance_data['cis_benchmark']['compliance_score']:.1f}%")
    print(f"[+] NIST CSF compliance: {compliance_data['nist_csf']['compliance_score']:.1f}%")
    print(f"[+] ISO 27001 compliance: {compliance_data['iso_27001']['compliance_score']:.1f}%")
    print(f"[+] GDPR compliance: {compliance_data['gdpr']['compliance_score']:.1f}%")

    # Risk management
    print("[*] Generating risk heat map and business impact analysis...")
    risk_manager = RiskManager(hourly_rate=hourly_rate)
    risk_management_data = {
        'heat_map': risk_manager.generate_risk_heat_map(scored_risks),
        'prioritized_risks': risk_manager.prioritize_risks(scored_risks),
    }
    print("[+] Risk heat map generated")
    if risk_management_data['prioritized_risks']:
        roi = risk_management_data['prioritized_risks'][0]['roi']['roi_percentage']
        print(f"[+] Top priority risk ROI: {roi:.1f}%")
    else:
        print("[+] No prioritized risks found")

    return {
        'compliance_data': compliance_data,
        'risk_management_data': risk_management_data,
    }


# ---------------------------------------------------------------------------
# Report generation & export
# ---------------------------------------------------------------------------

def generate_reports(
    args: argparse.Namespace,
    data: Dict[str, Any],
    analysis: Dict[str, Any],
    scoring: Dict[str, Any],
    compliance: Dict[str, Any],
    ldap_conn: LDAPConnection,
) -> Optional[Dict[str, Any]]:
    """Generate HTML report, JSON export, and baseline comparison.

    Returns:
        Baseline comparison data (or None).
    """
    print("[*] Generating HTML report...")

    # Build output filename
    safe_domain = re.sub(r'[^\w\-_\.]', '_', args.domain)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if args.output == 'report.html':
        output_file = f"AtilKurt_{safe_domain}_{timestamp}.html"
    else:
        output_file = args.output

    # Build analysis summary counts for Executive Summary (all analyses overview)
    analysis_summary_counts = {k: len(analysis.get(k, [])) for k in CONSOLIDATION_RISK_KEYS}
    analysis_summary_counts['shadow_admins'] = len(analysis.get('shadow_admins', []))
    analysis_summary_counts['acl_escalation_paths'] = len(analysis.get('acl_escalation_paths', []))
    analysis_summary_counts['misconfig_findings'] = len(analysis.get('misconfig_findings', []))

    report_generator = HTMLReportGenerator()
    report_generator.generate(
        users=data['users'],
        computers=data['computers'],
        groups=data['groups'],
        gpos=data['gpos'],
        risks=scoring['scored_risks'],
        misconfig_findings=analysis['misconfig_findings'],
        domain_score=scoring['domain_score'],
        executive_summary=scoring['executive_summary'],
        output_file=output_file,
        legacy_os_data=analysis['legacy_os_results'],
        acl_security_data=analysis['acl_security_results'],
        compliance_data=compliance['compliance_data'],
        risk_management_data=compliance['risk_management_data'],
        domain=args.domain,
        dc_ip=args.dc_ip,
        kerberoasting_targets=analysis['kerberoasting_targets'],
        asrep_targets=analysis['asrep_targets'],
        analysis_summary_counts=analysis_summary_counts,
    )
    print(f"[+] HTML report generated: {output_file}")

    # Baseline comparison
    baseline_comparison = None
    if args.baseline:
        print("[*] Comparing with baseline...")
        comparator = BaselineComparator()
        baseline_comparison = comparator.compare_full(
            {'risks': scoring['scored_risks']},
            args.baseline,
        )
        if baseline_comparison.get('comparison'):
            comp = baseline_comparison['comparison']
            print(
                f"[+] Baseline: {comp['summary']['new_count']} new, "
                f"{comp['summary']['resolved_count']} resolved risks"
            )
        else:
            print("[-] Baseline comparison failed")

    # JSON export
    if args.json_export:
        _export_json(args.json_export, data, analysis, scoring, compliance,
                     baseline_comparison)

    # Kerberoasting export
    if args.kerberoasting_export:
        print("[*] Exporting Kerberoasting targets...")
        ExportFormats.export_kerberoasting_list(
            analysis['kerberoasting_targets'], args.kerberoasting_export
        )
        print(f"[+] Kerberoasting targets export saved: {args.kerberoasting_export}")

    return baseline_comparison


def _export_json(
    path: str,
    data: Dict[str, Any],
    analysis: Dict[str, Any],
    scoring: Dict[str, Any],
    compliance: Dict[str, Any],
    baseline_comparison: Optional[Dict[str, Any]],
) -> None:
    """Write full results to a JSON file."""
    export_data = {
        "users": data["users"],
        "computers": data["computers"],
        "groups": data["groups"],
        "gpos": data["gpos"],
        "risks": scoring["scored_risks"],
        "domain_score": scoring["domain_score"],
        "executive_summary": scoring["executive_summary"],
        "compliance_data": compliance["compliance_data"],
        "risk_management_data": compliance["risk_management_data"],
        "baseline_comparison": baseline_comparison,
    }
    export_data.update(build_export_analysis_slice(analysis))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, default=str)
    print(f"[+] JSON export saved: {path}")


# ---------------------------------------------------------------------------
# Privilege escalation checker
# ---------------------------------------------------------------------------

def check_privilege_escalation(
    username: str,
    data: Dict[str, Any],
) -> None:
    """Check if a specific user can escalate to Domain Admin."""
    print(f"[*] Checking if user '{username}' can become Domain Admin...")
    calculator = PrivilegeCalculator()
    result = calculator.can_user_become_domain_admin(
        username, data['users'], data['groups'], data['computers']
    )
    print(f"[+] Can escalate: {result['can_escalate']}")
    if result['can_escalate']:
        print(f"[+] Shortest path depth: {result['shortest_path']['depth']}")
        print(f"[+] Path: {' → '.join(result['shortest_path']['path'])}")
        print(f"[+] Probability: {result['probability']}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """AtilKurt — Active Directory Security Health Check Tool."""
    parser = build_parser()
    args = parser.parse_args()

    validate_output_paths(args)
    setup_logging(args)

    print("[*] AtilKurt - Active Directory Security Health Check")
    print("[*] Starting analysis...")

    password_manager: Optional[SecurePasswordManager] = None
    ldap_conn: Optional[LDAPConnection] = None

    try:
        # --- Password -------------------------------------------------------
        password, password_manager = resolve_password(args)

        # --- Stealth mode ----------------------------------------------------
        random_delay = args.random_delay if args.random_delay else (0, 0)
        stealth = create_stealth_mode(
            enabled=True,
            rate_limit=args.rate_limit,
            random_delay_min=random_delay[0] if len(random_delay) > 0 else 0,
            random_delay_max=random_delay[1] if len(random_delay) > 1 else 0,
            min_logging=args.stealth,
        )
        if args.stealth:
            print("[*] Stealth mode enabled (enhanced rate limiting)")
        else:
            print(f"[*] Rate limiting enabled ({args.rate_limit}s between queries)")

        # --- Progress persistence -------------------------------------------
        persistence = None
        if args.resume or args.checkpoint or args.incremental:
            persistence = ProgressPersistence()
            if args.resume:
                print(f"[*] Resuming from checkpoint: {args.resume}")

        # --- LDAP connection -------------------------------------------------
        print("[*] Establishing LDAP connection...")
        # Avoid logging username in production; keep dc_ip only
        print(f"[*] Connecting to {args.dc_ip}...")
        ldap_conn = LDAPConnection(
            domain=args.domain,
            username=args.username,
            password=password,
            dc_ip=args.dc_ip,
            use_ssl=args.ssl,
            timeout=args.timeout,
            page_size=args.page_size,
            enable_paging=True,
            max_retries=args.max_retries,
            validate_certificate=not args.no_validate_cert,
        )

        try:
            ldap_conn.connect()
        except LDAPConnectionError as e:
            print(f"[-] LDAP connection failed: {e}")
            sys.exit(1)

        print("[+] LDAP connection established successfully")

        # --- Data collection -------------------------------------------------
        show_progress = not args.no_progress
        data = collect_data(ldap_conn, show_progress)

        # --- Security analysis -----------------------------------------------
        analysis = run_security_analysis(ldap_conn, data)

        # --- Risk scoring ----------------------------------------------------
        scoring = score_and_consolidate(analysis, data)

        # --- Compliance & risk management ------------------------------------
        compliance = generate_compliance_and_risk(
            ldap_conn, scoring['scored_risks'], data, args.hourly_rate
        )

        # --- Checkpoint ------------------------------------------------------
        if args.checkpoint and persistence:
            checkpoint_data = {
                'domain': args.domain,
                'users': data['users'],
                'computers': data['computers'],
                'groups': data['groups'],
                'risks': scoring['scored_risks'],
                'domain_score': scoring['domain_score'],
            }
            persistence.save_checkpoint(args.checkpoint, checkpoint_data)
            print(f"[+] Checkpoint saved: {args.checkpoint}")

        # --- Reports & export ------------------------------------------------
        generate_reports(args, data, analysis, scoring, compliance, ldap_conn)

        # --- Privilege escalation check --------------------------------------
        if args.check_user:
            check_privilege_escalation(args.check_user, data)

        print("[+] Analysis completed successfully!")

    except ValidationError as e:
        print(f"[-] Validation error: {e}")
        sys.exit(1)
    except (LDAPConnectionError, LDAPSearchError) as e:
        print(f"[-] LDAP error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if ldap_conn is not None:
            ldap_conn.disconnect()
        if password_manager is not None:
            password_manager.clear_password()


if __name__ == '__main__':
    main()
