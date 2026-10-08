#!/usr/bin/env python3
"""
AtilKurt - Active Directory Security Health Check Tool
Main execution file
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import os
import re
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from core.ldap_connection import LDAPConnection
from core.validators import validate_output_file
from core.exceptions import AnalysisError, ValidationError, LDAPConnectionError, LDAPSearchError
from core.collectors.user_collector import UserCollector
from core.collectors.computer_collector import ComputerCollector
from core.collectors.group_collector import GroupCollector
from core.collectors.gpo_collector import GPOCollector
from core.stealth_mode import create_stealth_mode
from analysis.registry import (
    run_all_analyses,
    get_consolidated_risk_lists,
    deduplicate_risks,
    build_export_analysis_slice,
    CONSOLIDATION_RISK_KEYS,
    get_analysis_step_keys,
)
from analysis.exploitability_scorer import ExploitabilityScorer
from analysis.privilege_calculator import PrivilegeCalculator
from analysis.domain_admin_takeover_analyzer import DomainAdminTakeoverAnalyzer
from analysis.password_policy_analyzer import PasswordPolicyAnalyzer
from analysis.baseline_comparator import BaselineComparator
from scoring.risk_scorer import RiskScorer
from reporting.html_report import HTMLReportGenerator
from reporting.export_formats import ExportFormats
from reporting.compliance_reporter import ComplianceReporter
from core.secure_password import SecurePasswordManager
from core.progress_persistence import ProgressPersistence, IncrementalScanner
from risk.risk_manager import RiskManager

logger = logging.getLogger(__name__)
PACKAGE_VERSION = "1.0"


def _package_version() -> str:
    """Return the installed package version, falling back to the source version."""
    try:
        from importlib.metadata import version
        return version("atilkurt")
    except Exception:
        return PACKAGE_VERSION


class _PrivateFileHandler(logging.StreamHandler):
    """Write logs through an owner-only file descriptor opened without symlinks."""

    def __init__(self, filename: str) -> None:
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        if not hasattr(os, "O_NOFOLLOW") and os.path.islink(filename):
            raise OSError("Refusing to write logs through a symbolic link")

        descriptor = os.open(filename, flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            else:
                os.chmod(filename, 0o600)
            stream = os.fdopen(descriptor, "a", encoding="utf-8")
        except Exception:
            os.close(descriptor)
            raise
        super().__init__(stream)

    def close(self) -> None:
        """Flush and close the owned file stream."""
        try:
            self.stream.close()
        finally:
            super().close()


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def _positive_int(value: str) -> int:
    """Parse a strictly positive integer for argparse."""
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _finite_positive_float(value: str) -> float:
    """Parse a finite, strictly positive float for argparse."""
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return parsed


def _finite_nonnegative_float(value: str) -> float:
    """Parse a finite, non-negative float for argparse."""
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("must be a finite non-negative number")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description='AtilKurt - Active Directory Security Health Check Tool',
        epilog='Operational commands: Atilkurt doctor | quality | verify-finding | keygen | sign | verify | audit | watch. Use COMMAND --help for details.',
    )
    parser.add_argument('--version', action='version', version=f'AtilKurt {_package_version()}')
    parser.add_argument('-d', '--domain', required=True,
                        help='Domain name (e.g., example.com)')
    parser.add_argument('-u', '--username',
                        help='LDAP username (without domain prefix)')
    parser.add_argument('-p', '--password',
                        help='[DEPRECATED] LDAP password via CLI — use env var '
                             'ATILKURT_PASS or interactive prompt instead')
    parser.add_argument('--dc-ip',
                        help='Domain Controller IP address or hostname '
                             '(default: domain name)')
    parser.add_argument('--output', default='report.html',
                        help='Output HTML report file')
    parser.add_argument(
        '--lan', '--lang', '--language',
        dest='language',
        choices=('en', 'tr'),
        default='en',
        help='Report language: en or tr (default: en)',
    )
    parser.add_argument(
        '--single-file-report',
        action=argparse.BooleanOptionalAction,
        default=True,
        help='Embed all report assets into the HTML file (default: enabled)',
    )
    parser.add_argument('--json-export',
                        help='Optional JSON export file path')
    parser.add_argument('--ssl', action='store_true',
                        help='Use LDAPS on port 636 (default: plaintext LDAP on port 389)')
    parser.add_argument('--stealth', action='store_true',
                        help='Enable stealth mode (enhanced rate limiting)')
    parser.add_argument('--rate-limit', type=_finite_nonnegative_float, default=None,
                        help='Minimum seconds between LDAP network queries '
                             '(default: 0; stealth default: 0.5)')
    parser.add_argument('--random-delay', type=_finite_nonnegative_float, nargs=2,
                        metavar=('MIN', 'MAX'),
                        help='Random delay range in seconds (e.g., --random-delay 1 5)')
    parser.add_argument('--page-size', type=_positive_int, default=5000,
                        help='LDAP page size for large result sets (default: 5000)')
    parser.add_argument('--timeout', type=_positive_int, default=30,
                        help='Base LDAP timeout in seconds (default: 30)')
    parser.add_argument('--max-retries', type=_positive_int, default=3,
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
    parser.add_argument('--max-workers', type=_positive_int, default=5,
                        help='Maximum parallel workers (default: 5)')
    parser.add_argument('--analysis-profile', choices=['full', 'fast'], default='full',
                        help='Analysis profile to run (default: full)')
    parser.add_argument('--skip-analysis', action='append', choices=get_analysis_step_keys(),
                        default=[],
                        help='Skip one analysis step by key; can be used multiple times')

    # Progress persistence arguments
    parser.add_argument('--resume',
                        help='Resume from checkpoint ID')
    parser.add_argument('--checkpoint',
                        help='Save checkpoint with specified ID')
    parser.add_argument('--incremental', action='store_true',
                        help='Enable incremental scanning')

    # Risk management arguments
    parser.add_argument('--hourly-rate', type=_finite_positive_float, default=100.0,
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
    parser.add_argument(
        '--event-log', action='append', default=[], metavar='FILE',
        help='Offline Windows event evidence (.json, .jsonl, .xml, or optional .evtx); repeatable',
    )
    parser.add_argument(
        '--posture-file', action='append', default=[], metavar='FILE',
        help='Offline DC/GPO posture evidence (.json, .xml, .inf, or text); repeatable',
    )
    parser.add_argument(
        '--attack-graph-export',
        help='Export the Tier-0 evidence graph in BloodHound OpenGraph-shaped JSON',
    )
    parser.add_argument('--review-file', help='Finding decisions and expiring exceptions JSON')
    parser.add_argument('--validation-evidence', action='append', default=[], metavar='FILE',
                        help='Local collector evidence JSON; repeatable')
    parser.add_argument('--validation-script', help='Write the local read-only PowerShell evidence collector')
    parser.add_argument('--review-export', help='Write the current review document as JSON')
    parser.add_argument('--evidence-max-age-days', type=_positive_int, default=30,
                        help='Maximum age of review evidence (default: 30, maximum: 365 days)')
    parser.add_argument('--remediation-scenario', help='JSON scenario with removed_edge_ids to simulate')
    parser.add_argument('--offline-snapshot', help='Regenerate reports from a JSON export without LDAP or credentials')
    parser.add_argument('--verify-effective-access', action='store_true', help='Read bounded tokenGroups for principals in critical/ACL findings')
    parser.add_argument('--token-limit', type=_positive_int, default=50, help='Maximum token-group reads (1..500, default: 50)')
    parser.add_argument('--token-delay', type=_finite_nonnegative_float, default=0.1, help='Seconds between token-group reads (default: 0.1)')
    parser.add_argument('--quality-dataset', help='Labelled offline rule evaluation dataset JSON')
    parser.add_argument('--quality-export', help='Export rule fixture metrics')
    parser.add_argument('--retest', help='Previous JSON assessment whose selected findings will be rechecked')
    parser.add_argument('--retest-finding', action='append', default=[], metavar='ID', help='Finding ID to recheck; repeatable; defaults to all findings in --retest')
    parser.add_argument('--retest-export', help='Export remediation verification results')
    parser.add_argument('--history-db', help='Private SQLite database for scan history, notifications, tasks and audit')
    parser.add_argument('--notifications-export', help='Export only new critical, reopened or expired-exception notifications')
    parser.add_argument('--ticket-file', help='Import assigned work items with owner, status and due date')
    parser.add_argument('--tickets-export', '--ticket-export', dest='tickets_export', help='Export stable work items for issue-tracker ingestion')
    parser.add_argument('--audit-export', help='Export the verified audit hash chain')
    parser.add_argument('--csv-export', help='Export findings to CSV')
    parser.add_argument('--siem-export', help='Export findings to newline-delimited SIEM JSON')
    parser.add_argument('--cef-export', help='Export findings to CEF')
    parser.add_argument('--export-changes-only', action='store_true', help='Integration exports contain only findings changed since the previous history run')
    parser.add_argument('--trusted-key', action='append', default=[], metavar='FILE', help='Trusted public evidence-signing key; repeatable')
    parser.add_argument('--require-signed-evidence', action='store_true', help='Reject unsigned review, collector, offline and retest evidence')
    parser.add_argument('--signing-key', help='Private key used to sign JSON workflow exports')
    from core.engagement_cli import add_engagement_arguments
    add_engagement_arguments(parser)

    # Logging
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output (INFO level)')
    parser.add_argument('--debug', action='store_true',
                        help='Debug output (DEBUG level)')
    parser.add_argument('--log-file',
                        help='Optional log file path')

    return parser


def validate_cli_arguments(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Validate relationships and upper bounds that argparse types cannot express."""
    if not args.dc_ip:
        args.dc_ip = args.domain
    from core.engagement_cli import validate_engagement_arguments
    validate_engagement_arguments(parser, args)
    if not args.username and not args.offline_snapshot:
        parser.error('--username is required unless --offline-snapshot is supplied')
    if args.evidence_max_age_days > 365:
        parser.error('--evidence-max-age-days must be between 1 and 365')
    if args.random_delay and args.random_delay[0] > args.random_delay[1]:
        parser.error("--random-delay MIN must not exceed MAX")
    if args.timeout > 300:
        parser.error("--timeout must be between 1 and 300 seconds")
    if args.page_size > 5000:
        parser.error("--page-size must be between 1 and 5000")
    if args.max_workers > 64:
        parser.error("--max-workers must be between 1 and 64")
    if args.token_limit > 500 or args.token_delay > 60:
        parser.error('--token-limit must be <=500 and --token-delay <=60')
    if args.retest_finding and not args.retest:
        parser.error('--retest-finding requires --retest')
    if args.require_signed_evidence and not args.trusted_key:
        parser.error('--require-signed-evidence requires at least one --trusted-key')
    if (args.ticket_file or args.tickets_export or args.notifications_export or args.audit_export) and not args.history_db:
        args.history_db = '.atilkurt_history.sqlite3'
    if args.export_changes_only and not args.history_db:
        parser.error('--export-changes-only requires --history-db')
    for option, paths in (("--event-log", args.event_log), ("--posture-file", args.posture_file)):
        for path_value in paths:
            path = Path(path_value)
            if not path.is_file():
                parser.error(f"{option} must reference a readable regular file: {path_value}")
    if args.baseline and not Path(args.baseline).is_file():
        parser.error(f"--baseline must reference a readable regular file: {args.baseline}")
    for option in ('review_file', 'remediation_scenario', 'offline_snapshot'):
        if getattr(args, option) and not Path(getattr(args, option)).is_file():
            parser.error(f"--{option.replace('_', '-')} must reference a readable regular file")
    for path in args.validation_evidence:
        if not Path(path).is_file():
            parser.error('--validation-evidence must reference a readable regular file')
    for path in [args.quality_dataset, args.retest, args.ticket_file, args.signing_key, *args.trusted_key]:
        if path and not Path(path).is_file():
            parser.error('Workflow input must reference a readable regular file')


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
            fh = _PrivateFileHandler(log_file)
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
        if args.attack_graph_export:
            args.attack_graph_export = validate_output_file(args.attack_graph_export)
        for option in ('validation_script', 'review_export', 'quality_export', 'retest_export',
                       'notifications_export', 'tickets_export', 'audit_export', 'csv_export', 'siem_export', 'cef_export',
                       'engagement_export', 'docx_export', 'pdf_export'):
            if getattr(args, option, None):
                setattr(args, option, validate_output_file(getattr(args, option)))
        from core.validators import validate_distinct_paths
        outputs = {name: getattr(args, name, None) for name in (
            'output', 'json_export', 'kerberoasting_export', 'attack_graph_export', 'validation_script',
            'review_export', 'quality_export', 'retest_export', 'notifications_export', 'tickets_export',
            'audit_export', 'csv_export', 'siem_export', 'cef_export', 'history_db', 'log_file',
            'engagement_export', 'docx_export', 'pdf_export',
        )}
        args._report_output_path = _report_output_path(args)
        outputs['output'] = args._report_output_path
        inputs = {name: getattr(args, name, None) for name in (
            'baseline', 'review_file', 'remediation_scenario', 'offline_snapshot', 'quality_dataset',
            'retest', 'ticket_file', 'signing_key', 'scope_file', 'protocol_evidence', 'gpo_context', 'rsop_file',
        )}
        for name in ('event_log', 'posture_file', 'validation_evidence', 'trusted_key', 'bloodhound_import', 'federation_snapshot'):
            inputs.update({f'{name}[{index}]': path for index, path in enumerate(getattr(args, name, []))})
        from core.progress_persistence import validate_checkpoint_id
        for name in ('resume', 'checkpoint'):
            if getattr(args, name, None):
                try:
                    validate_checkpoint_id(getattr(args, name))
                except ValueError as exc:
                    raise ValidationError(str(exc)) from exc
                checkpoint_path = str(Path('.atilkurt_checkpoints') / f'{getattr(args, name)}.json')
                if name == 'resume':
                    inputs['resume'] = checkpoint_path
                elif args.checkpoint != args.resume:
                    outputs['checkpoint'] = checkpoint_path
        validate_distinct_paths(outputs, inputs)
        from core.engagement_cli import validate_shared_file_outputs
        validate_shared_file_outputs(args, outputs)
    except ValidationError as e:
        print(f"[-] Invalid output path: {e}", file=sys.stderr)
        sys.exit(1)


def _report_output_path(args) -> str:
    if args.output != 'report.html':
        return args.output
    safe_domain = re.sub(r'[^\w\-_\.]', '_', args.domain)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f'AtilKurt_{safe_domain}_{timestamp}.html'


# ---------------------------------------------------------------------------
# Password resolution
# ---------------------------------------------------------------------------

def resolve_password(args: argparse.Namespace) -> tuple[str, SecurePasswordManager]:
    """Resolve password from env var, CLI arg (deprecated), or interactive prompt.

    Returns:
        Tuple of (password, password_manager).
    """
    password_manager = SecurePasswordManager()

    # 1. Prefer environment variable, then drop it so later process listings
    # and child environments do not keep the secret.
    env_pass = os.environ.pop('ATILKURT_PASS', None)
    if env_pass:
        return password_manager.set_password(env_pass), password_manager

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
    use_parallel: bool = False,
    max_workers: int = 5,
    stealth_settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect all AD objects via LDAP.

    Returns:
        Dictionary with keys: users, computers, groups, gpos.
    """
    print("[*] Collecting Active Directory data...")

    if use_parallel:
        return _collect_data_parallel(ldap_conn, show_progress, max_workers, stealth_settings)

    user_collector = UserCollector(ldap_conn, show_progress=show_progress)
    users = _collect_scoped(user_collector, ldap_conn)
    print(f"[+] Collected {len(users)} users")

    computer_collector = ComputerCollector(ldap_conn, show_progress=show_progress)
    computers = _collect_scoped(computer_collector, ldap_conn)
    print(f"[+] Collected {len(computers)} computers")

    group_collector = GroupCollector(ldap_conn, show_progress=show_progress)
    groups = _collect_scoped(group_collector, ldap_conn)
    print(f"[+] Collected {len(groups)} groups")

    gpo_collector = GPOCollector(ldap_conn, show_progress=show_progress)
    gpos = _collect_scoped(gpo_collector, ldap_conn)
    print(f"[+] Collected {len(gpos)} GPOs")

    return {
        'users': users,
        'computers': computers,
        'groups': groups,
        'gpos': gpos,
    }


def _collect_scoped(collector, ldap_conn):
    from core.assessment_scope import ScopeLimitError
    try:
        return collector.collect()
    except ScopeLimitError as exc:
        print(f'[*] Collection not assessed: {exc}')
        ldap_conn.merge_query_audit([{'status': 'failed', 'reason': str(exc), 'scope': 'engagement',
                                    'attributes': [], 'unobserved_attributes': []}])
        return []


def _clone_ldap_connection(ldap_conn: LDAPConnection) -> LDAPConnection:
    """Create a new LDAP connection with the same runtime settings."""
    connection = LDAPConnection(
        domain=ldap_conn.domain,
        username=ldap_conn.username,
        password=ldap_conn.password,
        dc_ip=ldap_conn.dc_ip,
        use_ssl=ldap_conn.use_ssl,
        timeout=ldap_conn.base_timeout,
        page_size=ldap_conn.page_size,
        enable_paging=ldap_conn.enable_paging,
        max_retries=ldap_conn.max_retries,
        retry_delay=ldap_conn.retry_delay,
        adaptive_timeout=ldap_conn.adaptive_timeout,
        enable_cache=ldap_conn.enable_cache,
        validate_certificate=ldap_conn.validate_certificate,
    )
    connection.assessment_scope = getattr(ldap_conn, 'assessment_scope', None)
    return connection


def _apply_stealth_to_connection(ldap_conn: LDAPConnection, stealth_settings: dict[str, Any] | None) -> None:
    """Attach rate limiting to a connection's search method when requested."""
    if not stealth_settings:
        return
    stealth = create_stealth_mode(**stealth_settings)
    if stealth.enabled:
        ldap_conn.pre_search_hook = stealth.apply_delay


def _collect_with_new_connection(
    base_conn: LDAPConnection,
    collector_cls: Any,
    show_progress: bool,
    stealth_settings: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Run one collector with an isolated LDAP connection."""
    from core.assessment_scope import ScopeLimitError
    conn = _clone_ldap_connection(base_conn)
    try:
        _apply_stealth_to_connection(conn, stealth_settings)
        conn.connect()
        collector = collector_cls(conn, show_progress=show_progress)
        return _collect_scoped(collector, conn)
    except ScopeLimitError as exc:
        conn.merge_query_audit([{'status': 'failed', 'reason': str(exc), 'scope': 'engagement',
                                'attributes': [], 'unobserved_attributes': []}])
        return []
    finally:
        if hasattr(base_conn, 'merge_query_audit'):
            base_conn.merge_query_audit(getattr(conn, 'query_audit', []))
            if getattr(conn, 'query_audit_overflow', False):
                base_conn.query_audit_overflow = True
        conn.disconnect()


def _collect_data_parallel(
    ldap_conn: LDAPConnection,
    show_progress: bool,
    max_workers: int,
    stealth_settings: dict[str, Any] | None,
) -> dict[str, Any]:
    """Collect top-level AD object sets concurrently with isolated connections."""
    collectors = {
        "users": UserCollector,
        "computers": ComputerCollector,
        "groups": GroupCollector,
        "gpos": GPOCollector,
    }
    worker_count = max(1, min(int(max_workers or 1), len(collectors)))
    print(f"[*] Parallel collection enabled ({worker_count} workers)")

    collected: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_key = {
            executor.submit(
                _collect_with_new_connection,
                ldap_conn,
                collector_cls,
                show_progress,
                stealth_settings,
            ): key
            for key, collector_cls in collectors.items()
        }
        for future in as_completed(future_to_key):
            key = future_to_key[future]
            collected[key] = future.result()
            print(f"[+] Collected {len(collected[key])} {key}")

    return {
        "users": collected.get("users", []),
        "computers": collected.get("computers", []),
        "groups": collected.get("groups", []),
        "gpos": collected.get("gpos", []),
    }


# ---------------------------------------------------------------------------
# Security analysis
# ---------------------------------------------------------------------------

def run_security_analysis(
    ldap_conn: LDAPConnection,
    data: dict[str, Any],
    analysis_profile: str = "full",
    skip_analyses: list[str] | None = None,
) -> dict[str, Any]:
    """Run all security analyzers and return consolidated results.

    Args:
        ldap_conn: Active LDAP connection.
        data: Collected AD data (users, computers, groups, gpos).

    Returns:
        Dictionary with all analysis results.
    """
    def progress_callback(description: str, step_result: dict[str, Any], duration: float | None = None) -> None:
        duration_suffix = f" in {duration:.1f}s" if duration is not None else ""
        counts = [len(v) for v in step_result.values() if isinstance(v, list)]
        if counts:
            print(f"[+] {description}: {counts[0]} items{duration_suffix}")
        else:
            for key, value in step_result.items():
                if isinstance(value, dict):
                    if key == "legacy_os_results":
                        print(
                            f"[+] Legacy OS: {value.get('total_count', 0)} computers, "
                            f"{value.get('eol_count', 0)} EOL{duration_suffix}"
                        )
                        return
                    if key == "tier_data":
                        td = value
                        print(f"[+] TIER: T0={td.get('tier_0', {}).get('count', 0)}, "
                              f"T1={td.get('tier_1', {}).get('count', 0)}, "
                              f"T2={td.get('tier_2', {}).get('count', 0)}{duration_suffix}")
                        return
                    if key == "acl_security_results":
                        print(
                            f"[+] ACL: {len(value.get('acl_risks', []))} risks, "
                            f"{len(value.get('shadow_admins', []))} Shadow Admins{duration_suffix}"
                        )
                        return
        if not counts:
            print(f"[+] {description}: done{duration_suffix}")

    def status_callback(description: str) -> None:
        print(f"[*] Running {description}...")

    print("[*] Performing security analysis...")
    results = run_all_analyses(
        ldap_conn,
        data,
        progress_callback=progress_callback,
        status_callback=status_callback,
        profile=analysis_profile,
        skip_keys=skip_analyses or [],
    )

    return results


def apply_package_c_evidence(
    args: argparse.Namespace,
    data: dict[str, Any],
    analysis: dict[str, Any],
) -> None:
    """Apply optional offline telemetry, posture, and snapshot evidence."""
    from core.engagement_workflow import apply_engagement
    apply_engagement(args, data, analysis)
    if args.event_log:
        from analysis.event_correlation_analyzer import EventCorrelationAnalyzer

        print(f"[*] Correlating offline event evidence from {len(args.event_log)} file(s)...")
        existing = deduplicate_risks(list(itertools.chain(*get_consolidated_risk_lists(analysis))))
        result = EventCorrelationAnalyzer().analyze(args.event_log, existing)
        analysis["event_correlation_risks"] = result["risks"]
        analysis["event_correlation"] = result["summary"]
        print(f"[+] Event correlation: {len(result['risks'])} findings from {result['summary']['parsed_events']} events")

    posture_paths = args.posture_file
    observations = []
    review_document = getattr(args, '_workflow_review_document', None)
    if review_document and review_document.get('observations'):
        from core.finding_review import FindingReviewManager
        observations = FindingReviewManager().apply([], data, args.domain, review_document,
                                                    max_age_days=args.evidence_max_age_days)['observations']
    if posture_paths or observations:
        from analysis.posture_evidence_analyzer import PostureEvidenceAnalyzer

        print(f"[*] Verifying DC/GPO posture evidence from {len(posture_paths)} file(s)...")
        result = PostureEvidenceAnalyzer().analyze(posture_paths, observations=observations)
        analysis["posture_evidence_risks"] = result["risks"]
        analysis["posture_evidence"] = {
            "summary": result["summary"],
            "evidence": result["evidence"],
        }
        print(f"[+] Posture evidence: {len(result['risks'])} findings")

    if args.baseline:
        print("[*] Building security snapshot delta...")
        current = deduplicate_risks(list(itertools.chain(*get_consolidated_risk_lists(analysis))))
        from core.product_workflow import load_workflow_document
        baseline = load_workflow_document(args.baseline, args)
        baseline_domain = baseline.get('domain') or (baseline.get('data') or {}).get('domain')
        if baseline_domain and str(baseline_domain).casefold().strip('.') != args.domain.casefold().strip('.'):
            from core.exceptions import ValidationError
            raise ValidationError('Baseline snapshot belongs to a different domain')
        result = BaselineComparator().compare_snapshot(data, analysis, current, args.baseline, baseline_document=baseline)
        analysis["snapshot_delta_risks"] = result.get("risks", [])
        analysis["snapshot_delta"] = result
        summary = result.get("summary") or {}
        print(
            f"[+] Snapshot delta: {summary.get('new_risks', 0)} new risks, "
            f"{summary.get('object_field_changes', 0)} object changes, "
            f"{summary.get('added_attack_edges', 0)} new attack edges"
        )


# ---------------------------------------------------------------------------
# Risk scoring & consolidation
# ---------------------------------------------------------------------------

def score_and_consolidate(
    analysis: dict[str, Any],
    data: dict[str, Any],
    domain: str | None = None,
    dc_ip: str | None = None,
    review_document: dict[str, Any] | None = None,
    evidence_max_age_days: int = 30,
    input_risks: list[dict[str, Any]] | None = None,
    removed_edge_ids: list[str] | None = None,
) -> dict[str, Any]:
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
    shadow_admin_risks: list[dict[str, Any]] = []
    for sa in analysis.get('shadow_admins') or []:
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

    acl_escalation_risks: list[dict[str, Any]] = []
    for path in analysis.get('acl_escalation_paths') or []:
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

    risk_lists = get_consolidated_risk_lists(analysis)
    all_risks_iter = itertools.chain(
        *risk_lists,
        shadow_admin_risks,
        acl_escalation_risks,
    )
    all_risks = deduplicate_risks(list(all_risks_iter))
    if input_risks is not None:
        all_risks = input_risks

    from core.finding_review import FindingReviewManager
    review_center = FindingReviewManager().apply(
        all_risks, data, domain or '', review_document, max_age_days=evidence_max_age_days,
    )
    if review_document and review_document.get('reviews') and analysis.get('attack_graph_v2'):
        from analysis.attack_graph_v2_analyzer import AttackGraphV2Analyzer
        from core.finding_evidence import is_disproved
        acl_findings = analysis.get('comprehensive_acl_risks') or []
        FindingReviewManager().apply(acl_findings, data, domain or '', review_document,
                                    max_age_days=evidence_max_age_days)
        refreshed = AttackGraphV2Analyzer().analyze(users, groups, computers, analysis)
        analysis['attack_graph_v2'] = refreshed['graph']
        analysis['attack_graph_v2_risks'] = refreshed['risks']
        all_risks = [risk for risk in all_risks if not str(risk.get('type') or '').startswith('attack_graph_')]
        all_risks.extend(refreshed['risks'])
        # Legacy ACL-derived summaries lack edge-level provenance. Recheck any
        # summary sourced by a principal whose supporting grant was disproved.
        from core.ad_security import sid_text
        disproved_sids = {finding.get('trustee') for finding in acl_findings if is_disproved(finding)}
        impacted_names = {str(obj.get('sAMAccountName') or obj.get('name') or '').casefold()
                          for obj in users + groups if sid_text(obj.get('objectSid')) in disproved_sids}
        for risk in all_risks:
            if risk.get('type') in {'shadow_admin', 'acl_privilege_escalation_path'} and str(risk.get('affected_object') or '').casefold() in impacted_names:
                basis = risk['review_basis']
                basis['requires_validation'] = True
                basis['evidence'] = {'requires_runtime_validation': True, 'reason': 'Supporting ACL grant was disproved; re-evaluate this derived summary'}
        review_center = FindingReviewManager().apply(
            all_risks, data, domain or '', review_document, max_age_days=evidence_max_age_days,
        )

    from analysis.confidence_scorer import ConfidenceScorer
    ConfidenceScorer().enrich_risks(all_risks)

    print("[*] Calculating exploitability scores...")
    exploitability_scorer = ExploitabilityScorer()
    for risk in all_risks:
        risk["exploitability"] = exploitability_scorer.score_risk(risk)

    scored_risks = scorer.score_risks(all_risks, users=users, groups=groups,
                                       computers=computers)
    domain_score = scorer.calculate_domain_score(scored_risks)
    print(f"[+] Domain security score: {domain_score:.1f}/100")

    executive_summary = scorer.generate_executive_summary(scored_risks, users,
                                                          computers, groups)
    top = executive_summary['top_critical_risks']
    print(f"[+] Top critical risk: {top[0]['title'] if top else 'None'}")

    print("[*] Mapping Domain Admin takeover paths...")
    takeover = DomainAdminTakeoverAnalyzer().analyze(
        scored_risks,
        users=users,
        groups=groups,
        computers=computers,
        domain=domain,
        dc_ip=dc_ip,
    )
    print(
        f"[+] Domain Admin takeover paths: {takeover['summary']['open_path_count']} open "
        f"({takeover['summary']['da_equivalent_open_count']} DA-equivalent)"
    )

    from analysis.scan_coverage import build_scan_coverage
    from analysis.remediation_simulator import simulate_remediation
    coverage = build_scan_coverage(analysis, scored_risks, review_center)
    simulation = simulate_remediation(analysis.get('attack_graph_v2') or {}, removed_edge_ids)

    return {
        'scored_risks': scored_risks,
        'domain_score': domain_score,
        'executive_summary': executive_summary,
        'shadow_admin_risks': shadow_admin_risks,
        'acl_escalation_risks': acl_escalation_risks,
        'domain_admin_takeover': takeover,
        'review_center': review_center,
        'scan_coverage': coverage,
        'remediation_simulation': simulation,
    }


# ---------------------------------------------------------------------------
# Compliance & risk management
# ---------------------------------------------------------------------------

def generate_compliance_and_risk(
    ldap_conn: LDAPConnection,
    scored_risks: list[dict[str, Any]],
    data: dict[str, Any],
    hourly_rate: float,
) -> dict[str, Any]:
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
    data: dict[str, Any],
    analysis: dict[str, Any],
    scoring: dict[str, Any],
    compliance: dict[str, Any],
    ldap_conn: LDAPConnection,
) -> dict[str, Any] | None:
    """Generate HTML report, JSON export, and baseline comparison.

    Returns:
        Baseline comparison data (or None).
    """
    from core.product_workflow import product_workspace_transaction
    from core.engagement_workflow import refresh_engagement_graph
    refresh_engagement_graph(args, data, analysis)

    with product_workspace_transaction(args, data, analysis, scoring) as workspace:
        return _write_reports(args, data, analysis, scoring, compliance, workspace)


def _write_reports(args, data, analysis, scoring, compliance, product_workspace):
    """Publish reports while the caller holds the history transaction."""
    from core.product_workflow import export_product_workspace

    print("[*] Generating HTML report...")
    scoring['product_workspace'] = product_workspace

    output_file = getattr(args, '_report_output_path', None) or _report_output_path(args)

    # Build analysis summary counts for Executive Summary (all analyses overview)
    analysis_summary_counts = {k: len(analysis.get(k, [])) for k in CONSOLIDATION_RISK_KEYS}
    analysis_summary_counts['shadow_admins'] = len(analysis.get('shadow_admins') or [])
    analysis_summary_counts['acl_escalation_paths'] = len(analysis.get('acl_escalation_paths') or [])
    analysis_summary_counts['misconfig_findings'] = len(analysis.get('misconfig_findings', []))
    takeover = scoring.get('domain_admin_takeover') or {}
    analysis['domain_admin_takeover'] = takeover
    analysis_summary_counts['domain_admin_takeover'] = int(
        (takeover.get('summary') or {}).get('open_path_count') or 0
    )

    report_generator = HTMLReportGenerator(language=args.language)
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
        domain_admin_takeover=takeover,
        inline_assets=args.single_file_report,
        review_center=scoring.get('review_center'),
        scan_coverage=scoring.get('scan_coverage'),
        remediation_simulation=scoring.get('remediation_simulation'),
        product_workspace=product_workspace,
    )
    print(f"[+] HTML report generated: {output_file}")

    # Baseline comparison (the enriched snapshot delta is built before scoring).
    baseline_comparison = analysis.get("snapshot_delta")

    # JSON export
    if args.json_export:
        _export_json(args.json_export, data, analysis, scoring, compliance,
                     baseline_comparison, language=args.language, signing_key=getattr(args, 'signing_key', None))

    # Kerberoasting export
    if args.kerberoasting_export:
        print("[*] Exporting Kerberoasting targets...")
        ExportFormats.export_kerberoasting_list(
            analysis['kerberoasting_targets'], args.kerberoasting_export
        )
        print(f"[+] Kerberoasting targets export saved: {args.kerberoasting_export}")

    if args.attack_graph_export:
        print("[*] Exporting Tier-0 evidence graph...")
        ExportFormats.export_attack_graph(analysis.get("attack_graph_v2") or {}, args.attack_graph_export)
        print(f"[+] Attack graph export saved: {args.attack_graph_export}")

    if args.validation_script:
        from core.validation_collector import build_validation_script
        from core.secure_file import atomic_write_text
        atomic_write_text(args.validation_script, build_validation_script(scoring['review_center']))
        print(f'[+] Validation collector saved: {args.validation_script}')
    if args.review_export:
        from core.evidence_signing import write_document
        write_document(args.review_export, scoring['review_center']['document'], getattr(args, 'signing_key', None))
        print(f'[+] Review document saved: {args.review_export}')
    export_product_workspace(args, product_workspace, scoring['scored_risks'])
    from core.engagement_workflow import export_engagement
    export_engagement(args, product_workspace, data, scoring['scored_risks'])

    return baseline_comparison


def _export_json(
    path: str,
    data: dict[str, Any],
    analysis: dict[str, Any],
    scoring: dict[str, Any],
    compliance: dict[str, Any],
    baseline_comparison: dict[str, Any] | None,
    language: str = 'en',
    signing_key: str | None = None,
) -> None:
    """Write full results to a JSON file."""
    export_data = {
        'schema_version': 2,
        'domain': (scoring.get('review_center') or {}).get('domain'),
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
        'review_center': scoring.get('review_center'),
        'scan_coverage': scoring.get('scan_coverage'),
        'remediation_simulation': scoring.get('remediation_simulation'),
        'analysis_execution': analysis.get('analysis_execution'),
        'scan_context': data.get('scan_context'),
        'collection_health': data.get('collection_health'),
        'effective_access': analysis.get('effective_access'),
        'product_workspace': scoring.get('product_workspace'),
        'engagement_scope': data.get('engagement_scope'),
        'engagement': analysis.get('engagement'),
        'federated_graph': analysis.get('federated_graph'),
    }
    export_data.update(build_export_analysis_slice(analysis))
    if language == 'tr':
        from reporting.localization import localize_export_payload
        export_data = localize_export_payload(export_data, language)
    from core.evidence_signing import write_document
    write_document(path, export_data, signing_key)
    print(f"[+] JSON export saved: {path}")


# ---------------------------------------------------------------------------
# Privilege escalation checker
# ---------------------------------------------------------------------------

def check_privilege_escalation(
    username: str,
    data: dict[str, Any],
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


def calculate_incremental_diff(
    persistence: ProgressPersistence,
    domain: str,
    current_data: dict[str, Any],
    current_checkpoint_id: str | None = None,
) -> dict[str, Any] | None:
    """Compare current collection data with the latest compatible checkpoint."""
    checkpoints = persistence.list_checkpoints(domain)
    previous_checkpoint = None
    for checkpoint in checkpoints:
        checkpoint_id = checkpoint.get("checkpoint_id")
        if current_checkpoint_id and checkpoint_id == current_checkpoint_id:
            continue
        previous_checkpoint = checkpoint
        break

    if not previous_checkpoint:
        print("[*] Incremental scan: no previous checkpoint found")
        return None

    previous_payload = persistence.load_checkpoint(previous_checkpoint["checkpoint_id"])
    if not previous_payload:
        print("[*] Incremental scan: previous checkpoint could not be loaded")
        return None

    previous_data = previous_payload.get("data", previous_payload)
    if not isinstance(previous_data, dict):
        raise ValidationError('Incremental checkpoint data must be an object')
    if previous_payload.get('domain') and str(previous_payload['domain']).casefold().strip('.') != domain.casefold().strip('.'):
        raise ValidationError('Incremental checkpoint belongs to a different domain')
    scanner = IncrementalScanner(persistence)
    key_fields = {
        "users": ["sAMAccountName"],
        "computers": ["name"],
        "groups": ["name"],
        "gpos": ["name"],
    }
    diff: dict[str, Any] = {
        "baseline_checkpoint": previous_checkpoint["checkpoint_id"],
        "collections": {},
    }

    for collection_name, fields in key_fields.items():
        current_items = current_data.get(collection_name, []) or []
        previous_items = previous_data.get(collection_name, []) or []
        if not isinstance(previous_items, list) or any(not isinstance(row, dict) for row in previous_items):
            raise ValidationError(f'Incremental checkpoint {collection_name} must be a list of objects')
        collection_diff = {
            "new": scanner.find_new_items(current_items, previous_items, fields),
            "changed": scanner.find_changed_items(current_items, previous_items, fields),
            "deleted": scanner.find_deleted_items(current_items, previous_items, fields),
        }
        diff["collections"][collection_name] = collection_diff
        print(
            f"[+] Incremental {collection_name}: "
            f"{len(collection_diff['new'])} new, "
            f"{len(collection_diff['changed'])} changed, "
            f"{len(collection_diff['deleted'])} deleted"
        )

    return diff


def build_checkpoint_payload(
    args: argparse.Namespace,
    data: dict[str, Any],
    analysis: dict[str, Any],
    scoring: dict[str, Any],
    compliance: dict[str, Any],
) -> dict[str, Any]:
    """Build a full checkpoint payload that can be resumed without recollection."""
    return {
        "domain": args.domain,
        "created_at": datetime.now().isoformat(),
        "data": data,
        "analysis": analysis,
        "scoring": scoring,
        "compliance": compliance,
        "users": data.get("users", []),
        "computers": data.get("computers", []),
        "groups": data.get("groups", []),
        "gpos": data.get("gpos", []),
        "risks": scoring.get("scored_risks", []),
        "domain_score": scoring.get("domain_score"),
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def load_workflow_inputs(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    """Merge endpoint observations while keeping reviewer decisions explicit."""
    from core.finding_review import empty_review_document, load_review_document
    signature_options = {'trusted_keys': args.trusted_key, 'require_signed': args.require_signed_evidence}
    document = load_review_document(args.review_file, args.domain, **signature_options) if args.review_file else empty_review_document(args.domain)
    args._signature_verifications = []
    if args.review_file:
        args._signature_verifications.append({'source': args.review_file, **document.get('signature_verification', {})})
    for path in args.validation_evidence:
        observations = load_review_document(path, args.domain, **signature_options)
        args._signature_verifications.append({'source': path, **observations.get('signature_verification', {})})
        document['observations'].extend(observations.get('observations', []))
        if len(document['observations']) > 10000:
            raise ValidationError('Too many endpoint observations')
    removed = []
    if args.remediation_scenario:
        scenario = _load_bounded_json(args.remediation_scenario)
        removed = scenario.get('removed_edge_ids')
        if not isinstance(removed, list) or len(removed) > 100000 or any(not isinstance(item, str) for item in removed):
            raise ValidationError('Remediation scenario requires a list of removed_edge_ids')
    args._workflow_review_document = document
    return document, removed


def _load_bounded_json(path: str) -> dict[str, Any]:
    with Path(path).open('rb') as stream:
        payload = stream.read(64 * 1024 * 1024 + 1)
    if len(payload) > 64 * 1024 * 1024:
        raise ValidationError('Snapshot or scenario exceeds the 64 MiB limit')
    try:
        document = json.loads(payload.decode('utf-8-sig'))
    except (ValueError, UnicodeError) as exc:
        raise ValidationError('Snapshot or scenario is not valid JSON') from exc
    if not isinstance(document, dict):
        raise ValidationError('Snapshot or scenario must be a JSON object')
    return document


def generate_offline_report(args: argparse.Namespace, document: dict[str, Any], removed: list[str]) -> None:
    """Re-evaluate saved evidence and review expiry without opening a connection."""
    from analysis.registry import EXPORT_KEY_TO_ANALYSIS_KEY
    from core.product_workflow import load_workflow_document
    snapshot = load_workflow_document(args.offline_snapshot, args)
    if str(snapshot.get('domain') or '').casefold().strip('.') != args.domain.casefold().strip('.'):
        raise ValidationError('Offline snapshot belongs to a different domain or lacks domain metadata')
    if not args.review_file:
        saved_document = (snapshot.get('review_center') or {}).get('document')
        if saved_document:
            saved_document.setdefault('observations', []).extend(document['observations'])
            document = saved_document
    args._workflow_review_document = document
    data = {key: snapshot.get(key, []) for key in ('users', 'computers', 'groups', 'gpos')}
    if any(not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows) for rows in data.values()):
        raise ValidationError('Offline snapshot contains invalid directory collections')
    _restore_snapshot_binary_attributes(data)
    data['collection_health'] = snapshot.get('collection_health') or {'status': 'unknown', 'queries': []}
    data['scan_context'] = {**(snapshot.get('scan_context') or {}), 'fresh_ldap': False}
    risks = snapshot.get('risks', [])
    if not isinstance(risks, list) or any(not isinstance(risk, dict) for risk in risks):
        raise ValidationError('Offline snapshot contains invalid findings')
    analysis = {key: snapshot.get(export_key) for export_key, key in EXPORT_KEY_TO_ANALYSIS_KEY.items()}
    analysis['analysis_execution'] = snapshot.get('analysis_execution')
    analysis['effective_access'] = snapshot.get('effective_access')
    analysis['engagement'] = snapshot.get('engagement') or {}
    analysis['federated_graph'] = snapshot.get('federated_graph')
    args._saved_federated_graph = snapshot.get('federated_graph')
    data['engagement_scope'] = snapshot.get('engagement_scope')
    for key in CONSOLIDATION_RISK_KEYS:
        if not isinstance(analysis.get(key), list):
            analysis[key] = []
    for key in ('misconfig_findings', 'kerberoasting_targets', 'asrep_targets'):
        analysis[key] = analysis.get(key) or []
    analysis['legacy_os_results'] = analysis.get('legacy_os_results') or {}
    analysis['acl_security_results'] = analysis.get('acl_security_results') or {}
    apply_package_c_evidence(args, data, analysis)
    replacements = []
    if args.event_log:
        replacements.append(('event_', 'event_correlation_risks'))
    if args.posture_file or args.validation_evidence:
        replacements.append(('posture_', 'posture_evidence_risks'))
    if args.baseline:
        replacements.append(('snapshot_', 'snapshot_delta_risks'))
    if getattr(args, 'sysvol_dir', []):
        replacements.append(('sysvol_', 'shared_file_risks'))
    if getattr(args, 'protocol_evidence', None):
        replacements.append(('protocol_', 'protocol_verification_risks'))
    for prefix, key in replacements:
        risks = [risk for risk in risks if not str(risk.get('type') or '').startswith(prefix)]
        risks.extend(analysis.get(key) or [])
    scoring = score_and_consolidate(
        analysis, data, domain=args.domain, dc_ip=args.dc_ip, review_document=document,
        evidence_max_age_days=args.evidence_max_age_days, input_risks=risks, removed_edge_ids=removed,
    )
    manager = RiskManager(hourly_rate=args.hourly_rate)
    compliance = {
        'compliance_data': ComplianceReporter().generate_compliance_report(scoring['scored_risks']),
        'risk_management_data': {
            'heat_map': manager.generate_risk_heat_map(scoring['scored_risks']),
            'prioritized_risks': manager.prioritize_risks(scoring['scored_risks']),
        },
    }
    generate_reports(args, data, analysis, scoring, compliance, None)
    print('[+] Offline report completed. Directory evidence was reused; no LDAP connection was opened.')


def _restore_snapshot_binary_attributes(data: dict[str, Any]) -> None:
    """Restore the bytes repr emitted by existing JSON exports, without eval."""
    import ast
    binary_fields = {'objectSid', 'nTSecurityDescriptor', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
                     'msDS-GroupMSAMembership', 'objectGUID'}

    def restore(value):
        if isinstance(value, list):
            return [restore(item) for item in value]
        if isinstance(value, str) and value.startswith(("b'", 'b"')):
            if len(value) > 1024 * 1024:
                raise ValidationError('Snapshot binary attribute exceeds the size limit')
            try:
                decoded = ast.literal_eval(value)
            except (ValueError, SyntaxError) as exc:
                raise ValidationError('Snapshot contains an invalid binary attribute') from exc
            if not isinstance(decoded, bytes):
                raise ValidationError('Snapshot binary attribute is not bytes')
            return decoded
        return value

    for key in ('users', 'groups', 'computers', 'gpos'):
        rows = data.get(key) or []
        for obj in rows:
            for field in binary_fields & obj.keys():
                obj[field] = restore(obj[field])


def load_resume_checkpoint(persistence, checkpoint_id: str, domain: str):
    """Reject invalid resume requests before credentials or LDAP are used."""
    try:
        payload = persistence.load_checkpoint(checkpoint_id)
    except ValueError as exc:
        raise ValidationError('Invalid resume checkpoint identifier') from exc
    if not isinstance(payload, dict):
        raise ValidationError('Resume checkpoint was not found or could not be read')
    if str(payload.get('domain') or '').casefold().strip('.') != domain.casefold().strip('.'):
        raise ValidationError('Resume checkpoint belongs to a different or unspecified domain')
    sections = ('data', 'analysis', 'scoring', 'compliance')
    if not all(key in payload for key in sections):
        return None  # A valid partial checkpoint still requires fresh collection.
    if any(not isinstance(payload[key], dict) for key in sections):
        raise ValidationError('Resume checkpoint sections must be objects')
    data, analysis = payload['data'], payload['analysis']
    for key in ('users', 'computers', 'groups', 'gpos'):
        if not isinstance(data.get(key), list) or any(not isinstance(row, dict) for row in data[key]):
            raise ValidationError(f'Resume checkpoint {key} must be a list of objects')
    required_analysis = {'misconfig_findings': list, 'kerberoasting_targets': list, 'asrep_targets': list,
                         'legacy_os_results': dict, 'acl_security_results': dict}
    for key, expected_type in required_analysis.items():
        if not isinstance(analysis.get(key), expected_type):
            raise ValidationError(f'Resume checkpoint is missing valid {key} analysis results')
    for key in (*CONSOLIDATION_RISK_KEYS, 'misconfig_findings', 'kerberoasting_targets', 'asrep_targets'):
        if key in analysis and (
            not isinstance(analysis[key], list) or any(not isinstance(row, dict) for row in analysis[key])
        ):
            raise ValidationError(f'Resume checkpoint analysis {key} must be a list of objects')
    for parent, key in ((data, 'scan_context'), (analysis, 'analysis_execution'),
                        (payload['scoring'], 'review_center')):
        if parent.get(key) is not None and not isinstance(parent[key], dict):
            raise ValidationError(f'Resume checkpoint {key} must be an object')
    saved_reviews = (payload['scoring'].get('review_center') or {}).get('document')
    if saved_reviews is not None:
        from core.finding_review import validate_review_document
        validate_review_document(saved_reviews, domain)
    execution = analysis.get('analysis_execution') or {}
    completed = execution.get('completed_steps', [])
    if not isinstance(completed, list) or any(not isinstance(key, str) for key in completed):
        raise ValidationError('Resume checkpoint completed_steps must be a list of analysis keys')
    for key in ('skipped_steps', 'partial_steps'):
        if not isinstance(execution.get(key, {}), dict):
            raise ValidationError(f'Resume checkpoint {key} must be an object')
    _restore_snapshot_binary_attributes(data)
    return payload


def main() -> None:
    """AtilKurt — Active Directory Security Health Check Tool."""
    from core.utility_cli import COMMANDS, utility_main
    if len(sys.argv) > 1 and sys.argv[1] in COMMANDS:
        sys.exit(utility_main(sys.argv[1:], resolve_password))
    parser = build_parser()
    args = parser.parse_args()
    validate_cli_arguments(parser, args)

    validate_output_paths(args)
    setup_logging(args)

    print("[*] AtilKurt - Active Directory Security Health Check")
    print("[*] Starting analysis...")

    password_manager: SecurePasswordManager | None = None
    ldap_conn: LDAPConnection | None = None

    try:
        from core.engagement_workflow import prepare_engagement_inputs
        prepare_engagement_inputs(args)
        review_document, removed_edge_ids = load_workflow_inputs(args)
        if args.offline_snapshot:
            generate_offline_report(args, review_document, removed_edge_ids)
            return
        persistence = ProgressPersistence() if args.resume or args.checkpoint or args.incremental else None
        checkpoint_payload = None
        if args.resume:
            checkpoint_payload = load_resume_checkpoint(persistence, args.resume, args.domain)
            if checkpoint_payload is None:
                print('[*] Partial checkpoint validated; running a fresh scan')
        # --- Password -------------------------------------------------------
        password, password_manager = resolve_password(args)

        # --- Stealth mode ----------------------------------------------------
        random_delay = args.random_delay if args.random_delay else (0.0, 0.0)
        rate_limit = args.rate_limit
        if rate_limit is None:
            rate_limit = 0.5 if args.stealth else 0.0
        delay_enabled = bool(
            args.stealth
            or rate_limit > 0
            or (len(random_delay) > 1 and random_delay[1] > 0)
        )
        stealth_settings = {
            "enabled": delay_enabled,
            "rate_limit": rate_limit,
            "random_delay_min": random_delay[0] if len(random_delay) > 0 else 0,
            "random_delay_max": random_delay[1] if len(random_delay) > 1 else 0,
            "min_logging": args.stealth,
        }
        stealth = create_stealth_mode(
            **stealth_settings,
        )
        if args.stealth:
            print(f"[*] Stealth mode enabled ({rate_limit}s minimum delay between LDAP network queries)")
        elif delay_enabled:
            print(f"[*] Rate limiting enabled ({rate_limit}s between LDAP network queries)")
        else:
            print("[*] Rate limiting disabled")

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
        ldap_conn.assessment_scope = args._assessment_scope
        args._active_ldap = ldap_conn

        try:
            ldap_conn.connect()
        except LDAPConnectionError as e:
            print(f"[-] LDAP connection failed: {e}", file=sys.stderr)
            sys.exit(1)

        print("[+] LDAP connection established successfully")
        if not args.scope_file:
            from core.ad_identity import forest_configuration_dn
            configuration_dn = forest_configuration_dn(ldap_conn)
            if configuration_dn:
                args._assessment_scope.metadata_roots.append(configuration_dn)
        if not args.ssl:
            print(
                "[!] LDAP is using port 389 without TLS. Prefer --ssl so credentials "
                "and directory data are not sent in the clear."
            )
        if stealth.enabled:
            ldap_conn.pre_search_hook = stealth.apply_delay

        resumed_from_checkpoint = checkpoint_payload is not None
        if resumed_from_checkpoint:
            data = checkpoint_payload["data"]
            analysis = checkpoint_payload["analysis"]
            scoring = checkpoint_payload["scoring"]
            compliance = checkpoint_payload["compliance"]
            if not args.review_file:
                saved_reviews = (scoring.get('review_center') or {}).get('document')
                if saved_reviews:
                    saved_reviews.setdefault('observations', []).extend(review_document['observations'])
                    review_document = saved_reviews
                    args._workflow_review_document = review_document
            print(f"[+] Loaded full checkpoint: {args.resume}")

        if not resumed_from_checkpoint:
            # --- Data collection ---------------------------------------------
            show_progress = not args.no_progress
            data = collect_data(
                ldap_conn,
                show_progress,
                use_parallel=args.parallel,
                max_workers=args.max_workers,
                stealth_settings=stealth_settings if args.parallel else None,
            )

            incremental_diff = None
            if args.incremental and persistence:
                incremental_diff = calculate_incremental_diff(
                    persistence,
                    args.domain,
                    data,
                    current_checkpoint_id=args.checkpoint,
                )

            # --- Security analysis -------------------------------------------
            analysis = run_security_analysis(
                ldap_conn,
                data,
                analysis_profile=args.analysis_profile,
                skip_analyses=args.skip_analysis,
            )
            if args.verify_effective_access:
                from core.effective_access import collect_effective_tokens
                from analysis.registry import ANALYSIS_STEP_REGISTRY
                initial_risks = [risk for rows in get_consolidated_risk_lists(analysis) for risk in rows]
                analysis['effective_access'] = collect_effective_tokens(ldap_conn, data, initial_risks,
                                                                       limit=args.token_limit, delay=args.token_delay)
                completed = set(analysis['analysis_execution']['completed_steps'])
                runners = {key: runner for key, _, runner in ANALYSIS_STEP_REGISTRY}
                for key in ('acl_security', 'dcsync', 'attack_graph_v2'):
                    if key in completed:
                        analysis.update(runners[key](ldap_conn, {**data, '_analysis_results': analysis}))
            from core.diagnostics import collection_health
            from datetime import timezone
            data['collection_health'] = collection_health(ldap_conn, data)
            data['scan_context'] = {'fresh_ldap': True, 'collected_at': datetime.now(timezone.utc).isoformat(),
                                    'profile': args.analysis_profile}
            apply_package_c_evidence(args, data, analysis)
            if incremental_diff:
                analysis["incremental_diff"] = incremental_diff

            # --- Risk scoring ------------------------------------------------
            scoring = score_and_consolidate(
                analysis, data, domain=args.domain, dc_ip=args.dc_ip, review_document=review_document,
                evidence_max_age_days=args.evidence_max_age_days, removed_edge_ids=removed_edge_ids,
            )

            # --- Compliance & risk management --------------------------------
            compliance = generate_compliance_and_risk(
                ldap_conn, scoring['scored_risks'], data, args.hourly_rate
            )
            data['collection_health'] = collection_health(ldap_conn, data)

            # --- Checkpoint --------------------------------------------------
            checkpoint_id = args.checkpoint
            if args.incremental and persistence and not checkpoint_id:
                checkpoint_id = persistence.create_checkpoint_id(args.domain)
            if checkpoint_id and persistence:
                persistence.save_checkpoint(
                    checkpoint_id,
                    build_checkpoint_payload(args, data, analysis, scoring, compliance),
                )
                print(f"[+] Checkpoint saved: {checkpoint_id}")

        else:
            data['scan_context'] = {**(data.get('scan_context') or {}), 'fresh_ldap': False}
            # A full checkpoint can be enriched with newly supplied offline
            # evidence without repeating LDAP collection and registered analyses.
            apply_package_c_evidence(args, data, analysis)
            scoring = score_and_consolidate(
                analysis, data, domain=args.domain, dc_ip=args.dc_ip, review_document=review_document,
                evidence_max_age_days=args.evidence_max_age_days, removed_edge_ids=removed_edge_ids,
            )
            compliance = generate_compliance_and_risk(
                ldap_conn, scoring['scored_risks'], data, args.hourly_rate
            )

        # --- Reports & export ------------------------------------------------
        generate_reports(args, data, analysis, scoring, compliance, ldap_conn)

        # --- Privilege escalation check --------------------------------------
        if args.check_user:
            check_privilege_escalation(args.check_user, data)

        print("[+] Analysis completed successfully!")

    except ValidationError as e:
        print(f"[-] Validation error: {e}", file=sys.stderr)
        sys.exit(1)
    except AnalysisError as e:
        print(f"[-] Analysis error: {e}", file=sys.stderr)
        sys.exit(1)
    except (LDAPConnectionError, LDAPSearchError) as e:
        print(f"[-] LDAP error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
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
