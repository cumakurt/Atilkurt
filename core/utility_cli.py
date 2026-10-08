"""Standalone diagnostics, quality, signing, auditing and recurring assessments."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from core.exceptions import AtilKurtException, ValidationError
from core.evidence_signing import generate_keys, read_json, sign_document, unwrap_document, write_document

COMMANDS = {"doctor", "quality", "keygen", "sign", "verify", "audit", "watch", "verify-finding"}


def _positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def utility_main(argv: list[str], password_resolver) -> int:
    parser = argparse.ArgumentParser(prog="Atilkurt", description="AtilKurt operational commands")
    subparsers = parser.add_subparsers(dest="command", required=True)
    doctor = subparsers.add_parser("doctor", help="Check installation and optional LDAP connectivity")
    doctor.add_argument("-d", "--domain")
    doctor.add_argument("-u", "--username")
    doctor.add_argument("--dc-ip")
    doctor.add_argument("--ssl", action=argparse.BooleanOptionalAction, default=True)
    doctor.add_argument("--timeout", type=_positive, default=10)
    doctor.add_argument("--output")
    doctor.set_defaults(password=None)
    focused = subparsers.add_parser('verify-finding', help='Recheck selected finding configurations with targeted LDAP BASE reads')
    focused.add_argument('-d', '--domain', required=True)
    focused.add_argument('-u', '--username', required=True)
    focused.add_argument('--dc-ip')
    focused.add_argument('--ssl', action=argparse.BooleanOptionalAction, default=True)
    focused.add_argument('--snapshot', required=True)
    focused.add_argument('--finding', action='append', required=True)
    focused.add_argument('--scope-file')
    focused.add_argument('--max-queries', type=_positive, default=100)
    focused.add_argument('--timeout', type=_positive, default=15)
    focused.add_argument('--trusted-key', action='append', default=[])
    focused.add_argument('--require-signed-evidence', action='store_true')
    focused.add_argument('--output', required=True)
    focused.set_defaults(password=None)
    quality = subparsers.add_parser("quality", help="Evaluate labelled offline rule fixtures")
    quality.add_argument("--dataset")
    quality.add_argument("--output")
    keys = subparsers.add_parser("keygen", help="Create a private/public evidence signing key pair")
    keys.add_argument("--private-key", required=True)
    keys.add_argument("--public-key", required=True)
    signing = subparsers.add_parser("sign", help="Sign an evidence, review or audit JSON document")
    signing.add_argument("--input", required=True)
    signing.add_argument("--output", required=True)
    signing.add_argument("--signing-key", required=True)
    verifying = subparsers.add_parser("verify", help="Verify a signed document using explicit trusted keys")
    verifying.add_argument("--input", required=True)
    verifying.add_argument("--trusted-key", action="append", required=True)
    verifying.add_argument("--output")
    audit = subparsers.add_parser("audit", help="Verify and export the local audit chain")
    audit.add_argument("--history-db", required=True)
    audit.add_argument("--output")
    audit.add_argument("--signing-key")
    watch = subparsers.add_parser("watch", help="Run repeated fresh scans with deduplicated local notifications")
    watch.add_argument("--interval", type=_positive, default=3600, help="Seconds between scans (minimum 60)")
    watch.add_argument("--runs", type=int, default=0, help="Number of scans; 0 runs until Ctrl+C")
    watch.add_argument("--scan-timeout", type=_positive, default=3600)
    watch.add_argument("--history-db", default=".atilkurt_history.sqlite3")
    args, remaining = parser.parse_known_args(argv)
    if remaining and args.command != "watch":
        parser.error("unrecognized arguments: " + " ".join(remaining))
    try:
        if args.command != 'watch':
            from core.validators import validate_distinct_paths
            outputs = {name: getattr(args, name, None) for name in ('output', 'private_key', 'public_key')}
            inputs = {name: getattr(args, name, None) for name in ('input', 'dataset', 'signing_key', 'history_db', 'snapshot', 'scope_file')}
            inputs.update({f'trusted_key[{index}]': path for index, path in enumerate(getattr(args, 'trusted_key', []))})
            validate_distinct_paths(outputs, inputs)
        if args.command == 'verify-finding':
            if args.timeout > 300 or args.max_queries > 10000:
                parser.error('Focused verification requires timeout <=300 and max queries <=10000')
            from analysis.focused_verifier import validate_selected_findings, verify_selected_findings
            from core.assessment_scope import AssessmentScope
            from core.ldap_connection import LDAPConnection
            from core.validators import validate_domain, validate_server_address
            domain = validate_domain(args.domain)
            host = validate_server_address(args.dc_ip or domain)
            previous, _ = unwrap_document(read_json(args.snapshot), args.trusted_key, args.require_signed_evidence)
            scope = AssessmentScope(domain, read_json(args.scope_file) if args.scope_file else None,
                                    max_queries=args.max_queries, max_seconds=600)
            scope.check_host(host, 'ldaps' if args.ssl else 'ldap')
            validate_selected_findings(previous, domain, args.finding)
            connection, manager = None, None
            try:
                password, manager = password_resolver(args)
                connection = LDAPConnection(domain, args.username, password, host, use_ssl=args.ssl,
                                            timeout=args.timeout, max_retries=1, enable_cache=False)
                connection.assessment_scope = scope
                connection.connect()
                result = verify_selected_findings(connection, previous, args.finding)
                result['scope'] = scope.snapshot()
                write_document(args.output, result)
                print(f"[+] Focused verification saved: {args.output} ({result['objects_read']} objects read)")
                return 0
            finally:
                if connection:
                    connection.disconnect()
                if manager:
                    manager.clear_password()
        if args.command == "doctor":
            if args.timeout > 300 or args.username and not args.domain:
                parser.error("Use a timeout of at most 300 seconds and provide a domain when binding")
            from core.diagnostics import run_doctor
            from core.validators import validate_domain, validate_server_address

            if args.domain:
                args.domain = validate_domain(args.domain)
            if args.dc_ip:
                args.dc_ip = validate_server_address(args.dc_ip)
            connection, secret_manager = None, None
            try:
                if args.username:
                    from core.ldap_connection import LDAPConnection

                    password, secret_manager = password_resolver(args)
                    connection = LDAPConnection(
                        args.domain,
                        args.username,
                        password,
                        args.dc_ip or args.domain,
                        use_ssl=args.ssl,
                        timeout=args.timeout,
                        max_retries=1,
                        enable_cache=False,
                    )
                    connection.connect()
                result = run_doctor(args.domain, args.dc_ip, use_ssl=args.ssl, timeout=args.timeout, ldap=connection)
            finally:
                if connection:
                    connection.disconnect()
                if secret_manager:
                    secret_manager.clear_password()
            if args.output:
                write_document(args.output, result)
            for check in result["checks"]:
                print(f"[{check['status']}] {check['name']}: {check['detail']}")
            return int(result["summary"]["fail"] > 0)
        if args.command == "quality":
            from analysis.rule_quality import evaluate_quality

            dataset = read_json(args.dataset) if args.dataset else None
            if dataset is not None and (
                dataset.get("schema_version") != 1 or not isinstance(dataset.get("cases"), list)
            ):
                raise ValidationError("Quality dataset requires schema_version 1")
            result = evaluate_quality(dataset.get("cases") if dataset else None)
            if args.output:
                write_document(args.output, result)
            print(f"[+] Quality fixtures: {result['summary']['passed']}/{result['summary']['cases']} passed.")
            print("[*] These results measure the supplied fixtures, not production false-positive rates.")
            return int(result["summary"]["failed"] > 0)
        if args.command == "keygen":
            identifier = generate_keys(args.private_key, args.public_key)
            print(f"[+] Signing key pair created. Public key ID: {identifier}")
        elif args.command == "sign":
            result = sign_document(read_json(args.input), args.signing_key)
            write_document(args.output, result)
            print(f"[+] Signed document saved: {args.output}")
        elif args.command == "verify":
            result, verification = unwrap_document(read_json(args.input), args.trusted_key, require_signed=True)
            if args.output:
                write_document(args.output, result)
            print(f"[+] Signature verified: {verification['key_id']}")
        elif args.command == "audit":
            from core.assessment_history import AssessmentHistory

            if not Path(args.history_db).is_file():
                raise ValidationError("Audit requires an existing history database")
            with AssessmentHistory(args.history_db) as history:
                result = history.audit_document()
            if args.output:
                write_document(args.output, result, args.signing_key)
            print(f"[+] Audit chain verified: {len(result['entries'])} entries, head {result['chain_head']}")
        elif args.command == "watch":
            if args.interval < 60 or args.runs < 0 or args.runs > 100000 or args.scan_timeout > 86400:
                parser.error("Watch requires interval >=60, runs 0..100000 and scan timeout <=86400")
            if any(
                option.split("=", 1)[0] in ("--resume", "--offline-snapshot", "--password", "-p")
                or option.startswith("-p")
                and not option.startswith("--")
                for option in remaining
            ):
                parser.error("Watch requires fresh scans and credentials supplied through ATILKURT_PASS")
            from AtilKurt import build_parser
            scan_args = build_parser().parse_args(remaining)
            if scan_args.resume or scan_args.offline_snapshot or scan_args.password is not None:
                parser.error("Watch requires fresh scans and credentials supplied through ATILKURT_PASS")
            return run_watch(remaining, args.history_db, args.interval, args.runs, args.scan_timeout)
        return 0
    except (AtilKurtException, OSError, ValueError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


def run_watch(scan_arguments: list[str], database: str, interval: int, runs: int, timeout: int) -> int:
    from AtilKurt import build_parser, validate_cli_arguments, validate_output_paths
    scan_parser = build_parser()
    parsed_scan = scan_parser.parse_args([
        *scan_arguments, '--history-db', database,
        '--notifications-export', str(Path(database).with_suffix('.notifications.json')),
    ])
    if parsed_scan.resume or parsed_scan.offline_snapshot or parsed_scan.password is not None:
        raise ValidationError('Watch requires fresh scans and credentials supplied through ATILKURT_PASS')
    validate_cli_arguments(scan_parser, parsed_scan)
    validate_output_paths(parsed_scan)
    # Resolve once before starting the loop; normal scans validate the rest of
    # the CLI. Secret material is never written to the history or notification file.
    secret = os.environ.pop("ATILKURT_PASS", None)
    if not secret:
        raise ValidationError("Recurring scans require ATILKURT_PASS from a protected environment")
    notification_path = str(Path(database).with_suffix(".notifications.json"))
    command = [
        sys.executable,
        str(Path(__file__).resolve().parents[1] / "AtilKurt.py"),
        *scan_arguments,
        "--history-db",
        database,
        "--notifications-export",
        notification_path,
        "--no-progress",
    ]
    environment = dict(os.environ, ATILKURT_PASS=secret)
    trusted_keys = [*parsed_scan.trusted_key]
    if parsed_scan.signing_key:
        trusted_keys.append(parsed_scan.signing_key)
    print(f"[*] Watching at {interval}-second intervals. Press Ctrl+C to stop.")
    completed, last_status = 0, 0
    try:
        while runs == 0 or completed < runs:
            started = time.monotonic()
            with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as output:
                try:
                    result = subprocess.run(command, env=environment, stdout=output, stderr=output, timeout=timeout)
                    last_status = result.returncode
                    if last_status:
                        print(
                            "[-] Recurring scan failed; no success or closure was recorded. Run the scan directly for diagnostics.",
                            file=sys.stderr,
                        )
                    elif Path(notification_path).is_file():
                        document, _ = unwrap_document(read_json(notification_path), trusted_keys)
                        notifications = document.get("notifications") or []
                        if notifications:
                            print(f"[+] Important changes: {len(notifications)}. Details: {notification_path}")
                except subprocess.TimeoutExpired:
                    last_status = 1
                    print("[-] Recurring scan exceeded its time limit.", file=sys.stderr)
            completed += 1
            if runs and completed >= runs:
                break
            remaining = interval - (time.monotonic() - started)
            while remaining > 0:
                pause = min(60, remaining)
                time.sleep(pause)
                remaining -= pause
    except KeyboardInterrupt:
        return 0
    finally:
        environment.pop("ATILKURT_PASS", None)
    return last_status
