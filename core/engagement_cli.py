"""CLI declarations and preflight for engagement extensions."""

from __future__ import annotations

from pathlib import Path

from core.exceptions import ValidationError


def _positive(value):
    import argparse
    try:
        number = int(value)
        if number > 0:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError('must be a positive integer')


def add_engagement_arguments(parser):
    section = parser.add_argument_group('Pentest engagement workflows')
    section.add_argument('--scope-file', help='JSON engagement domain/OU/host/service scope and UTC windows')
    section.add_argument('--max-queries', type=_positive, help='Shared network request budget (default: 100000)')
    section.add_argument('--max-scan-seconds', type=_positive, help='Shared network execution time limit (default: 3600)')
    for flag, help_text in (
        ('protocol-target', 'Opt-in SMB signing and verified LDAPS TLS checks for this host'),
        ('adcs-endpoint', 'Opt-in HEAD observation of an HTTP(S) enrollment endpoint; redirects not followed'),
        ('sysvol-dir', 'Read-only offline shared-file directory inspection; values are redacted'),
        ('sysvol-host', 'Opt-in authenticated read-only SYSVOL and NETLOGON inspection on this host'),
        ('bloodhound-import', 'Offline SharpHound/BloodHound JSON or ZIP input (schemas 3..6)'),
        ('federation-snapshot', 'Merge a separately collected domain graph snapshot'),
        ('gpo-target', 'DN of an explicit live GPO applicability target'),
    ):
        section.add_argument('--' + flag, action='append', default=[], help=help_text + '; repeatable')
    section.add_argument('--protocol-evidence', help='Fresh local signing/channel-binding/EPA policy evidence JSON')
    section.add_argument('--gpo-context', help='Offline effective GPO target/container/filter input JSON')
    section.add_argument('--rsop-file', help='gpresult XML; bind target and timestamp in --gpo-context')
    section.add_argument('--plan-start', help='Unique graph node ID, label or SID for attack path start')
    section.add_argument('--plan-goal', help='Unique graph node ID, label or SID for attack path goal')
    section.add_argument('--plan-max-hops', type=_positive, default=8, help='Attack planner hop limit (1..16)')
    section.add_argument('--engagement-export', help='Export engagement checks and attack plan to JSON')
    section.add_argument('--docx-export', help='Write the client delivery report as a real .docx')
    section.add_argument('--pdf-export', help='Write the client delivery report as a real .pdf')
    section.add_argument('--mask-client-report', action='store_true', help='Mask identities in DOCX/PDF shared copies')


def validate_engagement_arguments(parser, args):
    if bool(getattr(args, 'plan_start', None)) != bool(getattr(args, 'plan_goal', None)):
        parser.error('--plan-start and --plan-goal must be supplied together')
    for field, upper in (('plan_max_hops', 16), ('max_queries', 10000000), ('max_scan_seconds', 86400)):
        value = getattr(args, field, None)
        if value is not None and value > upper:
            parser.error(f'--{field.replace("_", "-")} must be <= {upper}')
    for field in ('scope_file', 'protocol_evidence', 'gpo_context', 'rsop_file'):
        value = getattr(args, field, None)
        if value and not Path(value).is_file():
            parser.error(f'--{field.replace("_", "-")} must reference an existing file')
    for field in ('bloodhound_import', 'federation_snapshot'):
        paths = getattr(args, field, [])
        if len(paths) > 20 or any(not Path(path).is_file() for path in paths):
            parser.error(f'--{field.replace("_", "-")} requires at most 20 existing files')
    for field in ('protocol_target', 'sysvol_host', 'gpo_target', 'adcs_endpoint'):
        if len(getattr(args, field, [])) > 100:
            parser.error(f'--{field.replace("_", "-")} is limited to 100 targets')
    from core.validators import validate_server_address
    try:
        for field in ('protocol_target', 'sysvol_host'):
            for host in getattr(args, field, []):
                validate_server_address(host)
        from urllib.parse import urlsplit
        for endpoint in getattr(args, 'adcs_endpoint', []):
            parts = urlsplit(endpoint)
            if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password or parts.fragment or parts.port not in (None, 80, 443):
                raise ValidationError('AD CS endpoints require standard HTTP(S) URLs without credentials/fragments')
            validate_server_address(parts.hostname)
    except (ValidationError, ValueError) as exc:
        parser.error(str(exc))
    for path in getattr(args, 'sysvol_dir', []):
        if not Path(path).is_dir() or Path(path).is_symlink():
            parser.error('--sysvol-dir requires an existing nonsymlink directory')
    if getattr(args, 'offline_snapshot', None) and any(getattr(args, field, []) for field in ('protocol_target', 'adcs_endpoint', 'sysvol_host', 'gpo_target')):
        parser.error('Live service/file/GPO checks cannot be requested with --offline-snapshot')
    for field, extension in (('docx_export', '.docx'), ('pdf_export', '.pdf')):
        if getattr(args, field, None) and Path(getattr(args, field)).suffix.casefold() != extension:
            parser.error(f'--{field.replace("_", "-")} requires a {extension} filename')


def validate_shared_file_outputs(args, outputs):
    for root in getattr(args, 'sysvol_dir', []):
        directory = Path(root).resolve()
        for path in outputs.values():
            if path and directory in Path(path).resolve().parents:
                raise ValidationError('Outputs cannot be written inside an inspected shared-file directory')
