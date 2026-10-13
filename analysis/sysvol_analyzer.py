"""Read-only, bounded SYSVOL/NETLOGON inspection without secret recovery."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import xml.etree.ElementTree as ET

from core.exceptions import ValidationError

MAX_FILES = 1000
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
EXTENSIONS = {'.xml', '.ps1', '.bat', '.cmd', '.vbs', '.ini', '.inf', '.config', '.json', '.txt'}
SECRET = re.compile(r'''(?im)\b(password|passwd|pwd|secret|api[_-]?key|connectionstring)\b\s*[=:]\s*["']?([^\r\n"';]{4,})''')
PLACEHOLDER = re.compile(r'(?i)^(?:\$|%|\{|<|change.?me|example|placeholder|redacted|none|null|false|true)')


def _inspect(content, location, *, redact_secrets=True):
    if b'\x00' in content[:100]:
        encoding = 'utf-16' if content.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-16-le'
        text = content.decode(encoding, errors='replace')
    else:
        text = content.decode('utf-8-sig', errors='replace')
    records = []
    if Path(location).suffix.casefold() == '.xml':
        if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
            raise ValidationError('SYSVOL XML entities/DTDs are unsupported')
        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise ValidationError('SYSVOL XML is malformed') from exc
        for element in root.iter():
            for name, value in element.attrib.items():
                if name.split('}')[-1].casefold() == 'cpassword' and value.strip():
                    records.append({'type': 'sysvol_gpp_cpassword', 'title': 'GPP password ciphertext exposed in policy file',
                                    'severity': 'High', 'requires_validation': False, 'line': None,
                                    'evidence': 'Nonempty cpassword attribute observed; value redacted and not decrypted.'})
                    if not redact_secrets:
                        records[-1].update(secret_value=value, evidence='cpassword = ' + json.dumps(value))
    for match in SECRET.finditer(text):
        candidate = match.group(2).strip()
        if PLACEHOLDER.match(candidate) or len(candidate) < 4:
            continue
        records.append({'type': 'sysvol_suspected_secret', 'title': 'Suspected hardcoded secret in shared script/configuration',
                        'severity': 'Medium', 'requires_validation': True, 'line': text.count('\n', 0, match.start()) + 1,
                        'evidence': f'{match.group(1)} assignment found; value redacted. Confirm context locally.'})
        if not redact_secrets:
            records[-1].update(secret_value=candidate, evidence=f'{match.group(1)} = ' + json.dumps(candidate))
    for record in records:
        record.update({'affected_object': location, 'source': 'sysvol_read_only',
                       'description': record['evidence'], 'recommendation': 'Remove stored credentials and rotate the affected secret after confirming ownership.',
                       'file_sha256': hashlib.sha256(content).hexdigest()})
    return records


class SharedFileInspection:
    def __init__(self, *, redact_secrets=True):
        self.redact_secrets = redact_secrets
        self.risks = []
        self.errors = []
        self.files = 0
        self.total_bytes = 0
        self.skipped = 0

    def inspect(self, content, location):
        if len(content) > MAX_FILE_BYTES or self.files >= MAX_FILES or self.total_bytes + len(content) > MAX_TOTAL_BYTES:
            raise ValidationError('Shared-file inspection budget exhausted')
        self.files += 1
        self.total_bytes += len(content)
        try:
            self.risks.extend(_inspect(content, location, redact_secrets=self.redact_secrets))
        except ValidationError as exc:
            self.errors.append({'file': location, 'reason': str(exc)})

    def result(self):
        return {'schema_version': 1, 'risks': self.risks, 'files_read': self.files, 'bytes_read': self.total_bytes,
                'skipped': self.skipped, 'errors': self.errors, 'status': 'partial' if self.errors or self.skipped else 'completed',
                'limitation': 'Only supported text files are inspected; ciphertext is not decrypted. Secret candidates require contextual confirmation.',
                'secrets_redacted': self.redact_secrets}


def inspect_local_shared_files(roots, *, redact_secrets=True):
    inspection = SharedFileInspection(redact_secrets=redact_secrets)
    for root_value in roots:
        root = Path(root_value)
        if not root.is_dir() or root.is_symlink():
            raise ValidationError('Shared-file root must be an existing nonsymlink directory')
        root = root.resolve()
        stack = [(root, 0)]
        visited = 0
        while stack:
            directory, depth = stack.pop()
            try:
                for path in directory.iterdir():
                    visited += 1
                    if visited > MAX_FILES * 10:
                        raise ValidationError('Shared-file directory entry budget exhausted')
                    if path.is_symlink():
                        inspection.skipped += 1
                    elif path.is_dir():
                        if depth < 10:
                            stack.append((path, depth + 1))
                        else:
                            inspection.skipped += 1
                    elif path.suffix.casefold() in EXTENSIONS and path.is_file():
                        size = path.stat().st_size
                        if size > MAX_FILE_BYTES:
                            inspection.skipped += 1
                            continue
                        if inspection.files >= MAX_FILES or inspection.total_bytes + size > MAX_TOTAL_BYTES:
                            raise ValidationError('Shared-file inspection budget exhausted before read')
                        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                        with os.fdopen(descriptor, 'rb') as stream:
                            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                                raise ValidationError('Shared-file input is not a regular file')
                            content = stream.read(MAX_FILE_BYTES + 1)
                        inspection.inspect(content, str(path.relative_to(root)))
            except (OSError, ValidationError) as exc:
                inspection.errors.append({'file': str(directory.relative_to(root)), 'reason': str(exc)})
                if isinstance(exc, ValidationError):
                    return inspection.result()
    return inspection.result()


def inspect_remote_shared_files(host, username, password, domain, scope, *, timeout=15, connection_factory=None, redact_secrets=True):
    if connection_factory is None:
        from impacket.smbconnection import SMBConnection
        connection_factory = SMBConnection
    inspection, connection = SharedFileInspection(redact_secrets=redact_secrets), None
    try:
        scope.consume(host, 'smb')
        connection = connection_factory(host, host, sess_port=445, timeout=timeout)
        scope.consume(host, 'smb')
        connection.login(username.split('\\')[-1].split('@')[0], password, domain)
        visited = 0
        for share in ('SYSVOL', 'NETLOGON'):
            stack = [('', 0)]
            while stack:
                directory, depth = stack.pop()
                scope.consume(host, 'smb')
                for entry in connection.listPath(share, directory + '\\*'):
                    name = entry.get_longname()
                    if name in ('.', '..'):
                        continue
                    visited += 1
                    if visited > MAX_FILES * 10:
                        raise ValidationError('Remote directory entry budget exhausted')
                    if any(character in name for character in ('/', '\\', '\x00')):
                        raise ValidationError('Unsafe remote shared-file name')
                    location = directory + '\\' + name if directory else name
                    # Reparse points/DFS referrals are never followed to other servers.
                    if entry.get_attributes() & 0x400:
                        inspection.skipped += 1
                        continue
                    if entry.is_directory():
                        if depth < 10:
                            stack.append((location, depth + 1))
                        else:
                            inspection.skipped += 1
                    elif Path(name).suffix.casefold() in EXTENSIONS:
                        file_size = entry.get_filesize()
                        if file_size > MAX_FILE_BYTES:
                            inspection.skipped += 1
                            continue
                        if inspection.files >= MAX_FILES or inspection.total_bytes + file_size > MAX_TOTAL_BYTES:
                            raise ValidationError('Remote file inspection budget exhausted before read')
                        chunks, size = [], [0]
                        remaining = min(MAX_FILE_BYTES, MAX_TOTAL_BYTES - inspection.total_bytes)

                        def receive(chunk, size=size, chunks=chunks, remaining=remaining):
                            size[0] += len(chunk)
                            if size[0] > remaining:
                                raise ValidationError('Remote file exceeds read limit')
                            chunks.append(chunk)

                        scope.consume(host, 'smb')
                        connection.getFile(share, location, receive)
                        inspection.inspect(b''.join(chunks), f'//{host}/{share}/{location}')
    except Exception as exc:
        inspection.errors.append({'file': f'//{host}', 'reason': str(exc)[:300]})
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception as exc:
                inspection.errors.append({'file': f'//{host}', 'reason': f'Connection cleanup failed: {str(exc)[:200]}'})
    return inspection.result()
