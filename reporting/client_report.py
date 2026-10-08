"""Real, private DOCX/PDF client deliverables with optional identity masking."""

from __future__ import annotations

from copy import deepcopy
from html import escape
import io
import json
import os
from pathlib import Path
import re
import tempfile
import zipfile

from core.exceptions import ExportError

SECRET_FIELDS = r'password|passwd|pwd|cpassword|secret|credential|private.?key|api[_-]?key|(?:access|refresh|auth)[_-]?token|tokenvalue|authorization|connection[_-]?string|ms.?mcs.?admpwd|mslaps.?password'
SECRET_KEYS = re.compile(r'(?i)(?:' + SECRET_FIELDS + r')$')
SECRET_ASSIGNMENT = re.compile(
    r'(?im)(\b(?:' + SECRET_FIELDS + r')\b\s*[=:]\s*)'
    r'''(?:"(?:\\.|[^"\\\r\n])*(?:"|$)|'(?:\\.|[^'\\\r\n])*(?:'|$)|(?:Bearer|Basic)\s+[^\s"';]+|[^\s"';]+)'''
)
IDENTITY_KEY = re.compile(r'(?i)(?:,\s*DC=|^S-1-\d+-|@|(?:[a-z0-9_-]+\.)+[a-z]{2,}|^(?:\d{1,3}\.){3}\d{1,3}$)')


def _sanitize(value):
    if isinstance(value, dict):
        return {key: '[REDACTED]' if SECRET_KEYS.search(str(key)) else _sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, str):
        return SECRET_ASSIGNMENT.sub(r'\1[REDACTED]', value)
    if isinstance(value, bytes):
        return '[BINARY EVIDENCE OMITTED]'
    return value


def client_document(domain, data, risks, workspace, *, masked=False):
    document = _sanitize({'domain': domain, 'scope': data.get('engagement_scope') or {'coverage': 'unspecified'},
                          'context': data.get('scan_context') or {}, 'collection_health': {key: (data.get('collection_health') or {}).get(key)
                          for key in ('status', 'completed_queries', 'failed_queries')},
                          'findings': deepcopy(risks), 'engagement': workspace.get('engagement') or {}})
    if not masked:
        return document
    identities = {str(domain)}
    for kind in ('users', 'computers', 'groups', 'gpos'):
        for row in data.get(kind, []):
            for key in ('sAMAccountName', 'name', 'displayName', 'distinguishedName', 'dNSHostName', 'objectSid', 'mail', 'userPrincipalName'):
                value = row.get(key)
                if isinstance(value, str) and value:
                    identities.add(value)
    for risk in risks:
        for key in ('affected_object', 'target_object', 'trustee'):
            if isinstance(risk.get(key), str) and risk[key]:
                identities.add(risk[key])
    definition = (data.get('engagement_scope') or {}).get('definition') or {}
    for field in ('domains', 'ous', 'metadata_roots', 'hosts', 'computer_hosts', 'excluded_hosts', 'excluded_dns'):
        identities.update(str(value) for value in definition.get(field, []))

    def collect(value, field=''):
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(key, str) and IDENTITY_KEY.search(key):
                    identities.add(key)
                collect(item, key)
        elif isinstance(value, list):
            for item in value:
                collect(item, field)
        elif isinstance(value, str):
            if field in {'domain', 'target', 'host', 'file', 'dn', 'container', 'start', 'goal', 'nodes', 'labels', 'label',
                         'start_label', 'goal_label', 'principal', 'node_id'} and value:
                identities.add(value)
            if field in {'source', 'member'} and ('/' in value or '\\' in value):
                identities.add(value)
            identities.update(re.findall(r'(?<![\w.-])(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}(?![\w.-])', value))

    collect(document)
    # Stable numbering uses sorted identities and preserves relationships within one deliverable.
    identities = sorted(identities, key=lambda value: (value.casefold(), value))
    mapping = {value.casefold(): f'IDENTITY-{index:04d}' for index, value in enumerate(identities, 1)}
    pattern = re.compile('|'.join(re.escape(value) for value in sorted(identities, key=len, reverse=True)), re.I) if identities else None

    def mask(value):
        if isinstance(value, dict):
            return {mask(key) if isinstance(key, str) and IDENTITY_KEY.search(key) else key: mask(item)
                    for key, item in value.items()}
        if isinstance(value, list):
            return [mask(item) for item in value]
        if isinstance(value, str) and pattern:
            value = pattern.sub(lambda match: mapping[match.group().casefold()], value)
            value = re.sub(r'S-1-\d+(?:-\d+){2,}', '[SID]', value, flags=re.I)
            value = re.sub(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', '[IP]', value)
            value = re.sub(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', '[EMAIL]', value)
        return value

    document = mask(document)
    document['masked'] = True
    return document


def _paragraphs(document, language):
    tr = language == 'tr'
    labels = {'title': 'Sızma Testi Değerlendirme Raporu' if tr else 'Pentest Assessment Report',
              'scope': 'Kapsam ve Sınırlamalar' if tr else 'Scope and Limitations',
              'findings': 'Bulgular' if tr else 'Findings', 'evidence': 'Kanıt' if tr else 'Evidence',
              'reproduction': 'Doğrulama Adımları' if tr else 'Reproduction / Verification',
              'impact': 'Etki' if tr else 'Impact', 'remediation': 'Düzeltme' if tr else 'Remediation'}
    paragraphs = [(1, labels['title']), (0, document['domain']), (1, labels['scope']),
                  (0, json.dumps(document['scope'], ensure_ascii=False, default=str)),
                  (0, json.dumps(document['context'], ensure_ascii=False, default=str)),
                  (0, 'Kısmi ve bilinmeyen sonuçlar riskin giderildiğini kanıtlamaz.' if tr else 'Partial or unknown results do not prove absence or remediation.'),
                  (1, labels['findings'])]
    for finding in document['findings']:
        paragraphs.extend([(2, str(finding.get('title') or finding.get('type') or 'Finding')),
                           (0, f"ID: {finding.get('finding_id', '—')} | {finding.get('severity', 'unknown')} | {finding.get('affected_object', '')}"),
                           (0, str(finding.get('description') or '')),
                           (2, labels['evidence']), (0, json.dumps(finding.get('evidence') or finding.get('review_basis') or {}, ensure_ascii=False, default=str)),
                           (2, labels['reproduction']), (0, str(finding.get('validation_steps') or finding.get('verification_steps') or
                            ('Hedef yapılandırmayı salt okunur yöntemlerle kontrol edin ve yerel önkoşulları doğrulayın.' if tr else 'Read the affected configuration and verify local prerequisites using the recorded evidence and source.'))),
                           (2, labels['impact']), (0, str(finding.get('impact') or '')),
                           (2, labels['remediation']), (0, str(finding.get('mitigation') or finding.get('recommendation') or ''))])
    for key, value in document['engagement'].items():
        paragraphs.extend([(1, key.replace('_', ' ').title()), (0, json.dumps(value, ensure_ascii=False, default=str))])
    return paragraphs


def _atomic_bytes(path, payload):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.atilkurt-report-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def export_client_report(path, document, *, language='en'):
    paragraphs = _paragraphs(document, language)
    suffix = Path(path).suffix.casefold()
    payload = io.BytesIO()
    if suffix == '.docx':
        parts = []
        for level, value in paragraphs:
            value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str(value))
            style = f'<w:pPr><w:pStyle w:val="Heading{level}"/></w:pPr>' if level else ''
            parts.append(f'<w:p>{style}<w:r><w:t xml:space="preserve">{escape(value)}</w:t></w:r></w:p>')
        with zipfile.ZipFile(payload, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>')
            archive.writestr('_rels/.rels', '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
            archive.writestr('word/_rels/document.xml.rels', '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
            archive.writestr('word/styles.xml', '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="Heading 1"/><w:rPr><w:b/><w:sz w:val="32"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="Heading 2"/><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style></w:styles>')
            archive.writestr('word/document.xml', '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' + ''.join(parts) + '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134"/></w:sectPr></w:body></w:document>')
    elif suffix == '.pdf':
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
        import reportlab

        font = Path(__file__).parent / 'vendor' / 'fonts' / 'DejaVuSans.ttf'
        if not font.is_file():
            font = Path(reportlab.__file__).parent / 'fonts' / 'Vera.ttf'
        pdfmetrics.registerFont(TTFont('AtilKurtReport', str(font)))
        styles = getSampleStyleSheet()
        for name in ('BodyText', 'Heading1', 'Heading2'):
            styles[name].fontName = 'AtilKurtReport'
            styles[name].wordWrap = 'CJK'
        story = []
        for level, value in paragraphs:
            style = styles['Heading' + str(level)] if level else styles['BodyText']
            text = str(value)
            for offset in range(0, max(1, len(text)), 4000):
                story += [Paragraph(escape(text[offset:offset + 4000]).replace('\n', '<br/>'), style), Spacer(1, 8)]
        SimpleDocTemplate(payload, title='AtilKurt Assessment', author='AtilKurt').build(story)
    else:
        raise ExportError('Client reports require .docx or .pdf extensions')
    _atomic_bytes(path, payload.getvalue())
