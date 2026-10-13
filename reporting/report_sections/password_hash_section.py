"""Current key material, provenance and incomplete collection in one report tab."""

import json

from reporting.report_sections.product_sections import _escape


def _shown_digest(value, empty_marker):
    if not value:
        return '—'
    if value == empty_marker:
        return value + ' (empty placeholder)'
    return value


def _history_text(record):
    entries = record.get('nt_history') or []
    if not entries:
        return '—'
    return ', '.join(f"{entry.get('index')}: {entry.get('ntlm')}" for entry in entries)


def _lm_ntlm_pair(record):
    """Pwdump order so the NTLM digest stays visible next to LM."""
    lm, ntlm = record.get('lm'), record.get('ntlm')
    if not lm and not ntlm:
        return '—'
    return f'{lm or "—"}:{ntlm or "—"}'


def _export_rows(records):
    rows = []
    for record in records:
        rows.append({
            'account': record.get('account') or '',
            'sid': record.get('sid') or '',
            'status': record.get('status') or '',
            'ntlm': record.get('ntlm') or '',
            'lm': record.get('lm') or '',
            'pair': _lm_ntlm_pair(record),
            'history': _history_text(record) if record.get('nt_history') else '',
            'kerberos': '\n'.join(
                f"{key.get('algorithm')}: {key.get('kerberos_key')}" for key in record.get('kerberos_keys') or []),
            'gaps': json.dumps(record.get('errors') or [], ensure_ascii=False),
        })
    return rows


def _fitted_table(records, language):
    """Account, NTLM and LM stay inside the page; the rest wraps in a detail row."""
    tr = language == 'tr'
    headers = ['Hesap', 'NTLM', 'LM', 'Durum'] if tr else ['Account', 'NTLM', 'LM', 'Status']
    detail_label = 'Ayrıntı' if tr else 'Details'
    head = ''.join(f'<th>{_escape(header)}</th>' for header in headers)
    body = []
    for record in records:
        kerberos = '\n'.join(
            f"{key.get('algorithm')}: {key.get('kerberos_key')}" for key in record.get('kerberos_keys') or []) or '—'
        detail = (
            f"SID: {_escape(record.get('sid') or '—')}\n"
            f"LM:NTLM: {_escape(_lm_ntlm_pair(record))}\n"
            f"{'NT geçmişi' if tr else 'NT history'}: {_escape(_history_text(record))}\n"
            f"{'Kerberos anahtarları' if tr else 'Kerberos keys'}: {_escape(kerberos)}\n"
            f"{'Eksik kanıt' if tr else 'Evidence gaps'}: {_escape(json.dumps(record.get('errors') or [], ensure_ascii=False))}"
        )
        body.append(
            '<tr>'
            f'<td>{_escape(record.get("account") or "—")}</td>'
            f'<td>{_escape(_shown_digest(record.get("ntlm"), "31d6cfe0d16ae931b73c59d7e0c089c0"))}</td>'
            f'<td>{_escape(_shown_digest(record.get("lm"), "aad3b435b51404eeaad3b435b51404ee"))}</td>'
            f'<td>{_escape(record.get("status") or "—")}</td>'
            '</tr>'
            f'<tr><td colspan="4"><details><summary>{detail_label}</summary>'
            f'<pre class="hash-detail">{detail}</pre></details></td></tr>'
        )
    if not body:
        empty = 'Kayıt yok.' if tr else 'No records.'
        body.append(f'<tr><td colspan="4">{empty}</td></tr>')
    return (
        '<table class="table table-dark table-hover hash-fit" id="passwordHashesTable">'
        '<colgroup><col class="account"><col class="ntlm"><col class="lm"><col class="status"></colgroup>'
        f'<thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table>'
    )


def password_hash_section(result, language='en'):
    tr = language == 'tr'
    title = 'Parola Özetleri' if tr else 'Password Hashes'
    if not result:
        content = '<p>' + ('Toplama istenmedi. Yeni taramada --collect-password-hashes kullanın.' if tr else
                           'Collection was not requested. Use --collect-password-hashes on a fresh scan.') + '</p>'
    else:
        summary = result.get('summary') or {}
        content = (
            f'<p><strong>{_escape(result.get("status"))}</strong> · DRSUAPI · {_escape(result.get("target"))}'
            f' · {_escape(result.get("collected_at"))}</p>'
            '<p>' + ('Kapsamdaki hesapların güncel NTLM/LM özetleri, NT parola geçmişi ve mevcut Kerberos uzun süreli anahtarları. '
                      'Yerel SAM/LSA, silinmiş nesneler ve bilet yanıtları bu toplamada yoktur. '
                      'Boş özet yer tutucuları, parolanın boş olduğunu kanıtlamaz. '
                      'Toplama LDAP TLS ayarından bağımsız SMB/RPC kullanır.' if tr else
                      result.get('limitation', '') + ' Collection uses SMB/RPC independently of LDAP TLS settings.') + '</p>'
        )
        authorization = result.get('authorization') or {}
        if authorization.get('status') == 'not_authorized':
            content += '<p>' + ('Değerlendirme hesabının domain kökünde hem DS-Replication-Get-Changes hem de '
                                'DS-Replication-Get-Changes-All hakkı yok. Hiçbir hesap için özet istenmedi. '
                                'Bu bir yetki boşluğudur; hesapların parolasız olduğunu göstermez.' if tr else
                                'The assessment account is not granted both DS-Replication-Get-Changes and '
                                'DS-Replication-Get-Changes-All on the domain root. No account hashes were requested. '
                                'This is an authorization gap and does not show that accounts have no password.') + '</p>'
        elif authorization.get('status') == 'unknown':
            content += '<p>' + ('Replikasyon yetkisi doğrulanamadı; toplama yine de denendi.' if tr else
                                'Replication authorization could not be verified; collection was still attempted.') + '</p>'
        labels = [('requested', 'Kapsamdaki hesap' if tr else 'Inventory accounts'),
                  ('attempted', 'Denenen' if tr else 'Attempted'),
                  ('collected', 'NTLM alınan' if tr else 'NTLM returned'),
                  ('failed', 'Eksik / başarısız' if tr else 'Incomplete / failed'),
                  ('not_attempted', 'Denenmeyen' if tr else 'Not attempted'),
                  ('kerberos_keys', 'Kerberos anahtarı' if tr else 'Kerberos keys'),
                  ('password_history', 'Parola geçmişi özeti' if tr else 'Password-history digests')]
        content += '<div class="row g-2 mb-4">' + ''.join(
            f'<div class="col"><div class="card card-body"><span>{label}</span><strong>{_escape(summary.get(key, "—"))}</strong></div></div>'
            for key, label in labels) + '</div>'
        export_headers = (['Hesap', 'SID', 'Durum', 'NTLM', 'LM', 'LM:NTLM', 'NT geçmişi', 'Kerberos anahtarları', 'Eksik kanıt'] if tr else
                          ['Account', 'SID', 'Status', 'NTLM', 'LM', 'LM:NTLM', 'NT history', 'Kerberos keys', 'Evidence gaps'])
        payload = json.dumps({'headers': export_headers, 'rows': _export_rows(result.get('records') or [])},
                             ensure_ascii=True).replace('<', '\\u003c')
        content += (
            '<div class="d-flex justify-content-end mb-2">'
            '<button type="button" class="btn btn-sm btn-success" onclick="exportPasswordHashes()">'
            '<i class="fas fa-file-excel"></i> ' + ('Excel\'e Aktar' if tr else 'Export to Excel') + '</button></div>'
            + _fitted_table(result.get('records') or [], language)
            + '<script>window.passwordHashExport=' + payload + ';'
            'function exportPasswordHashes(){var data=window.passwordHashExport||{headers:[],rows:[]};'
            'var keys=["account","sid","status","ntlm","lm","pair","history","kerberos","gaps"];'
            'function cell(value){var text=value==null?"":String(value);if("=+-@".indexOf(text.charAt(0))>=0){text="\'"+text;}'
            'return \'"\'+text.replace(/"/g,\'""\')+\'"\';}'
            'var lines=[data.headers.map(cell).join(",")];'
            'data.rows.forEach(function(row){lines.push(keys.map(function(key){return cell(row[key]);}).join(","));});'
            'var blob=new Blob(["\\ufeff"+lines.join("\\r\\n")],{type:"text/csv;charset=utf-8;"});'
            'var link=document.createElement("a");var url=URL.createObjectURL(blob);'
            'link.href=url;link.download="AtilKurt_Password_Hashes.csv";'
            'document.body.appendChild(link);link.click();document.body.removeChild(link);URL.revokeObjectURL(url);}'
            '</script>'
        )
        if result.get('errors'):
            content += f'<pre class="text-wrap">{_escape(json.dumps(result["errors"], ensure_ascii=False))}</pre>'
        if result.get('error_summary'):
            content += f'<pre class="text-wrap">{_escape(json.dumps(result["error_summary"], ensure_ascii=False))}</pre>'
        if any(row.get('code') == 8439 for row in result.get('error_summary', [])):
            content += '<p>' + ('8439: DC, replikasyon hedefini çözemedi. Bu kod tek başına nesnenin yokluğunu veya yetki reddini kanıtlamaz. '
                                'Hedef DC, nesne kimliği ve hesabın replikasyon yetkileri doğrulanmalıdır.' if tr else
                                '8439: The DC could not resolve the replication target. This code alone does not prove object absence or access denial. '
                                'Verify the target DC, object identity and account replication permissions.') + '</p>'
    return (f'<div class="tab-pane fade" id="password-hashes" role="tabpanel" aria-labelledby="password-hashes-tab">'
            '<style>'
            '#password-hashes .hash-fit{width:100%;table-layout:fixed}'
            '#password-hashes .hash-fit .account{width:18%}'
            '#password-hashes .hash-fit .ntlm,#password-hashes .hash-fit .lm{width:34%}'
            '#password-hashes .hash-fit .status{width:14%}'
            '#password-hashes .hash-fit th,#password-hashes .hash-fit td{word-break:break-word;overflow-wrap:anywhere;vertical-align:top}'
            '#password-hashes .hash-fit td:nth-child(2),#password-hashes .hash-fit td:nth-child(3){font-family:ui-monospace,monospace}'
            '#password-hashes .hash-detail{white-space:pre-wrap;word-break:break-all;margin:0.5rem 0 0}'
            '</style>'
            f'<h2>{title}</h2><div class="card"><div class="card-body">{content}</div></div></div>')
