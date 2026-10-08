"""Localized engagement results in the existing offline report."""

from __future__ import annotations

import json

from reporting.report_sections.product_sections import _escape, _table


class EngagementSectionsMixin:
    def _generate_engagement_sections(self, workspace):
        tr = self.language == 'tr'
        engagement = workspace.get('engagement') or {}
        heading = 'Sızma Testi Çalışma Alanı' if tr else 'Pentest Workspace'

        def card(title, content):
            return f'<section class="card mb-4"><div class="card-body"><h3>{_escape(title)}</h3>{content}</div></section>'

        scope = engagement.get('scope') or {}
        content = card('Kapsam ve bütçe' if tr else 'Scope and budget',
                       f'<p>{_escape(scope.get("coverage", "unspecified"))} · {scope.get("requests", 0)} / {scope.get("max_queries", "—")}</p>'
                       f'<pre class="text-wrap">{_escape(json.dumps(scope.get("definition", {}), ensure_ascii=False))}</pre>')
        if engagement.get('protocols'):
            result = engagement['protocols']
            rows = [[row.get('target'), row.get('check'), row.get('status'),
                     row.get('value', row.get('http_status', '—')), row.get('reason') or row.get('evidence') or '']
                    for row in result.get('checks', [])]
            content += card('Protokol doğrulaması' if tr else 'Protocol verification',
                            _table(['Hedef', 'Kontrol', 'Durum', 'Değer', 'Kanıt'] if tr else ['Target', 'Check', 'Status', 'Value', 'Evidence'], rows, '—')
                            + f'<p>{_escape(result.get("limitation"))}</p>')
        if engagement.get('shared_files'):
            rows = [[result.get('status'), result.get('files_read'), result.get('skipped'), len(result.get('risks', [])),
                     json.dumps(result.get('errors', []), ensure_ascii=False)] for result in engagement['shared_files']]
            content += card('SYSVOL / NETLOGON', _table(['Durum', 'Dosya', 'Atlanan', 'Bulgu', 'Eksik kanıt'] if tr else
                            ['Status', 'Files', 'Skipped', 'Findings', 'Evidence gaps'], rows, '—'))
        if engagement.get('attack_plan'):
            result = engagement['attack_plan']
            rows = [[' → '.join(row.get('labels') or row['nodes']), row['status'], ', '.join(row['relationships']), '; '.join(row['prerequisites'])]
                    for row in result.get('paths', [])]
            content += card('Hedefe yönelik yollar' if tr else 'Goal-directed paths',
                            f'<p>{_escape(result.get("start_label") or result["start"])} → {_escape(result.get("goal_label") or result["goal"])}</p>'
                            + _table(['Yol', 'Durum', 'İlişkiler', 'Önkoşullar'] if tr else ['Path', 'Status', 'Relationships', 'Prerequisites'], rows, '—')
                            + f'<p>{_escape(result.get("limitation"))} · truncated={result.get("truncated", False)}</p>')
        if engagement.get('effective_gpo'):
            result = engagement['effective_gpo']
            rows = [[target['target'], policy['gpo_id'], policy['status'], policy['order'], policy['enforced'], '; '.join(policy['prerequisites'])]
                    for target in result.get('targets', []) for policy in target['policies']]
            content += card('Etkin GPO' if tr else 'Effective GPO',
                            _table(['Hedef', 'GPO', 'Durum', 'Sıra', 'Zorunlu', 'Önkoşullar'] if tr else
                                   ['Target', 'GPO', 'Status', 'Order', 'Enforced', 'Prerequisites'], rows, '—')
                            + f'<p>{_escape(result.get("limitation"))}</p>')
            for target in result.get('targets', []):
                content += f'<p>{_escape(target["target"])}: {_escape(json.dumps(target.get("comparison", {}), ensure_ascii=False))}</p>'
        for key, label in (('bloodhound', 'BloodHound'), ('federation', 'Birleşik grafik' if tr else 'Federated graph')):
            if engagement.get(key):
                content += card(label, f'<pre class="text-wrap">{_escape(json.dumps(engagement[key], ensure_ascii=False, default=str))}</pre>')
        return f'<div class="tab-pane fade" id="pentest-workspace" role="tabpanel" aria-labelledby="pentest-workspace-tab"><h2>{heading}</h2>{content}</div>'
