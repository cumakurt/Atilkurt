"""Accuracy, evidence health, remediation, history and work-item report panes."""

from __future__ import annotations

import html
from pathlib import Path

from reporting.html_safety import json_for_html_script

LABELS = {
    "en": {
        "accuracy": "Accuracy & Evidence",
        "operations": "Remediation Operations",
        "quality": "Rule quality",
        "quality_note": "Metrics describe labelled offline scenarios, not production false-positive rates. Unrepresented rules are not measured.",
        "cases": "Scenarios",
        "family": "Rule family",
        "tp": "True positives",
        "fp": "False positives",
        "fn": "Missed risks",
        "precision": "Precision",
        "recall": "Recall",
        "abstained": "Unknown results",
        "health": "Collection health",
        "health_note": "Unobserved attributes may be unset, unsupported or unreadable. Their absence is not proof of security.",
        "query": "Query",
        "scope": "Scope",
        "returned": "Returned objects",
        "unobserved": "Unobserved attributes",
        "tokens": "Effective access evidence",
        "tokens_note": "Bounded tokenGroups reads strengthen group-based checks. Claims, conditional ACEs and endpoint access still need validation.",
        "principal": "Principal",
        "groups": "Group count",
        "status": "Status",
        "source": "Source",
        "signatures": "Evidence signatures",
        "key_id": "Key ID",
        "audit": "Audit chain",
        "audit_note": "Export and sign the audit head to protect against a complete database rewrite.",
        "roots": "Shared root causes",
        "roots_note": "Groups connect explicit grants to findings and paths. Original findings and alternate paths remain available.",
        "finding_count": "Findings",
        "cause": "Cause",
        "target": "Target",
        "verification": "Remediation verification",
        "verification_note": "LDAP-backed closure requires fresh full collection and complete analysis. Runtime and ownership conditions need independent retesting; offline rebuilds and missing checks cannot close findings.",
        "history": "Scan history",
        "history_note": "Enable local history with --history-db PATH. Only fresh scans are plotted.",
        "time": "Time (UTC)",
        "score": "Security score",
        "fresh": "Fresh scan",
        "rebuilt": "Rebuilt report",
        "coverage": "Analysis coverage",
        "notifications": "Important changes",
        "tasks": "Work items",
        "owner": "Owner",
        "due": "Due date (UTC)",
        "notes": "Notes",
        "save": "Save task draft",
        "export": "Export task file",
        "draft": "Export assignments and import them with --ticket-file and --history-db. Closure is verified by a fresh --retest assessment.",
        "saved": "Task draft saved. Export the file to keep it.",
        "invalid": "Select a finding and provide an owner and valid due date.",
        "open": "Open",
        "in_progress": "In progress",
        "awaiting_verification": "Awaiting verification",
        "resolved": "Resolved",
        "still_present": "Still present",
        "insufficient_evidence": "Insufficient evidence",
        "completed": "Completed",
        "partial": "Partial",
        "unknown": "Unknown",
        "collected": "Collected",
        "verified": "Verified",
        "unsigned": "Unsigned",
        "disabled": "Disabled",
        "new_critical": "New critical finding",
        "reopened": "Reopened finding",
        "exception_expired": "Expired exception",
        "unassigned": "Unassigned",
        "none": "No records available.",
        "shown": "First 100 query records shown; the JSON export retains the full bounded ledger.",
        "history_disabled": "History is not enabled. Assignments can be prepared here and imported into a history-enabled scan.",
    },
    "tr": {
        "accuracy": "Doğruluk ve Kanıt",
        "operations": "Düzeltme ve Takip",
        "quality": "Kural doğruluğu",
        "quality_note": "Ölçümler etiketli çevrimdışı senaryolar içindir; üretim ortamının yanlış pozitif oranını göstermez. Senaryosu olmayan kurallar ölçülmemiştir.",
        "cases": "Senaryolar",
        "family": "Kural ailesi",
        "tp": "Doğru risk tespitleri",
        "fp": "Yanlış pozitifler",
        "fn": "Kaçırılan riskler",
        "precision": "Tespit isabeti",
        "recall": "Riskleri yakalama oranı",
        "abstained": "Bilinmeyen sonuçlar",
        "health": "Veri toplama sağlığı",
        "health_note": "Görülmeyen öznitelikler boş, desteklenmeyen veya okunamayan değerler olabilir. Görülmemeleri güvenlik kanıtı değildir.",
        "query": "Sorgu",
        "scope": "Kapsam",
        "returned": "Dönen nesneler",
        "unobserved": "Gözlemlenmeyen öznitelikler",
        "tokens": "Etkin yetki kanıtı",
        "tokens_note": "Sınırlı tokenGroups sorguları grup temelli kontrolleri güçlendirir. Koşullu izinler, talepler ve bilgisayar erişimi ayrıca doğrulanmalıdır.",
        "principal": "Hesap",
        "groups": "Grup sayısı",
        "status": "Durum",
        "source": "Kaynak",
        "signatures": "Kanıt imzaları",
        "key_id": "Anahtar kimliği",
        "audit": "İşlem günlüğü zinciri",
        "audit_note": "Veritabanının tamamen yeniden yazılmasını tespit etmek için günlük özetini dışa aktarın ve imzalayın.",
        "roots": "Ortak kök nedenler",
        "roots_note": "Gruplar açık yetki kayıtlarını bulgu ve yollarla ilişkilendirir. Asıl bulgular ve alternatif yollar görünür kalır.",
        "finding_count": "Bulgular",
        "cause": "Neden",
        "target": "Hedef",
        "verification": "Düzeltme doğrulaması",
        "verification_note": "LDAP bulgularını kapatmak için güncel ve tam veri ile tüm analizler gerekir. Çalışma zamanı ve sahiplik koşulları bağımsız doğrulama gerektirir; çevrimdışı raporlar ve eksik kontroller bulguyu kapatamaz.",
        "history": "Tarama geçmişi",
        "history_note": "Yerel geçmiş için --history-db PATH kullanın. Grafikte yalnızca yeni taramalar gösterilir.",
        "time": "Zaman (UTC)",
        "score": "Güvenlik puanı",
        "fresh": "Yeni tarama",
        "rebuilt": "Yeniden oluşturulan rapor",
        "coverage": "Analiz kapsamı",
        "notifications": "Önemli değişiklikler",
        "tasks": "İş kayıtları",
        "owner": "Sorumlu",
        "due": "Son tarih (UTC)",
        "notes": "Notlar",
        "save": "İş taslağını kaydet",
        "export": "İş dosyasını dışa aktar",
        "draft": "Atamaları dışa aktarın; --ticket-file ve --history-db ile içe alın. Kapatma, yeni bir --retest taramasıyla doğrulanır.",
        "saved": "İş taslağı kaydedildi. Saklamak için dosyayı dışa aktarın.",
        "invalid": "Bulgu seçin; sorumlu ve geçerli bir son tarih belirtin.",
        "open": "Açık",
        "in_progress": "Devam ediyor",
        "awaiting_verification": "Doğrulama bekliyor",
        "resolved": "Düzeltildi",
        "still_present": "Devam ediyor",
        "insufficient_evidence": "Veri yetersiz",
        "completed": "Tamamlandı",
        "partial": "Kısmi",
        "unknown": "Bilinmiyor",
        "collected": "Toplandı",
        "verified": "Doğrulandı",
        "unsigned": "İmzasız",
        "disabled": "Kapalı",
        "new_critical": "Yeni kritik bulgu",
        "reopened": "Yeniden açılan bulgu",
        "exception_expired": "Süresi dolan istisna",
        "unassigned": "Atanmamış",
        "none": "Gösterilecek kayıt yok.",
        "shown": "İlk 100 sorgu gösterilir; JSON çıktısı sınırlandırılmış kayıt listesinin tamamını içerir.",
        "history_disabled": "Geçmiş etkin değil. Atamaları burada hazırlayıp geçmişin etkin olduğu bir taramaya aktarabilirsiniz.",
    },
}


def _escape(value):
    return html.escape(str(value if value is not None else "—"), quote=True)


def _table(headers, rows, empty):
    if not rows:
        return f'<p class="text-muted">{_escape(empty)}</p>'
    head = "".join(f"<th>{_escape(value)}</th>" for value in headers)
    body = "".join("<tr>" + "".join(f"<td>{_escape(value)}</td>" for value in row) + "</tr>" for row in rows)
    return f'<div class="table-responsive"><table class="table table-dark table-hover"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


class ProductSectionsMixin:
    def _generate_product_sections(self, workspace, center):
        if not workspace:
            return ""
        labels = LABELS[self.language]

        def table(keys, rows):
            return _table([labels[key] for key in keys], rows, labels["none"])

        def status(value):
            return labels.get(value, value or labels["unknown"])

        def card(title, content, note=""):
            return f'<section class="card mb-4"><div class="card-body"><h3>{_escape(labels[title])}</h3><p class="text-muted">{_escape(labels.get(note, note))}</p>{content}</div></section>'

        def percent(value):
            return "—" if value is None else f"{value * 100:.1f}%"

        quality = workspace["quality"]
        quality_rows = [
            [
                row["rule"],
                row["cases"],
                row["true_positive"],
                row["false_positive"],
                row["false_negative"],
                row["abstained"],
                percent(row["precision"]),
                percent(row["recall"]),
            ]
            for row in quality["rules"]
        ]
        accuracy = card(
            "quality",
            table(["family", "cases", "tp", "fp", "fn", "abstained", "precision", "recall"], quality_rows),
            "quality_note",
        )
        health = workspace["collection_health"]
        query_rows = [
            [
                row["query_id"],
                row["scope"],
                row["returned_objects"],
                status(row["status"]),
                ", ".join(
                    f"{name} ({count}/{row['returned_objects']})"
                    for name, count in row.get("unobserved_attribute_counts", {}).items()
                    if count
                )
                or ", ".join(row.get("unobserved_attributes") or []),
            ]
            for row in (health.get("queries") or [])[:100]
        ]
        health_content = f"<p>{_escape(labels['status'])}: <strong>{_escape(status(health.get('status')))}</strong></p>"
        health_content += table(["query", "scope", "returned", "status", "unobserved"], query_rows)
        health_content += f'<p class="small text-muted">{_escape(labels["shown"])}</p>'
        accuracy += card("health", health_content, "health_note")
        token_rows = [
            [row["principal"], status(row["status"]), row.get("group_count"), row["source"]]
            for row in workspace["effective_access"].get("principals") or []
        ]
        accuracy += card("tokens", table(["principal", "status", "groups", "source"], token_rows), "tokens_note")
        signature_rows = [
            [row["source"], status(row.get("status")), row.get("key_id", "—")]
            for row in workspace.get("signatures") or []
        ]
        accuracy += card("signatures", table(["source", "status", "key_id"], signature_rows))
        audit = workspace["audit"]
        accuracy += card(
            "audit",
            f"<p>{_escape(status(audit['status']))} · {_escape(audit.get('entries', 0))}</p><code>{_escape(audit.get('chain_head', '—'))}</code>",
            "audit_note",
        )
        finding_names = {row["finding_id"]: row.get("title") for row in center["findings"]}
        roots = workspace["root_causes"]["groups"]
        root_rows = [
            [
                finding_names.get(row["finding_ids"][0], row["title"]) if row["finding_count"] == 1 else row["title"],
                row["finding_count"],
                ", ".join(row["affected_objects"]),
            ]
            for row in roots[:300]
        ]
        operations = card("roots", table(["cause", "finding_count", "target"], root_rows), "roots_note")
        verification_rows = [
            [finding_names.get(row["finding_id"], row.get("title")), row["affected_object"], status(row["status"])]
            for row in workspace["verification"]["findings"][:500]
        ]
        operations += card("verification", table(["cause", "target", "status"], verification_rows), "verification_note")
        history_rows = [
            [row["created_at"], f"{row['score']:.1f}", status("fresh" if row["fresh"] else "rebuilt"), row["coverage"]]
            for row in workspace["history"]["runs"]
        ]
        history_content = (
            '<div style="height:240px"><canvas id="history-score-chart"></canvas></div>' if history_rows else ""
        )
        history_content += table(["time", "score", "status", "coverage"], history_rows)
        operations += card("history", history_content, "history_note")
        alert_rows = [
            [status(row["kind"]), finding_names.get(row["finding_id"], row.get("title")), row.get("affected_object")]
            for row in workspace["history"]["notifications"]
        ]
        operations += card("notifications", table(["status", "cause", "target"], alert_rows))
        task_rows = [
            [
                finding_names.get(row["finding_id"], row.get("title", row["finding_id"])),
                status(row["owner"]) if row["owner"] == "unassigned" else row["owner"],
                status(row["status"]),
                row.get("due_at"),
            ]
            for row in workspace["tickets"][:500]
        ]
        options = "".join(
            f'<option value="{_escape(row["finding_id"])}">{_escape(row.get("affected_object"))} · {_escape(row.get("title"))}</option>'
            for row in center["findings"]
        )
        task_statuses = "".join(
            f'<option value="{name}">{_escape(labels[name])}</option>'
            for name in ("open", "in_progress", "awaiting_verification")
        )
        form = f"""<p class="text-muted">{_escape(labels["draft"])}</p>
        <form id="task-draft-form" class="row g-3">
            <div class="col-md-6"><label for="task-finding">{_escape(labels["cause"])}</label><select id="task-finding" class="form-select">{options}</select></div>
            <div class="col-md-6"><label for="task-owner">{_escape(labels["owner"])}</label><input id="task-owner" class="form-control" required maxlength="200"></div>
            <div class="col-md-6"><label for="task-status">{_escape(labels["status"])}</label><select id="task-status" class="form-select">{task_statuses}</select></div>
            <div class="col-md-6"><label for="task-due">{_escape(labels["due"])}</label><input id="task-due" type="datetime-local" class="form-control"></div>
            <div class="col-12"><label for="task-notes">{_escape(labels["notes"])}</label><textarea id="task-notes" class="form-control" maxlength="8000"></textarea></div>
            <div class="col-12"><button class="btn btn-primary" type="submit">{_escape(labels["save"])}</button><button id="task-export" class="btn btn-outline-info ms-2" type="button">{_escape(labels["export"])}</button></div>
        </form><p id="task-message" class="mt-3" role="status"></p>"""
        operations += card("tasks", table(["cause", "owner", "status", "due"], task_rows) + form)
        config = {
            "domain": center["domain"],
            "tickets": workspace["tickets"],
            "history": workspace["history"]["runs"],
            "labels": labels,
        }
        script = (Path(__file__).resolve().parents[1] / "product_workspace.js").read_text()
        return f"""<div class="tab-pane fade" id="accuracy-evidence" role="tabpanel" aria-labelledby="accuracy-evidence-tab"><h2>{_escape(labels["accuracy"])}</h2>{accuracy}</div>
        <div class="tab-pane fade" id="remediation-operations" role="tabpanel" aria-labelledby="remediation-operations-tab"><h2>{_escape(labels["operations"])}</h2>{operations}</div>
        <script type="application/json" id="product-workspace-data">{json_for_html_script(config)}</script><script>{script}</script>"""
