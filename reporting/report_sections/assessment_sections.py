"""Offline review, coverage, exception, and remediation-workspace presentation."""

from __future__ import annotations

import html
from pathlib import Path

from core.validation_collector import build_validation_script
from reporting.html_safety import json_for_html_script

LABELS = {
    "en": {
        "review": "Finding Validation",
        "coverage": "Scan Coverage",
        "exceptions": "Risk Exceptions",
        "simulation": "Remediation Simulation",
        "finding": "Finding",
        "target": "Target",
        "status": "Status",
        "select": "Select a finding",
        "reason": "Reason",
        "reviewer": "Reviewer / owner",
        "expires": "Expires at (UTC)",
        "source": "Evidence source",
        "checks": "Prerequisite checks",
        "pass": "Present / verified",
        "fail": "Absent / disproved",
        "unknown": "Unknown",
        "confirmed": "Confirmed",
        "false_positive": "False positive",
        "insufficient_evidence": "Insufficient evidence",
        "needs_validation": "Requires validation",
        "detected": "Detected",
        "not_reviewed": "Not reviewed",
        "active": "Active",
        "expired": "Expired",
        "configuration_changed": "Configuration changed",
        "rule_changed": "Rule changed",
        "conflicting_reviews": "Conflicting reviews",
        "conflicting_exceptions": "Conflicting exceptions",
        "stale_evidence": "Stale evidence",
        "save": "Save review draft",
        "export": "Export review file",
        "import": "Import review file",
        "collector": "Download evidence collector",
        "observations": "Endpoint observations",
        "draft_note": "Decisions are local drafts. Export the review file and regenerate the report to apply scores and statuses.",
        "exception_note": "Exceptions accept risk for a limited period. Attack paths and compliance evidence remain visible.",
        "accept": "Save exception draft",
        "revoke": "Remove exception draft",
        "completed": "Completed",
        "partial": "Incomplete",
        "ldap_query_failed": "LDAP read failed",
        "skipped": "Skipped",
        "execution_unknown": "Execution not recorded",
        "execution": "Analysis execution",
        "control_evidence": "Controls with imported policy evidence",
        "pending": "Findings awaiting validation",
        "score_scope": "The score covers supported findings; execution coverage does not prove every host or control is secure.",
        "step": "Analysis",
        "control": "Control",
        "evidence_imported": "Evidence imported",
        "not_verified": "Not verified",
        "simulate": "Simulate selected removals",
        "reset": "Reset scenario",
        "scenario": "Export scenario",
        "simulation_note": "Prediction within the collected graph and six hops. No directory changes are made. Operational dependencies and uncollected relationships are outside this model.",
        "before": "Before",
        "after": "After",
        "exposed": "Sources reaching Tier 0",
        "pairs": "Reachable source / target pairs",
        "closed": "Sources with all modeled paths closed",
        "edges": "Control relationships to remove",
        "no_graph": "Run a full scan with attack_graph_v2 to populate the simulation.",
        "saved": "Draft saved. Export the review file to keep it.",
        "removed": "Exception removed from draft.",
        "invalid": "Check the reason, owner, expiration and evidence. Confirmation requires every prerequisite; disproof requires at least one failed prerequisite.",
        "imported": "Review file imported into the draft.",
        "invalid_import": "The file is invalid, too large, or belongs to another domain.",
        "evidence_time": "Evidence collected at (UTC)",
        "updated": "Simulation updated.",
        "configuration_changed_note": "Configuration or rule changes invalidate a saved decision or exception.",
        "no_exceptions": "No saved exceptions.",
        "no_findings": "No findings in this assessment.",
        "no_observations": "No endpoint observations imported.",
        "record": "Record",
        "value": "Value",
        "source_time": "Source / time",
        "remove_review": "Remove review draft",
        "available": "Available",
        "conflicting_evidence": "Conflicting evidence",
        "invalid_timestamp": "Invalid timestamp",
        "unbound_evidence": "Evidence target or source missing",
    },
    "tr": {
        "review": "Bulgu Doğrulama",
        "coverage": "Tarama Kapsamı",
        "exceptions": "Risk İstisnaları",
        "simulation": "Düzeltme Simülasyonu",
        "finding": "Bulgu",
        "target": "Hedef",
        "status": "Durum",
        "select": "Bir bulgu seçin",
        "reason": "Gerekçe",
        "reviewer": "İnceleyen / sorumlu",
        "expires": "Bitiş zamanı (UTC)",
        "source": "Kanıt kaynağı",
        "checks": "Ön koşul kontrolleri",
        "pass": "Mevcut / doğrulandı",
        "fail": "Yok / çürütüldü",
        "unknown": "Bilinmiyor",
        "confirmed": "Doğrulandı",
        "false_positive": "Yanlış pozitif",
        "insufficient_evidence": "Veri yetersiz",
        "needs_validation": "Doğrulama gerekli",
        "detected": "Tespit edildi",
        "not_reviewed": "İncelenmedi",
        "active": "Etkin",
        "expired": "Süresi doldu",
        "configuration_changed": "Yapılandırma değişti",
        "rule_changed": "Kural değişti",
        "conflicting_reviews": "Çelişkili kararlar",
        "conflicting_exceptions": "Çelişkili istisnalar",
        "stale_evidence": "Kanıt güncel değil",
        "save": "İnceleme taslağını kaydet",
        "export": "İnceleme dosyasını dışa aktar",
        "import": "İnceleme dosyasını içe aktar",
        "collector": "Kanıt toplama betiğini indir",
        "observations": "Bilgisayar gözlemleri",
        "draft_note": "Kararlar yerel taslaktır. Puan ve durumlara uygulamak için inceleme dosyasını dışa aktarın ve raporu yeniden oluşturun.",
        "exception_note": "İstisnalar riski belirli bir süre kabul eder. Saldırı yolları ve uyumluluk kanıtları görünür kalır.",
        "accept": "İstisna taslağını kaydet",
        "revoke": "İstisna taslağını kaldır",
        "completed": "Tamamlandı",
        "partial": "Eksik",
        "ldap_query_failed": "LDAP okuması başarısız",
        "skipped": "Atlandı",
        "execution_unknown": "Çalıştırma kaydı yok",
        "execution": "Analizlerin çalıştırılma oranı",
        "control_evidence": "Politika kanıtı içe aktarılan kontroller",
        "pending": "Doğrulama bekleyen bulgular",
        "score_scope": "Puan, kanıtla desteklenen bulguları kapsar; çalışma kapsamı her bilgisayarın veya kontrolün güvenli olduğunu kanıtlamaz.",
        "step": "Analiz",
        "control": "Kontrol",
        "evidence_imported": "Kanıt içe aktarıldı",
        "not_verified": "Doğrulanmadı",
        "simulate": "Seçilen kaldırmaları simüle et",
        "reset": "Senaryoyu sıfırla",
        "scenario": "Senaryoyu dışa aktar",
        "simulation_note": "Toplanan grafik ve altı adımla sınırlı tahmindir. Dizin değiştirilmez. İşletim bağımlılıkları ve toplanmayan ilişkiler bu modelin dışındadır.",
        "before": "Önce",
        "after": "Sonra",
        "exposed": "Tier 0'a ulaşan kaynaklar",
        "pairs": "Ulaşılabilen kaynak / hedef çiftleri",
        "closed": "Modellenen tüm yolları kapanan kaynaklar",
        "edges": "Kaldırılacak kontrol ilişkileri",
        "no_graph": "Simülasyon için attack_graph_v2 içeren tam tarama çalıştırın.",
        "saved": "Taslak kaydedildi. Saklamak için inceleme dosyasını dışa aktarın.",
        "removed": "İstisna taslaktan kaldırıldı.",
        "invalid": "Gerekçe, sorumlu, bitiş zamanı ve kanıtı kontrol edin. Doğrulama tüm ön koşulları, çürütme en az bir başarısız ön koşulu gerektirir.",
        "imported": "İnceleme dosyası taslağa alındı.",
        "invalid_import": "Dosya geçersiz, çok büyük veya başka bir domaine ait.",
        "evidence_time": "Kanıt toplama zamanı (UTC)",
        "updated": "Simülasyon güncellendi.",
        "configuration_changed_note": "Yapılandırma veya kural değişiklikleri kayıtlı kararı ve istisnayı geçersiz kılar.",
        "no_exceptions": "Kayıtlı istisna yok.",
        "no_findings": "Bu değerlendirmede bulgu yok.",
        "no_observations": "Bilgisayar gözlemi içe aktarılmadı.",
        "record": "Kayıt",
        "value": "Değer",
        "source_time": "Kaynak / zaman",
        "remove_review": "İnceleme taslağını kaldır",
        "available": "Mevcut",
        "conflicting_evidence": "Çelişkili kanıt",
        "invalid_timestamp": "Geçersiz zaman",
        "unbound_evidence": "Kanıt hedefi veya kaynağı eksik",
    },
}


CHECK_LABELS = {
    "en": {
        "template_configuration": "Vulnerable template configuration",
        "enrollment_permissions": "Enrollment available to the relevant principal",
        "ca_publication": "Template published by the certification authority",
        "ca_policy": "Certification authority policy permits the suspected path",
        "affected_version_or_configuration": "Affected version or configuration",
        "service_exposure": "Required service is exposed",
        "effective_policy": "Effective policy permits the suspected condition",
        "effective_laps_policy": "LAPS policy confirms the suspected weakness",
        "attribute_read_visibility": "Attribute visibility is sufficient for this conclusion",
        "target_configuration": "Target configuration confirms the condition",
        "key_ownership": "Key ownership is inconsistent with authorized use",
        "unauthorized_key_or_write_access": "Unauthorized key or write access exists",
        "domain_root_scope": "Grant applies to the domain root",
        "get_changes": "Effective Get-Changes permission",
        "get_changes_all": "Effective Get-Changes-All permission",
        "principal_token": "Principal and group token verified",
        "event_identity": "Event provider and identity verified",
        "activity_context": "Event context supports the suspected activity",
        "unauthorized_activity": "Activity was unauthorized",
        "condition_verified": "Reported condition independently verified",
        "security_impact_verified": "Security impact independently verified",
        "explicit_skip": "Explicitly skipped",
        "fast_profile": "Omitted by fast profile",
        "execution_not_recorded": "Execution not recorded",
        "simulation_limit": "Simulation limits exceeded. Exposure was not computed; the assessment remains available.",
        "edge_search": "Search by source, target, or permission",
        "edge_display": "Relationships shown / matching",
    },
    "tr": {
        "template_configuration": "Şablon yapılandırması şüpheli koşulu taşıyor",
        "enrollment_permissions": "İlgili hesabın sertifika kayıt izni var",
        "ca_publication": "Şablon sertifika otoritesinde yayınlanıyor",
        "ca_policy": "Sertifika otoritesi politikası şüpheli yola izin veriyor",
        "affected_version_or_configuration": "Etkilenen sürüm veya yapılandırma mevcut",
        "service_exposure": "Gerekli servis erişilebilir",
        "effective_policy": "Uygulanan politika şüpheli koşula izin veriyor",
        "effective_laps_policy": "LAPS politikası şüpheli zayıflığı doğruluyor",
        "attribute_read_visibility": "Öznitelik okuma görünürlüğü bu sonuç için yeterli",
        "target_configuration": "Hedef yapılandırması koşulu doğruluyor",
        "key_ownership": "Anahtar sahipliği yetkili kullanımla uyumsuz",
        "unauthorized_key_or_write_access": "İzinsiz anahtar veya yazma erişimi mevcut",
        "domain_root_scope": "İzin domain köküne uygulanıyor",
        "get_changes": "Etkin Get-Changes izni var",
        "get_changes_all": "Etkin Get-Changes-All izni var",
        "principal_token": "Hesap ve grup üyelikleri doğrulandı",
        "event_identity": "Olay sağlayıcısı ve kimlik bilgisi doğrulandı",
        "activity_context": "Olay bağlamı şüpheli etkinliği destekliyor",
        "unauthorized_activity": "Etkinlik yetkisiz gerçekleştirildi",
        "condition_verified": "Bildirilen koşul bağımsız doğrulandı",
        "security_impact_verified": "Güvenlik etkisi bağımsız doğrulandı",
        "explicit_skip": "Kullanıcı tarafından atlandı",
        "fast_profile": "Hızlı profil nedeniyle atlandı",
        "execution_not_recorded": "Çalıştırma kaydı yok",
        "simulation_limit": "Simülasyon sınırı aşıldı. Erişim hesaplanmadı; tarama sonuçları kullanılabilir.",
        "edge_search": "Kaynak, hedef veya izinle ara",
        "edge_display": "Gösterilen / eşleşen ilişkiler",
    },
}


class AssessmentSectionsMixin:
    def _generate_assessment_sections(self, center, coverage, simulation):
        labels = {**LABELS[self.language], **CHECK_LABELS[self.language]}

        def esc(value):
            return html.escape(str(value or ""))

        def text(key):
            return esc(labels.get(key, key))

        def step_description(row):
            from analysis.registry import ANALYSIS_STEP_DEFAULTS
            from reporting.ciso_dashboard import ANALYSIS_DISPLAY_LABELS

            result_key = next(iter(ANALYSIS_STEP_DEFAULTS.get(row["key"], {})), row["key"])
            return esc(ANALYSIS_DISPLAY_LABELS.get(result_key, row["description"]))

        findings = center.get("findings", [])
        options = "".join(
            f'<option value="{esc(f["finding_id"])}">{esc(f.get("affected_object"))} — {esc(f.get("title") or f.get("type"))}</option>'
            for f in findings
        )
        table_rows = "".join(
            f"<tr><td>{esc(f.get('title') or f.get('type'))}<br><code>{esc(f['finding_id'])}</code></td>"
            f"<td>{esc(f.get('affected_object'))}</td><td>{text(f.get('finding_status', 'detected'))}"
            f"<br><small>{text(f.get('review_status', 'not_reviewed'))}</small></td></tr>"
            for f in findings
        )
        controls = "".join(
            f"<tr><td><code>{esc(row['control'])}</code></td><td>{text(row['status'])}</td><td>{row['source_count']}</td></tr>"
            for row in coverage.get("controls", [])
        )
        steps = "".join(
            f"<tr><td>{step_description(row)}<br><code>{esc(row['key'])}</code></td><td>{text(row['status'] if row['status'] != 'unknown' else 'execution_unknown')}</td><td>{text(row['reason'])}</td></tr>"
            for row in coverage.get("analysis_steps", [])
        )
        summary = coverage.get("summary") or {}
        execution = summary.get("execution_percent")
        execution_label = f"{execution}%" if execution is not None else labels["execution_unknown"]
        observations = center.get("observations", [])
        observation_rows = "".join(
            f"<tr><td>{esc(row.get('target'))}</td><td>{esc(row.get('name'))}</td>"
            f"<td><code>{esc(row.get('value'))}</code><br>{text(row.get('status', 'unknown'))}</td><td>{esc(row.get('source'))}<br>{esc(row.get('collected_at'))}</td></tr>"
            for row in observations[:500]
        )
        configuration = {
            "center": center,
            "simulation": simulation,
            "labels": labels,
            "collector": build_validation_script(center),
        }
        script = Path(__file__).resolve().parents[1].joinpath("assessment_workspace.js").read_text(encoding="utf-8")
        return f"""
        <style>
        .assessment-form {{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}}
        .assessment-form label {{display:block;margin-bottom:5px}}
        .assessment-form input,.assessment-form select,.assessment-form textarea {{width:100%;background:var(--bg-card);color:var(--text-primary);border:1px solid var(--border-subtle);padding:9px;border-radius:5px}}
        .assessment-wide {{grid-column:1/-1}}
        .assessment-actions {{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0}}
        .assessment-metrics {{display:flex;flex-wrap:wrap;gap:32px;margin:20px 0}}
        .assessment-metrics strong {{display:block;font-size:1.3rem;color:var(--accent)}}
        .assessment-check {{display:flex;gap:12px;align-items:center;padding:8px 0}}
        .assessment-check select {{max-width:190px}}
        .simulation-list {{max-height:420px;overflow:auto;padding:12px;border:1px solid var(--border-subtle)}}
        .simulation-list label {{display:flex;gap:10px;margin:8px 0;align-items:baseline}}
        .simulation-list input {{width:auto}}
        #assessment-message {{min-height:24px}}
        </style>
        <section class="tab-pane fade" id="finding-validation" role="tabpanel" aria-labelledby="finding-validation-tab">
          <h3>{text("review")}</h3><p>{text("draft_note")}</p>
          <div class="assessment-actions"><button type="button" class="toolbar-btn" id="review-import">{text("import")}</button>
          <input type="file" id="review-file-input" accept=".json,application/json" hidden>
          <button type="button" class="toolbar-btn" id="review-export">{text("export")}</button>
          <button type="button" class="toolbar-btn" id="validation-collector-download">{text("collector")}</button></div>
          <form id="finding-review-form" class="assessment-form">
            <div class="assessment-wide"><label for="review-finding">{text("select")}</label><select id="review-finding" required>{options}</select></div>
            <div><label for="review-status">{text("status")}</label><select id="review-status">{"".join(f'<option value="{status}">{text(status)}</option>' for status in ("insufficient_evidence", "confirmed", "false_positive"))}</select></div>
            <div><label for="review-owner">{text("reviewer")}</label><input id="review-owner" required maxlength="200"></div>
            <div><label for="review-expiration">{text("expires")}</label><input id="review-expiration" type="datetime-local" required></div>
            <div><label for="review-collected-at">{text("evidence_time")}</label><input id="review-collected-at" type="datetime-local" required></div>
            <div class="assessment-wide"><label for="review-source">{text("source")}</label><input id="review-source" maxlength="1000"></div>
            <div class="assessment-wide"><label for="review-reason">{text("reason")}</label><textarea id="review-reason" required maxlength="4000"></textarea></div>
            <div class="assessment-wide"><h5>{text("checks")}</h5><div id="review-checks"></div></div>
            <div class="assessment-actions assessment-wide"><button class="toolbar-btn" type="submit">{text("save")}</button>
            <button class="toolbar-btn" type="button" id="review-remove">{text("remove_review")}</button></div>
          </form><p id="assessment-message" role="status" aria-live="polite"></p>
          <div class="table-responsive"><table class="table"><thead><tr><th>{text("finding")}</th><th>{text("target")}</th><th>{text("status")}</th></tr></thead><tbody>{table_rows}</tbody></table></div>
          <h5>{text("observations")} ({len(observations)})</h5>
          <div class="table-responsive"><table class="table"><thead><tr><th>{text("target")}</th><th>{text("record")}</th><th>{text("value")}</th><th>{text("source_time")}</th></tr></thead><tbody>{observation_rows}</tbody></table></div>
        </section>
        <section class="tab-pane fade" id="scan-coverage" role="tabpanel" aria-labelledby="scan-coverage-tab">
          <h3>{text("coverage")}</h3><p>{text("score_scope")}</p>
          <div class="assessment-metrics"><div>{text("execution")}<strong>{esc(execution_label)}</strong>{summary.get("completed_steps", 0)} / {summary.get("total_steps", 0)}</div>
          <div>{text("control_evidence")}<strong>{summary.get("posture_controls_with_evidence", 0)} / {summary.get("total_posture_controls", 0)}</strong></div>
          <div>{text("pending")}<strong>{summary.get("validation_required", 0)}</strong></div></div>
          <div class="table-responsive"><table class="table"><thead><tr><th>{text("control")}</th><th>{text("status")}</th><th>{text("source")}</th></tr></thead><tbody>{controls}</tbody></table></div>
          <div class="table-responsive"><table class="table"><thead><tr><th>{text("step")}</th><th>{text("status")}</th><th>{text("reason")}</th></tr></thead><tbody>{steps}</tbody></table></div>
        </section>
        <section class="tab-pane fade" id="risk-exceptions" role="tabpanel" aria-labelledby="risk-exceptions-tab">
          <h3>{text("exceptions")}</h3><p>{text("exception_note")}</p><p>{text("configuration_changed_note")}</p>
          <form id="risk-exception-form" class="assessment-form">
            <div class="assessment-wide"><label for="exception-finding">{text("select")}</label><select id="exception-finding" required>{options}</select></div>
            <div><label for="exception-owner">{text("reviewer")}</label><input id="exception-owner" required maxlength="200"></div>
            <div><label for="exception-expiration">{text("expires")}</label><input id="exception-expiration" type="datetime-local" required></div>
            <div class="assessment-wide"><label for="exception-reason">{text("reason")}</label><textarea id="exception-reason" required maxlength="4000"></textarea></div>
            <div class="assessment-actions assessment-wide"><button type="submit" class="toolbar-btn">{text("accept")}</button>
            <button type="button" class="toolbar-btn" id="exception-remove">{text("revoke")}</button>
            <button type="button" class="toolbar-btn" id="exception-export">{text("export")}</button></div>
          </form><p id="exception-message" role="status" aria-live="polite"></p><div id="exception-records"></div>
        </section>
        <section class="tab-pane fade" id="remediation-simulation" role="tabpanel" aria-labelledby="remediation-simulation-tab">
          <h3>{text("simulation")}</h3><p>{text("simulation_note")}</p>
          <div class="assessment-metrics"><div>{text("exposed")}<strong><span id="simulation-before">0</span> → <span id="simulation-after">0</span></strong></div>
          <div>{text("pairs")}<strong><span id="simulation-before-pairs">0</span> → <span id="simulation-after-pairs">0</span></strong></div></div>
          <h5>{text("edges")}</h5><div class="assessment-form"><div><label for="simulation-filter">{text("edge_search")}</label><input type="search" id="simulation-filter"></div></div>
          <p id="simulation-edge-count"></p><div id="simulation-edges" class="simulation-list"></div>
          <div class="assessment-actions"><button type="button" class="toolbar-btn" id="simulation-run">{text("simulate")}</button>
          <button type="button" class="toolbar-btn" id="simulation-reset">{text("reset")}</button>
          <button type="button" class="toolbar-btn" id="simulation-export">{text("scenario")}</button></div>
          <p id="simulation-message" role="status" aria-live="polite"></p><h5>{text("closed")}</h5><ul id="simulation-closed"></ul>
        </section>
        <script type="application/json" id="assessment-workspace-data">{json_for_html_script(configuration)}</script>
        <script>{script}</script>
        """
