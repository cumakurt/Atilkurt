"""Report language selection and Turkish-localization regressions."""

from __future__ import annotations

from reporting.html_report import HTMLReportGenerator
from reporting.compliance_reporter import ComplianceReporter
from reporting.localization import (
    localize_export_payload,
    localize_finding_list,
    localize_html_document,
)


def _sample_risk() -> dict:
    return {
        "type": "user_password_never_expires",
        "title": "Password Never Expires",
        "description": "The password for this account never expires.",
        "affected_object": "svc_backup",
        "object_type": "user",
        "severity": "high",
        "impact": "An attacker may retain access.",
        "attack_scenario": "An attacker cracks and reuses the password.",
        "mitigation": "Rotate the password.",
        "mitre_attack": "T1078.002",
        "evidence": "CN=svc_backup,OU=Services,DC=example,DC=com / S-1-5-21-1234",
        "final_score": 72.0,
    }


def _render(language: str, compliance_data: dict | None = None) -> str:
    return HTMLReportGenerator(language=language)._generate_html(
        users=[{
            "sAMAccountName": "svc_backup",
            "displayName": "Backup Service",
            "memberOf": [],
            "distinguishedName": "CN=svc_backup,OU=Services,DC=example,DC=com",
        }],
        computers=[],
        groups=[],
        gpos=[],
        risks=[_sample_risk()],
        misconfig_findings=[],
        domain_score=28.0,
        executive_summary={"summary": "English summary", "top_critical_risks": []},
        compliance_data=compliance_data,
        inline_assets=False,
    )


def test_english_report_remains_the_default_presentation():
    report = _render("en")

    assert '<html lang="en">' in report
    assert "Active Directory Security Report" in report
    assert "Password Never Expires" in report
    assert "Impact &amp; Attack Scenario" in report


def test_turkish_report_localizes_interface_and_finding_narrative():
    report = _render("tr")

    assert '<html lang="tr">' in report
    assert "Active Directory Güvenlik Raporu" in report
    assert "Gösterge Paneli" in report
    assert "Kritik Riskler" in report
    assert "Kullanıcı Parolasının Süresiz Olması" in report
    assert "Etki ve Saldırı Senaryosu" in report
    assert "Yönetici Özeti" in report
    assert "The password for this account never expires." not in report
    assert "Impact &amp; Attack Scenario" not in report
    assert "No scan finding currently maps to a Domain Admin technique." not in report
    assert "No risks found for this user." not in report
    # Localization must not rename JavaScript lookup keys used by report logic.
    assert "'Critical': 'danger'" in report


def test_turkish_localization_preserves_technical_identifiers():
    localized = localize_finding_list([_sample_risk()], "tr")[0]

    assert localized["type"] == "user_password_never_expires"
    assert localized["affected_object"] == "svc_backup"
    assert localized["mitre_attack"] == "T1078.002"
    assert "CN=svc_backup,OU=Services,DC=example,DC=com" in localized["evidence"]
    assert "S-1-5-21-1234" in localized["evidence"]


def test_turkish_json_payload_keeps_schema_and_localizes_human_fields():
    payload = {
        "users": [{"sAMAccountName": "svc_backup"}],
        "computers": [],
        "groups": [],
        "gpos": [],
        "risks": [_sample_risk()],
    }

    localized = localize_export_payload(payload, "tr")

    assert localized["report_language"] == "tr"
    assert localized["users"] == payload["users"]
    assert localized["risks"][0]["type"] == "user_password_never_expires"
    assert localized["risks"][0]["title"] == "Kullanıcı Parolasının Süresiz Olması"
    assert "tespit edildi" in localized["risks"][0]["description"]


def test_turkish_report_localizes_compliance_views():
    compliance = ComplianceReporter().generate_compliance_report([_sample_risk()])

    report = _render("tr", compliance_data=compliance)

    assert "Uyumluluk Raporlaması" in report
    assert "Genel Uyumluluk Puanı" in report
    assert "Kullanıcı Parolasının Süresiz Olması" in report
    assert "NIST Siber Güvenlik Çerçevesi" in report
    assert "Protect" not in report


def test_html_localization_does_not_modify_bundled_vendor_javascript():
    source = (
        '<html lang="en"><script>/*! Bootstrap v5.3.0 */ const label="Title";</script>'
        '<p>Title</p></html>'
    )

    localized = localize_html_document(source, "tr")

    assert 'const label="Title"' in localized
    assert "<p>Başlık</p>" in localized
