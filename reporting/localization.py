"""Report-localization helpers.

The scanner and analyzers deliberately keep their stable field names and risk
type identifiers in English.  This module localizes only presentation data so
filters, scoring, baselines, and integrations continue to work unchanged.
"""

from __future__ import annotations

from copy import deepcopy
import re
from typing import Any


SUPPORTED_LANGUAGES = frozenset({"en", "tr"})


def normalize_language(language: str | None) -> str:
    """Return a supported two-letter report language."""
    normalized = str(language or "en").strip().lower()
    if normalized not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported report language: {language}")
    return normalized


# Stable risk identifiers are intentionally not translated in exported data.
# These labels are used only when a human-readable Turkish title is required.
RISK_TYPE_TITLES_TR = {
    "user_password_never_expires": "Kullanıcı Parolasının Süresiz Olması",
    "password_not_required": "Parola Gerektirmeyen Hesap",
    "kerberos_preauth_disabled": "Kerberos Ön Kimlik Doğrulamasının Devre Dışı Olması",
    "user_with_spn": "SPN Tanımlı Kullanıcı Hesabı",
    "admin_count_set": "Korumalı Yönetici Hesabı İşareti",
    "inactive_privileged_account": "Etkin Olmayan Ayrıcalıklı Hesap",
    "disabled_user_account": "Devre Dışı Kullanıcı Hesabı",
    "disabled_domain_admin": "Devre Dışı Etki Alanı Yöneticisi",
    "disabled_enterprise_admin": "Devre Dışı Kuruluş Yöneticisi",
    "locked_user_account": "Kilitli Kullanıcı Hesabı",
    "service_account_password_never_expires": "Süresiz Parolalı Hizmet Hesabı",
    "recently_created_account": "Yakın Zamanda Oluşturulan Hesap",
    "recently_modified_group_membership": "Yakın Zamanda Değişen Grup Üyeliği",
    "reversible_encryption_enabled": "Geri Döndürülebilir Parola Şifrelemesi",
    "privileged_user_outside_protected_users": "Protected Users Dışındaki Ayrıcalıklı Kullanıcı",
    "privileged_user_without_smartcard": "Akıllı Kart Zorunluluğu Olmayan Ayrıcalıklı Kullanıcı",
    "unconstrained_delegation": "Sınırlandırılmamış Yetkilendirme",
    "unconstrained_delegation_user": "Sınırlandırılmamış Yetkilendirmeli Kullanıcı",
    "constrained_delegation": "Kısıtlanmış Yetkilendirme",
    "computer_unconstrained_delegation": "Sınırlandırılmamış Yetkilendirmeli Bilgisayar",
    "computer_broad_constrained_delegation": "Geniş Kapsamlı Kısıtlanmış Yetkilendirme",
    "duplicate_spn": "Yinelenen SPN Kaydı",
    "kerberos_legacy_encryption": "Eski Kerberos Şifreleme Türü",
    "privileged_account_delegatable": "Yetkilendirilebilir Ayrıcalıklı Hesap",
    "eol_operating_system": "Destek Ömrü Sona Ermiş İşletim Sistemi",
    "legacy_operating_system": "Eski İşletim Sistemi",
    "inactive_computer": "Etkin Olmayan Bilgisayar",
    "never_used_computer": "Hiç Kullanılmamış Bilgisayar",
    "computer_account_expired": "Süresi Dolmuş Bilgisayar Hesabı",
    "too_many_domain_admins": "Fazla Sayıda Etki Alanı Yöneticisi",
    "nested_admin_group": "İç İçe Yönetici Grubu",
    "operators_group_members": "Operatör Grubu Üyeleri",
    "empty_group": "Boş Grup",
    "deeply_nested_group": "Derin İç İçe Grup Yapısı",
    "privilege_escalation_path": "Yetki Yükseltme Yolu",
    "delegation_privilege_escalation": "Yetkilendirme Üzerinden Yetki Yükseltme",
    "spn_privilege_escalation": "SPN Üzerinden Yetki Yükseltme",
    "computer_delegation_privilege_path": "Bilgisayar Yetkilendirme Üzerinden Yetki Yolu",
    "acl_generic_all": "ACL GenericAll Yetkisi",
    "acl_write_dacl": "ACL WriteDACL Yetkisi",
    "acl_write_owner": "ACL WriteOwner Yetkisi",
    "acl_generic_write": "ACL GenericWrite Yetkisi",
    "acl_write_property": "ACL WriteProperty Yetkisi",
    "acl_dcsync": "ACL Üzerinden DCSync Yetkisi",
    "acl_force_change_password": "ACL ile Parola Değiştirme Yetkisi",
    "acl_write_service_principal_name": "ACL ile SPN Yazma Yetkisi",
    "acl_write_user_account_control": "ACL ile Kullanıcı Hesabı Denetimi Yazma Yetkisi",
    "acl_write_member": "ACL ile Grup Üyeliği Yazma Yetkisi",
    "acl_ds_replication_get_changes": "Dizin Çoğaltma Değişikliklerini Alma Yetkisi",
    "acl_ds_replication_get_changes_all": "Tüm Dizin Çoğaltma Değişikliklerini Alma Yetkisi",
    "acl_ds_replication_get_changes_in_filtered_set": "Filtreli Dizin Çoğaltma Yetkisi",
    "acl_all_extended_rights": "Tüm Genişletilmiş ACL Hakları",
    "dcsync_rights": "DCSync Hakları",
    "shadow_admin": "Gölge Yönetici",
    "acl_inheritance_risk": "ACL Devralma Riski",
    "acl_privilege_escalation_path": "ACL Yetki Yükseltme Yolu",
    "kerberoasting_target": "Kerberoasting Hedefi",
    "asrep_roasting_target": "AS-REP Roasting Hedefi",
    "service_account_high_privilege": "Yüksek Ayrıcalıklı Hizmet Hesabı",
    "service_account_without_msa": "MSA Kullanmayan Hizmet Hesabı",
    "gpo_modification_rights": "GPO Değiştirme Yetkileri",
    "gpo_linked_to_privileged_ou": "Ayrıcalıklı OU'ya Bağlı GPO",
    "password_policy_weak": "Zayıf Parola İlkesi",
    "weak_fine_grained_password_policy": "Zayıf Ayrıntılı Parola İlkesi",
    "trust_relationship_risk": "Güven İlişkisi Riski",
    "gpp_password_found": "GPP İçinde Saklanan Parola",
    "laps_not_configured": "LAPS Yapılandırılmamış",
    "laps_access_analysis": "LAPS Erişim Yetkileri",
    "zerologon_vulnerable": "ZeroLogon Güvenlik Açığı",
    "printnightmare_vulnerable": "PrintNightmare Güvenlik Açığı",
    "petitpotam_vulnerable": "PetitPotam Güvenlik Açığı",
    "shadow_credentials": "Gölge Kimlik Bilgileri",
    "key_credential_link_present": "Anahtar Kimlik Bilgisi Bağlantısı",
    "nopac_vulnerable": "NoPac Güvenlik Açığı",
    "ldap_signing_disabled": "LDAP İmzalama Zorunlu Değil",
    "ntlm_restriction_weak": "Zayıf NTLM Kısıtlaması",
    "smb_signing_disabled": "SMB İmzalama Zorunlu Değil",
    "certificate_services_detected": "Active Directory Sertifika Hizmetleri Algılandı",
    "certificate_esc1": "AD CS ESC1 Yanlış Yapılandırması",
    "certificate_esc2": "AD CS ESC2 Yanlış Yapılandırması",
    "certificate_esc3": "AD CS ESC3 Yanlış Yapılandırması",
    "certificate_esc4": "AD CS ESC4 Yanlış Yapılandırması",
    "certificate_esc5": "AD CS ESC5 Yanlış Yapılandırması",
    "certificate_esc6": "AD CS ESC6 Yanlış Yapılandırması",
    "certificate_esc7": "AD CS ESC7 Yanlış Yapılandırması",
    "certificate_esc8": "AD CS ESC8 Yanlış Yapılandırması",
    "certificate_esc9": "AD CS ESC9 Yanlış Yapılandırması",
    "certificate_esc10": "AD CS ESC10 Yanlış Yapılandırması",
    "certificate_esc11": "AD CS ESC11 Yanlış Yapılandırması",
    "certificate_esc13": "AD CS ESC13 Yanlış Yapılandırması",
    "certificate_esc14": "AD CS ESC14 Yanlış Yapılandırması",
    "certificate_esc15": "AD CS ESC15 Yanlış Yapılandırması",
    "certificate_esc16": "AD CS ESC16 Yanlış Yapılandırması",
    "certificate_certifried": "Certifried Sertifika Hizmeti Riski",
    "rbcd_delegation": "Kaynak Tabanlı Kısıtlanmış Yetkilendirme (RBCD)",
    "sid_history_present": "SID Geçmişi Bulunması",
    "foreign_security_principal": "Yabancı Güvenlik Sorumlusu",
    "fine_grained_password_policy": "Ayrıntılı Parola İlkesi",
    "bitlocker_recovery_in_ad": "AD İçinde BitLocker Kurtarma Bilgisi",
    "adminsdholder_analysis": "AdminSDHolder Yapılandırma Riski",
    "ou_delegation_risk": "OU Yetkilendirme Riski",
    "ou_gpo_inheritance_blocked": "OU Üzerinde GPO Devralması Engellenmiş",
    "ad_recycle_bin_enabled": "Active Directory Geri Dönüşüm Kutusu Durumu",
    "ad_recycle_bin_deleted_objects": "Silinmiş Active Directory Nesneleri",
    "printer_object_risk": "Yazıcı Nesnesi Riski",
    "exchange_objects_found": "Exchange Nesneleri Algılandı",
    "dns_zone_found": "DNS Bölgesi Algılandı",
    "machine_account_quota_high": "Yüksek Makine Hesabı Kotası",
    "krbtgt_password_age": "Eski KRBTGT Parolası",
    "krbtgt_weak_encryption": "Zayıf KRBTGT Şifrelemesi",
    "stale_inactive_account": "Uzun Süredir Etkin Olmayan Hesap",
    "stale_ancient_password": "Çok Eski Hesap Parolası",
    "stale_description_credential": "Açıklama Alanında Kimlik Bilgisi",
    "stale_computer_account": "Atıl Bilgisayar Hesabı",
    "stale_orphan_sid": "Sahipsiz SID",
    "golden_gmsa_root_key": "Golden gMSA Kök Anahtarı Riski",
    "golden_gmsa_excessive_readers": "Golden gMSA İçin Aşırı Okuma Yetkisi",
    "gmsa_misconfiguration": "gMSA Yanlış Yapılandırması",
    "gmsa_legacy_service_account": "Eski Tip Hizmet Hesabı Kullanımı",
    "password_spray_risk": "Parola Püskürtme Riski",
    "password_spray_no_lockout": "Hesap Kilitlemesiz Parola Püskürtme Riski",
    "backup_operator_risk": "Backup Operators Grubu Riski",
    "sensitive_operator_risk": "Hassas Operatör Grubu Riski",
    "coercion_spoolsample": "SpoolSample Kimlik Doğrulama Zorlama Riski",
    "coercion_dfscoerce": "DFSCoerce Kimlik Doğrulama Zorlama Riski",
    "coercion_webclient": "WebClient Kimlik Doğrulama Zorlama Riski",
    "lateral_movement_unrestricted": "Sınırsız Yanal Hareket Riski",
    "lateral_movement_tier_violation": "Katman Modeli İhlali",
    "lateral_movement_rdp_exposure": "RDP Üzerinden Yanal Hareket Riski",
    "honeypot_candidate": "Aldatma Sistemi Adayı",
    "honeypot_recommendation": "Aldatma Sistemi Önerisi",
    "audit_policy_insufficient": "Yetersiz Denetim İlkesi",
    "audit_sacl_missing": "Eksik Denetim SACL Kaydı",
    "replication_suspicious_change": "Şüpheli Çoğaltma Değişikliği",
    "replication_tombstone_risk": "Çoğaltma Tombstone Riski",
    "ldap_anonymous_enabled": "Anonim LDAP Erişimi Açık",
    "ldap_prewin2k_broad_membership": "Pre-Windows 2000 Grubunda Geniş Üyelik",
    "ldap_guest_enabled": "Konuk Hesabı Etkin",
    "ldap_legacy_functional_level": "Eski Etki Alanı İşlev Düzeyi",
    "hidden_primary_group_privilege": "Birincil Grup Üzerinden Gizli Ayrıcalık",
    "privileged_computer_account": "Ayrıcalıklı Bilgisayar Hesabı",
    "builtin_admin_renamed": "Yerleşik Yönetici Hesabının Adı Değiştirilmiş",
    "hybrid_azure_sso_account": "Azure Seamless SSO Hesabı Riski",
    "hybrid_entra_connect_account": "Entra Connect Hesabı Riski",
    "hybrid_adfs_service": "AD FS Hizmet Hesabı Riski",
    "hybrid_join_not_observed": "Hibrit Katılım Algılanmadı",
    "rodc_missing_never_reveal": "RODC NeverReveal Listesi Eksik",
    "rodc_privileged_reveal": "RODC Üzerinde Ayrıcalıklı Parola Açığa Çıkması",
    "rodc_broad_revealed_secrets": "RODC Üzerinde Geniş Kapsamlı Gizli Bilgi Önbelleği",
    "rodc_allowed_group_privileged": "RODC Parola Çoğaltma Grubunda Ayrıcalıklı Üye",
    "dmsa_schema_enabled": "Yetkilendirilmiş MSA Şeması Etkin",
    "dmsa_predecessor_link": "dMSA Öncül Hesap Bağlantısı",
    "dmsa_object_present": "Yetkilendirilmiş MSA Nesnesi",
    "sccm_system_management_present": "SCCM System Management Kapsayıcısı",
    "sccm_management_point": "SCCM Yönetim Noktası",
    "windows_laps_not_deployed": "Windows LAPS Dağıtılmamış",
    "windows_laps_plaintext": "Windows LAPS Parolası Düz Metin Olarak Saklanıyor",
}


_TYPE_TOKEN_TRANSLATIONS = {
    "acl": "ACL", "ad": "AD", "admin": "yönetici", "account": "hesap",
    "analysis": "analizi", "anonymous": "anonim", "audit": "denetim",
    "backup": "yedekleme", "broad": "geniş kapsamlı", "certificate": "sertifika",
    "computer": "bilgisayar", "configuration": "yapılandırma", "credential": "kimlik bilgisi",
    "delegation": "yetkilendirme", "disabled": "devre dışı", "enabled": "etkin",
    "encryption": "şifreleme", "excessive": "aşırı", "expired": "süresi dolmuş",
    "group": "grup", "hidden": "gizli", "inactive": "etkin olmayan",
    "legacy": "eski", "machine": "makine", "missing": "eksik", "not": "değil",
    "password": "parola", "policy": "ilkesi", "present": "bulunması",
    "privilege": "ayrıcalık", "privileged": "ayrıcalıklı", "replication": "çoğaltma",
    "risk": "riski", "security": "güvenlik", "service": "hizmet", "shadow": "gölge",
    "signing": "imzalama", "stale": "atıl", "trust": "güven", "unrestricted": "sınırsız",
    "user": "kullanıcı", "vulnerable": "güvenlik açığı", "weak": "zayıf",
    "without": "olmayan", "write": "yazma", "rights": "hakları", "path": "yolu",
}


def risk_type_label(risk_type: Any, language: str = "en") -> str:
    """Return a localized display label without changing the stable type value."""
    value = str(risk_type or "unknown")
    if normalize_language(language) == "en":
        return value
    if value in RISK_TYPE_TITLES_TR:
        return RISK_TYPE_TITLES_TR[value]
    words = [_TYPE_TOKEN_TRANSLATIONS.get(token, token.upper() if len(token) <= 4 else token)
             for token in value.split("_")]
    return " ".join(words).strip().capitalize() or "Bilinmeyen Risk"


_CATEGORY_TR = {
    "identity": "Kimlik", "privilege": "Ayrıcalık", "kerberos": "Kerberos",
    "delegation": "Yetkilendirme", "acl": "ACL", "legacy systems": "Eski Sistemler",
    "dcsync": "DCSync", "password policy": "Parola İlkesi", "trust": "Güven İlişkileri",
    "certificate": "Sertifika", "gpp": "GPP", "laps": "LAPS",
    "vulnerabilities": "Güvenlik Açıkları", "credential access": "Kimlik Bilgisine Erişim",
    "credential_access": "Kimlik Bilgisine Erişim", "attack_path": "Saldırı Yolu",
    "operations_groups": "Operatör Grupları", "protocol_abuse": "Protokol Kötüye Kullanımı",
    "protocol_relay": "Protokol Aktarımı", "persistence_secrets": "Kalıcılık Sırları",
    "trust_hybrid": "Güven ve Hibrit Kimlik", "attack path": "Saldırı Yolu",
    "user": "Kullanıcı", "computer": "Bilgisayar", "group": "Grup", "other": "Diğer",
}

_SEVERITY_TR = {
    "critical": "Kritik", "high": "Yüksek", "medium": "Orta", "low": "Düşük",
    "unknown": "Bilinmiyor", "passed": "Başarılı", "failed": "Başarısız",
    "warning": "Uyarı", "partial": "Kısmi", "open": "Açık",
    "not observed": "Gözlemlenmedi", "active": "Etkin", "disabled": "Devre Dışı",
    "locked": "Kilitli", "yes": "Evet", "no": "Hayır", "ok": "Uygun",
}


def _finding_family(risk_type: str) -> str:
    value = risk_type.lower()
    if any(token in value for token in ("password", "credential", "kerberoast", "asrep", "spn", "gmsa", "krbtgt", "gpp")):
        return "credential"
    if any(token in value for token in ("acl", "privilege", "admin", "dcsync", "operator", "gpo")):
        return "privilege"
    if any(token in value for token in ("delegation", "rbcd", "dmsa")):
        return "delegation"
    if any(token in value for token in ("certificate", "esc", "certifried")):
        return "certificate"
    if any(token in value for token in ("ldap", "ntlm", "smb", "coercion", "nopac", "zerologon", "printnightmare", "petitpotam")):
        return "protocol"
    if any(token in value for token in ("stale", "inactive", "legacy", "eol", "expired", "never_used")):
        return "hygiene"
    return "configuration"


_FINDING_NARRATIVES_TR = {
    "credential": {
        "impact": "Başarılı kötüye kullanım, parola veya kimlik doğrulama materyalinin ele geçirilmesine ve yetkisiz hesap erişimine yol açabilir.",
        "attack_scenario": "Bir saldırgan bu zayıflığı kimlik bilgisi elde etmek, çevrimdışı parola saldırısı yapmak veya daha ayrıcalıklı bir hesaba ilerlemek için kullanabilir.",
        "mitigation": "Etkilenen hesapların parolalarını güvenli biçimde yenileyin, güçlü kimlik doğrulama denetimleri uygulayın ve gereksiz eski yapılandırmaları kaldırın.",
    },
    "privilege": {
        "impact": "Başarılı kötüye kullanım, yetkisiz yetki yükseltmeye ve ayrıcalıklı Active Directory nesnelerinin denetiminin ele geçirilmesine yol açabilir.",
        "attack_scenario": "Düşük ayrıcalıklı bir oturum, tespit edilen hak veya üyelik yolunu izleyerek Etki Alanı Yöneticisi düzeyinde etki oluşturabilir.",
        "mitigation": "Gereksiz ayrıcalıkları kaldırın, grup üyeliklerini ve ACL kayıtlarını en az ayrıcalık ilkesine göre sınırlandırın ve değişiklikleri izleyin.",
    },
    "delegation": {
        "impact": "Yetkilendirme yapılandırmasının kötüye kullanılması, ayrıcalıklı kullanıcıların kimliğine bürünülmesine ve yüksek değerli hizmetlere erişilmesine neden olabilir.",
        "attack_scenario": "Yetkilendirilmiş hesabı veya sistemi ele geçiren bir saldırgan, Kerberos bilet akışını kullanarak ayrıcalıklı bir kullanıcı adına işlem yapabilir.",
        "mitigation": "Gereksiz yetkilendirmeyi kaldırın, kapsamı yalnızca gerekli hizmetlerle sınırlandırın ve ayrıcalıklı hesapları yetkilendirmeye karşı koruyun.",
    },
    "certificate": {
        "impact": "Sertifika hizmetlerinin kötüye kullanılması kalıcı kimlik doğrulama, kullanıcı kimliğine bürünme ve etki alanı düzeyinde yetki elde edilmesiyle sonuçlanabilir.",
        "attack_scenario": "Bir saldırgan tehlikeli şablon veya sertifika yetkisini kullanarak ayrıcalıklı bir kimlik adına geçerli sertifika alabilir.",
        "mitigation": "Sertifika şablonlarını ve CA yetkilerini daraltın, güçlü kayıt onayı uygulayın ve ayrıcalıklı kimlikler adına verilen sertifikaları izleyin.",
    },
    "protocol": {
        "impact": "Protokol zayıflığı kimlik doğrulama aktarımı, uzaktan kod çalıştırma veya etki alanı hizmetlerinin ele geçirilmesi için kullanılabilir.",
        "attack_scenario": "Ağ erişimi olan bir saldırgan, eksik bütünlük denetimini veya savunmasız hizmeti kullanarak kimlik doğrulamayı yönlendirebilir ya da ayrıcalık yükseltebilir.",
        "mitigation": "İlgili sistemleri güncelleyin, protokol imzalama ve kanal bağlama denetimlerini zorunlu kılın ve gereksiz hizmetleri kapatın.",
    },
    "hygiene": {
        "impact": "Atıl veya eski nesneler saldırı yüzeyini genişletir, hesap sahipliğini belirsizleştirir ve bilinen güvenlik açıklarının kullanılma olasılığını artırır.",
        "attack_scenario": "Bir saldırgan unutulmuş hesabı veya güncel olmayan sistemi ilk erişim, kalıcılık ya da yanal hareket amacıyla kullanabilir.",
        "mitigation": "İş gereksinimi olmayan nesneleri devre dışı bırakın veya kaldırın; kalan sistemleri desteklenen sürümlere yükseltin ve sahipliklerini doğrulayın.",
    },
    "configuration": {
        "impact": "Bu yapılandırma Active Directory güvenlik duruşunu zayıflatır ve yetkisiz erişim veya kalıcılık olasılığını artırabilir.",
        "attack_scenario": "Bir saldırgan tespit edilen yapılandırma boşluğunu erişimini genişletmek, savunmaları aşmak veya ortamda kalıcılık sağlamak için kullanabilir.",
        "mitigation": "Yapılandırmayı Microsoft güvenlik temel çizgileri ve en az ayrıcalık ilkesiyle uyumlu hale getirin; düzeltmeyi yeniden taramayla doğrulayın.",
    },
}


def _affected_label(finding: dict[str, Any]) -> str:
    affected = finding.get("affected_object")
    if affected not in (None, "", [], {}):
        return str(affected)
    objects = finding.get("affected_objects")
    if isinstance(objects, list) and objects:
        return ", ".join(str(item) for item in objects[:3])
    return "ilgili Active Directory nesnesi"


def _localize_finding(finding: dict[str, Any], finding_kind: str = "risk") -> dict[str, Any]:
    localized = deepcopy(finding)
    risk_type = str(localized.get("type") or localized.get("risk_type") or finding_kind)
    title = risk_type_label(risk_type, "tr")
    if finding_kind == "misconfiguration" and risk_type in {"misconfiguration", "unknown"}:
        title = "Güvenlik Yapılandırması Bulgusu"
    family = _finding_family(risk_type)
    narrative = _FINDING_NARRATIVES_TR[family]
    affected = _affected_label(localized)

    localized["title"] = title
    localized["description"] = (
        f"{affected} üzerinde “{title}” bulgusu tespit edildi. "
        "Bu bulgu yetkili güvenlik incelemesi kapsamında doğrulanmalı ve önceliğine göre giderilmelidir."
    )
    localized["impact"] = narrative["impact"]
    localized["attack_scenario"] = narrative["attack_scenario"]
    localized["mitigation"] = narrative["mitigation"]
    for key in ("recommendation", "remediation"):
        if key in localized:
            localized[key] = narrative["mitigation"]
    for key in ("business_impact", "risk_explanation", "what_attackers_can_do"):
        if key in localized:
            localized[key] = narrative["impact"]
    if isinstance(localized.get("exploitability"), dict):
        localized["exploitability"] = _localize_structure(localized["exploitability"])
    return localized


def localize_finding_list(
    findings: list[dict[str, Any]] | None,
    language: str = "en",
    *,
    finding_kind: str = "risk",
) -> list[dict[str, Any]]:
    """Return a localized deep copy of report findings."""
    if normalize_language(language) == "en":
        return findings if findings is not None else []
    return [
        _localize_finding(item, finding_kind) if isinstance(item, dict) else deepcopy(item)
        for item in (findings or [])
    ]


TEXT_TRANSLATIONS_TR = {
    "AtilKurt - Active Directory Security Report": "AtilKurt - Active Directory Güvenlik Raporu",
    "Active Directory Security Report": "Active Directory Güvenlik Raporu",
    "Enterprise Active Directory Security Health Check Report generated by AtilKurt": "AtilKurt tarafından oluşturulan kurumsal Active Directory güvenlik sağlık denetimi raporu",
    "Skip to main content": "Ana içeriğe geç",
    "Generated by AtilKurt on": "AtilKurt tarafından oluşturulma tarihi:",
    "Dashboard": "Gösterge Paneli", "Domain Admin Map": "Etki Alanı Yöneticisi Haritası",
    "Domain Admin takeover map": "Etki Alanı Yöneticisi Ele Geçirme Haritası",
    "All Risks": "Tüm Riskler", "Security Risks": "Güvenlik Riskleri",
    "Critical Risks": "Kritik Riskler", "High Risks": "Yüksek Riskler",
    "Medium Risks": "Orta Riskler", "Low Risks": "Düşük Riskler",
    "Privileged Accounts": "Ayrıcalıklı Hesaplar", "Delegation Risks": "Yetkilendirme Riskleri",
    "Password Issues": "Parola Sorunları", "Users": "Kullanıcılar", "Computers": "Bilgisayarlar",
    "Groups": "Gruplar", "Kerberos": "Kerberos", "Paths": "Yollar",
    "Kerberoasting": "Kerberoasting", "Services": "Hizmetler", "GPO": "GPO",
    "DCSync": "DCSync", "Password Policy": "Parola İlkesi", "Trusts": "Güven İlişkileri",
    "Certificates": "Sertifikalar", "GPP Passwords": "GPP Parolaları", "LAPS": "LAPS",
    "Vulnerabilities": "Güvenlik Açıkları", "Advanced Analysis": "Gelişmiş Analiz",
    "AD Hygiene": "AD Sağlığı", "Legacy OS": "Eski İşletim Sistemleri",
    "ACL Security": "ACL Güvenliği", "Compliance": "Uyumluluk",
    "Risk Management": "Risk Yönetimi", "Red Team Playbook": "Red Team Uygulama Rehberi",
    "Blue Team Checklists": "Blue Team Kontrol Listeleri", "Recommendations": "Öneriler",
    "Directory": "Dizin", "Directory Objects": "Dizin Nesneleri",
    "Executive Summary": "Yönetici Özeti", "Executive Summary:": "Yönetici Özeti:",
    "Complete Analysis Summary": "Tam Analiz Özeti", "Analysis": "Analiz",
    "Finding": "Bulgu", "Findings": "Bulgular", "Risks": "Riskler",
    "Risk Distribution": "Risk Dağılımı", "Risks by Category": "Kategoriye Göre Riskler",
    "Top 10 Riskiest Objects": "En Riskli 10 Nesne", "Most Risky Object": "En Riskli Nesne",
    "Quick Wins (0-30 Days)": "Hızlı Kazanımlar (0-30 Gün)",
    "Quick Wins (High Impact, Low Effort)": "Hızlı Kazanımlar (Yüksek Etki, Düşük Efor)",
    "Medium-Term Actions (30-90 Days)": "Orta Vadeli Eylemler (30-90 Gün)",
    "Long-Term Improvements (90+ Days)": "Uzun Vadeli İyileştirmeler (90+ Gün)",
    "Long-Term Improvements": "Uzun Vadeli İyileştirmeler",
    "Type": "Tür", "Type:": "Tür:", "Name": "Ad", "Title": "Başlık",
    "Description": "Açıklama", "Description:": "Açıklama:", "Status": "Durum",
    "Score": "Puan", "Risk Score": "Risk Puanı", "Risk Count": "Risk Sayısı",
    "Risk Count:": "Risk Sayısı:", "Total Risk Score": "Toplam Risk Puanı",
    "Number of Risks": "Risk Sayısı", "Total risks:": "Toplam risk:",
    "Affected": "Etkilenen", "Affected:": "Etkilenen:",
    "Affected (from scan):": "Etkilenen (taramadan):",
    "Affected targets (from scan):": "Etkilenen hedefler (taramadan):",
    "Affected objects:": "Etkilenen nesneler:", "Affected Users:": "Etkilenen Kullanıcılar:",
    "Affected Computers:": "Etkilenen Bilgisayarlar:", "Target Account:": "Hedef Hesap:",
    "Privileged Account:": "Ayrıcalıklı Hesap:", "Privileged Groups:": "Ayrıcalıklı Gruplar:",
    "Service Principal Names:": "Hizmet Sorumlusu Adları:",
    "Impact": "Etki", "Impact:": "Etki:", "Impact &amp; Attack Scenario": "Etki ve Saldırı Senaryosu",
    "Attack Scenario:": "Saldırı Senaryosu:", "Attack scenario:": "Saldırı senaryosu:",
    "Mitigation": "Azaltım", "Mitigation:": "Azaltım:", "Remediation": "Düzeltme",
    "Recommendation:": "Öneri:", "What is the risk?": "Risk nedir?",
    "What an attacker could do:": "Bir saldırgan ne yapabilir:",
    "Details": "Ayrıntılar", "Details:": "Ayrıntılar:", "Actions": "Eylemler",
    "Category:": "Kategori:", "Severity / Likelihood": "Önem Derecesi / Olasılık",
    "Critical": "Kritik", "Critical:": "Kritik:", "High": "Yüksek", "High:": "Yüksek:",
    "Medium": "Orta", "Medium:": "Orta:", "Low": "Düşük", "Low:": "Düşük:",
    "UNKNOWN": "BİLİNMİYOR", "PASSED": "BAŞARILI", "FAILED": "BAŞARISIZ", "WARNING": "UYARI",
    "Unknown": "Bilinmiyor", "Active": "Etkin", "Disabled": "Devre Dışı", "Locked": "Kilitli",
    "YES": "EVET", "Yes": "Evet", "No": "Hayır", "OK": "Uygun", "N/A": "Uygulanamaz",
    "User": "Kullanıcı", "Computer": "Bilgisayar", "Group": "Grup", "Workstation": "İş İstasyonu",
    "Username": "Kullanıcı Adı", "Username:": "Kullanıcı Adı:", "Display Name": "Görünen Ad",
    "Display Name:": "Görünen Ad:", "Computer Name": "Bilgisayar Adı", "Computer Name:": "Bilgisayar Adı:",
    "Group Name": "Grup Adı", "Group Name:": "Grup Adı:", "Distinguished name": "Ayırt Edici Ad",
    "Operating System": "İşletim Sistemi", "Operating System:": "İşletim Sistemi:",
    "Account Status:": "Hesap Durumu:", "Account Created": "Hesap Oluşturulma Tarihi",
    "Account Created:": "Hesap Oluşturulma Tarihi:", "Account Age": "Hesap Yaşı",
    "Account Age:": "Hesap Yaşı:", "Account Age (Days)": "Hesap Yaşı (Gün)", "Age (Days)": "Yaş (Gün)",
    "Last Logon": "Son Oturum Açma", "Last Logon:": "Son Oturum Açma:",
    "Password Last Set:": "Parolanın Son Ayarlanma Tarihi:", "Password Never Expires": "Parola Süresiz",
    "Pwd Never Expires": "Parola Süresiz", "Password Never Changed": "Parola Hiç Değiştirilmemiş",
    "Same Password Since Creation": "Oluşturulduğundan Beri Aynı Parola",
    "Member Count:": "Üye Sayısı:", "Members": "Üyeler", "Admin Count:": "Yönetici İşareti:",
    "SPN": "SPN", "Service Account": "Hizmet Hesabı", "Service Account:": "Hizmet Hesabı:",
    "Privileged": "Ayrıcalıklı", "Privileged:": "Ayrıcalıklı:", "Admin Groups": "Yönetici Grupları",
    "Domain Admins": "Etki Alanı Yöneticileri", "Enterprise Admins": "Kuruluş Yöneticileri",
    "Schema Admins": "Şema Yöneticileri", "Domain Admin Members": "Etki Alanı Yöneticisi Üyeleri",
    "Enterprise Admin Members": "Kuruluş Yöneticisi Üyeleri", "Schema Admin Members": "Şema Yöneticisi Üyeleri",
    "Domain Admin Groups:": "Etki Alanı Yöneticisi Grupları:",
    "Enterprise Admin Groups:": "Kuruluş Yöneticisi Grupları:", "Schema Admin Groups:": "Şema Yöneticisi Grupları:",
    "Disabled Accounts": "Devre Dışı Hesaplar", "Locked Accounts": "Kilitli Hesaplar",
    "Total Disabled Accounts": "Toplam Devre Dışı Hesap", "Total Locked Accounts": "Toplam Kilitli Hesap",
    "Disabled Time": "Devre Dışı Bırakılma Zamanı", "Locked Time": "Kilitlenme Zamanı",
    "Last 10 Days": "Son 10 Gün", "Last 30 Days": "Son 30 Gün", "Last 60 Days": "Son 60 Gün",
    "Last 90 Days": "Son 90 Gün", "Last 10 days": "Son 10 gün", "Last 30 days": "Son 30 gün",
    "Last 60 days": "Son 60 gün", "Last 90 days": "Son 90 gün",
    "Recently Created Accounts": "Yakın Zamanda Oluşturulan Hesaplar",
    "Recently Modified Group Memberships": "Yakın Zamanda Değiştirilen Grup Üyelikleri",
    "Recently Created:": "Yakın Zamanda Oluşturuldu:", "Group Changed:": "Grup Değişikliği:",
    "Group Added": "Gruba Eklendi", "Account Activity": "Hesap Etkinliği",
    "User Details:": "Kullanıcı Ayrıntıları:", "Computer Details:": "Bilgisayar Ayrıntıları:",
    "Group Details:": "Grup Ayrıntıları:", "User Risks": "Kullanıcı Riskleri",
    "Computer Risks": "Bilgisayar Riskleri", "Group Risks": "Grup Riskleri",
    "Password Issues Details": "Parola Sorunlarının Ayrıntıları",
    "Exploitability Information": "Kötüye Kullanılabilirlik Bilgisi",
    "Exploitability Score:": "Kötüye Kullanılabilirlik Puanı:", "Difficulty:": "Zorluk:",
    "Complexity:": "Karmaşıklık:", "Attack Vector:": "Saldırı Vektörü:",
    "Exploitation Commands": "Kötüye Kullanım Komutları", "Exploitation Tools:": "Kötüye Kullanım Araçları:",
    "Public Exploits:": "Herkese Açık Kötüye Kullanımlar:", "Metasploit Modules:": "Metasploit Modülleri:",
    "Proof of Concept:": "Kavram Kanıtı:", "Objective:": "Amaç:", "Prerequisites:": "Ön Koşullar:",
    "Procedure:": "Prosedür:", "Tools:": "Araçlar:", "Detection note:": "Tespit notu:",
    "Detection / SIEM": "Tespit / SIEM", "Detection:": "Tespit:", "Event IDs": "Olay Kimlikleri",
    "Response": "Müdahale", "Response actions": "Müdahale eylemleri",
    "CIS Reference:": "CIS Referansı:", "Microsoft Reference:": "Microsoft Referansı:",
    "LDAP Query:": "LDAP Sorgusu:", "Compliance Reporting": "Uyumluluk Raporlaması",
    "Overall Compliance Score": "Genel Uyumluluk Puanı", "Compliance Score": "Uyumluluk Puanı",
    "Average compliance across all frameworks": "Tüm çerçevelerdeki ortalama uyumluluk",
    "Total Controls:": "Toplam Denetim:", "Passed:": "Başarılı:", "Failed:": "Başarısız:",
    "Warnings:": "Uyarılar:", "Failed Controls:": "Başarısız Denetimler:", "Functions:": "İşlevler:",
    "Articles:": "Maddeler:", "CIS Benchmark": "CIS Karşılaştırma Ölçütü",
    "NIST Cybersecurity Framework": "NIST Siber Güvenlik Çerçevesi",
    "Identify": "Tanımla", "Protect": "Koru", "Detect": "Tespit Et",
    "Respond": "Müdahale Et", "Recover": "Kurtar",
    "Identify -": "Tanımla -", "Protect -": "Koru -", "Detect -": "Tespit Et -",
    "Respond -": "Müdahale Et -", "Recover -": "Kurtar -",
    "Risk Heat Map": "Risk Isı Haritası", "Prioritized Risks by ROI": "Yatırım Getirisine Göre Öncelikli Riskler",
    "Cost:": "Maliyet:", "Effort": "Efor", "Payback:": "Geri Ödeme:", "ROI:": "Yatırım Getirisi:",
    "Timeline": "Zaman Çizelgesi", "Period": "Dönem", "Count": "Sayı",
    "Open paths": "Açık yollar", "All open paths": "Tüm açık yollar", "DA-equivalent": "Etki alanı yöneticisine eşdeğer",
    "Techniques in catalog": "Katalogdaki teknikler", "Open paths evidenced in this domain": "Bu etki alanında kanıtlanan açık yollar",
    "Remaining pentest catalog": "Kalan sızma testi kataloğu", "All": "Tümü", "All Severities": "Tüm Önem Dereceleri",
    "All Types": "Tüm Türler", "Why this becomes Domain Admin:": "Bunun Etki Alanı Yöneticisine dönüşme nedeni:",
    "Starting access a tester assumes:": "Test uzmanının varsaydığı başlangıç erişimi:",
    "Why this finding is in the map:": "Bu bulgunun haritada bulunma nedeni:",
    "Matched finding types:": "Eşleşen bulgu türleri:", "Logical attack chain": "Mantıksal saldırı zinciri",
    "How to break the path": "Yol nasıl kesilir", "No named object": "Adlandırılmış nesne yok",
    "DA equivalent": "Etki alanı yöneticisine eşdeğer", "Enables DA targeting": "Etki alanı yöneticisinin hedeflenmesini sağlar",
    "open": "açık", "not observed": "gözlemlenmedi",
    "ACL Security Analysis": "ACL Güvenlik Analizi", "Legacy Operating Systems": "Eski İşletim Sistemleri",
    "Privilege Escalation Paths": "Yetki Yükseltme Yolları", "Escalation Path": "Yetki Yükseltme Yolu",
    "Misconfiguration Checklist": "Yanlış Yapılandırma Kontrol Listesi",
    "Audit Policy Analysis": "Denetim İlkesi Analizi", "Backup Operators & Sensitive Groups": "Backup Operators ve Hassas Gruplar",
    "Coercion Attacks": "Kimlik Doğrulama Zorlama Saldırıları", "gMSA Configuration": "gMSA Yapılandırması",
    "KRBTGT Account Health": "KRBTGT Hesap Sağlığı", "Lateral Movement": "Yanal Hareket",
    "Machine Account Quota": "Makine Hesabı Kotası", "Replication Metadata": "Çoğaltma Meta Verisi",
    "LDAP Directory Exposure": "LDAP Dizin Açıklığı", "Hidden Privilege & Primary Group": "Gizli Ayrıcalık ve Birincil Grup",
    "Hybrid Identity (Entra / ADFS)": "Hibrit Kimlik (Entra / ADFS)", "RODC Password Replication": "RODC Parola Çoğaltması",
    "Delegated MSA / BadSuccessor": "Yetkilendirilmiş MSA / BadSuccessor", "SCCM Attack Surface": "SCCM Saldırı Yüzeyi",
    "Password Spray Risk": "Parola Püskürtme Riski", "Golden gMSA Exposure": "Golden gMSA Açıklığı",
    "Honeypot & Deception": "Aldatma Sistemleri", "Stale & Dormant Objects": "Atıl Nesneler",
    "Fine-Grained Password Policy Overrides": "Ayrıntılı Parola İlkesi Geçersiz Kılmaları",
    "Kerberos Account Encryption & Delegation Protection": "Kerberos Hesap Şifrelemesi ve Yetkilendirme Koruması",
    "LDAP/NTLM/SMB Security": "LDAP/NTLM/SMB Güvenliği",
    "Kerberoasting & AS-REP Roasting Targets": "Kerberoasting ve AS-REP Roasting Hedefleri",
    "All Security Risks": "Tüm Güvenlik Riskleri", "User-Related Risks": "Kullanıcıyla İlişkili Riskler",
    "Computer-Related Risks": "Bilgisayarla İlişkili Riskler", "Group-Related Risks": "Grupla İlişkili Riskler",
    "Kerberos & Delegation Risks": "Kerberos ve Yetkilendirme Riskleri",
    "Privileged Account Risks": "Ayrıcalıklı Hesap Riskleri", "Service Account Risks": "Hizmet Hesabı Riskleri",
    "GPO Abuse Risks": "GPO Kötüye Kullanım Riskleri", "DCSync Rights Risks": "DCSync Hak Riskleri",
    "Password Policy Issues": "Parola İlkesi Sorunları", "Trust Relationship Risks": "Güven İlişkisi Riskleri",
    "Certificate Service Risks": "Sertifika Hizmeti Riskleri", "GPP Password Risks": "GPP Parola Riskleri",
    "LAPS Configuration Risks": "LAPS Yapılandırma Riskleri", "ZeroLogon Vulnerabilities": "ZeroLogon Güvenlik Açıkları",
    "PrintNightmare Vulnerabilities": "PrintNightmare Güvenlik Açıkları", "PetitPotam Risks": "PetitPotam Riskleri",
    "Shadow Credentials Risks": "Gölge Kimlik Bilgisi Riskleri",
    "Extended LDAP Security (RBCD, sIDHistory, PSO, BitLocker, etc.)": "Genişletilmiş LDAP Güvenliği (RBCD, sIDHistory, PSO, BitLocker vb.)",
    "Password Spray Risk Analysis": "Parola Püskürtme Risk Analizi", "Honeypot & Deception Detection": "Aldatma Sistemi Tespiti",
    "AD CS Extended (ESC5-15, Certifried)": "Genişletilmiş AD CS (ESC5-15, Certifried)",
    "Coercion Attacks (SpoolSample, DFSCoerce, WebClient)": "Kimlik Doğrulama Zorlama Saldırıları (SpoolSample, DFSCoerce, WebClient)",
    "gMSA Configuration Issues": "gMSA Yapılandırma Sorunları", "Lateral Movement Analysis": "Yanal Hareket Analizi",
    "Replication Metadata Analysis": "Çoğaltma Meta Verisi Analizi",
    "Hybrid Identity (Entra Connect / ADFS)": "Hibrit Kimlik (Entra Connect / ADFS)",
    "Privileged Identity Protection": "Ayrıcalıklı Kimlik Koruması",
    "Advanced Security Analysis": "Gelişmiş Güvenlik Analizi", "Password Security Statistics": "Parola Güvenlik İstatistikleri",
    "Admin Group Memberships": "Yönetici Grubu Üyelikleri", "Computer Information": "Bilgisayar Bilgileri",
    "Group Information": "Grup Bilgileri", "Object Details": "Nesne Ayrıntıları",
    "Search Directory Objects": "Dizin Nesnelerinde Ara", "Export to Excel": "Excel'e Aktar",
    "View Details": "Ayrıntıları Görüntüle", "View All Password Issues": "Tüm Parola Sorunlarını Görüntüle",
    "Security Score": "Güvenlik Puanı", "Domain score:": "Etki alanı puanı:",
    "Base Score:": "Temel Puan:", "Final Score:": "Nihai Puan:", "Score:": "Puan:",
    "Domain:": "Etki Alanı:", "Domains:": "Etki Alanları:", "DC:": "Etki Alanı Denetleyicisi:",
    "Domain Controller": "Etki Alanı Denetleyicisi", "Domain / OUs": "Etki Alanı / OU'lar",
    "Domain Admins, Enterprise Admins, etc.": "Etki Alanı Yöneticileri, Kuruluş Yöneticileri vb.",
    "Account lockout / failed logon (brute force)": "Hesap kilitleme / başarısız oturum açma (kaba kuvvet)",
    "Privileged group membership changes": "Ayrıcalıklı grup üyeliği değişiklikleri",
    "Fine-grained password policy overrides": "Ayrıntılı parola ilkesi geçersiz kılmaları",
    "Password spray risk accounts": "Parola püskürtme riski taşıyan hesaplar",
    "Machine account quota": "Makine hesabı kotası", "RODC password replication": "RODC parola çoğaltması",
    "Hidden privilege / primary group": "Gizli ayrıcalık / birincil grup",
    "ACL security (comprehensive)": "ACL güvenliği (kapsamlı)",
    "Kerberos account encryption &amp; delegation protection": "Kerberos hesap şifrelemesi ve yetkilendirme koruması",
    "Domain security (LDAP/NTLM/SMB)": "Etki alanı güvenliği (LDAP/NTLM/SMB)",
    "All Password Issues": "Tüm Parola Sorunları",
    "Not Changed for 90+ Days": "90 Günden Uzun Süredir Değiştirilmemiş",
    "Not Changed for 365+ Days": "365 Günden Uzun Süredir Değiştirilmemiş",
    "Per-finding: Event IDs, Detection/SIEM, Response actions, Remediation.": "Her bulgu için: olay kimlikleri, tespit/SIEM, müdahale eylemleri ve düzeltme.",
    "No disabled Domain Admin or Enterprise Admin accounts were found.": "Devre dışı Etki Alanı Yöneticisi veya Kuruluş Yöneticisi hesabı bulunamadı.",
    "No executive description available.": "Yönetici özeti açıklaması yok.",
    "No exploitable findings for playbook. Run full scan with domain/DC context.": "Uygulama rehberi için kötüye kullanılabilir bulgu yok. Etki alanı/DC bağlamıyla tam tarama çalıştırın.",
    "No scan finding currently maps to a Domain Admin technique. Review the catalog below — several DA paths require host, CA, or network evidence that LDAP cannot always prove.": "Mevcut tarama bulgularından hiçbiri bir Etki Alanı Yöneticisi tekniğiyle eşleşmiyor. Aşağıdaki kataloğu inceleyin; bazı yollar LDAP taramasının tek başına doğrulayamayacağı ana makine, CA veya ağ kanıtı gerektirir.",
    "Absence of evidence is not evidence of absence. These techniques remain on a Domain Admin assessment checklist even when this LDAP-only scan did not observe the supporting attributes.": "Kanıt bulunmaması, riskin bulunmadığını göstermez. Yalnızca LDAP kullanan tarama destekleyici öznitelikleri gözlemlemese bile bu teknikler Etki Alanı Yöneticisi değerlendirme listesinde kalır.",
    "This view is written the way an internal penetration test is scoped: every technique that can become Domain Admin (or a Domain Admin equivalent such as DCSync, KRBTGT, or a privileged certificate). Each open path is backed by findings from this scan. Stages describe attack logic for assessment and defense — not exploit procedures.": "Bu görünüm iç sızma testi kapsamına göre hazırlanmıştır: Etki Alanı Yöneticisine veya DCSync, KRBTGT ya da ayrıcalıklı sertifika gibi eşdeğer bir yetkiye dönüşebilecek tüm teknikleri içerir. Her açık yol bu taramanın bulgularıyla desteklenir. Aşamalar kötüye kullanım prosedürlerini değil, değerlendirme ve savunma için saldırı mantığını açıklar.",
    "\"Group Added\" time is approximate (based on account's last modification time).": "“Gruba Eklenme” zamanı yaklaşıktır (hesabın son değiştirilme zamanına dayanır).",
    "Accounts vulnerable to Kerberoasting and AS-REP roasting attacks. These accounts can be targeted for offline password cracking.": "Kerberoasting ve AS-REP roasting saldırılarına açık hesaplar. Bu hesaplar çevrimdışı parola kırma saldırılarında hedeflenebilir.",
    "Admin Privilege Age:": "Yönetici Ayrıcalığı Yaşı:", "Days Since EOL:": "Destek Sonundan Beri Geçen Gün:",
    "EOL Status:": "Destek Ömrü Durumu:", "Object": "Nesne", "Path:": "Yol:",
    "Privileged Access": "Ayrıcalıklı Erişim", "Privileged Account Targeting": "Ayrıcalıklı Hesapların Hedeflenmesi",
    "Privileged group": "Ayrıcalıklı grup", "Top 5 Critical Risks": "En Önemli 5 Kritik Risk",
    "Analysis of Access Control Lists, Shadow Admins, and privilege escalation paths through ACLs.": "Erişim denetim listelerinin, gölge yöneticilerin ve ACL üzerinden yetki yükseltme yollarının analizi.",
    "Chains of permissions that allow a lower-privilege account to reach Domain Admin (or equivalent) by abusing ACLs step by step.": "Düşük ayrıcalıklı bir hesabın ACL haklarını adım adım kötüye kullanarak Etki Alanı Yöneticisine veya eşdeğer yetkiye ulaşmasını sağlayan izin zincirleri.",
    "Computers running legacy or end-of-life operating systems pose significant security risks.": "Eski veya destek ömrü sona ermiş işletim sistemlerini çalıştıran bilgisayarlar önemli güvenlik riskleri oluşturur.",
    "Dangerous permissions on critical objects (domain, users, groups). Findings are grouped by permission and trustee; each card lists all affected objects.": "Kritik nesnelerdeki tehlikeli izinler (etki alanı, kullanıcılar ve gruplar). Bulgular izin ve güvenlik sorumlusuna göre gruplanır; her kart etkilenen nesneleri listeler.",
    "Initial access (phishing, vuln, or stolen low-privilege creds).": "İlk erişim (oltalama, güvenlik açığı veya çalınmış düşük ayrıcalıklı kimlik bilgileri).",
    "Prioritize credential theft and lateral movement toward Domain Admins / Enterprise Admins.": "Etki Alanı Yöneticileri / Kuruluş Yöneticilerine yönelik kimlik bilgisi hırsızlığını ve yanal hareketi önceliklendirin.",
    "Remove or restrict the dangerous ACL permissions along this path (especially on the first hop). Ensure only Tier-0/Tier-1 accounts have sensitive rights on domain and admin objects.": "Bu yol üzerindeki tehlikeli ACL izinlerini, özellikle ilk adımda, kaldırın veya kısıtlayın. Etki alanı ve yönetici nesnelerinde hassas hakların yalnızca Tier-0/Tier-1 hesaplarında bulunduğunu doğrulayın.",
    "This section contains findings based on CIS Benchmark and Microsoft Security Baseline recommendations.": "Bu bölüm CIS karşılaştırma ölçütü ve Microsoft Güvenlik Temel Çizgisi önerilerine dayanan bulguları içerir.",
    "Users or accounts that have dangerous ACL permissions on critical objects but are": "Kritik nesneler üzerinde tehlikeli ACL izinleri bulunan ancak",
    "not": "üyesi olmayan",
    "members of Domain Admins or Enterprise Admins. They can often achieve the same impact as a Domain Admin if compromised.": "Etki Alanı Yöneticileri veya Kuruluş Yöneticileri üyesi hesaplar. Ele geçirildiklerinde çoğu zaman Etki Alanı Yöneticisiyle aynı etkiyi oluşturabilirler.",
    "Search": "Ara", "Clear": "Temizle", "Export": "Dışa Aktar", "Loading...": "Yükleniyor...",
    "Close": "Kapat", "Export report": "Raporu dışa aktar", "Export risk": "Riski dışa aktar",
    "Filter by severity": "Önem derecesine göre filtrele", "Filter by type": "Türe göre filtrele",
    "Report sections": "Rapor bölümleri", "Scroll to top": "Başa dön", "Search in section": "Bölümde ara",
    "Search report sections": "Rapor bölümlerinde ara", "Search risks": "Risklerde ara",
    "Sort by": "Sırala", "Toggle sidebar": "Kenar çubuğunu aç/kapat", "breadcrumb": "İçerik yolu",
    "Search by username or issue...": "Kullanıcı adı veya soruna göre ara...",
    "Search findings by title, category, or description...": "Bulguları başlık, kategori veya açıklamaya göre ara...",
    "Search in current section...": "Geçerli bölümde ara...", "Search paths by user, group, or description...": "Yolları kullanıcı, grup veya açıklamaya göre ara...",
    "Search risks...": "Risklerde ara...", "Search sections...": "Bölümlerde ara...",
    "Search targets by account, SPN, or description...": "Hedefleri hesap, SPN veya açıklamaya göre ara...",
    "Search users, groups, or computers...": "Kullanıcı, grup veya bilgisayarlarda ara...",
    "Copy section to clipboard": "Bölümü panoya kopyala", "Export this risk": "Bu riski dışa aktar",
    "Print report": "Raporu yazdır",
    "Previous": "Önceki", "Next": "Sonraki", "Page 1": "Sayfa 1",
    "Score (High to Low)": "Puan (Yüksekten Düşüğe)", "Score (Low to High)": "Puan (Düşükten Yükseğe)",
    "Title (A-Z)": "Başlık (A-Z)", "Title (Z-A)": "Başlık (Z-A)",
    "No risks found in this category.": "Bu kategoride risk bulunamadı.",
    "No critical risks found.": "Kritik risk bulunamadı.", "No risky objects found.": "Riskli nesne bulunamadı.",
    "No risks found for this user.": "Bu kullanıcı için risk bulunamadı.",
    "No risks found for this computer.": "Bu bilgisayar için risk bulunamadı.",
    "No risks found for this group.": "Bu grup için risk bulunamadı.",
    "No password issues found.": "Parola sorunu bulunamadı.", "No disabled accounts found.": "Devre dışı hesap bulunamadı.",
    "No locked accounts found.": "Kilitli hesap bulunamadı.", "No recently created accounts found.": "Yakın zamanda oluşturulan hesap bulunamadı.",
    "No recently modified group memberships found.": "Yakın zamanda değiştirilen grup üyeliği bulunamadı.",
    "No Domain Admin members found.": "Etki Alanı Yöneticisi üyesi bulunamadı.",
    "No Enterprise Admin members found.": "Kuruluş Yöneticisi üyesi bulunamadı.",
    "No Schema Admin members found.": "Şema Yöneticisi üyesi bulunamadı.",
    "No actions in this category.": "Bu kategoride eylem yok.", "No quick wins identified.": "Hızlı kazanım belirlenmedi.",
    "No long-term improvements identified.": "Uzun vadeli iyileştirme belirlenmedi.",
    "No analysis data available.": "Analiz verisi yok.", "No heat map data available.": "Isı haritası verisi yok.",
    "No prioritized risks available.": "Önceliklendirilmiş risk yok.", "No ACL security risks detected.": "ACL güvenlik riski algılanmadı.",
    "No privilege escalation paths detected.": "Yetki yükseltme yolu algılanmadı.",
    "No legacy operating systems detected.": "Eski işletim sistemi algılanmadı.",
    "No misconfiguration issues found.": "Yanlış yapılandırma sorunu bulunamadı.",
    "No Kerberoasting or AS-REP roasting targets found.": "Kerberoasting veya AS-REP roasting hedefi bulunamadı.",
    "No CIS Benchmark data available.": "CIS karşılaştırma ölçütü verisi yok.",
    "No NIST CSF data available.": "NIST CSF verisi yok.", "No ISO 27001 data available.": "ISO 27001 verisi yok.",
    "No GDPR data available.": "GDPR verisi yok.",
    "This group has no members.": "Bu grubun üyesi yok.", "This user is not a member of any groups.": "Bu kullanıcı hiçbir grubun üyesi değil.",
    "object(s)": "nesne", "item(s)": "öğe", "more": "daha", "instances": "örnek",
}


_PHRASE_REPLACEMENTS_TR = (
    ("User risk analysis", "Kullanıcı risk analizi"),
    ("Computer risk analysis", "Bilgisayar risk analizi"),
    ("Group risk analysis", "Grup risk analizi"),
    ("Privileged identity protection", "Ayrıcalıklı kimlik koruması"),
    ("Kerberos & delegation", "Kerberos ve yetkilendirme"),
    ("Privilege escalation paths", "Yetki yükseltme yolları"),
    ("Legacy / EOL operating systems", "Eski / destek ömrü sona ermiş işletim sistemleri"),
    ("Service account risks", "Hizmet hesabı riskleri"),
    ("GPO abuse risks", "GPO kötüye kullanım riskleri"),
    ("Password policy issues", "Parola ilkesi sorunları"),
    ("Trust relationship risks", "Güven ilişkisi riskleri"),
    ("certificate risks", "sertifika riskleri"),
    ("stored passwords", "saklanan parolalar"),
    ("configuration", "yapılandırması"),
    ("Stale objects", "Atıl nesneler"),
    ("Audit policy", "Denetim ilkesi"),
    ("attack surface", "saldırı yüzeyi"),
    ("directory exposure", "dizin açıklığı"),
    ("Misconfiguration findings", "Yanlış yapılandırma bulguları"),
    ("Overall AD Security Score", "Genel AD Güvenlik Puanı"),
    ("Privileged Accounts", "Ayrıcalıklı Hesaplar"),
    ("Delegation Risks", "Yetkilendirme Riskleri"),
    ("Password never changed", "Parola hiç değiştirilmemiş"),
    ("No data available", "Veri yok"),
    ("No description.", "Açıklama yok."),
    ("No impact description.", "Etki açıklaması yok."),
    ("No attack scenario.", "Saldırı senaryosu yok."),
    ("No mitigation provided.", "Azaltım önerisi yok."),
    ("Exploitability Score:", "Kötüye Kullanılabilirlik Puanı:"),
    ("Difficulty:", "Zorluk:"),
)


def _translate_simple_text(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return value
    compact = re.sub(r"\s+", " ", stripped)
    translated = TEXT_TRANSLATIONS_TR.get(stripped, TEXT_TRANSLATIONS_TR.get(compact))
    if translated is None:
        translated = _SEVERITY_TR.get(stripped.lower())
    if translated is None:
        translated = _CATEGORY_TR.get(stripped.lower())
    if translated is None:
        translated = stripped
        for source, target in _PHRASE_REPLACEMENTS_TR:
            translated = translated.replace(source, target)

    dynamic_patterns = (
        (r"^Showing (\d+) of (\d+) risks$", r"\1 / \2 risk gösteriliyor"),
        (r"^Showing (\d+) risks$", r"\1 risk gösteriliyor"),
        (r"^Showing (\d+)-(\d+) of (\d+)$", r"\3 kaydın \1-\2 arası gösteriliyor"),
        (r"^Affected Users: (\d+) item\(s\)$", r"Etkilenen Kullanıcılar: \1 öğe"),
        (r"^All Password Issues \((\d+)\)$", r"Tüm Parola Sorunları (\1)"),
        (r"^View All Password Issues \((\d+)\)$", r"Tüm Parola Sorunlarını Görüntüle (\1)"),
        (r"^Security Risks \((\d+)\)$", r"Güvenlik Riskleri (\1)"),
        (r"^Base Score:\s*(.+)$", r"Temel Puan: \1"),
        (r"^Final Score:\s*(.+)$", r"Nihai Puan: \1"),
        (r"^Score:\s*(.+)$", r"Puan: \1"),
        (r"^Domain score:\s*(.+)$", r"Etki alanı puanı: \1"),
        (r"^(\d+) risks?$", r"\1 risk"),
        (r"^(\d+) findings?$", r"\1 bulgu"),
        (r"^(\d+) instances$", r"\1 örnek"),
        (r"^\+?(\d+) more$", r"+\1 daha"),
        (r"^(\d+) days ago$", r"\1 gün önce"),
        (r"^(\d+) days old$", r"\1 günlük"),
        (r"^Page (\d+)$", r"Sayfa \1"),
    )
    for pattern, replacement in dynamic_patterns:
        translated = re.sub(pattern, replacement, translated, flags=re.IGNORECASE)
    leading = value[: len(value) - len(value.lstrip())]
    trailing = value[len(value.rstrip()):]
    return f"{leading}{translated}{trailing}"


_STRUCTURAL_KEYS = frozenset({
    "type", "risk_type", "severity", "severity_level", "status", "object_type",
    "id", "control_id", "article_id", "mitre", "mitre_attack", "ldap_query",
    "dn", "distinguishedName", "sid", "objectSid", "category", "color", "trend",
    "command", "procedure_code", "proof_of_concept", "event_ids", "url",
})
_HUMAN_KEYS = frozenset({
    "title", "label", "description", "impact", "attack_scenario", "mitigation",
    "recommendation", "remediation", "summary", "headline", "control_name",
    "article_name", "objective", "prerequisites", "detection", "detection_note",
    "response", "why", "why_da", "action", "starting_access", "issue", "detail",
    "details_str", "business_impact", "risk_explanation", "what_attackers_can_do",
    "ciso_summary",
})


def _technical_markers(value: str) -> str:
    markers = re.findall(
        r"(?:CVE-\d{4}-\d+|T\d{4}(?:\.\d{3})?|\b\d{4}\b|msDS-[A-Za-z0-9-]+|"
        r"msLAPS-[A-Za-z0-9-]+|ms-Mcs-[A-Za-z0-9-]+|LDAP|SMB|NTLM|Kerberos|S4U2\w+|"
        r"DCSync|KRBTGT|PKINIT|SYSVOL|GPO|RBCD|gMSA|dMSA|ADFS|AD FS|Entra)",
        value,
        flags=re.IGNORECASE,
    )
    return ", ".join(dict.fromkeys(markers))


def _human_value_for_key(key: str, value: str) -> str:
    if key == "ciso_summary":
        patterns = {
            "total": r"(?:analyses,|assessment.*?)(?:\s+)(\d+) risk",
            "critical": r"Critical:\s*(\d+)",
            "high": r"High:\s*(\d+)",
            "identity": r"Identity and privilege-related findings:\s*(\d+)",
            "delegation": r"Delegation-related risks:\s*(\d+)",
        }
        numbers = {}
        for name, pattern in patterns.items():
            match = re.search(pattern, value)
            numbers[name] = int(match.group(1)) if match else 0
        if numbers["total"] == 0 and "did not identify any scored risks" in value:
            return (
                "Bu Active Directory güvenlik değerlendirmesinde puanlanmış risk belirlenmedi. "
                "Denetimlerin düzenli olarak yinelenmesi önerilir."
            )
        parts = [
            "Bu rapor kapsamlı Active Directory güvenlik sağlık denetimini özetler. "
            f"Toplam {numbers['total']} risk belirlenip puanlandı."
        ]
        if numbers["critical"]:
            parts.append(
                f"Kritik bulgu sayısı {numbers['critical']}; bunlar derhal giderilmelidir."
            )
        if numbers["high"]:
            parts.append(
                f"Yüksek önem dereceli bulgu sayısı {numbers['high']}; "
                "bunlar öncelikli olarak ele alınmalıdır."
            )
        if numbers["identity"]:
            parts.append(f"Kimlik ve ayrıcalıkla ilişkili {numbers['identity']} bulgu vardır.")
        if numbers["delegation"]:
            parts.append(f"Yetkilendirmeyle ilişkili {numbers['delegation']} risk vardır.")
        parts.append(
            "Kategori ayrıntıları tam analiz özeti tablosunda ve risk sekmelerinde yer alır."
        )
        return " ".join(parts)
    translated = _translate_simple_text(value)
    if translated != value:
        return translated
    if key in {"control_name", "article_name"}:
        return "Güvenlik denetimi"
    if key in {"recommendation", "remediation", "mitigation"}:
        return "İlgili güvenli yapılandırmayı uygulayın, en az ayrıcalığı sağlayın ve düzeltmeyi yeniden denetleyin."
    if key in {"detection", "detection_note"}:
        markers = _technical_markers(value)
        suffix = f" Teknik göstergeler: {markers}." if markers else ""
        return f"İlgili kimlik doğrulama ve dizin değişikliği olaylarını SIEM üzerinde izleyin.{suffix}"
    if key == "response":
        return "Kaynak hesabı ve sistemi inceleyin, şüpheli oturumları sınırlandırın ve etkilenen kimlik bilgilerini güvenli biçimde yenileyin."
    if key in {"objective", "why", "why_da", "action", "starting_access", "prerequisites"}:
        markers = _technical_markers(value)
        suffix = f" İlgili teknik öğeler: {markers}." if markers else ""
        return f"Bu saldırı yolunun güvenlik etkisini yetkili değerlendirme kapsamında doğrulayın.{suffix}"
    if key in {"description", "detail", "details_str", "summary", "headline"}:
        return "Bu bölümde tarama sırasında elde edilen güvenlik bulguları ve bunların öncelikleri özetlenmektedir."
    return translated


_DA_PATH_NAMES_TR = {
    "dcsync": "DCSync / Dizin Çoğaltma Hakları",
    "kerberoasting": "Ayrıcalıklı veya Zayıf Hizmet Hesaplarında Kerberoasting",
    "asrep": "Ön Kimlik Doğrulaması Kapalı Hesaplarda AS-REP Roasting",
    "unconstrained_delegation": "Sınırlandırılmamış Kerberos Yetkilendirmesi",
    "constrained_delegation": "Ayrıcalıklı Hizmete Kısıtlanmış Yetkilendirme / S4U",
    "rbcd": "Kaynak Tabanlı Kısıtlanmış Yetkilendirme (RBCD)",
    "shadow_credentials": "Gölge Kimlik Bilgileri (Key Credential Link)",
    "adcs": "AD CS Şablon / CA Kötüye Kullanımı (ESC1–ESC16)",
    "gpo_acl": "Etki Alanı Denetleyicileri veya Ayrıcalıklı OU'larda GPO Değişikliği",
    "gpp_passwords": "GPP / SYSVOL İçinde Saklanan Parolalar",
    "acl_generic_all": "Ayrıcalıklı Nesnelerde Tehlikeli ACL",
    "escalation_graph": "Etki Alanı Yöneticilerine Uzanan Zincirleme Yetki Yolu",
    "ops_groups": "Yerleşik Operatör Grupları",
    "laps": "Okunabilir LAPS / Windows LAPS Yerel Yönetici Sırları",
    "machine_quota": "Makine Hesabı Kotası ve Bilgisayar Yazma Yetkisi",
    "nopac": "Makine Kotasıyla noPac Güvenlik Açığı",
    "relay_coerce": "Kimlik Doğrulama Zorlaması ve Eksik LDAP/SMB İmzalama",
    "krbtgt": "Eski KRBTGT Sırrı (Golden Ticket Penceresi)",
    "gmsa_kds": "Golden gMSA / Okunabilir KDS Kök Anahtarı",
    "trusts": "Güven SID Geçmişi / SID Filtreleme Riski",
    "hybrid": "Entra Connect, Seamless SSO veya AD FS Kimliği",
    "rodc": "RODC Üzerinde Önbelleğe Alınmış Ayrıcalıklı Sırlar",
    "dmsa": "Yetkilendirilmiş MSA / BadSuccessor Yolu",
    "sccm": "SCCM Üzerinden Etki Alanı Denetimi",
    "password_spray": "Ayrıcalıklı Hesaplara Parola Püskürtme Yolu",
    "hidden_primary_group": "Birincil Grup Üzerinden Gizli Ayrıcalık",
    "ldap_recon": "Anonim veya Geniş LDAP Dizin Keşfi",
}


def _localize_domain_admin_takeover(data: Any) -> Any:
    localized = deepcopy(data)
    if not isinstance(localized, dict):
        return localized
    summary = localized.get("summary")
    if isinstance(summary, dict):
        count = int(summary.get("open_path_count") or 0)
        summary["headline"] = f"Bu taramada Etki Alanı Yöneticisine ulaşabilen {count} açık saldırı yolu belirlendi."
    for collection in ("open_paths", "unobserved_paths"):
        for path in localized.get(collection) or []:
            if not isinstance(path, dict):
                continue
            path_id = str(path.get("id") or "")
            path["name"] = _DA_PATH_NAMES_TR.get(path_id, risk_type_label(path_id, "tr"))
            path["why_da"] = "Bu yol ayrıcalıklı kimliklere, etki alanı sırlarına veya Etki Alanı Yöneticisine eşdeğer denetime ulaşılmasını sağlayabilir."
            path["starting_access"] = "Taramada gösterilen hesaba, sisteme veya yazma yetkisine erişebilen düşük ayrıcalıklı bir başlangıç oturumu."
            markers = _technical_markers(str(path.get("detection") or ""))
            path["detection"] = "İlgili kimlik doğrulama, çoğaltma ve dizin değişikliği olaylarını izleyin."
            if markers:
                path["detection"] += f" Teknik göstergeler: {markers}."
            for index, stage in enumerate(path.get("stages") or [], 1):
                if isinstance(stage, dict):
                    stage["title"] = f"{index}. yol aşamasını doğrulayın"
                    stage["why"] = "Bu aşama, tespit edilen erişimin daha yüksek ayrıcalığa dönüştüğü mantıksal bağlantıyı gösterir."
                    stage["action"] = "İlgili yetkiyi ve hedef nesneyi inceleyin; gereksiz erişimi kaldırıp sonucu yeniden tarayın."
            if path.get("break_path"):
                path["break_path"] = [
                    "Gereksiz yetkiyi veya yapılandırmayı kaldırın ve en az ayrıcalık ilkesini uygulayın.",
                    "Etkilenen kimlik bilgilerini yenileyin; ilgili olayları SIEM üzerinde izleyin.",
                ]
            for evidence in path.get("evidence_summaries") or []:
                if isinstance(evidence, dict):
                    evidence["title"] = risk_type_label(evidence.get("type"), "tr")
    return localized


def _localize_structure(data: Any, parent_key: str = "") -> Any:
    if isinstance(data, list):
        return [_localize_structure(item, parent_key) for item in data]
    if not isinstance(data, dict):
        if isinstance(data, str) and parent_key in _HUMAN_KEYS:
            return _human_value_for_key(parent_key, data)
        return deepcopy(data)

    if ("type" in data or "risk_type" in data) and any(
        key in data for key in ("title", "description", "impact", "mitigation", "affected_object")
    ):
        return _localize_finding(data)

    localized: dict[Any, Any] = {}
    for key, value in data.items():
        key_text = str(key)
        if parent_key in {"risk_distribution", "risk_by_category"}:
            new_key = _translate_simple_text(key_text)
        else:
            new_key = key
        if key_text in _STRUCTURAL_KEYS:
            localized[new_key] = deepcopy(value)
        elif isinstance(value, str) and key_text in _HUMAN_KEYS:
            localized[new_key] = _human_value_for_key(key_text, value)
        else:
            localized[new_key] = _localize_structure(value, key_text)
    return localized


def localize_report_structure(
    data: Any,
    language: str = "en",
    *,
    structure_kind: str | None = None,
) -> Any:
    """Localize human-readable values while preserving structural identifiers."""
    if normalize_language(language) == "en":
        return data
    if structure_kind == "domain_admin_takeover":
        return _localize_domain_admin_takeover(data)
    return _localize_structure(data)


def localize_export_payload(payload: dict[str, Any], language: str = "en") -> dict[str, Any]:
    """Return a localized JSON export without translating schema or AD identities."""
    if normalize_language(language) == "en":
        return payload
    localized = deepcopy(payload)
    localized["report_language"] = "tr"
    if isinstance(localized.get("risks"), list):
        localized["risks"] = localize_finding_list(localized["risks"], "tr")
    if "executive_summary" in localized:
        localized["executive_summary"] = _localize_structure(localized["executive_summary"])
    if "risk_management_data" in localized:
        localized["risk_management_data"] = _localize_structure(localized["risk_management_data"])
    if "compliance_data" in localized:
        localized["compliance_data"] = _localize_structure(localized["compliance_data"])
    if "domain_admin_takeover" in localized:
        localized["domain_admin_takeover"] = _localize_domain_admin_takeover(
            localized["domain_admin_takeover"]
        )
    # Analyzer slices contain lists of risk-shaped dictionaries.
    for key, value in list(localized.items()):
        if key in {"users", "computers", "groups", "gpos", "risks"}:
            continue
        localized[key] = _localize_structure(value, key)
    return localized


_PLAYBOOK_TITLE_TR = {
    "AS-REP Roasting": "AS-REP Roasting",
    "Kerberoasting": "Kerberoasting",
    "RBCD (Resource-Based Constrained Delegation)": "RBCD (Kaynak Tabanlı Kısıtlanmış Yetkilendirme)",
    "DCSync (Credential Dumping via Replication)": "DCSync (Çoğaltma Yoluyla Kimlik Bilgisi Çıkarma)",
    "NTLM Relay (LDAP/SMB Signing Disabled)": "NTLM Aktarımı (LDAP/SMB İmzalama Kapalı)",
    "GPP Password Extraction": "GPP Parolalarını Çıkarma",
    "Unconstrained Delegation Abuse": "Sınırlandırılmamış Yetkilendirmeyi Kötüye Kullanma",
    "Privileged Account Targeting": "Ayrıcalıklı Hesapların Hedeflenmesi",
    "Shadow Credentials (Key Credential Link)": "Gölge Kimlik Bilgileri (Key Credential Link)",
}


def localize_playbook_value(value: Any, field: str, language: str = "en") -> Any:
    """Localize Purple Team narratives while leaving commands and identifiers intact."""
    if normalize_language(language) == "en" or not isinstance(value, str):
        return value
    if field in {"procedure_code", "tools", "mitre_id", "event_ids", "affected"}:
        return value
    if field in {"title", "finding"}:
        return _PLAYBOOK_TITLE_TR.get(value, _translate_simple_text(value))
    if field == "objective":
        return "Bu tekniğin etkilenen hedeflerde oluşturabileceği kimlik bilgisi erişimi veya yetki yükseltme etkisini kontrollü biçimde doğrulayın."
    if field == "prerequisites":
        return "Yalnızca yetkili test kapsamında, gerekli ağ erişimi ve uygun test hesabıyla çalışın."
    if field in {"detection", "detection_note"}:
        markers = _technical_markers(value)
        suffix = f" Teknik göstergeler: {markers}." if markers else ""
        return f"İlgili güvenlik olaylarını SIEM üzerinde izleyin ve olağandışı kaynakları araştırın.{suffix}"
    if field == "response":
        return "Kaynak hesabı ve sistemi inceleyin, şüpheli erişimi sınırlandırın ve etkilenen kimlik bilgilerini yenileyin."
    if field == "remediation":
        return "İlgili yanlış yapılandırmayı kaldırın, en az ayrıcalığı uygulayın ve düzeltmeyi yeniden taramayla doğrulayın."
    return _translate_simple_text(value)


_SCRIPT_REPLACEMENTS_TR = {
    "Section copied to clipboard!": "Bölüm panoya kopyalandı!",
    "No data to export": "Dışa aktarılacak veri yok",
    "No visible risks to export": "Dışa aktarılacak görünür risk yok",
    "CSV exported:": "CSV dışa aktarıldı:",
    "Showing ${visible} of ${total} risks": "${total} riskin ${visible} kadarı gösteriliyor",
    "Title,Severity,Score,Affected,Description": "Başlık,Önem Derecesi,Puan,Etkilenen,Açıklama",
    "Title": "Başlık", "Severity": "Önem Derecesi", "Affected": "Etkilenen",
    "Description": "Açıklama", "Unknown Risk": "Bilinmeyen Risk", "Unknown": "Bilinmiyor",
    "Showing ": "Gösterilen: ", " of ": " / ", " risks": " risk",
    " days ago": " gün önce", " days old": " günlük",
    "Risk Distribution": "Risk Dağılımı", "Risk Types": "Risk Türleri",
}


def _localize_script(match: re.Match[str]) -> str:
    value = match.group(0)
    if any(marker in value for marker in (
        "Bootstrap v5.3.0",
        "Chart.js v4.4.0",
        "@license lucide",
    )):
        return value
    # Longer phrases can safely occur inside HTML-bearing JavaScript strings;
    # replacing them also covers modal content assembled at click time.
    for source, target in sorted(TEXT_TRANSLATIONS_TR.items(), key=lambda item: len(item[0]), reverse=True):
        if len(source) >= 8 and (" " in source or ":" in source):
            value = value.replace(source, target)
    for source, target in sorted(_SCRIPT_REPLACEMENTS_TR.items(), key=lambda item: len(item[0]), reverse=True):
        pattern = rf"(?P<quote>[\"'`]){re.escape(source)}(?P=quote)"
        value = re.sub(
            pattern,
            lambda literal, replacement=target: (
                f"{literal.group('quote')}{replacement}{literal.group('quote')}"
            ),
            value,
        )
    value = value.replace("risk.type || risk.title", "risk.title || risk.type")
    severity_expression = (
        "({'critical':'Kritik','high':'Yüksek','medium':'Orta','low':'Düşük'}"
        "[String(severity).toLowerCase()] || severity)"
    )
    value = value.replace("${escapeHtml(severity)}", f"${{escapeHtml({severity_expression})}}")
    return value


def _localize_attributes(html: str) -> str:
    def replace(match: re.Match[str]) -> str:
        prefix, quote, value = match.groups()
        return f"{prefix}{quote}{_translate_simple_text(value)}{quote}"

    return re.sub(
        r"((?:placeholder|title|aria-label|alt|content)=)([\"'])(.*?)(?:\2)",
        replace,
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )


def localize_html_document(html: str, language: str = "en") -> str:
    """Translate visible report chrome and browser-side messages to Turkish."""
    if normalize_language(language) == "en":
        return html

    localized = html.replace('<html lang="en">', '<html lang="tr">')
    localized = _localize_attributes(localized)
    localized = re.sub(r"<script\b[^>]*>.*?</script>", _localize_script, localized,
                       flags=re.IGNORECASE | re.DOTALL)
    localized = re.sub(
        r"This view is written the way an internal penetration test is scoped:.*?"
        r"not exploit procedures\.",
        (
            "Bu görünüm iç sızma testi kapsamına göre hazırlanmıştır. Etki Alanı Yöneticisine "
            "veya eşdeğer denetime dönüşebilecek teknikleri, bu taramadaki kanıtlarla birlikte "
            "gösterir. Aşamalar kötüye kullanım prosedürlerini değil, değerlendirme ve savunma "
            "için saldırı mantığını açıklar."
        ),
        localized,
        flags=re.IGNORECASE | re.DOTALL,
    )

    protected: list[str] = []

    def protect(match: re.Match[str]) -> str:
        protected.append(match.group(0))
        return f"\x00ATILKURT_PROTECTED_{len(protected) - 1}\x00"

    localized = re.sub(r"<(?:script|style|pre|code)\b[^>]*>.*?</(?:script|style|pre|code)>", protect, localized,
                       flags=re.IGNORECASE | re.DOTALL)
    localized = re.sub(
        r"(?<=>)([^<>]+)(?=<)",
        lambda match: _translate_simple_text(match.group(1)),
        localized,
    )
    for index, value in enumerate(protected):
        localized = localized.replace(f"\x00ATILKURT_PROTECTED_{index}\x00", value)

    # A few report messages are split by nested markup; translating the stable
    # surrounding fragments keeps the resulting sentence natural.
    fragment_replacements = {
        "No risks found": "Risk bulunamadı",
        "No data available": "Veri yok",
        "Search risks": "Risklerde ara",
        "Search targets": "Hedeflerde ara",
        "Filter by": "Şuna göre filtrele",
        "Sort by": "Şuna göre sırala",
        "Use only in authorized engagements.": "Yalnızca yetkili çalışmalar kapsamında kullanın.",
    }
    for source, target in fragment_replacements.items():
        localized = localized.replace(source, target)
    return localized
