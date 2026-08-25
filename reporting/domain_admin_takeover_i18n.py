"""Turkish narratives for the Domain Admin takeover map.

English source text lives in ``analysis.domain_admin_takeover_playbooks`` and
``analysis.domain_admin_takeover_analyzer`` (``DA_PATH_CATALOG``). Command *bodies*
stay in English; only human-readable labels and narrative fields are localized.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


DA_PATH_NAMES_TR: dict[str, str] = {
    'dcsync': 'DCSync / Dizin Çoğaltma Hakları',
    'kerberoasting': 'Ayrıcalıklı veya Zayıf Hizmet Hesaplarında Kerberoasting',
    'asrep': 'Ön Kimlik Doğrulaması Kapalı Hesaplarda AS-REP Roasting',
    'unconstrained_delegation': 'Sınırlandırılmamış Kerberos Yetkilendirmesi',
    'constrained_delegation': 'Ayrıcalıklı Hizmete Kısıtlanmış Yetkilendirme / S4U',
    'rbcd': 'Kaynak Tabanlı Kısıtlanmış Yetkilendirme (RBCD)',
    'shadow_credentials': 'Gölge Kimlik Bilgileri (Key Credential Link)',
    'adcs': 'AD CS Şablon / CA Kötüye Kullanımı (ESC1–ESC16)',
    'gpo_acl': "Etki Alanı Denetleyicileri veya Ayrıcalıklı OU'larda GPO Değişikliği",
    'gpp_passwords': 'GPP / SYSVOL İçinde Saklanan Parolalar',
    'acl_generic_all': 'Ayrıcalıklı Nesnelerde Tehlikeli ACL',
    'escalation_graph': 'Etki Alanı Yöneticilerine Uzanan Zincirleme Yetki Yolu',
    'ops_groups': 'Yerleşik Operatör Grupları',
    'laps': 'Okunabilir LAPS / Windows LAPS Yerel Yönetici Sırları',
    'machine_quota': 'Makine Hesabı Kotası ve Bilgisayar Yazma Yetkisi',
    'nopac': 'Makine Kotasıyla noPac Güvenlik Açığı',
    'relay_coerce': 'Kimlik Doğrulama Zorlaması ve Eksik LDAP/SMB İmzalama',
    'krbtgt': 'Eski KRBTGT Sırrı (Golden Ticket Penceresi)',
    'gmsa_kds': 'Golden gMSA / Okunabilir KDS Kök Anahtarı',
    'trusts': 'Güven SID Geçmişi / SID Filtreleme Riski',
    'hybrid': 'Entra Connect, Seamless SSO veya AD FS Kimliği',
    'rodc': 'RODC Üzerinde Önbelleğe Alınmış Ayrıcalıklı Sırlar',
    'dmsa': 'Yetkilendirilmiş MSA / BadSuccessor Yolu',
    'sccm': 'SCCM Üzerinden Etki Alanı Denetimi',
    'password_spray': 'Ayrıcalıklı Hesaplara Parola Püskürtme Yolu',
    'hidden_primary_group': 'Birincil Grup Üzerinden Gizli Ayrıcalık',
    'ldap_recon': 'Anonim veya Geniş LDAP Dizin Keşfi',
}


DA_PATH_NARRATIVE_TR: dict[str, dict[str, Any]] = {
    'dcsync': {
        "why_da": 'Çoğaltma hakları, bir güvenilir tarafa KRBTGT ve Domain Admins dahil herhangi bir hesabın parola özetlerini isteme yetkisi verir. Bu, Domain Admins grubuna hiç katılmadan Etki Alanı Yöneticisine eşdeğer bir kontroldür.',
        "starting_access": 'DS-Replication-Get-Changes / Get-Changes-All haklarına zaten sahip olan veya bu hakları elde edebilen bir güvenlik sorumlusu.',
        "detection": 'Çoğaltma denetim erişimi içeren Windows 4662, 4661 ve DC olmayan konaklardan gelen olağandışı LDAP/DRSUAPI trafiği.',
        "stages": [
            {
                "title": 'Çoğaltma güvenilir taraflarını doğrulayın',
                "why": 'Bu genişletilmiş hakları yalnızca küçük bir varsayılan güvenlik sorumlusu kümesi taşımalıdır.',
                "action": 'Etki alanı adlandırma bağlamında Get-Changes / Get-Changes-All taşıyan her DC olmayan, yerleşik olmayan güvenilir tarafı gözden geçirin.',
            },
            {
                "title": 'Güvenilir tarafı DA eşdeğeri kabul edin',
                "why": 'Bu güvenilir tarafın çalınmış veya zorlanmış oturumu KRBTGT ve ayrıcalıklı özetleri isteyebilir.',
                "action": 'Hak kaldırılana kadar bu hesabın ele geçirilmesinin etki alanı ele geçirme anlamına geldiğini varsayın.',
            },
            {
                "title": 'Kaldırın ve izleyin',
                "why": "Kalıcı çoğaltma ACE'leri en yaygın 'gölge DA' durumudur.",
                "action": "ACE'yi kaldırın, KRBTGT'yi iki kez döndürün ve beklenmeyen kaynaklardan gelen 4662 çoğaltmasını uyarın.",
            },
        ],
        "break_path": [
            'DS-Replication-Get-Changes-All hakkını, DC bilgisayar hesabı veya belgelenmiş Entra Connect gMSA olmayan her hesaptan kaldırın.',
            "Yetkisiz bir çoğaltma hakkı bulunduğunda KRBTGT'yi iki kez döndürün.",
        ],
        "poc_roadmap": [
            {
                "step": "Adlandırılmış güvenilir tarafa karşı çoğaltma ACE'sini doğrulayın",
                "detail": "Tarama kanıtı, etki alanı adlandırma bağlamında DS-Replication-Get-Changes ve/veya DS-Replication-Get-Changes-All taşıyan {TARGETS} listeler. Varsayılan sahipler Domain Controller bilgisayar hesapları ve belgelenmiş bir Entra Connect gMSA'dır. Diğer her güvenilir taraf PoC başlangıç noktasıdır.",
                "expected": 'dsacls / Get-Acl çıktısı, etki alanı NC üzerinde GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 ve/veya 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 için güvenilir tarafı gösterir.',
            },
            {
                "step": 'Güvenilir tarafı Domain Admin eşdeğeri kabul edin',
                "detail": 'Bu genişletilmiş haklar, KRBTGT ve Domain Admins dahil etki alanındaki herhangi bir sır için DRS GetNCChanges isteğine yetki verir. Hesabın Domain Admins grubuna eklenmesi gerekmez.',
                "expected": 'Değerlendirme kaydı, {TARGET} ele geçirilmesinin etki alanı ele geçirme anlamına geldiğini belirtir.',
            },
            {
                "step": 'Yetkili DCSync doğrulaması (kanıttan sonra durun)',
                "detail": 'Yetkili bir testte, kanıtlanan güvenilir taraf olarak dizin çoğaltması isteyin ve yalnızca hakkı göstermek için yeterli kanıt (örneğin KRBTGT pwdLastSet / özet varlığı) yakalayın. Tüm etki alanını dökmeyin.',
                "expected": "{TARGET} olarak etki alanı NC'ye karşı başarılı bir GetNCChanges PoC'dir. Ardından ACE'yi kaldırın ve KRBTGT'yi iki kez döndürün.",
            },
            {
                "step": 'Yolu kapatın',
                "detail": "DC olmayan, belgelenmemiş senkronizasyon sorumlularından ACE'yi kaldırın; ardından önceden çoğaltılmış anahtarın ölmesi için KRBTGT'yi çift döndürün.",
                "expected": 'Yeniden tarama varsayılan olmayan çoğaltma güvenilir tarafı göstermez; DC olmayan konaklardan 4662 uyarılır.',
            },
        ],
        "command_labels": {
            'dcsync_dsacls': "dsacls — etki alanı NC çoğaltma ACE'leri",
            'dcsync_powershell_acl': 'PowerShell — çoğaltma genişletilmiş-hak güvenilir tarafları',
            'dcsync_ldap_trustee': 'LDAP — kanıtlanan güvenilir tarafın hâlâ var ve etkin olduğunu doğrulayın',
            'dcsync_secretsdump': 'Impacket — kanıtlanan güvenilir taraf olarak DCSync (yetkili değerlendirme)',
            'dcsync_mimikatz': 'Mimikatz — yalnızca KRBTGT DCSync (yetkili değerlendirme)',
        },
    },
    'kerberoasting': {
        "why_da": 'Hizmet biletleri hizmet hesabı sırrıyla şifrelenir. Bu hesap Domain Admin ise, ayrıcalıklı bir gruba iç içe geçmişse veya bir DC/yönetici iş istasyonunda oturum açabiliyorsa, sırrın ele geçirilmesi bir Etki Alanı Yöneticisi yoludur.',
        "starting_access": 'Herhangi bir kimliği doğrulanmış etki alanı kullanıcısı (TGS-REQ normal bir Kerberos işlemidir).',
        "detection": "Yüksek değerli SPN'ler için olağandışı TGS-REQ hacmi (4769), özellikle RC4 etype 0x17.",
        "stages": [
            {
                "title": "Kullanıcı hesaplarındaki SPN'leri envanterleyin",
                "why": "SPN'li kullanıcı hesapları Kerberoasting hedef kümesidir; bilgisayar hesaplarını kırmak çok daha zordur.",
                "action": "Eski parolalı, RC4 kullanan ve ayrıcalıklı grup üyeliği olan etkin kullanıcı SPN'lerine öncelik verin.",
            },
            {
                "title": 'Hesap sırrını ele geçirin',
                "why": 'Çevrimdışı kırma hesabı kilitlemez ve basit oturum açma izlemesine görünmez.',
                "action": "Kırılabilir herhangi bir ayrıcalıklı SPN'yi, parola döndürülüp SPN kaldırılana veya gMSA'ya taşınana kadar açık DA yolu sayın.",
            },
            {
                "title": "Kimliği DA'ya doğru kullanın",
                "why": "Ele geçirilen hesap zaten DA olabilir veya DA'ya oturum açma, GPO ya da ACL kenarları taşıyabilir.",
                "action": "Yolu kapalı ilan etmeden önce ele geçirilen hesabın gruplarını, kısıtlanmış yetkilendirmesini ve nesne ACL'lerini eşleyin.",
            },
        ],
        "break_path": [
            "Hizmetleri yalnızca AES şifrelemesi olan gMSA/dMSA'ya taşıyın.",
            "Ayrıcalıklı kullanıcılardan SPN'leri kaldırın; kullanıcı SPN'i kalmalıysa uzun, rastgele parolalar zorunlu kılın.",
        ],
        "poc_roadmap": [
            {
                "step": "Bu taramadan SPN'li kullanıcı hesaplarını envanterleyin",
                "detail": "Kerberoasting hedefleri servicePrincipalName taşıyan etkin kullanıcı hesaplarıdır; bilgisayar hesapları değildir. Ayrıcalıklı, eski parolalı veya hâlâ RC4'e izin veren {TARGETS} için öncelik verin.",
                "expected": 'Get-ADUser, listelenen her hedef için servicePrincipalName dolu ve Enabled=$true gösterir.',
            },
            {
                "step": 'Herhangi bir etki alanı kullanıcısı olarak TGS isteyin (normal Kerberos)',
                "detail": 'SPN için TGS-REQ meşru bir Kerberos işlemidir. Bilet hizmet hesabı sırrına şifrelenir ve kilitleme olmadan çevrimdışı saldırıya açıktır.',
                "expected": 'Hedef SPN için 4769 beklenir. Çevrimdışı kırma bant dışıdır; zayıf veya ayrıcalıklı bir SPN zaten açık bir DA yoludur.',
            },
            {
                "step": "Ele geçirilen kimliği Domain Admin'e eşleyin",
                "detail": "Hesap Domain Admins içindeyse, bir DC'de oturum açabiliyorsa veya Tier 0'a GenericAll/WriteDACL/RBCD taşıyorsa, kırılan sır bir DA bitişidir.",
                "expected": '{TARGET} için grup üyeliği, adminCount ve ACL kenarları DA adımı olarak belgelenir.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Hizmeti gMSA/dMSA'ya taşıyın, kullanıcı SPN'lerini düşürün ve yalnızca AES şifrelemeyi zorunlu kılın.",
                "expected": "Yeniden tarama ayrıcalıklı kullanıcı SPN'i göstermez; bu adlar için 4769 hacmi tabana döner.",
            },
        ],
        "command_labels": {
            'kerb_get_aduser': 'PowerShell — kanıtlanan hesapta SPN, şifreleme ve ayrıcalık',
            'kerb_ldap_spn_hunt': "LDAP — tüm etkin kullanıcı SPN'leri (envanter)",
            'kerb_getuserspns': 'Impacket — kanıtlanan SPN hesabı için TGS iste (yetkili değerlendirme)',
            'kerb_rubeus': 'Rubeus — belirli bir kullanıcıyı Kerberoast et (yetkili değerlendirme)',
            'kerb_cme': 'NetExec — LDAP üzerinden Kerberoasting (yetkili değerlendirme)',
        },
    },
    'asrep': {
        "why_da": 'DONT_REQUIRE_PREAUTH, herkesin o hesap için şifreli bir TGT istemesine izin verir. Hesap ayrıcalıklıysa veya parolası ayrıcalıklı bir kimlikte yeniden kullanılıyorsa, bu kimliği doğrulanmamış bir başlangıç konumundan Etki Alanı Yöneticisi yolu olur.',
        "starting_access": "Bir KDC'ye ağ erişimi; AS-REQ için geçerli etki alanı kimlik bilgisi gerekmez.",
        "detection": 'Beklenmeyen kaynaklardan Pre-Authentication Type 0 içeren 4768.',
        "stages": [
            {
                "title": 'DONT_REQUIRE_PREAUTH hesaplarını bulun',
                "why": 'Bu bayrak modern sistemlerde nadiren gerekir ve klasik yüksek sinyal bir bulgudur.',
                "action": 'Ön kimlik doğrulama bayrağı temizlenmiş etkin kullanıcıları, özellikle adminCount=1 olanları numaralandırın.',
            },
            {
                "title": 'Sırrı çevrimdışı ele geçirin',
                "why": 'AS-REP hesap parolasına şifrelenir ve kilitleme tetiklemeden saldırıya açıktır.',
                "action": 'Ele geçirilen ayrıcalıklı bir AS-REP hesabını, bayrak temizlenip parola döndürülene kadar DA eşdeğeri sayın.',
            },
        ],
        "break_path": [
            'Her hesapta DONT_REQUIRE_PREAUTH bayrağını temizleyin.',
            'Etkilenen parolaları döndürün ve ayrıcalıklı kullanıcıları Protected Users grubuna alın.',
        ],
        "poc_roadmap": [
            {
                "step": "Kanıtlanan hesaplarda DONT_REQUIRE_PREAUTH'u doğrulayın",
                "detail": 'userAccountControl biti 0x400000 (DONT_REQUIRE_PREAUTH), herkesin geçerli kimlik bilgisi olmadan {TARGETS} için şifreli bir TGT istemesine izin verir.',
                "expected": 'Get-ADUser DoesNotRequirePreAuth=$true ve Enabled=$true gösterir.',
            },
            {
                "step": 'Parola olmadan AS-REP isteyin',
                "detail": 'AS-REP hesap parolasına şifrelenir. Çevrimdışı kırma hesabı kilitlemez. Hesap ayrıcalıklıysa veya parola bir DA kimliğinde yeniden kullanılıyorsa, bu kimliği doğrulanmamış bir DA yoludur.',
                "expected": 'GetNPUsers/Rubeus, {TARGET} için bir $krb5asrep$ özeti döndürür.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": "DONT_REQUIRE_PREAUTH'u temizleyin, parolayı döndürün ve ayrıcalıklı kullanıcıları Protected Users'a alın.",
                "expected": 'Yeniden tarama ön kimlik doğrulaması kapalı etkin kullanıcı göstermez; 4768 Pre-Authentication Type 0 kaybolur.',
            },
        ],
        "command_labels": {
            'asrep_get_aduser': 'PowerShell — kanıtlanan hesapta ön kimlik doğrulama bayrağı',
            'asrep_hunt': 'PowerShell — etki alanı genelinde DONT_REQUIRE_PREAUTH envanteri',
            'asrep_getnpusers': 'Impacket — kanıtlanan hesap için parola olmadan AS-REP (yetkili değerlendirme)',
            'asrep_rubeus': 'Rubeus — belirli bir kullanıcıyı AS-REP roast et (yetkili değerlendirme)',
        },
    },
    'unconstrained_delegation': {
        "why_da": "Sınırlandırılmamış yetkilendirme, kullanıcı yetkilendirilmiş aracıya kimlik doğruladığında kullanıcının TGT'sini bellekte saklar. Bir Domain Admin (veya DC üzerinden KRBTGT) kimlik doğrulamaya zorlanabilirse, o TGT Etki Alanı Yöneticisidir.",
        "starting_access": 'Sınırlandırılmamış yetkilendirme için güvenilen bir konak veya hesabın ele geçirilmesi, artı ayrıcalıklı bir TGT zorlama veya bekleme yolu.',
        "detection": 'İletilmiş TGT seçenekli 4769; DA hesaplarından sınırlandırılmamış konaklarda 4624.',
        "stages": [
            {
                "title": 'DC olmayan sınırlandırılmamış temsilcileri belirleyin',
                "why": 'Domain Controllers tasarım gereği bayrağa sahiptir; diğer her konak ek bir TGT önbelleğidir.',
                "action": 'Domain Controllers olmayan TRUSTED_FOR_DELEGATION bilgisayar/kullanıcılarını listeleyin.',
            },
            {
                "title": 'O konakta ayrıcalıklı bir TGT elde edin',
                "why": "Yazdırma biriktiricisi, diğer zorlama veya bir yöneticinin paylaşımı gezinmesi DA TGT'sini belleğe bırakabilir.",
                "action": 'Ayrıcalıklı kullanıcıların dokunduğu herhangi bir sınırlandırılmamış üye sunucuyu DA iniş bölgesi kabul edin.',
            },
        ],
        "break_path": [
            "DC'ler dışında her yerde sınırlandırılmamış yetkilendirmeyi kapatın.",
            'Kalan ihtiyaçları kısıtlanmış veya kaynak tabanlı kısıtlanmış yetkilendirmeye taşıyın.',
            "Ayrıcalıklı kullanıcıları Protected Users'a ekleyerek TGT'lerinin yetkilendirilmesini engelleyin.",
        ],
        "poc_roadmap": [
            {
                "step": "Domain Controllers'ı ek sınırlandırılmamış temsilcilerden ayırın",
                "detail": "TRUSTED_FOR_DELEGATION DC'lerde beklenir. Tarama kanıtı {TARGETS}, kendisine kimlik doğrulayan herkesin TGT'sini önbelleğe alan bir üye sunucu veya kullanıcıdır.",
                "expected": 'Get-ADComputer/User TrustedForDelegation=$true gösterir ve nesne Domain Controllers içinde değildir.',
            },
            {
                "step": "Ayrıcalıklı bir TGT'nin o konağa inebileceğini gösterin",
                "detail": "Yazdırma biriktiricisi, diğer zorlama veya bir yöneticinin paylaşımı gezinmesi belleğe bir DA TGT'si bırakır. Protected Users bunu engeller; DA hesaplarında bu grubun yokluğu PoC'nin parçasıdır.",
                "expected": "Konak DA iniş bölgesi olarak belgelenir; iletilmiş-TGT 4769 ve DA SID'lerinden 4624 algılama çiftidir.",
            },
            {
                "step": 'Yolu kapatın',
                "detail": "DC'ler dışında her yerde sınırlandırılmamış yetkilendirmeyi temizleyin; kalanları kısıtlanmış veya RBCD'ye taşıyın; Tier 0'ı Protected Users'a ekleyin.",
                "expected": 'Yeniden tarama yalnızca TRUSTED_FOR_DELEGATION taşıyan DC bilgisayar hesaplarını gösterir.',
            },
        ],
        "command_labels": {
            'unconst_computers': "PowerShell — DC'ler hariç sınırlandırılmamış bilgisayar hesapları",
            'unconst_target': 'PowerShell — kanıtlanan sınırlandırılmamış nesne',
            'unconst_finddelegation': 'Impacket — sınırlandırılmamış/kısıtlanmış/RBCD temsilcilerini listele (yetkili değerlendirme)',
            'unconst_rubeus_monitor': "Rubeus — sınırlandırılmamış konakta gelen TGT'leri izle (yetkili değerlendirme)",
        },
    },
    'constrained_delegation': {
        "why_da": "Kısıtlanmış yetkilendirme, güvenilen hesabın izin verilen SPN'lere başka bir kullanıcı olarak hizmet bileti istemesine izin verir. Bu SPN'ler bir domain controller, LDAP, DC üzerinde CIFS veya başka bir Tier 0 hizmeti içeriyorsa sonuç Etki Alanı Yöneticisi eşdeğeri kimliğe bürünmedir.",
        "starting_access": "Bir DC veya başka bir Tier 0 SPN'e kısıtlanmış yetkilendirme için güvenilen hesabın ele geçirilmesi.",
        "detection": "Beklenmeyen aracılardan DC SPN'lerine yönelik 4769 S4U (Service-for-User) trafiği.",
        "stages": [
            {
                "title": 'DC olmayanlarda msDS-AllowedToDelegateTo envanteri',
                "why": 'Yetkilendirmeye izin verilen liste, çalınmış kısıtlanmış-yetkilendirme hesabının etki yarıçapıdır.',
                "action": "İzin verilen SPN'leri bir domain controller üzerinde ldap/, cifs/ veya krbtgt/ içeren her konağı işaretleyin.",
            },
            {
                "title": 'Güvenilen hesabı DA basamak taşı kabul edin',
                "why": 'S4U2Self artı S4U2Proxy, ayrıcalıklı bir kullanıcı olarak kullanılabilir bir hizmet bileti üretir.',
                "action": "Hibe kaldırılana kadar bu hesabın ele geçirilmesinin listelenen her SPN'in denetimi anlamına geldiğini varsayın.",
            },
        ],
        "break_path": [
            "DC ve diğer Tier 0 SPN'lere kısıtlanmış yetkilendirmeyi kaldırın.",
            'Sınırlandırılmamış tarzı geniş hibeler yerine belgelenmiş sahipli kaynak tabanlı kısıtlanmış yetkilendirme kullanın.',
            "Ayrıcalıklı kullanıcıları Protected Users'a alarak yetkilendirilmelerini engelleyin.",
        ],
        "poc_roadmap": [
            {
                "step": 'Kanıtlanan hesapta msDS-AllowedToDelegateTo okuyun',
                "detail": "{TARGETS}, listelenen SPN'lere S4U2Self/S4U2Proxy hizmet biletleri isteyebilir. Bir Domain Controller üzerinde ldap/, cifs/, http/ veya host/ Domain Admin eşdeğeri kimliğe bürünmedir.",
                "expected": 'Get-ADObject, AllowedToDelegateTo içinde bir DC veya başka Tier 0 SPN gösterir.',
            },
            {
                "step": "S4U'nun o SPN'e ayrıcalıklı kullanıcı olarak kimliğe bürünebileceğini kanıtlayın",
                "detail": "Güvenilen hesabın ele geçirilmesi yeterlidir; KDC, kimliğe bürünülen kullanıcı olarak izin verilen SPN'e hizmet bileti verir.",
                "expected": "Administrator olarak bir DC SPN'ine karşı getST/Rubeus s4u yetkili PoC'dir. Ardından hibeyi kaldırın.",
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Tier 0 SPN'lere kısıtlanmış yetkilendirmeyi kaldırın; belgelenmiş sahipli kaynak tabanlı hibeleri tercih edin; DA için Protected Users.",
                "expected": "Yeniden tarama DC SPN'lerine işaret eden DC olmayan allowed-to-delegate girişi göstermez.",
            },
        ],
        "command_labels": {
            'const_allowed': "PowerShell — kanıtlanan nesnede yetkilendirmeye izin verilen SPN'ler",
            'const_hunt': 'PowerShell — boş olmayan herhangi bir msDS-AllowedToDelegateTo',
            'const_getst': "Impacket — bir DC SPN'ine S4U2Self/S4U2Proxy (yetkili değerlendirme)",
            'const_rubeus_s4u': 'Rubeus — kısıtlanmış yetkilendirme S4U (yetkili değerlendirme)',
        },
    },
    'rbcd': {
        "why_da": 'RBCD, seçilen bir hesabın hedef hizmete kullanıcı olarak kimliğe bürünmesine izin verir. Bir DC veya ayrıcalıklı sunucuya yöneltildiğinde Etki Alanı Yöneticisi eşdeğeri hizmet biletleri üretir.',
        "starting_access": 'Yüksek değerli bir bilgisayarda msDS-AllowedToActOnBehalfOfOtherIdentity yazma erişimi veya saldırganın zaten denetlediği bir bilgisayar hesabı.',
        "detection": 'msDS-AllowedToActOnBehalfOfOtherIdentity değişiklikleri (5136) ve olağandışı S4U etkinliği.',
        "stages": [
            {
                "title": 'Yazılabilir bilgisayar nesneleri veya mevcut RBCD hibelerini bulun',
                "why": 'MachineAccountQuota veya bir bilgisayarda GenericWrite, RBCD özniteliğini ayarlamak için yeterlidir.',
                "action": "DC'ler, PKI, ADFS ve yönetici iş istasyonlarında msDS-AllowedToActOnBehalfOfOtherIdentity'yi gözden geçirin.",
            },
            {
                "title": 'O kaynağa ayrıcalıklı bir kullanıcı olarak kimliğe bürünün',
                "why": 'S4U2Self/S4U2Proxy ardından o kullanıcı olarak kullanılabilir bir hizmet bileti üretir.',
                "action": 'Bir DC veya DA iş istasyonuna yönelik herhangi bir RBCD hibesini açık DA yolu sayın.',
            },
        ],
        "break_path": [
            'MachineAccountQuota değerini 0 yapın.',
            'Beklenmeyen msDS-AllowedToActOnBehalfOfOtherIdentity değerlerini denetleyin ve temizleyin.',
            'Authenticated Users ve benzerlerinden bilgisayar nesnelerinde GenericWrite/GenericAll kaldırın.',
        ],
        "poc_roadmap": [
            {
                "step": "Yüksek değerli bir bilgisayarda msDS-AllowedToActOnBehalfOfOtherIdentity'yi doğrulayın",
                "detail": '{TARGETS} üzerindeki RBCD, listelenen sorumluların o konağa kullanıcı olarak kimliğe bürünmesine izin verir. Bir DC, PKI veya DA iş istasyonuna yöneltildiğinde bu bir DA hizmet biletidir.',
                "expected": 'Öznitelik boş değildir veya bir güvenilir tarafın bilgisayar nesnesinde GenericWrite/GenericAll hakkı vardır.',
            },
            {
                "step": 'Hibe henüz yoksa yazma ilkelini gösterin',
                "detail": 'MachineAccountQuota > 0 artı bir DC/bilgisayarda GenericWrite, denetlenen bir bilgisayar hesabından RBCD ayarlamak için yeterlidir.',
                "expected": "PoC, Tier 0'a yönelik mevcut bir RBCD ACE'sini veya birini oluşturabilecek bir yazma yolunu kaydeder.",
            },
            {
                "step": 'Kaynağa ayrıcalıklı kullanıcı olarak yetkili S4U',
                "detail": "İzin verilen sorumludan S4U2Self/S4U2Proxy, {TARGET}'e Administrator olarak kullanılabilir bir CIFS/LDAP bileti üretir.",
                "expected": "Hedef konağa DA sınıfı bir kullanıcı olarak hizmet bileti PoC'dir. Ardından özniteliği temizleyin.",
            },
        ],
        "command_labels": {
            'rbcd_read': 'PowerShell — kanıtlanan bilgisayarda RBCD özniteliği',
            'rbcd_hunt': 'PowerShell — RBCD ayarlı herhangi bir bilgisayar',
            'rbcd_quota': 'PowerShell — MachineAccountQuota (RBCD eşlik ilkeli)',
            'rbcd_impacket_write': 'Impacket — denetlenen bilgisayardan RBCD yaz (yetkili değerlendirme)',
            'rbcd_getst': 'Impacket — RBCD hedefine Administrator olarak S4U bileti (yetkili değerlendirme)',
        },
    },
    'shadow_credentials': {
        "why_da": "Yeni bir anahtar kimlik bilgisi, saldırganın parolayı bilmeden o nesne olarak PKINIT ile kimlik doğrulamasına izin verir. Bir Domain Admin, DC bilgisayar hesabı veya KRBTGT'ye komşu kimliklere yazıldığında bu etki alanı ele geçirmedir.",
        "starting_access": 'GenericWrite/GenericAll dahil bir kullanıcı veya bilgisayarda msDS-KeyCredentialLink yazma erişimi.',
        "detection": 'adminCount=1 nesnelerde msDS-KeyCredentialLink üzerinde LDAP 5136; beklenmeyen PKINIT 4768.',
        "stages": [
            {
                "title": 'msDS-KeyCredentialLink yazabilenleri belirleyin',
                "why": "Birçok helpdesk veya bilgisayar yönetimi ACL'i yanlışlıkla bu özniteliği içerir.",
                "action": "Ayrıcalıklı kullanıcılarda, DC'lerde ve AdminSDHolder şablonunda GenericWrite/WriteProperty kontrol edin.",
            },
            {
                "title": 'PKINIT üzerinden hedef olarak kimlik doğrulayın',
                "why": 'Eklenen cihaz anahtarı kaldırılıp hesap düzeltilene kadar geçerli bir kimlik bilgisidir.',
                "action": 'Ayrıcalıklı nesnelerdeki açıklanamayan KeyCredentialLink değerlerini doğrulanmış kalıcılık kabul edin.',
            },
        ],
        "break_path": [
            'Ayrıcalıklı nesnelerdeki beklenmeyen msDS-KeyCredentialLink değerlerini kaldırın.',
            'Bu özniteliğe yazma erişimini yalnızca Identity/PAM sistemleriyle sınırlayın.',
        ],
        "poc_roadmap": [
            {
                "step": 'msDS-KeyCredentialLink yazabilenleri belirleyin',
                "detail": "{TARGETS} (veya AdminSDHolder) üzerinde GenericWrite/GenericAll/WriteProperty, bir cihaz anahtarı eklemek için yeterlidir. Bir DA kullanıcısına, DC bilgisayarına veya KRBTGT'ye komşu nesneye yazıldığında bu etki alanı ele geçirmedir.",
                "expected": 'ACL incelemesi, ayrıcalıklı bir nesnede msDS-KeyCredentialLink yazma hakkı olan Tier 0 olmayan bir güvenilir taraf gösterir.',
            },
            {
                "step": 'Açıklanamayan KeyCredentialLink değerlerini kalıcılık kabul edin',
                "detail": 'Bir anahtar kimlik bilgisi, sahibinin parola olmadan o nesne olarak PKINIT ile kimlik doğrulamasına izin verir.',
                "expected": 'Get-ADObject, eşleşen bir Windows Hello/PAM değişiklik bileti olmadan ayrıcalıklı bir nesnede msDS-KeyCredentialLink dolu gösterir.',
            },
            {
                "step": 'Hedef olarak yetkili PKINIT, ardından anahtarı kaldırın',
                "detail": 'Yetkili bir testte bir anahtar ekleyin, kimlik doğrulayın, ardından hemen silin ve döndürün.',
                "expected": "{TARGET} olarak PKINIT 4768 PoC'dir. adminCount=1 nesnelerdeki beklenmeyen anahtarlar kaldırılır.",
            },
        ],
        "command_labels": {
            'shadow_read': 'PowerShell — kanıtlanan nesnede KeyCredentialLink',
            'shadow_hunt': 'PowerShell — anahtar kimlik bilgisi bulunan ayrıcalıklı nesneler',
            'shadow_certipy': 'Certipy — kanıtlanan hesaba karşı Shadow Credentials (yetkili değerlendirme)',
            'shadow_whisker': 'Whisker — anahtar kimlik bilgisi ekle (yetkili değerlendirme)',
        },
    },
    'adcs': {
        "why_da": 'Ayrıcalıklı veya rastgele bir kullanıcı olarak etki alanı kimlik doğrulamasına izin veren bir sertifika Etki Alanı Yöneticisi eşdeğeridir. ESC1/ESC6/ESC8/ESC9/ESC15 en yaygın DA sınıfı sorunlardır.',
        "starting_access": "Zayıf bir şablonda kayıt hakları veya ESC'ye bağlı olarak bir web kayıt uç noktasına NTLM zorlaması.",
        "detection": 'Ayrıcalıklı UPN/SAN değerleri için sertifika düzenleme; CA denetim olayları 4886/4887.',
        "stages": [
            {
                "title": 'Tehlikeli şablonları ve CA bayraklarını belirleyin',
                "why": 'Kayıt sahibinin sağladığı SAN artı Client Authentication EKU klasik bir ESC1 DA yoludur.',
                "action": "SAN'a izin veren, yönetici onayı olmayan ve Domain Users/computers'a kayıt veren şablonları gözden geçirin.",
            },
            {
                "title": 'Ayrıcalıklı bir kimlik olarak sertifika alın',
                "why": "Schannel veya PKINIT ardından o kimliği LDAP/CIFS'e doğrular.",
                "action": 'Bir Domain Admin adlandırmaya izin veren kaydedilebilir herhangi bir şablon açık bir DA yoludur.',
            },
        ],
        "break_path": [
            "Kullanılmayan şablonları kapatın; yönetici onayı zorunlu kılın; kayıt sahibinin sağladığı SAN'ı kaldırın.",
            'LDAP channel binding zorunlu kılın; HTTP web kaydını kapatın veya yalnızca Kerberos zorunlu kılın.',
            "Şema v1 şablonlarını (ESC15) yükseltin ve EDITF_ATTRIBUTESUBJECTALTNAME2'yi kapatın.",
        ],
        "poc_roadmap": [
            {
                "step": 'Kanıtlanan şablon/CA sorununu sınıflandırın (ESC1–ESC16)',
                "detail": 'Tarama kanıtı {TARGETS}, ayrıcalıklı bir kullanıcı olarak etki alanı kimlik doğrulamasında kullanılabilir bir sertifika düzenleyebilen bir şablon veya CA bayrağıdır. ESC1 (kayıt sahibi SAN + Client Auth), ESC6/ESC15 (EDITF_ATTRIBUTESUBJECTALTNAME2 / şema v1) ve ESC8 (HTTP web kaydı + NTLM) olağan DA sınıfı yollardır.',
                "expected": 'certipy find / Certify, şablonu geniş bir grup için kayıt haklarıyla zayıf olarak listeler.',
            },
            {
                "step": 'Bir Domain Admin UPN/SAN istenebileceğini gösterin',
                "detail": "Bir DA hesabını adlandıran bir sertifika PKINIT veya Schannel ile LDAP/CIFS'e kimlik doğrular.",
                "expected": "Düşük ayrıcalıklı bir kullanıcı olarak Administrator@{DOMAIN} için sertifika üreten kayıt PoC'dir.",
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Kullanılmayan şablonları kapatın, yönetici onayı zorunlu kılın, kayıt sahibi SAN'ını kaldırın, LDAP channel binding zorunlu kılın ve HTTP kaydını kapatın veya yalnızca Kerberos.",
                "expected": "Yeniden tarama kaydedilebilir DA sınıfı şablon göstermez; ayrıcalıklı SAN'lar için CA 4886/4887 uyarılır.",
            },
        ],
        "command_labels": {
            'adcs_certutil_templates': 'certutil — yayımlanmış şablonlar',
            'adcs_certipy_find': 'Certipy — zayıf şablonları numaralandır (salt okunur)',
            'adcs_ldap_template': 'PowerShell — kanıtlanan şablon nesnesi',
            'adcs_certipy_req': 'Certipy — ayrıcalıklı UPN olarak sertifika iste (yetkili değerlendirme, ESC1 sınıfı)',
            'adcs_certipy_auth': 'Certipy — düzenlenen PFX ile kimlik doğrula (yetkili değerlendirme)',
        },
    },
    'gpo_acl': {
        "why_da": "DC'lere dağıtılan anında zamanlanmış görevler, oturum açma betikleri veya yerel yönetici GPP, bir Domain Controller üzerinde SYSTEM olarak çalışır — bu Etki Alanı Yöneticisidir.",
        "starting_access": "Domain Controllers, Domain Admins veya bir Tier 0 OU'ya bağlı bir GPO üzerinde WriteDACL/WriteOwner/GenericWrite.",
        "detection": "GPC nesnelerinde 5136; beklenmeyen SYSVOL dosya yazmaları; GPO sürüm değişikliğinden kısa süre sonra DC'lerde 4688.",
        "stages": [
            {
                "title": "Tier 0'a bağlı GPO'ları bulun",
                "why": 'Default Domain Controllers Policy ve OU=Domain Controllers üzerindeki herhangi bir GPO en yüksek değerlidir.',
                "action": "Bu GPO'larda Edit settings, Delete veya Modify security taşıyan güvenilir tarafları listeleyin.",
            },
            {
                "title": 'Ayrıcalıklı bir oturum açma veya hizmet itin',
                "why": "DC'deki sonraki gpupdate saldırgan denetimli kodu SYSTEM olarak çalıştırır.",
                "action": "DC'ye bağlı bir GPO'nun yönetici olmayan herhangi bir düzenleyicisini açık DA yolu sayın.",
            },
        ],
        "break_path": [
            'GPO düzenleme haklarını küçük bir Tier 0 grubuyla sınırlayın.',
            'GPO denetimini (5136/5137) ve SYSVOL bütünlük izlemeyi etkinleştirin.',
        ],
        "poc_roadmap": [
            {
                "step": "Domain Controllers veya diğer Tier 0 OU'lara bağlı GPO'ları belirleyin",
                "detail": "Tarama kanıtı {TARGETS}, DC'lere veya ayrıcalıklı kullanıcılara uygulanan bir GPO'yu düzenleyebilir. Anında görevler, başlangıç betikleri veya GPP yerel yönetici DC üzerinde SYSTEM olarak çalışır.",
                "expected": "Get-GPOReport / GPMC, DC'ye bağlı bir GPO'da Tier 0 olmayan bir güvenilir taraf için Edit settings, Modify security veya Delete gösterir.",
            },
            {
                "step": "Sonraki gpupdate'in DC'de SYSTEM olarak kod yürütme olduğunu gösterin",
                "detail": "Bu Domain Admin'dir. Üretimde görev eklemeyin; ACL'yi ve bağlantıyı belgelendirin.",
                "expected": 'PoC, bir yük değil, ACL artı OU=Domain Controllers (veya Default Domain Controllers Policy) bağlantısıdır.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": 'GPO düzenlemeyi küçük bir Tier 0 grubuyla sınırlayın; 5136/5137 ve SYSVOL bütünlük izlemeyi etkinleştirin.',
                "expected": "Yeniden tarama DC'ye bağlı GPO'larda yalnızca Tier 0 düzenleyicileri gösterir.",
            },
        ],
        "command_labels": {
            'gpo_get_gpo': 'PowerShell — GPO kimliği ve durumu',
            'gpo_acl': "PowerShell — kanıtlanan GPO'yu kim düzenleyebilir",
            'gpo_links': "PowerShell — GPO'nun nereye bağlı olduğu",
            'gpo_sysvol_list': 'SMB — SYSVOL GPO içeriğini listele (salt okunur kanıt)',
            'gpo_sharpgpoabuse_note': 'Yetkili değerlendirme notu — DC zamanlanmış görevi dağıtmayın',
        },
    },
    'gpp_passwords': {
        "why_da": "Groups.xml içindeki cpassword yayımlanmış bir AES anahtarıyla kurtarılabilir. Saklanan hesap bir domain admin, bir DC'nin yerel yöneticisi veya yaygın yeniden kullanılan ayrıcalıklı bir parolaysa, bu standart bir kullanıcıdan DA yoludur.",
        "starting_access": 'SYSVOL okuyabilen herhangi bir kimliği doğrulanmış kullanıcı (varsayılan).',
        "detection": "Olağandışı iş istasyonlarından Groups.xml/Services.xml erişimi; SYSVOL'da kalan cpassword dizeleri.",
        "stages": [
            {
                "title": 'SYSVOL GPP dosyalarını okuyun',
                "why": 'Authenticated Users neredeyse her etki alanında SYSVOL okuyabilir.',
                "action": 'Şifresi çözülmüş herhangi bir GPP kimlik bilgisini, kullanıldığı her yerde döndürülene kadar canlı kabul edin.',
            },
            {
                "title": 'Ele geçirilen kimliği yeniden kullanın',
                "why": 'Bu parolalar sıklıkla domain-join, yerel yönetici veya DC oturum açmalı hizmet hesaplarıdır.',
                "action": "Ele geçirilen hesabı ayrıcalıklı gruplara ve DC'lerde gelen yönetici haklarına eşleyin.",
            },
        ],
        "break_path": [
            "GPP kimlik bilgisi XML'ini SYSVOL'dan ve tüm GPO yedeklerinden silin.",
            'Ele geçirilen her parolayı döndürün; GPO içinde asla sır saklamayın.',
        ],
        "poc_roadmap": [
            {
                "step": "SYSVOL'da cpassword içeren Groups.xml / Services.xml bulun",
                "detail": 'Authenticated Users varsayılan olarak SYSVOL okuyabilir. Tarama kanıtı {TARGETS}, AES anahtarı herkese açık bilinen bir GPO tercih dosyasıdır.',
                "expected": 'XML bir cpassword özniteliği içerir; gpp-decrypt düz metni kurtarır.',
            },
            {
                "step": "Ele geçirilen hesabı DC oturum açma veya Domain Admins'e eşleyin",
                "detail": 'Bu parolalar sıklıkla domain-join, yerel yönetici veya hizmet hesaplarıdır. Bir DC veya DA kimliğinde yeniden kullanım DA bitişidir.',
                "expected": "Ele geçirilen kullanıcı adı ayrıcalıklı gruplara ve DC'lerde gelen yerel yöneticiye karşı belgelenir.",
            },
            {
                "step": 'Yolu kapatın',
                "detail": "XML'i SYSVOL ve yedeklerden silin, ele geçirilen her parolayı döndürün ve GPO içinde asla sır saklamayın.",
                "expected": 'SYSVOL üzerinde Select-String cpassword bulmaz; parolalar döndürülmüştür.',
            },
        ],
        "command_labels": {
            'gpp_select_string': "PowerShell — SYSVOL'da cpassword ara",
            'gpp_smbclient': 'smbclient — SYSVOL listele (herhangi bir kimliği doğrulanmış kullanıcı)',
            'gpp_getgpppassword': 'Get-GPPPassword — SYSVOL kimlik bilgilerini çöz (yetkili değerlendirme)',
            'gpp_decrypt': "gpp-decrypt — yakalanmış bir cpassword blob'unu çöz",
        },
    },
    'acl_generic_all': {
        "why_da": 'Domain Admins, AdminSDHolder veya bir DA kullanıcısı üzerinde GenericAll veya WriteDACL, saldırganın kendini eklemesine, parola sıfırlamasına veya kalıcı bir ACE eklemesine izin verir — hepsi Etki Alanı Yöneticisi sonuçlarıdır.',
        "starting_access": 'DA sınıfı bir nesnede GenericAll, WriteDACL, WriteOwner veya ForceChangePassword taşıyan bir güvenilir tarafın denetimi.',
        "detection": 'Beklenmeyen çağıranlardan ayrıcalıklı kullanıcılarda 4742/4738; AdminSDHolder üzerinde 5136.',
        "stages": [
            {
                "title": "Tier 0'a giden denetim kenarlarını grafikleyin",
                "why": "BloodHound tarzı ACL kenarları, çoğu iç testin tek bir CVE olmadan DA'ya ulaşma biçimidir.",
                "action": "Mevcut kimlikten Domain Admins'e GenericAll/WriteDACL/WriteOwner/AllExtendedRights izleyin.",
            },
            {
                "title": 'Nesneyi ele geçirin',
                "why": 'Parola sıfırlama, grup ekleme veya DACL yeniden yazma yeterlidir.',
                "action": 'AdminSDHolder veya Domain Admins üzerinde bu haklara sahip yönetici olmayan herhangi bir güvenilir taraf açık bir DA yoludur.',
            },
        ],
        "break_path": [
            "AdminSDHolder'ı Microsoft varsayılan DACL'ine sıfırlayın.",
            "Kullanıcılara, bilgisayarlara ve geniş gruplara verilen GenericAll/WriteDACL'yi kaldırın.",
            'SDProp çalıştırın ve adminCount=1 yetimlerini gözden geçirin.',
        ],
        "poc_roadmap": [
            {
                "step": 'DA sınıfı bir nesneye giden denetim kenarını grafikleyin',
                "detail": 'Tarama kanıtı {TARGETS}, Domain Admins, AdminSDHolder, bir DA kullanıcısı veya iç içe yönetici grubu üzerinde GenericAll, WriteDACL, WriteOwner, ForceChangePassword veya WriteMember taşır.',
                "expected": 'dsacls / BloodHound, Tier 0 nesnesinde denetim hakkı olan güvenilir tarafı gösterir.',
            },
            {
                "step": "DA'yı bitiren tek LDAP yazmasını adlandırın",
                "detail": "Parola sıfırlama, üye ekleme veya DACL yeniden yazma yeterlidir. Üretimde yazmayı yapmayın; ACE'yi ve nesneyi belgelendirin.",
                "expected": 'PoC şudur: O nesnesi üzerinde R hakkına sahip P sorumlusu; O DA sınıfıdır. Bu üçlü etki alanı ele geçirmedir.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": "AdminSDHolder'ı Microsoft varsayılanına sıfırlayın, geniş ACE'leri soyun, SDProp çalıştırın ve adminCount=1 yetimlerini gözden geçirin.",
                "expected": 'Yeniden tarama AdminSDHolder veya Domain Admins üzerinde yönetici olmayan GenericAll/WriteDACL göstermez.',
            },
        ],
        "command_labels": {
            'acl_dsacls_da': 'dsacls — Domain Admins ve AdminSDHolder',
            'acl_target': 'PowerShell — kanıtlanan nesnede güvenlik tanımlayıcısı',
            'acl_bloodhound_note': "BloodHound — Domain Admins'e GenericAll/WriteDACL",
            'acl_dacledit_note': "Impacket dacledit — ACE'yi oku (yetkili değerlendirme; salt okunur tercih edin)",
            'acl_bloodyad_note': "Yetkili değerlendirme notu — üretimde kendinizi Domain Admins'e eklemeyin",
        },
    },
    'escalation_graph': {
        "why_da": "Tekil ACL, yetkilendirme veya SPN bulguları sıklıkla yalnızca bir adımdır. Domain Admins, Enterprise Admins veya bir DC'de biten çok adımlı bir grafik, tek bir adım DA eşdeğeri olmasa bile tam bir ele geçirme yoludur.",
        "starting_access": "Domain Admins'e doğru puanlanmış bir yükseltme yolunun başında duran herhangi bir kimlik.",
        "detection": 'Aynı nesne zinciri boyunca 4728/4732 grup değişikliklerini 5136 ACL yazmalarıyla ilişkilendirin.',
        "stages": [
            {
                "title": "Domain Admins'e en kısa yolu okuyun",
                "why": 'Testçiler DA üyeliğinden değil, en ucuz adımdan (sıklıkla GenericWrite veya bir SPN) başlar.',
                "action": 'Her adımı kaydedin: kim kimi denetler ve hangi hak sonraki nesneyi DA basamak taşına çevirir.',
            },
            {
                "title": 'Önce en ucuz adımı kırın',
                "why": 'Bir kenarı kaldırmak birkaç DA yolunu birden çökertebilir.',
                "action": 'Daha fazla Domain Admins izlemesi eklemek yerine ilk yönetici olmayan adımı düzeltmeyi tercih edin.',
            },
        ],
        "break_path": [
            'Yönetici olmayan birinin ayrıcalıklı bir nesneye doğru tuttuğu ilk denetim kenarını kaldırın.',
            'Gereksiz iç içe yönetici gruplarını düzleştirin ve Domain Admins üyeliğini azaltın.',
        ],
        "poc_roadmap": [
            {
                "step": "En ucuz kimlikten Domain Admins'e her adımı yazın",
                "detail": 'Tarama kanıtı {TARGETS} puanlanmış çok adımlı bir yoldur. Tekil ACL, SPN veya yetkilendirme bulguları sıklıkla yalnızca bir kenardır; grafik tam ele geçirmedir.',
                "expected": 'En kısa yol listesi her nesneyi, her hakkı ve DA sınıfı terminali adlandırır.',
            },
            {
                "step": 'İlk yönetici olmayan adımı doğrulayın (en ucuz kırılmadır)',
                "detail": 'Testçiler DA üyeliğinden değil GenericWrite, bir SPN veya iç içe gruptan başlar.',
                "expected": 'İlk adım, bu katalogdaki eşleşen doğrulama komutuyla (ACL, Kerberoast, RBCD vb.) yeniden üretilir.',
            },
            {
                "step": 'Önce en ucuz kenarı kapatın',
                "detail": 'Yönetici olmayan bir denetim kenarını kaldırmak birkaç DA yolunu birden çökertebilir.',
                "expected": "Yeniden taramada o sorumlu için Domain Admins'e en kısa yol boştur.",
            },
        ],
        "command_labels": {
            'graph_bloodhound': "BloodHound — kanıtlanan sorumludan Domain Admins'e en kısa yol",
            'graph_member': 'PowerShell — kanıtlanan hesap için iç içe grup genişletmesi',
            'graph_follow_first_hop': 'İlk adımı eşleşen teknik oyun kitabıyla izleyin',
        },
    },
    'ops_groups': {
        "why_da": 'Bu grupların örtük DC etkileyen hakları vardır: SeBackupPrivilege (NTDS.dit), hizmet/sürücü yükleme, hesap manipülasyonu veya DNS DLL yükleme. Her biri belgelenmiş bir Etki Alanı Yöneticisi tekniğidir.',
        "starting_access": 'Backup Operators, Server Operators, Account Operators, Print Operators veya DnsAdmins üyeliği.',
        "detection": "Operatör gruplarına 4728/4732; DC'lerde DA olmayan hesaplar tarafından SeBackupPrivilege kullanımı (4672).",
        "stages": [
            {
                "title": 'Operatör grubu üyelerini numaralandırın',
                "why": 'Bu gruplar sertleştirilmiş bir etki alanında boş olmalıdır.',
                "action": 'Herhangi bir etkin üye, Domain Admins içinde olmasa bile DA sınıfı bir kimliktir.',
            },
            {
                "title": 'Örtük hakkı kötüye kullanın',
                "why": "NTDS yedekleme, yazdırma sürücüsü yükleme veya DNS hizmet DLL yürütmesi bir DC'de SYSTEM olarak çalışır.",
                "action": 'Üyeliğin kendisini yol kabul edin; ikinci bir bulgu beklemeyin.',
            },
        ],
        "break_path": [
            'Backup/Server/Account/Print Operators gruplarını boşaltın.',
            "DnsAdmins'i Windows Server 2022+ üzerinde en az ayrıcalıklı DNS rolleriyle veya özel yönetici katmanlarıyla değiştirin.",
        ],
        "poc_roadmap": [
            {
                "step": 'Backup, Server, Account, Print Operators ve DnsAdmins üyelerini numaralandırın',
                "detail": 'Tarama kanıtı {TARGETS} yerleşik bir operatör grubundadır. Bu gruplar boş olmalıdır. Üyelik tek başına DA sınıfıdır: SeBackupPrivilege (NTDS.dit), hizmet/sürücü yükleme, hesap manipülasyonu veya DNS DLL yükleme.',
                "expected": 'Get-ADGroupMember en az bir etkin sorumlu döndürür.',
            },
            {
                "step": 'Örtük DC etkileyen hakkı adlandırın',
                "detail": "Üretimde NTDS dökmeyin veya DNS DLL yüklemeyin. Ayrıcalığı ve DC'de SYSTEM olarak çalıştığını belgelendirin.",
                "expected": 'PoC, DC üzerinde bir yük değil, üyelik artı belgelenmiş örtük haktır.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Operatör gruplarını boşaltın; modern sunucularda DnsAdmins'i en az ayrıcalıklı DNS rolleriyle değiştirin.",
                "expected": 'Yeniden tarama sıfır etkin üye gösterir; bu gruplara 4728/4732 uyarılır.',
            },
        ],
        "command_labels": {
            'ops_members': 'PowerShell — operatör grubu üyeleri',
            'ops_target': 'PowerShell — kanıtlanan sorumlusunun grupları',
            'ops_backup_note': 'Yetkili değerlendirme notu — Backup Operators / NTDS',
            'ops_dnsadmin_note': 'Yetkili değerlendirme notu — DnsAdmins DLL yükleme',
        },
    },
    'laps': {
        "why_da": "Bir DC'nin veya Domain Admins tarafından kullanılan bir atlama konağının yerel yöneticisi LSASS/NTDS erişimi sağlar. Geniş LAPS okuma ACL'leri bu nedenle Etki Alanı Yöneticisi yolları olur.",
        "starting_access": 'Bir Domain Controller veya yönetici iş istasyonunda ms-Mcs-AdmPwd veya msLAPS-Password LDAP okuması.',
        "detection": 'Beklenmeyen çağıranlardan ms-Mcs-AdmPwd / msLAPS-* LDAP okumaları.',
        "stages": [
            {
                "title": 'LAPS özniteliklerini kim okuyabilir görün',
                "why": "Helpdesk gruplarına sıklıkla DC'ler dahil etki alanı genelinde LAPS okuma verilir.",
                "action": "Helpdesk tarafından kullanılan LAPS okuma kapsamlarından Domain Controllers'ı hariç tutun.",
            },
            {
                "title": 'Tier 0 konakta yerel yöneticüyü kullanın',
                "why": 'Bir DC veya DA iş istasyonunda yerel yönetici DA eşdeğeridir.',
                "action": 'DC nesnelerini kapsayan herhangi bir LAPS hibesi açık bir DA yoludur.',
            },
        ],
        "break_path": [
            "LAPS okumayı sahip destek katmanıyla sınırlayın; asla Authenticated Users'a vermeyin.",
            "Şifreli Windows LAPS kullanın; msLAPS-Password'u döndürün ve kısıtlayın.",
        ],
        "poc_roadmap": [
            {
                "step": 'DC veya DA iş istasyonlarında LAPS sırlarını kim okuyabilir görün',
                "detail": "Tarama kanıtı {TARGETS} ms-Mcs-AdmPwd veya msLAPS-Password okuyabilir. Bir DC veya Domain Admins'in kullandığı atlama konağında yerel yönetici DA eşdeğeridir (LSASS/NTDS).",
                "expected": "Bilgisayar nesnesinde dsacls, LAPS özniteliklerinde helpdesk veya Authenticated Users okuma ACE'si gösterir.",
            },
            {
                "step": 'Hibenin Tier 0 bilgisayarı kapsadığını doğrulayın',
                "detail": 'Helpdesk LAPS okuması sıklıkla Domain Controllers dahil etki alanı genelindedir.',
                "expected": 'PoC, LAPS özniteliği Tier 0 olmayan bir grup tarafından okunabilen bir DC veya yönetici iş istasyonunu listeler.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": 'LAPS okumayı sahip destek katmanıyla sınırlayın; asla Authenticated Users; şifreli Windows LAPS kullanın.',
                "expected": 'Yeniden tarama helpdesk grupları için DC nesnelerinde LAPS okuma göstermez.',
            },
        ],
        "command_labels": {
            'laps_dsacls': 'dsacls — kanıtlanan bilgisayarda LAPS öznitelikleri',
            'laps_get': 'PowerShell — Windows LAPS / eski LAPS okuma (erişiminiz olmamalıysa başarısız olur)',
            'laps_adshell': 'Yetkili değerlendirme — kanıtlanan güvenilir taraf olarak LAPS oku',
        },
    },
    'machine_quota': {
        "why_da": 'Bir bilgisayar hesabı oluşturmak saldırgana tamamen denetlediği bir güvenlik sorumlusu verir. RBCD, noPac sınıfı sorunlar veya yazılabilir bir DC nesnesiyle birleşince bu sorumlu bir DA yolu olur.',
        "starting_access": "ms-DS-MachineAccountQuota 0'dan büyükken herhangi bir kimliği doğrulanmış kullanıcı.",
        "detection": 'Join hesabı olmayanlar tarafından 4741 bilgisayar oluşturmaları; ardından RBCD öznitelik yazmaları.',
        "stages": [
            {
                "title": 'Denetlenen bir bilgisayar hesabı oluşturun veya belirleyin',
                "why": 'Kota > 0 varsayılandır ve birkaç modern DA zinciri için yeterlidir.',
                "action": 'Belgelenmiş bir join iş akışı gerektirmediği sürece kotayı 0 yapın.',
            },
            {
                "title": 'RBCD, noPac veya gölge kimlik bilgilerine zincirleyin',
                "why": 'Yeni bilgisayar, bu tekniklerin ihtiyaç duyduğu saldırgan denetimli düğümdür.',
                "action": 'Kota sıfır değilse ve herhangi bir DC zayıf ACL veya RBCD taşıyorsa bir DA yolu kaydedin.',
            },
        ],
        "break_path": [
            'ms-DS-MachineAccountQuota değerini 0 yapın.',
            "Bilgisayar nesnesi ACL'lerini sertleştirin; DC'leri CVE-2021-42278/42287 için yamalayın.",
        ],
        "poc_roadmap": [
            {
                "step": 'Etki alanında ms-DS-MachineAccountQuota okuyun',
                "detail": "Varsayılan 10'dur. Herhangi bir kimliği doğrulanmış kullanıcı ardından tamamen denetlediği bir bilgisayar oluşturabilir. Bu sorumlu, RBCD, noPac ve Shadow Credentials'ın ihtiyaç duyduğu düğümdür.",
                "expected": "Get-ADObject 0'dan büyük bir kota döndürür.",
            },
            {
                "step": 'Kotayı aynı taramadan bir DC yazma ilkeliniyle zincirleyin',
                "detail": "Kota tek başına DA değildir; kota artı RBCD/noPac/zayıf DC ACL'dir. Eşlik eden bulguyu kaydedin.",
                "expected": "PoC, bu rapordaki en az bir DC etkileyen ilkel ile birlikte kota > 0'dır.",
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Belgelenmiş bir join iş akışı gerektirmediği sürece kotayı 0 yapın; bilgisayar nesnesi ACL'lerini sertleştirin.",
                "expected": 'Yeniden tarama ms-DS-MachineAccountQuota=0 gösterir; join hesabı olmayanlardan 4741 uyarılır.',
            },
        ],
        "command_labels": {
            'quota_read': 'PowerShell — MachineAccountQuota',
            'quota_addcomputer': 'PowerMad / Impacket — denetlenen bilgisayar oluştur (yetkili değerlendirme)',
            'quota_then_rbcd': 'Sonraki adım — yeni bilgisayarı RBCD oyun kitabına besleyin',
        },
    },
    'nopac': {
        "why_da": "noPac sınıfı sorunlar, denetlenen bir bilgisayar hesabının sAMAccountName sahteciliği ile Kerberos TGT isteğini birleştirerek bir domain controller olarak kimliğe bürünmesine izin verir. Yamanmamış DC'ler artı MachineAccountQuota > 0, herhangi bir kimliği doğrulanmış kullanıcıdan Etki Alanı Yöneticisi yoludur.",
        "starting_access": "Yamanmamış domain controller'lara karşı bilgisayar hesabı oluşturabilen kimliği doğrulanmış etki alanı kullanıcısı.",
        "detection": '4741 ardından 4781 (bilgisayar yeniden adlandırma) ve bir iş istasyonundan DC adlı hesap için 4768.',
        "stages": [
            {
                "title": 'DC yama düzeyini ve makine kotasını doğrulayın',
                "why": "Zincir hem bir create-computer ilkelini hem de yamanmamış bir KDC'yi gerektirir.",
                "action": "Yamanmamış DC'leri kota > 0 ile birlikte, sömürüden önce bile açık DA yolu kabul edin.",
            },
            {
                "title": 'Herhangi bir kimliği doğrulanmış kullanıcının DC TGT isteyebileceğini varsayın',
                "why": "O TGT, DC'ler yamanıp kota sıfır olana kadar Domain Admin eşdeğeridir.",
                "action": "DC'leri yamalayın, ardından ms-DS-MachineAccountQuota'yu 0 yapın.",
            },
        ],
        "break_path": [
            "Her domain controller'ı CVE-2021-42278 ve CVE-2021-42287 için yamalayın.",
            'ms-DS-MachineAccountQuota değerini 0 yapın.',
        ],
        "poc_roadmap": [
            {
                "step": "Yamanmamış DC'leri MachineAccountQuota > 0 ile birlikte doğrulayın",
                "detail": 'CVE-2021-42278/42287, denetlenen bir bilgisayarın sAMAccountName sahteciliği ile TGT isteğini birleştirerek bir DC olarak kimliğe bürünmesine izin verir. Tarama kanıtı {TARGETS} artı kota > 0 kimliği doğrulanmış kullanıcı DA yoludur.',
                "expected": 'DC OS/derlemesi zayıf kümededir ve ms-DS-MachineAccountQuota 0 değildir.',
            },
            {
                "step": 'Sömürüyü üretime karşı çalıştırmayın',
                "detail": 'Üretim için PoC şudur: yamanmamış KDC + create-computer ilkeli. Sömürü yalnızca sahip olduğunuz bir laboratuvardadır.',
                "expected": 'Yama kanıtı (KB5008380 ve ilgili) eksiktir; kota sıfır değildir. Bu çift bulgudur.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Her DC'yi CVE-2021-42278 ve CVE-2021-42287 için yamalayın, ardından kotayı 0 yapın.",
                "expected": "Derlemeler yamanmıştır; kota 0'dır; DC adlı bir hesap için 4741+4781+4768 uyarılır.",
            },
        ],
        "command_labels": {
            'nopac_quota': 'PowerShell — kota eşlik kontrolü',
            'nopac_dc_os': 'PowerShell — Domain Controller OS / düzeltme eki envanteri',
            'nopac_lab_only': "Yalnızca laboratuvar notu — noPac kimliğe bürünme (üretim DC'lerine karşı çalıştırmayın)",
        },
    },
    'relay_coerce': {
        "why_da": "LDAP imzalama ve EPA/channel binding zorunlu değilse, zorlanmış bir DC makine hesabı LDAP'a aktarılarak DCSync, RBCD veya gölge kimlik bilgileri verebilir — birkaç LDAP yazmasıyla Etki Alanı Yöneticisi.",
        "starting_access": 'Bir DC veya ayrıcalıklı konağı zorlayacak ağ konumu (PetitPotam, PrinterBug, DFS, WebClient).',
        "detection": "DC'lerden beklenmeyen konaklara NTLM (4624 tip 3); DC makine hesaplarından LDAP yazmaları.",
        "stages": [
            {
                "title": 'İmzalama / channel binding boşluklarını doğrulayın',
                "why": 'LDAP imzalama ve EPA zorunluysa ve SMB imzalama gerekliyse relay ölür.',
                "action": "DC'lerde 'imzalama gerekli değil'i etki alanı genelinde DA kolaylaştırıcı kabul edin.",
            },
            {
                "title": 'Ayrıcalıklı bir makine hesabını zorlayın',
                "why": 'İmzalama kapalıyken DC bilgisayar hesabı ayrıcalıklı LDAP öznitelikleri yazabilir.',
                "action": 'Spooler/EFS/DFS maruziyetini imzalama boşluğuyla birleştirin; bu çift DA yoludur.',
            },
        ],
        "break_path": [
            "Tüm DC'lerde LDAP imzalama ve channel binding zorunlu kılın.",
            "SMB imzalama zorunlu kılın; DC'lerde yazdırma biriktiricisini kapatın; EFS RPC'yi kısıtlayın.",
        ],
        "poc_roadmap": [
            {
                "step": "DC'lerde LDAP imzalama, channel binding ve SMB imzalama boşluklarını doğrulayın",
                "detail": 'Tarama kanıtı {TARGETS} imzalamanın gerekli olmadığını ve/veya bir zorlama uç noktası (spooler, EFS, DFS, WebClient) gösterir. LDAP imzalama + EPA ve SMB imzalama zorunluysa relay ölür.',
                "expected": "NetSetup / GPO, DC'lerde LDAPServerIntegrity != 2 ve/veya SMB imzalamanın gerekli olmadığını gösterir.",
            },
            {
                "step": 'İmzalama boşluğunu bir zorlama ilkeliyle eşleştirin',
                "detail": "LDAP'a aktarılan zorlanmış bir DC makine hesabı DCSync, RBCD veya Shadow Credentials yazabilir.",
                "expected": "PoC çifttir: zorlanabilir DC + imzalama/EPA kapalı. Üretim DC'sini silahlandırılmış bir dinleyiciye aktarmayın.",
            },
            {
                "step": 'Yolu kapatın',
                "detail": "LDAP imzalama ve channel binding zorunlu kılın; SMB imzalama zorunlu kılın; DC'lerde spooler'ı kapatın; EFS RPC'yi kısıtlayın.",
                "expected": "Yeniden tarama imzalamanın gerekli olduğunu gösterir; DC'lerde spooler kapalıdır; DC'lerden beklenmeyen konaklara 4624 tip 3 uyarılır.",
            },
        ],
        "command_labels": {
            'relay_ldap_integrity': 'PowerShell — LDAP sunucu imzalama gereksinimi (DC)',
            'relay_smb_signing': "PowerShell — DC'de SMB imzalama",
            'relay_spooler': 'PowerShell — Domain Controllers üzerinde Print Spooler',
            'relay_ntlmrelayx_note': 'Yetkili değerlendirme notu — NTLM relay (yalnızca laboratuvar veya sıkı kapsamlı test)',
            'relay_coerce_note': "Zorlama envanteri (belirleyin, üretim DC'lerine ateş etmeyin)",
        },
    },
    'krbtgt': {
        "why_da": "KRBTGT her TGT'yi şifreler. İki kez döndürülmemiş eski bir KRBTGT parolası bir Golden Ticket penceresi bırakır: Domain Admins dahil herhangi bir kullanıcı için sahte TGT'ler.",
        "starting_access": 'Daha önce çalınmış bir KRBTGT özeti veya hâlâ eski anahtarı kullanabilen mevcut bir DCSync yolu.',
        "detection": "Politikaya göre olağandışı ömür veya şifreleme içeren anomali TGT'ler (4768/4769).",
        "stages": [
            {
                "title": 'KRBTGT parola yaşını ve geçmişini ölçün',
                "why": 'Microsoft rehberliği, şüphelenilen herhangi bir DC ele geçirmesinden sonra çift döndürmedir.',
                "action": "pwdLastSet yıllarca eskiyse, geçmişteki herhangi bir DCSync'in hâlâ çalıştığını varsayın.",
            },
            {
                "title": 'Her iki anahtar ölene kadar TGT sahteleyin',
                "why": 'Kerberos önceki KRBTGT anahtarını kabul eder. Tek döndürme yeterli değildir.',
                "action": 'Her iki anahtarın da değişmesi için bekleme süresiyle iki adımlı bir döndürme planlayın.',
            },
        ],
        "break_path": [
            "Microsoft iki aşamalı prosedürüyle KRBTGT'yi iki kez döndürün.",
            'Her DC ele geçirmesi veya yetkisiz çoğaltma hakkından sonra sıfırlayın.',
        ],
        "poc_roadmap": [
            {
                "step": 'KRBTGT parola yaşını ve geçmişini ölçün',
                "detail": 'Microsoft rehberliği, şüphelenilen herhangi bir DC ele geçirmesi veya yetkisiz DCSync sonrasında çift döndürmedir. Tarama kanıtı {TARGETS} eski bir KRBTGT sırrı gösterir — bir Golden Ticket penceresi.',
                "expected": 'KRBTGT üzerinde pwdLastSet eskidir; yalnızca bir döndürme (veya hiç) olmuştur.',
            },
            {
                "step": 'İki anahtarlı Kerberos penceresini açıklayın',
                "detail": "Kerberos hâlâ önceki KRBTGT anahtarını kabul eder. Tek döndürme yeterli değildir. DA dahil herhangi bir kullanıcı için sahte TGT'ler her iki anahtar değişene kadar geçerli kalır.",
                "expected": 'PoC şudur: KRBTGT yaşı/geçmişi artı bu rapordaki herhangi bir geçmiş DCSync yolu. Üretime karşı Golden Ticket üretmeyin.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Microsoft iki aşamalı prosedürüyle KRBTGT'yi iki kez döndürün; her DC ele geçirmesinden sonra sıfırlayın.",
                "expected": 'Gerekli bekleme süresiyle iki başarılı döndürme; 4768/4769 ömür anomalileri uyarılır.',
            },
        ],
        "command_labels": {
            'krbtgt_pwdlastset': 'PowerShell — KRBTGT parola yaşı',
            'krbtgt_microsoft_script': 'Microsoft — New-KrbtgtKeys iki aşamalı döndürme (değiştirin, bilet sahtelemeyin)',
            'krbtgt_golden_note': 'Yetkili değerlendirme notu — üretimde Golden Ticket sahtelemeyin',
        },
    },
    'gmsa_kds': {
        "why_da": "KDS kök anahtarını okuyabilen herkes mevcut ve gelecekteki gMSA parolalarını hesaplayabilir. DC'lerde, AD FS'te veya Entra Connect'te kullanılan bir gMSA Etki Alanı Yöneticisi eşdeğeridir.",
        "starting_access": 'gMSA yönetmemesi gereken sorumlular için KDS kök anahtar nesnesine okuma erişimi.',
        "detection": 'Configuration bölümünde CN=Master Root Keys LDAP okumaları, olağandışı çağıranlardan.',
        "stages": [
            {
                "title": "msKds-RootKeyData'yı kim okuyabilir görün",
                "why": "Varsayılan ACL'ler çoğu ekibin beklediğinden daha geniştir.",
                "action": 'Domain Users veya bir helpdesk grubu anahtarı okuyabiliyorsa her gMSA kapsamdadır.',
            },
            {
                "title": 'Ayrıcalıklı bir gMSA sırrı türetin',
                "why": 'gMSA parolaları kök anahtar ve kimlikten deterministiktir.',
                "action": "Okunabilir gMSA'ları DC hizmetlerine, AD FS'e ve Connect'e eşleyin.",
            },
        ],
        "break_path": [
            "KDS kök anahtar ACL'lerini Domain Controllers ve bir acil durum Tier 0 grubuyla sıkılaştırın.",
            "ACL azaltmasından sonra gMSA'ları döndürün.",
        ],
        "poc_roadmap": [
            {
                "step": "msKds-RootKeyData'yı kim okuyabilir görün",
                "detail": "KDS kök anahtarını okuyabilen herkes mevcut ve gelecekteki gMSA parolalarını hesaplayabilir. Tarama kanıtı {TARGETS} aşırı geniş bir okuyucudur. DC'lerde, AD FS'te veya Entra Connect'te bir gMSA DA eşdeğeridir.",
                "expected": 'Configuration bölümünde CN=Master Root Keys üzerinde dsacls Domain Users, bir helpdesk grubu veya başka beklenmeyen bir güvenilir taraf gösterir.',
            },
            {
                "step": "Okunabilir gMSA'ları Tier 0 hizmetlerine eşleyin",
                "detail": 'gMSA parolaları kök anahtar ve kimlikten deterministiktir.',
                "expected": 'PoC, KDS okuma + ayrıcalıklı bir gMSA (DC hizmeti, AD FS, Connect) listeler.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": "KDS ACL'lerini Domain Controllers ve bir acil durum Tier 0 grubuyla sıkılaştırın; ACL azaltmasından sonra gMSA'ları döndürün.",
                "expected": 'Yeniden tarama yalnızca Tier 0 okuyucuları gösterir; anahtar nesnesinin LDAP okumaları uyarılır.',
            },
        ],
        "command_labels": {
            'kds_dsacls': 'dsacls — KDS Master Root Keys',
            'kds_gmsa_list': 'PowerShell — gMSA envanteri ve izin verilen sorumlular',
            'kds_golden_note': 'Yetkili değerlendirme notu — Golden gMSA (üretim gMSA parolaları türetmeyin)',
        },
    },
    'trusts': {
        "why_da": "Bir orman güveninde SID filtreleme kapalıysa, bir PAC'teki ek SID'ler (başka bir ormandan Enterprise Admins dahil) onurlandırılır. Bu ormanlar arası bir Etki Alanı Yöneticisi yoludur.",
        "starting_access": 'Güvenilen bir etki alanının ele geçirilmesi veya SID History yazma hakkı olan bir sorumlu.',
        "detection": "Yerel RID 512/519 ile eşleşen yabancı düzenleyicilerden gelen oturum açma PAC SID'leri.",
        "stages": [
            {
                "title": 'Her güveni sınıflandırın',
                "why": 'SID filtreleme olmayan dış ve orman güvenleri tehlikeli durumlardır.',
                "action": 'Çift yönlü orman güvenlerini ve TREAT_AS_EXTERNAL / SID filtre kapalı herhangi bir güveni işaretleyin.',
            },
            {
                "title": 'Ayrıcalıklı bir SID enjekte edin veya yeniden kullanın',
                "why": 'SID History veya ExtraSids ardından güvenilen taraftaki DA haklarını yerel olarak verir.',
                "action": 'Filtrelenmemiş bir güvenin uzak tarafının ele geçirilmesi yerel bir DA yoludur.',
            },
        ],
        "break_path": [
            "Tüm orman güvenlerinde SID filtrelemeyi etkinleştirin; SID History'yi yalnızca sıkı kontrollü geçişlerde kullanın.",
            'Seçici kimlik doğrulamayı tercih edin.',
        ],
        "poc_roadmap": [
            {
                "step": 'Her güveni sınıflandırın: yön, tür, SID filtreleme, SID History',
                "detail": "Tarama kanıtı {TARGETS}, SID filtrelemenin kapalı olduğu veya SID History'nin kabul edildiği bir orman/dış güvendir. Bir PAC'teki ek SID'ler (başka bir ormandan Enterprise Admins dahil) ardından yerel olarak onurlandırılır.",
                "expected": "Get-ADTrust, yabancı DA SID'lerine izin veren ForestTransitive / DisableSIDHistory / SIDFilteringQuarantined değerleri gösterir.",
            },
            {
                "step": 'Üretimde SID enjekte etmeden DA sonucunu belirtin',
                "detail": 'Filtrelenmemiş bir güvenin uzak tarafının ele geçirilmesi yerel bir DA yoludur. PoC, SID enjeksiyonu değil güven bayrak kümesidir.',
                "expected": "Değerlendirme kaydı uzak taraf DA'yı yerel RID 512/519 kabulüne eşler.",
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Orman güvenlerinde SID filtrelemeyi etkinleştirin; SID History'yi yalnızca sıkı kontrollü geçişlerde kullanın; seçici kimlik doğrulamayı tercih edin.",
                "expected": "Yeniden tarama SID filtrelemenin etkin olduğunu gösterir; yerel 512/519 ile eşleşen yabancı düzenleyici PAC SID'leri uyarılır.",
            },
        ],
        "command_labels": {
            'trust_get': 'PowerShell — SID filtreleme dahil güven öznitelikleri',
            'trust_nltest': 'nltest — etki alanı güvenleri',
            'trust_sidhistory_note': 'Yetkili değerlendirme notu — üretimde ExtraSids enjekte etmeyin',
        },
    },
    'hybrid': {
        "why_da": "Connect hesapları sıklıkla DCSync taşır. AZUREADSSOACC senkronize herhangi bir kullanıcı için Seamless SSO biletlerini çözer. AD FS token-signing bulut Global Admin için SAML sahteleyerek hibrit ortamlarda DA'ya geri eşlenir.",
        "starting_access": 'MSOL_/Sync_ Connect hesabı, AZUREADSSOACC$ veya AD FS token-signing anahtarının denetimi.',
        "detection": 'Connect olmayan konaklardan MSOL_/Sync_ oturum açmaları; AZUREADSSOACC parola değişiklikleri.',
        "stages": [
            {
                "title": 'Hibrit kontrol düzlemi hesaplarını belirleyin',
                "why": "Bu nesneler Domain Admins içinde olmasa bile Tier 0'dır.",
                "action": 'DA veya çoğaltma haklarında MSOL_/Sync_/AAD_ üyeliği doğrulanmış bir DA yoludur.',
            },
            {
                "title": 'Senkronizasyon veya federasyon sırrını kötüye kullanın',
                "why": "Bulut yöneticisi artı parola writeback veya SSO silver ticket'lar şirket içi DA'yı kurtarır.",
                "action": "Connect sunucularını ve AD FS'i Domain Controllers gibi sertleştirin.",
            },
        ],
        "break_path": [
            "Connect'i Domain Admins'ten çıkarın; yalnızca belgelenmiş çoğaltma/parola haklarını verin.",
            "AZUREADSSOACC'yi döndürün; AD FS imzalama anahtarlarını HSM ile koruyun; Connect yöneticilerini Tier 0 ile sınırlayın.",
        ],
        "poc_roadmap": [
            {
                "step": "MSOL_/Sync_/AAD_ Connect hesaplarını, AZUREADSSOACC$ ve AD FS'i belirleyin",
                "detail": "Tarama kanıtı {TARGETS} hibrit kontrol düzlemidir. Connect sıklıkla DCSync taşır. AZUREADSSOACC Seamless SSO biletlerini çözer. AD FS token-signing bulut Global Admin için SAML sahteleyerek şirket içi DA'ya geri eşlenir.",
                "expected": 'Hesap Domain Admins içindedir veya çoğaltma hakları taşır ya da AZUREADSSOACC$/AD FS Tier 0 değildir.',
            },
            {
                "step": 'Bu nesneleri Domain Controllers kabul edin',
                "detail": "Bulut yöneticisi artı parola writeback veya SSO silver ticket'lar şirket içi DA'yı kurtarır.",
                "expected": 'PoC şudur: hibrit hesap ayrıcalıkları + sunucu Tier 0 OU/güvenlik sınırında değil.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Connect'i Domain Admins'ten çıkarın; yalnızca belgelenmiş çoğaltma/parola haklarını verin; AZUREADSSOACC'yi döndürün; AD FS imzalama anahtarlarını koruyun; Connect yöneticilerini Tier 0 ile sınırlayın.",
                "expected": "Yeniden tarama Connect'in DA'da olmadığını gösterir; Connect olmayan konaklardan MSOL_/Sync_ oturum açmaları uyarılır.",
            },
        ],
        "command_labels": {
            'hybrid_hunt': 'PowerShell — Entra Connect / SSO / AD FS kimlikleri',
            'hybrid_dcsync': 'PowerShell — kanıtlanan hibrit hesapta çoğaltma hakları',
            'hybrid_dcsync_cmd': 'Impacket — Connect hesabı çoğaltma hakkı taşıyorsa DCSync (yetkili değerlendirme)',
            'hybrid_sso_note': 'Yetkili değerlendirme notu — Seamless SSO silver ticket (yalnızca laboratuvar)',
        },
    },
    'rodc': {
        "why_da": "Domain Admins veya diğer Tier 0 hesaplarının bir RODC'de önbelleğe alınmasına izin verilirse, o RODC'nin çalınması bu özetleri verir. Bir RODC KRBTGT ayrıca açıklanan kümesi için TGT basar.",
        "starting_access": "Bir RODC'ye fiziksel veya yedek erişimi ya da krbtgt_###### hesabının çoğaltılması.",
        "detection": "RODC'lere karşı ayrıcalıklı kimlik doğrulama; msDS-RevealOnDemandGroup değişiklikleri.",
        "stages": [
            {
                "title": "RevealOnDemand ile NeverReveal'ı inceleyin",
                "why": "Denied RODC Password Replication Group tüm Tier 0'ı içermelidir.",
                "action": 'İzin verilen listede herhangi bir DA/EA/Schema Admin, RODC hırsızlığı yoluyla açık bir DA yoludur.',
            },
            {
                "title": 'RODC hırsızlığını varsayın',
                "why": "RODC'ler daha zayıf fiziksel denetimli şube sitelerinde durur.",
                "action": 'Site Tier 0 eşdeğeri değilse önbelleğe alınmış ayrıcalıklı sırları zaten ifşa olmuş kabul edin.',
            },
        ],
        "break_path": [
            "Denied RODC Password Replication Group'u her Tier 0 kimliğiyle doldurun.",
            "Allowed RODC Password Replication Group'tan ayrıcalıklı kullanıcıları kaldırın.",
        ],
        "poc_roadmap": [
            {
                "step": "Tier 0 için RevealOnDemand ile NeverReveal'ı inceleyin",
                "detail": "Tarama kanıtı {TARGETS}, Domain Admins veya diğer Tier 0'ın bir RODC'de önbelleğe alınmasına izin verildiğini gösterir. O RODC'nin çalınması bu özetleri verir; RODC KRBTGT açıklanan kümesi için TGT basar.",
                "expected": "Get-ADDomainController RODC politikası Allowed içinde bir DA sınıfı hesap listeler veya Denied'da eksiktir.",
            },
            {
                "step": 'Şube sitesinde daha zayıf fiziksel denetim varsayın',
                "detail": 'PoC, RODC hırsızlığı değil çoğaltma politikasıdır.',
                "expected": 'Denied RODC Password Replication Group her Tier 0 kimliğini içermez.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Denied'ı her Tier 0 kimliğiyle doldurun; Allowed'dan ayrıcalıklı kullanıcıları kaldırın.",
                "expected": 'Yeniden tarama izin verilen listede DA/EA/Schema Admin göstermez.',
            },
        ],
        "command_labels": {
            'rodc_policy': 'PowerShell — RODC parola çoğaltma politikası',
            'rodc_reveal': 'PowerShell — RODC üzerinde revealed / never-reveal öznitelikleri',
            'rodc_secrets_note': 'Yetkili değerlendirme notu — üretimde RODC NTDS dökmeyin',
        },
    },
    'dmsa': {
        "why_da": "Bir dMSA, yerini aldığı hesabın kimliğini miras alabilir. Bir Domain Admin'i öncül olarak bağlamak dMSA'yı Etki Alanı Yöneticisi eşdeğeri yapar.",
        "starting_access": "Herhangi bir OU'da msDS-DelegatedManagedServiceAccount için CreateChild, artı öncül-bağlantı özniteliğinde yazma.",
        "detection": 'msDS-DelegatedManagedServiceAccount oluşturma ve öncül-bağlantı özniteliğine yazmalar.',
        "stages": [
            {
                "title": 'dMSA nesneleri kim oluşturabilir görün',
                "why": 'Zayıf ormanlarda düzenli bir OU üzerinde CreateChild yeterlidir.',
                "action": 'dMSA oluşturmayı bir Tier 0 kimlik ekibiyle sınırlayın.',
            },
            {
                "title": 'Öncül bağlantılarını inceleyin',
                "why": 'Ayrıcalıklı bir hesaba bağlantı teorik değil aktif bir ele geçirmedir.',
                "action": 'Beklenmeyen msDS-ManagedAccountPrecededByLink değerlerini hemen silin.',
            },
        ],
        "break_path": [
            'Microsoft BadSuccessor azaltmalarını uygulayın; dMSA oluşturmayı (5137) ve öncül yazmalarını (5136) denetleyin.',
            "Yönetici olmayan gruplardan dMSA sınıfı için CreateChild'ı kaldırın.",
        ],
        "poc_roadmap": [
            {
                "step": 'msDS-DelegatedManagedServiceAccount nesneleri kim oluşturabilir görün',
                "detail": "Tarama kanıtı {TARGETS} bir dMSA CreateChild yapabilir. Bir Domain Admin'i öncül olarak bağlamak (BadSuccessor) dMSA'yı DA eşdeğeri yapar.",
                "expected": "Bir OU ACE'si Tier 0 olmayan bir gruba dMSA sınıfı için CreateChild verir.",
            },
            {
                "step": "Mevcut dMSA'larda öncül bağlantılarını inceleyin",
                "detail": 'Ayrıcalıklı bir hesaba bağlantı teorik değil aktif bir ele geçirmedir.',
                "expected": 'Herhangi bir dMSA üzerinde msDS-ManagedAccountPrecededByLink bir DA sınıfı hesaba işaret eder veya oluşturma hakları vardır.',
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Microsoft BadSuccessor azaltmalarını uygulayın; CreateChild'ı yönetici olmayanlardan kaldırın; 5137/5136 denetleyin.",
                "expected": 'Yeniden tarama beklenmeyen öncül bağlantısı ve geniş dMSA oluşturma hakkı göstermez.',
            },
        ],
        "command_labels": {
            'dmsa_objects': 'PowerShell — dMSA nesneleri ve öncül bağlantıları',
            'dmsa_ou_acl': 'dsacls — düzenli bir OU üzerinde CreateChild (örnek)',
            'dmsa_badsuccessor_note': "Yetkili değerlendirme notu — üretim Domain Admin'ini dMSA öncülü olarak bağlamayın",
        },
    },
    'sccm': {
        "why_da": 'SCCM istemci itme ve uygulama dağıtımı SYSTEM olarak çalışır. Bir Domain Controller veya bir DA iş istasyonuna itmek standart bir Etki Alanı Yöneticisi bitişidir.',
        "starting_access": 'Bir site sunucusu, bir yönetim noktası veya System Management kapsayıcısında GenericAll denetimi.',
        "detection": "DC konak adlarına istemci itme; DC'lerde beklenmeyen uygulamalar.",
        "stages": [
            {
                "title": 'Site sunucularını ve System Management kapsayıcısını belirleyin',
                "why": 'Site sunucusu bilgisayar hesapları sıklıkla aşırı AD hakları taşır.',
                "action": 'Her birincil site sunucusunu Tier 0 kabul edin.',
            },
            {
                "title": 'Bir DC veya DA iş istasyonuna SYSTEM olarak dağıtın',
                "why": 'İstemci itme birçok yapılandırmada hedefin zaten istemci olmasını gerektirmez.',
                "action": "Domain Controllers'a otomatik istemci itmeyi kapatın.",
            },
        ],
        "break_path": [
            "Site sunucularını Tier 0 yapın; System Management ACL'lerini kilitleyin; DC istemci itmeyi kapatın.",
            'Yönetim noktaları için HTTPS ve PKI zorunlu kılın.',
        ],
        "poc_roadmap": [
            {
                "step": 'Site sunucularını ve System Management kapsayıcısını belirleyin',
                "detail": 'Tarama kanıtı {TARGETS} bir site sunucusu, yönetim noktası veya System Management üzerinde GenericAll taşıyan bir güvenilir taraftır. İstemci itme ve uygulama dağıtımı SYSTEM olarak çalışır. Bir DC veya DA iş istasyonuna itmek standart bir DA bitişidir.',
                "expected": "Birincil site sunucusu bilgisayar hesabı aşırı AD hakları taşır veya DC'lere istemci itme açıktır.",
            },
            {
                "step": "Üretim DC'sine uygulama itmeyin",
                "detail": 'PoC şudur: site sunucusu denetimi + Domain Controllers içeren istemci itme kapsamı. Her birincil site sunucusunu Tier 0 kabul edin.',
                "expected": "Otomatik istemci itme DC konak adlarını içerir veya site sunucusu hesabı AD'de DA eşdeğeridir.",
            },
            {
                "step": 'Yolu kapatın',
                "detail": "Site sunucularını Tier 0 yapın; System Management ACL'lerini kilitleyin; DC istemci itmeyi kapatın; MP'ler için HTTPS/PKI zorunlu kılın.",
                "expected": "Yeniden tarama itme kapsamında DC göstermez; System Management ACL'leri yalnızca Tier 0'dır.",
            },
        ],
        "command_labels": {
            'sccm_container': 'dsacls — System Management kapsayıcısı',
            'sccm_hunt': 'PowerShell — olası site sunucusu bilgisayar hesapları',
            'sccm_misconfig_note': "Yetkili değerlendirme notu — DC'lere SYSTEM yükleri dağıtmayın",
        },
    },
    'password_spray': {
        "why_da": "Kilitleme kapalı veya zayıfsa ve ayrıcalıklı hesaplar mevsimsel parolaları paylaşıyorsa, bir püskürtme doğrudan Domain Admin'e isabet eder. Yönetici olmayan bir isabet bile Kerberoasting veya ACL kenarlarını açabilir.",
        "starting_access": "Kerberos/LDAP/NTLM'e ağ erişimi; geçerli hesap gerekmez.",
        "detection": 'Tek bir kaynaktan birçok kullanıcıya dağıtılmış 4625/4771.',
        "stages": [
            {
                "title": 'Kilitleme ve ayrıcalıklı parola hijyenini ölçün',
                "why": 'Kilitleme eşiği 0 açık bir püskürtme pistidir.',
                "action": 'Tüm ayrıcalıklı kullanıcılarda akıllı kart veya kimlik avına dayanıklı MFA bu yolu kaldırır.',
            },
            {
                "title": 'Püskürtün ardından ACL/Kerberos kenarlarını yürütün',
                "why": "İlk geçerli parola nadiren DA'dır; sıklıkla ilk adımdır.",
                "action": 'Püskürtme başarısını bu haritanın geri kalanıyla birleştirin; yalnız başına ele almayın.',
            },
        ],
        "break_path": [
            'Makul bir eşikle kilitlemeyi etkinleştirin; yaygın parolaları yasaklayın; ayrıcalıklı kullanıcılar için MFA zorunlu kılın.',
            'Tier 0 için Protected Users ve kimlik doğrulama siloları kullanın.',
        ],
        "poc_roadmap": [
            {
                "step": 'Kilitleme eşiğini ve ayrıcalıklı parola hijyenini ölçün',
                "detail": "Tarama kanıtı {TARGETS} kilitlemenin kapalı/zayıf olduğunu veya ayrıcalıklı hesapların Protected Users dışında / MFA olmadan olduğunu gösterir. Kilitleme eşiği 0, doğrudan Domain Admin'e isabet edebilen açık bir püskürtme pistidir.",
                "expected": 'Varsayılan etki alanı politikası kilitlemesi 0 veya çok yüksektir; DA hesapları akıllı kart/MFA olmadan parola kimlik doğrulamasını kabul eder.',
            },
            {
                "step": 'Üretim parolalarını püskürtmeyin',
                "detail": 'PoC politikadır: kilitleme kapalı + püskürtülebilir ayrıcalıklı hesaplar. Bir püskürtme üretim kullanılabilirlik olaydır.',
                "expected": "lockout=0 (veya zayıf) belgelendirin ve Protected Users'ta olmayan ayrıcalıklı kullanıcıları listeleyin.",
            },
            {
                "step": 'Yolu kapatın',
                "detail": 'Makul bir kilitleme etkinleştirin; yaygın parolaları yasaklayın; ayrıcalıklı kullanıcılarda kimlik avına dayanıklı MFA zorunlu kılın; Tier 0 için Protected Users ve kimlik doğrulama siloları.',
                "expected": 'Kilitleme açıktır; DA hesapları akıllı kart veya MFA gerektirir; dağıtılmış 4625/4771 uyarılır.',
            },
        ],
        "command_labels": {
            'spray_policy': 'PowerShell — varsayılan etki alanı kilitleme ve parola politikası',
            'spray_protected_users': "PowerShell — Protected Users'ta olmayan Domain Admins",
            'spray_note': 'Yetkili değerlendirme notu — üretimde parola püskürtmeyin',
        },
    },
    'hidden_primary_group': {
        "why_da": "primaryGroupID üyeliği member özniteliğinde görünmez. Hesap, çoğu grup incelemesinin kaçırmasına rağmen zaten bir Domain Admin'dir.",
        "starting_access": 'Birincil grubu Domain Admins (RID 512) veya başka bir Tier 0 grubu olan hesabın ele geçirilmesi.',
        "detection": 'primaryGroupID=512 için LDAP sorguları; 4738 birincil grup değişiklikleri.',
        "stages": [
            {
                "title": 'primaryGroupID 512/518/519 numaralandırın',
                "why": "Bu klasik 'gizli DA' numarasıdır.",
                "action": "Birincil grupları Domain Users / Domain Computers'a sıfırlayın ve yalnızca görünür üyelik kullanın.",
            },
        ],
        "break_path": [
            "Her ayrıcalıklı aykırıda primaryGroupID'yi düzeltin.",
            'Bilgisayar hesaplarını Domain Admins ve operatör gruplarından kaldırın.',
        ],
        "poc_roadmap": [
            {
                "step": 'primaryGroupID 512/518/519 numaralandırın',
                "detail": "Tarama kanıtı {TARGETS}, member'da görünmeyen ayrıcalıklı bir birincil gruba sahiptir. Hesap, grup incelemeleri kaçırmasına rağmen zaten Domain Admin'dir.",
                "expected": 'Get-ADUser/Computer primaryGroupID 512, 518 veya 519 gösterirken memberOf o grubu atlar.',
            },
            {
                "step": "Birincil grubu Domain Users / Domain Computers'a sıfırlayın",
                "detail": 'Yalnızca görünür üyelik. Bilgisayar hesaplarını DA ve operatör gruplarından kaldırın.',
                "expected": 'primaryGroupID 513 (kullanıcılar) veya 515 (bilgisayarlar) olur; gizli DA gider.',
            },
        ],
        "command_labels": {
            'hidden_pgid': 'PowerShell — ayrıcalıklı birincil gruplar',
            'hidden_target': 'PowerShell — kanıtlanan nesne birincil grubu',
            'hidden_fix_note': 'Düzeltme — normal bir birincil grup ayarlayın (sömürü değil değişiklik)',
        },
    },
    'ldap_recon': {
        "why_da": "Bu tek başına Etki Alanı Yöneticisi vermez. Bu haritadaki diğer her yolun ihtiyaç duyduğu hedef listesini (yöneticiler, SPN'ler, bilgisayarlar) oluşturmak için kimlik bilgisi gereksinimini kaldırır.",
        "starting_access": 'Bulguya bağlı olarak kimliği doğrulanmamış veya herhangi bir etki alanı kullanıcısı.',
        "detection": 'Anonim LDAP bağları; null oturumlardan 4662.',
        "stages": [
            {
                "title": 'Kimlik bilgisi olmadan numaralandırın',
                "why": 'Pre-Windows 2000 Compatible Access artı anonim LDAP en eski AD keşif yoludur.',
                "action": 'Önce numaralandırmayı kapatın ki kimliği doğrulanmamış aktörler DA yollarını bile göremesin.',
            },
        ],
        "break_path": [
            "Anonim LDAP'ı kapatın (dSHeuristics).",
            "Pre-Windows 2000 Compatible Access'ten Everyone/Authenticated Users'ı kaldırın.",
            "Guest'i kapatın.",
        ],
        "poc_roadmap": [
            {
                "step": "Anonim LDAP veya Pre-Windows 2000 Compatible Access'i doğrulayın",
                "detail": 'Bu tek başına Domain Admin vermez. Tarama kanıtı {TARGETS}, kimliği doğrulanmamış veya herhangi bir kullanıcının bu haritadaki diğer her yolun ihtiyaç duyduğu yönetici/SPN/bilgisayar hedef listesini oluşturabileceği anlamına gelir.',
                "expected": 'Anonim bağ başarılıdır, Guest açıktır veya Everyone Pre-Windows 2000 Compatible Access içindedir.',
            },
            {
                "step": 'Önce numaralandırmayı kapatın',
                "detail": "Anonim LDAP'ı kapatın, Pre-Windows 2000 Compatible Access'ten Everyone/Authenticated Users'ı kaldırın, Guest'i kapatın.",
                "expected": 'Anonim bağ başarısız olur; null oturumlardan 4662 kaybolur.',
            },
        ],
        "command_labels": {
            'ldap_anon': 'ldapsearch — anonim rootDSE / adlandırma bağlamları',
            'ldap_prewin2k': 'PowerShell — Pre-Windows 2000 Compatible Access üyeleri',
            'ldap_dsheuristics': 'PowerShell — dSHeuristics (anonim LDAP)',
            'ldap_enum_note': 'Yetkili değerlendirme — anonim bağdan sonra dizin listeleme',
        },
    },
}


def localize_da_path_playbook(path: dict) -> dict:
    """Return a deep copy of one path dict with Turkish narrative applied.

    Command ``command`` bodies are never translated. Only ``label`` fields on
    verify/assessment commands are replaced when a matching ``id`` exists in
    ``command_labels``.
    """
    localized = deepcopy(path)
    if not isinstance(localized, dict):
        return localized
    path_id = str(localized.get("id") or "")
    narrative = DA_PATH_NARRATIVE_TR.get(path_id)
    if not narrative:
        return localized

    for key in ("why_da", "starting_access", "detection"):
        if key in narrative:
            localized[key] = narrative[key]

    stages_tr = narrative.get("stages") or []
    stages = localized.get("stages")
    if isinstance(stages, list) and stages_tr:
        new_stages: list[dict[str, Any]] = []
        for index, stage in enumerate(stages):
            if not isinstance(stage, dict):
                new_stages.append(deepcopy(stage))
                continue
            item = deepcopy(stage)
            if index < len(stages_tr):
                src = stages_tr[index]
                item["title"] = src.get("title", item.get("title", ""))
                item["why"] = src.get("why", item.get("why", ""))
                item["action"] = src.get("action", item.get("action", ""))
            new_stages.append(item)
        localized["stages"] = new_stages

    break_tr = narrative.get("break_path")
    if isinstance(break_tr, list) and break_tr:
        localized["break_path"] = list(break_tr)

    labels = narrative.get("command_labels") or {}
    poc_tr = narrative.get("poc_roadmap") or []
    poc = localized.get("poc_roadmap")
    if isinstance(poc, list) and poc_tr:
        new_poc: list[dict[str, Any]] = []
        for index, entry in enumerate(poc):
            if not isinstance(entry, dict):
                new_poc.append(deepcopy(entry))
                continue
            item = deepcopy(entry)
            if index < len(poc_tr):
                src = poc_tr[index]
                item["step"] = src.get("step", item.get("step", ""))
                item["detail"] = src.get("detail", item.get("detail", ""))
                item["expected"] = src.get("expected", item.get("expected", ""))
            new_poc.append(item)
        localized["poc_roadmap"] = new_poc

    for collection in ("verify_commands", "assessment_commands"):
        commands = localized.get(collection)
        if not isinstance(commands, list):
            continue
        for cmd in commands:
            if not isinstance(cmd, dict):
                continue
            cmd_id = str(cmd.get("id") or "")
            if cmd_id in labels:
                cmd["label"] = labels[cmd_id]
            # intentionally leave cmd["command"] untouched

    return localized


def localize_domain_admin_takeover_tr(data: Any) -> Any:
    """Deep-copy and localize a Domain Admin takeover structure for Turkish UI."""
    localized = deepcopy(data)
    if not isinstance(localized, dict):
        return localized

    summary = localized.get("summary")
    if isinstance(summary, dict):
        count = int(summary.get("open_path_count") or 0)
        if count == 0:
            summary["headline"] = (
                "Bu taramada Etki Alanı Yöneticisine giden açık bir yol kanıtlanmadı. "
                "Aşağıdaki katalog, gözlemlenmeyen teknikler için sızma testi kontrol listesidir."
            )
        else:
            summary["headline"] = (
                f"Bu taramada Etki Alanı Yöneticisine ulaşabilen {count} açık saldırı yolu belirlendi."
            )

    for collection in ("open_paths", "unobserved_paths"):
        paths = localized.get(collection) or []
        if not isinstance(paths, list):
            continue
        new_paths: list[Any] = []
        for path in paths:
            if not isinstance(path, dict):
                new_paths.append(deepcopy(path))
                continue
            path_id = str(path.get("id") or "")
            path = localize_da_path_playbook(path)
            path["name"] = DA_PATH_NAMES_TR.get(path_id, path.get("name") or path_id)
            for evidence in path.get("evidence_summaries") or []:
                if not isinstance(evidence, dict):
                    continue
                ev_type = str(evidence.get("type") or "")
                title = str(evidence.get("title") or "").strip()
                evidence["title"] = title or ev_type
            new_paths.append(path)
        localized[collection] = new_paths

    return localized

