"""
GPP (Group Policy Preferences) Password Extractor Module
Reports recoverable cpassword material when evidence is present.
LDAP GPO objects alone are not treated as proof of embedded passwords.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)

_CPASSWORD_KEYS = (
    "cpassword",
    "gppCpassword",
    "gpp_cpassword",
    "encrypted_password",
)


class GPPPasswordExtractor:
    """Detect Group Policy Preference passwords when ciphertext evidence exists."""

    # AES-256 key published by Microsoft for GPP cpassword (publicly known).
    GPP_AES_KEY = (
        b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8"
        b"\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
    )
    GPP_AES_IV = b"\x00" * 16

    def __init__(self, ldap_connection: Any = None):
        """Initialize the extractor. LDAP is unused; SYSVOL is not read over SMB."""
        self.ldap = ldap_connection

    def analyze_gpp_passwords(self, gpos: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return findings only for GPOs that include cpassword evidence."""
        risks: list[dict[str, Any]] = []
        for gpo in gpos or []:
            evidence_count = self._cpassword_evidence_count(gpo)
            if evidence_count == 0 and not gpo.get("has_gpp_password"):
                continue
            gpo_name = str(gpo.get("name") or gpo.get("displayName") or "Unknown")
            gpo_path = gpo.get("gPCFileSysPath") or ""
            risks.append({
                "type": RiskTypes.GPP_PASSWORD_FOUND,
                "severity": Severity.CRITICAL,
                "title": f"GPP cpassword evidence: {gpo_name}",
                "description": (
                    f"GPO '{gpo_name}' includes recoverable Group Policy Preferences password "
                    f"material ({evidence_count or 1} value(s)). GPP cpassword uses a published AES key."
                ),
                "affected_object": gpo_name,
                "object_type": "gpo",
                "gpo_path": gpo_path,
                "impact": (
                    "Anyone who can read the cpassword value can recover the stored credential "
                    "and often move laterally with a local or service account."
                ),
                "attack_scenario": (
                    "Read Groups.xml / Services.xml from SYSVOL or from collected GPO evidence, "
                    "decrypt cpassword with the published AES key, and reuse the credential."
                ),
                "mitigation": (
                    "Remove passwords from Group Policy Preferences, rotate any exposed credentials, "
                    "and use gMSA or LAPS instead of GPP-stored secrets."
                ),
                "cis_reference": "CIS Benchmark prohibits storing passwords in GPP",
                "mitre_attack": MITRETechniques.UNSECURED_CREDENTIALS,
            })
        logger.info("Found %d GPP password risks", len(risks))
        return risks

    def decrypt_gpp_password(self, encrypted_password: str) -> str | None:
        """Decrypt a GPP cpassword using the published AES-256 key and null IV."""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import unpad

            payload = "".join(str(encrypted_password).split())
            payload += "=" * ((4 - len(payload) % 4) % 4)
            ciphertext = base64.b64decode(payload)
            cipher = AES.new(self.GPP_AES_KEY, AES.MODE_CBC, self.GPP_AES_IV)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted.decode("utf-16-le").rstrip("\x00")
        except Exception as exc:
            logger.debug("GPP cpassword decryption failed: %s", type(exc).__name__)
            return None

    @classmethod
    def _cpassword_evidence_count(cls, gpo: dict[str, Any]) -> int:
        """Count cpassword values on a GPO record without storing the secrets."""
        count = 0
        for key in _CPASSWORD_KEYS:
            value = gpo.get(key)
            if isinstance(value, str) and value.strip():
                count += 1
            elif isinstance(value, (list, tuple)):
                count += sum(1 for item in value if str(item).strip())
        nested = gpo.get("gpp_files")
        if isinstance(nested, (list, tuple)):
            for item in nested:
                if isinstance(item, dict):
                    count += cls._cpassword_evidence_count(item)
        return count
