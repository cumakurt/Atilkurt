"""Hybrid identity attack surface: Entra Connect, Seamless SSO, and ADFS."""

from __future__ import annotations

import logging
from typing import Any

from core.ad_identity import first_ldap_rdn, is_privileged_group_name
from core.constants import MITRETechniques, RiskTypes, Severity

logger = logging.getLogger(__name__)

CONNECT_PREFIXES = ("MSOL_", "SYNC_", "AAD_")
SSO_NAMES = {"AZUREADSSOACC"}
ADFS_SPN_MARKERS = ("HOST/ADFS", "HTTP/ADFS", "ADFS/SERVICES")


class HybridIdentityAnalyzer:
    """Detect on-premises hybrid-identity components that yield cloud or federation takeover."""

    def __init__(self, ldap_connection: Any):
        self.ldap = ldap_connection

    def analyze(self, users: list[dict[str, Any]], computers: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return hybrid-identity findings from collected accounts and targeted LDAP searches."""
        risks: list[dict[str, Any]] = []
        component_risks: list[dict[str, Any]] = []
        component_risks.extend(self._check_sso_account(computers, users))
        component_risks.extend(self._check_connect_accounts(users))
        component_risks.extend(self._check_adfs(users, computers))
        risks.extend(component_risks)
        if component_risks:
            risks.extend(self._check_hybrid_joined_coverage(computers))
        logger.info("Found %d hybrid identity risks", len(risks))
        return risks

    def _search(self, search_filter: str, attributes: list[str], size_limit: int = 50) -> list[dict[str, Any]]:
        try:
            return self.ldap.search(
                search_base=self.ldap.base_dn,
                search_filter=search_filter,
                attributes=attributes,
                size_limit=size_limit,
            ) or []
        except Exception as exc:
            logger.debug("Hybrid identity search failed: %s", exc)
            return []

    def _sam(self, obj: dict[str, Any]) -> str:
        return str(obj.get("sAMAccountName") or obj.get("name") or "Unknown")

    def _uac(self, obj: dict[str, Any]) -> int:
        try:
            return int(obj.get("userAccountControl") or 0)
        except (TypeError, ValueError):
            return 0

    def _is_privileged(self, obj: dict[str, Any]) -> bool:
        if str(obj.get("adminCount")) in {"1", "True", "true"}:
            return True
        membership = obj.get("memberOf") or []
        if not isinstance(membership, list):
            membership = [membership]
        return any(is_privileged_group_name(first_ldap_rdn(item)) for item in membership)

    def _check_sso_account(self, computers: list[dict[str, Any]], users: list[dict[str, Any]]) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        candidates = list(computers or []) + list(users or [])
        sso_objects = [
            obj for obj in candidates
            if self._sam(obj).upper().rstrip("$") in SSO_NAMES
        ]
        if not sso_objects:
            sso_objects = self._search(
                "(|(sAMAccountName=AZUREADSSOACC)(sAMAccountName=AZUREADSSOACC$))",
                ["sAMAccountName", "userAccountControl", "pwdLastSet", "servicePrincipalName", "whenChanged"],
                size_limit=5,
            )
        for obj in sso_objects:
            name = self._sam(obj)
            risks.append({
                "type": RiskTypes.HYBRID_AZURE_SSO_ACCOUNT,
                "severity": Severity.HIGH,
                "title": f"Microsoft Entra Seamless SSO computer account present: {name}",
                "description": (
                    "The AZUREADSSOACC account decrypts Kerberos tickets issued for Entra Seamless SSO. "
                    "A stolen password hash enables silver tickets that impersonate any federated user to Entra ID."
                ),
                "affected_object": name,
                "object_type": "computer",
                "impact": "Compromise of AZUREADSSOACC is a cloud identity path from a single on-premises computer account.",
                "attack_scenario": "DCSync or dump AZUREADSSOACC$, then craft a silver ticket for HTTP/autologon.microsoftazuread-sso.com.",
                "mitigation": (
                    "Rotate the Seamless SSO computer-account password regularly, restrict who can replicate "
                    "its secret, and prefer PTA/PHS with Conditional Access over Seamless SSO where possible."
                ),
                "mitre_attack": MITRETechniques.STEAL_FORGE_KERBEROS_SILVER,
            })
        return risks

    def _check_connect_accounts(self, users: list[dict[str, Any]]) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        matches = [
            user for user in (users or [])
            if any(self._sam(user).upper().startswith(prefix) for prefix in CONNECT_PREFIXES)
        ]
        if not matches:
            matches = self._search(
                "(|(sAMAccountName=MSOL_*)(sAMAccountName=Sync_*)(sAMAccountName=AAD_*))",
                ["sAMAccountName", "userAccountControl", "adminCount", "memberOf", "servicePrincipalName"],
                size_limit=30,
            )
        for user in matches:
            name = self._sam(user)
            privileged = self._is_privileged(user)
            risks.append({
                "type": RiskTypes.HYBRID_ENTRA_CONNECT_ACCOUNT,
                "severity": Severity.CRITICAL if privileged else Severity.HIGH,
                "title": f"Entra Connect / Directory Sync account: {name}",
                "description": (
                    f"Account '{name}' matches Microsoft Entra Connect naming. These accounts often have "
                    "Directory Replication (DCSync) or high write rights on on-premises identities."
                ),
                "affected_object": name,
                "object_type": "user",
                "impact": "Takeover of the Connect account can reset cloud-synced identities or DCSync the domain.",
                "attack_scenario": "Kerberoast or spray the MSOL_/Sync_ account, then DCSync or push a rogue Entra admin.",
                "mitigation": (
                    "Use a dedicated gMSA for Connect, remove Domain Admin membership, restrict replication "
                    "rights to the required objects, and rotate credentials after any suspected compromise."
                ),
                "mitre_attack": MITRETechniques.DCSYNC,
                "is_privileged": privileged,
            })
        return risks

    def _is_adfs_identity(self, obj: dict[str, Any]) -> bool:
        """Return True when SPNs identify an ADFS federation service."""
        spns = obj.get("servicePrincipalName") or []
        if not isinstance(spns, list):
            spns = [spns]
        for spn in spns:
            upper = str(spn).upper()
            if any(marker in upper for marker in ADFS_SPN_MARKERS):
                return True
            if "/ADFS." in upper or upper.endswith("/ADFS") or "/ADFS:" in upper:
                return True
        return False

    def _check_adfs(self, users: list[dict[str, Any]], computers: list[dict[str, Any]]) -> list[dict[str, Any]]:
        risks: list[dict[str, Any]] = []
        pool = list(users or []) + list(computers or [])
        for obj in pool:
            if not self._is_adfs_identity(obj):
                continue
            spns = obj.get("servicePrincipalName") or []
            if not isinstance(spns, list):
                spns = [spns]
            name = self._sam(obj)
            risks.append({
                "type": RiskTypes.HYBRID_ADFS_SERVICE,
                "severity": Severity.HIGH,
                "title": f"ADFS federation service identity: {name}",
                "description": (
                    f"'{name}' appears to host ADFS (SPNs: {', '.join(str(s) for s in spns[:6]) or 'name match'}). "
                    "The ADFS token-signing certificate is equivalent to a cloud golden ticket for federated domains."
                ),
                "affected_object": name,
                "object_type": "computer" if name.endswith("$") or obj.get("name") else "user",
                "impact": "Theft of the ADFS token-signing key forges SAML tokens for any federated user, including Global Admins.",
                "attack_scenario": "Compromise the ADFS server, export the token-signing certificate, and forge SAML assertions.",
                "mitigation": "Harden ADFS as a Tier 0 system, protect token-signing keys with HSM/TPM, and prefer managed Entra authentication.",
                "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
            })
        return risks

    def _check_hybrid_joined_coverage(self, computers: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not computers:
            return []
        hybrid = 0
        for computer in computers:
            ext = computer.get("msDS-ExternalDirectoryObjectId") or computer.get("msDS-CloudAnchor")
            if ext:
                hybrid += 1
        if hybrid:
            return []
        return [{
            "type": RiskTypes.HYBRID_JOIN_NOT_OBSERVED,
            "severity": Severity.LOW,
            "title": "No Entra hybrid-join identifiers observed on computer objects",
            "description": (
                "Collected computer objects do not expose msDS-ExternalDirectoryObjectId even though "
                "Entra Connect, Seamless SSO, or ADFS identities were observed. Hybrid device state "
                "may be incomplete or the collector may be missing the attribute."
            ),
            "affected_object": self.ldap.base_dn,
            "object_type": "configuration",
            "impact": "Hybrid-join state is unknown; cloud device identity risks may be unmeasured.",
            "attack_scenario": "Untracked hybrid devices can be used as PRT/Primary Refresh Token theft targets.",
            "mitigation": "Confirm whether Entra hybrid join is used and collect msDS-ExternalDirectoryObjectId for device inventory.",
            "mitre_attack": MITRETechniques.VALID_ACCOUNTS_DOMAIN,
        }]
