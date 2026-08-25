"""Confidence scoring and evidence-chain enrichment for scan findings."""

from __future__ import annotations

from typing import Any


class ConfidenceScorer:
    """Attach transparent confidence metadata without changing risk severity."""

    EVENT_PREFIXES = ("event_", "observed_")
    ACL_MARKERS = ("acl", "adminsdholder", "adcs_control", "adcs_ntauth", "broad_acl")
    HEURISTIC_MARKERS = ("vulnerable", "not_observed", "not_deployed", "unknown")
    SOURCE_LABELS = {
        "event_log": "Event log",
        "ldap_security_descriptor": "LDAP security descriptor",
        "ldap_attribute": "LDAP attribute",
        "analyzer_rule": "Analyzer rule",
        "runtime_gap": "Runtime coverage gap",
        "directory_object": "Directory object",
        "analyzer_conclusion": "Analyzer conclusion",
    }
    STRENGTH_LABELS = {
        "direct": "Direct",
        "inferred": "Inferred",
        "coverage_gap": "Coverage gap",
        "context": "Context",
        "derived": "Derived",
    }

    def enrich_risks(self, risks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Mutate and return the supplied risk dictionaries for pipeline compatibility."""
        for risk in risks:
            self.enrich(risk)
        return risks

    def enrich(self, risk: dict[str, Any]) -> dict[str, Any]:
        risk_type = str(risk.get("type") or "unknown").casefold()
        evidence = risk.get("evidence")
        evidence_dict = evidence if isinstance(evidence, dict) else {}
        chain: list[dict[str, Any]] = []

        if risk_type.startswith(self.EVENT_PREFIXES) or evidence_dict.get("event_ids"):
            score = 0.99
            basis = "Observed security telemetry"
            chain.append(self._step("event_log", "A matching Windows security event was observed", "direct"))
        elif any(marker in risk_type for marker in self.ACL_MARKERS) or evidence_dict.get("trustee_sid"):
            score = 0.95
            basis = "Parsed directory security descriptor"
            chain.append(self._step("ldap_security_descriptor", "An access-control entry directly supports the finding", "direct"))
        elif evidence_dict:
            score = 0.90
            basis = "Exact LDAP attribute or graph evidence"
            chain.append(self._step("ldap_attribute", "Directory attributes or graph relationships support the finding", "direct"))
        else:
            score = 0.72
            basis = "Configuration heuristic"
            chain.append(self._step("analyzer_rule", "The analyzer inferred the condition from collected configuration", "inferred"))

        if evidence_dict.get("requires_runtime_validation"):
            score = min(score, 0.60)
            basis = "Static evidence; runtime validation required"
            chain.append(self._step("runtime_gap", "Event or endpoint evidence is required for confirmation", "coverage_gap"))
        if any(marker in risk_type for marker in self.HEURISTIC_MARKERS) and not evidence_dict:
            score = min(score, 0.58)
            basis = "Heuristic or coverage-gap finding"
        if risk.get("cve") and not evidence_dict.get("probe_result"):
            score = min(score, 0.55)
            basis = "Version/configuration heuristic; no active probe"

        source_count = self._evidence_count(evidence)
        if risk.get("affected_object") not in (None, "", "Unknown"):
            chain.insert(0, self._step("directory_object", "The affected directory object was identified", "context"))
        chain.append(self._step("analyzer_conclusion", "The rule mapped the evidence to a security finding", "derived"))
        level = "high" if score >= 0.85 else "medium" if score >= 0.65 else "low"
        confidence = {
            "score": round(score * 100, 1),
            "level": level,
            "level_label": level.title(),
            "basis": basis,
            "evidence_count": source_count,
            "sources": list(dict.fromkeys(step["source"] for step in chain)),
        }
        risk["confidence"] = confidence
        risk["confidence_score"] = confidence["score"]
        risk["confidence_level"] = level
        risk["evidence_chain"] = chain
        return risk

    @classmethod
    def _step(cls, source: str, claim: str, strength: str) -> dict[str, str]:
        return {
            "source": source,
            "source_label": cls.SOURCE_LABELS.get(source, source),
            "claim": claim,
            "strength": strength,
            "strength_label": cls.STRENGTH_LABELS.get(strength, strength),
        }

    @staticmethod
    def _evidence_count(evidence: Any) -> int:
        if isinstance(evidence, dict):
            return sum(1 for value in evidence.values() if value not in (None, "", [], {}))
        if isinstance(evidence, list):
            return len(evidence)
        return 1 if evidence not in (None, "") else 0
