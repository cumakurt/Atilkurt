# Code quality and reporting audit — 2026-10-08

## Scope and method

Reviewed the CLI collection/analysis/scoring/export pipeline, LDAP paging and parallel workers, cache and checkpoint behavior, evidence/review boundaries, baseline comparison, history transactions, compliance calculations, and HTML/client/integration reports. The starting tree passed 588 tests and Ruff. Reproductions revealed defects outside that coverage; the fixes include a dedicated regression suite in `tests/test_deep_audit_regressions.py`.

This was a source review and local execution exercise, not a live domain assessment. No production directory was contacted. It does not establish that every analyzer or external integration is defect-free.

## High-impact fixes

- **P1 — HTML injection in compliance evidence.** LDAP-controlled names, details, descriptions, and queries could reach HTML without escaping. All four compliance renderers now escape nested display data without mutating the original evidence. Tests cover CIS, NIST, ISO, and GDPR.
- **P1 — Score inflation during regeneration.** A fallback rule with original medium severity scored 48, then 84, then 100 across repeated scoring. The previous derived severity was reused as input. `source_severity` now preserves the original input, including the existing review basis for older exports. Obsolete combination bonuses are removed before rescoring.
- **P1 — Unsupported compliance success.** Findings-only reports treated absent findings as passed controls. They now expose unknown checks, `assessment_basis`, and `assessment_status`, and show “Not assessed” in HTML. Numeric score fields remain present for consumers; see the compatibility notes below. Missing inventory and partial directory collection also prevent positive compliance claims.
- **P1 — Inverted trust filtering check.** The compliance analyzer treated the quarantine bit as disabled SID filtering. It now recognizes enabled quarantine, evaluates locally relevant external trusts, and leaves forest filtering without sufficient evidence unknown. Failed trust queries remain visible as unknown controls. The bit meaning was verified against [Microsoft's trustAttributes specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c).
- **P1 — Snapshot absence presented as remediation.** Snapshot comparison now reports absent findings as `unobserved_risks`. It does not populate verified resolved findings; the existing `--retest` workflow is responsible for closure.

## Additional corrections

- **P2 — Compliance calculations:** CIS Controls v8 counts the three implemented safeguard mappings instead of assuming 20 controls; repeated failures of one safeguard count once. Zero maximum password age no longer passes the configured age check, and decoded LDAP `timedelta` values are supported through the existing policy converter. Domain Admins are identified by the shared SID-aware identity helper. UTC-aware inactive-account timestamps are compared correctly.
- **P2 — Consistent report totals:** the HTML overall compliance score uses the exported total, including the fifth framework. Fallback checks now have the control identifiers and names expected by the HTML renderers.
- **P2 — Cache performance and expiry:** insertion no longer scans the whole cache before any deadline can have expired. Expiry uses the monotonic clock, and an explicit zero TTL invalidates the value instead of applying the default TTL. Expired entries are still discarded before evicting a live LRU entry.
- **P2 — Baseline input and identity:** nested checkpoint directory collections are loaded correctly. ACL grants with different targets, trustees, or permissions are distinguished; case-only changes to identity names no longer create new findings. Severity comparison uses original severity when available, avoiding comparisons between raw and derived scores.
- **P2 — Portable report assets:** external-asset reports copy nested fonts and webfonts. The wheel includes `vendor/webfonts/*`, so installed single-file reports can embed real icon fonts too.
- **P2 — Nessus export interoperability:** the existing high/critical export emits numeric severities and deterministic SHA-256-derived numeric plugin identifiers instead of Python's process-randomized hash. The severity representation follows the [Tenable Nessus file format](https://docs.tenable.com/quick-reference/nessus-file-format/Nessus-File-Format.pdf). Synthetic plugin identifiers are not official Tenable plugin assignments.

## Performance evidence

Local CPython 3.14.7 microbenchmark; three runs per size, median wall time, `TimedCache(maxsize=4096)`, sequential unique string keys and integer values, default TTL. Both revisions used the same workload on the same machine.

- 1,000 insertions: 13.335 ms before; 0.407 ms after.
- 4,000 insertions: 377.725 ms before; 3.176 ms after.
- 8,000 insertions: 1,475.675 ms before; 5.144 ms after.

These are cache-only timings, not LDAP or end-to-end scan benchmarks. Expiration cleanup still scans at an expiration boundary; the optimization removes repeated scans while all entries remain unexpired.

## Verification

- Full `make test` suite, including regression cases for the fixes.
- `make lint`, `git diff --check`, and formatting of the new regression module.
- `python -m pip check` and wheel build with `python -m pip wheel --no-deps .`.
- Shell syntax checks and ShellCheck for all three launch scripts.
- Built-in labelled quality evaluation: 49/49 fixtures passed. This is fixture accuracy, not measured production precision/recall.
- Wheel extracted outside the source checkout: English and Turkish offline runs produced HTML, JSON, PDF, DOCX, CSV, SIEM NDJSON, and CEF. The second run consumed the first run's snapshot and preserved its score. Nested external fonts and wheel asset membership were checked, along with PDF/DOCX container signatures.

## Compatibility and limits

Consumers of findings-only compliance exports must interpret the retained numeric `0.0` together with `assessment_basis: findings_only` and `assessment_status`; it is not a measured zero-percent compliance assessment. New `unknown_*` and `total_checks` fields expose the evidence boundary. Corrected scores can differ from previously generated reports, especially CIS Controls v8 and trust checks.

`compare_snapshot` retains `resolved_risks` as an empty compatibility field and adds `unobserved_risks`. The lower-level legacy `compare` API retains its original observation-difference field names. For older snapshots without original severity or review metadata, the original pre-scoring input cannot always be reconstructed.

Live AD permissions, real server paging/ranged attributes, and actual third-party ingestion were not exercised. Browser visual rendering was not checked interactively. Validation ran on the available Python 3.14.7 environment; the repository's Python 3.9/3.11/3.13 CI matrix was not executed locally. Two existing ldap3/pyasn1 deprecation warnings remain.
