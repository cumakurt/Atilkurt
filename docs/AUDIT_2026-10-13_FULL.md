# Application review, fixes and verification — 2026-10-13

## Outcome and boundaries

This review implements eight groups of confirmed defects or measured bottlenecks.
The baseline was commit `7c6f1b9` plus the user's uncommitted mobile-navigation
change in `reporting/saas_report_template.py` and its test in
`tests/test_domain_admin_takeover.py`. Those changes were preserved.
`.scannerwork/` was not changed. No live directory operation, credential
collection, deployment or commit was performed during this review.

AtilKurt is a read-only AD assessment CLI. Its critical flow is argument/scope
validation → LDAP inventory and optional evidence → registered analyzers →
review and evidence classification → scoring → HTML/JSON/integration/client
exports and optional history/checkpoints. Offline replay must preserve evidence
provenance and incompleteness without connecting to LDAP. A risky permission,
a supported graph capability, and a completed takeover are distinct claims.
An accepted risk remains an observed condition even when excluded from scoring.
An incomplete assessment must not become a clean result.

The review covered these boundaries, their existing tests, packaging/CI scripts,
the cache, graph identity and capability resolution, publication redaction,
directory/CISO presentation and checkpoint timestamps. Representative security
analyzers and shared ACL/identity helpers were inspected. This is not an
exhaustive proof of every rule in the analysis catalog or every AD deployment.

## Confirmed findings and applied changes

### F01 — High: domain graph confused permissions with complete capabilities

- **Location:** `AttackGraphV2Analyzer._add_control_edges`; graph consumers include
  takeover reporting and `simulate_remediation`.
- **Trigger/reproduction:** construct a domain node and an ACL finding for a
  single replication right, `GenericWrite`, or `WriteProperty`. The graph
  previously reported a Tier-0 route. Supplying the two replication rights
  created two independently traversable edges.
- **Expected/actual:** secret replication needs the relevant rights together
  on the same naming context; an arbitrary writable domain attribute is not
  itself domain administrative control. The graph previously treated each ACL
  row as an unconditional control grant. Consequently, removing one prerequisite
  could leave a fictitious alternative path.
- **Root cause/impact:** permission-to-edge conversion had no target-specific
  capability check. It overstated takeover exposure and distorted remediation.
- **Fix:** group valid replication permissions by resolved trustee and domain;
  emit one joint capability only for the required pair. Keep explicit full
  control/DACL/owner/all-extended-right grants, and exclude generic domain
  attribute writes from takeover claims. Raw ACL findings remain available.
- **Validation:** five negative permission cases and a positive pair/remediation
  test. The existing lab regression was corrected to supply both rights instead
  of encoding the incorrect single-right expectation; its path-closure checks
  remain. Reviewed/disproved findings still pass through the existing evidence
  filter before capability construction.
- **Protocol basis:** Microsoft's
  [IsGetNCChangesPermissionGranted procedure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/15bbda52-7742-4ce3-9327-018647b0fc26)
  and [Get-Changes-All definition](https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all).

### F02 — High: normalized graph names merged distinct identities

- **Location:** `AttackGraphV2Analyzer.analyze`, inventory node creation and
  membership lookup.
- **Reproduction:** two distinct SIDs named `a+b` and `a b` both became `user:a_b`;
  only the second node survived. Unicode/punctuation normalization has the same
  collision class.
- **Expected/actual:** both principals and their memberships must survive.
  Overwriting a dictionary entry could erase an account or attribute a control
  route to another account, producing false negatives or false positives.
- **Fix:** detect normalized-ID collisions before constructing nodes and append
  deterministic identity digests only to colliding IDs. Membership construction
  uses the assigned identity. Shortest-path tie traversal is sorted.
- **Validation:** distinct SIDs remain distinct; reversed inventory order yields
  the same graph. Existing graph and membership tests pass.

### F03 — High: unresolved explicit DN fell back to a privileged namesake

- **Location:** `AttackGraphV2Analyzer._control_target`.
- **Reproduction:** a grant on `CN=Admins,OU=Other,...` with display name `Admins`
  matched an inventoried Domain Admins SID at `CN=Admins,...` when the requested
  target was absent. This incorrectly produced a privileged route.
- **Root cause/impact:** display-name fallback ignored stronger but unresolved
  identity evidence. Users could remediate or prioritize the wrong object.
- **Fix:** an explicit unresolved DN never falls back to a label. Label-only
  matching is limited to unique labels across merged graph nodes.
- **Validation:** a namesake in a different OU no longer creates a route.

### F04 — High: requested secret redaction missed publication branches

- **Locations:** `redact_nested_secrets`, `generate_reports`,
  `build_checkpoint_payload`.
- **Reproduction:** put synthetic secrets in `password: [value]`, a nested secret
  object, a directory `ms-Mcs-AdmPwd` list, or compliance/risk-management text;
  request `--redact-secrets`. These values could survive in a publication or
  checkpoint even though scalar fields in other branches were redacted.
- **Root cause/impact:** secret-key handling only covered scalar strings/bytes;
  report/checkpoint redaction omitted the complete data and compliance branches.
  A user relying on the publishing option could share sensitive evidence.
- **Fix:** recursively redact secret-key containers, preserving null/empty
  values and container structure; apply publication redaction to data,
  analysis, scoring and compliance before rendering or checkpoint creation.
- **Validation:** multivalued/nested secret regression, checkpoint regression,
  render-boundary regression, and existing HTML/JSON/DOCX/PDF visibility tests.
  The explicitly requested unredacted product behavior remains supported.
- **Limit:** pattern-based redaction cannot recognize every secret in arbitrary
  prose. This change addresses the confirmed structural omissions, not a claim
  of universal secret detection.

### F05 — Medium: mutable LDAP cache could corrupt later evidence

- **Location:** `LDAPQueryCache.get_query_result` / `set_query_result`.
- **Reproduction:** cache a record with a membership list; append to that list in
  the original result or edit a subsequent cache hit. Later hits previously
  returned the modified content.
- **Root cause/impact:** shared object references crossed the cache boundary.
  Analyzers annotate records and publication code redacts them in place; later
  consumers could receive modified evidence, depending on execution order.
- **Fix:** deep-copy on insertion and retrieval at the LDAP-specific cache
  boundary. The general-purpose `TimedCache` contract is unchanged.
- **Validation:** nested-list mutation and independent-consumer mutation tests,
  plus existing cache and LDAP suites. Copies cost memory/time; no performance
  improvement is claimed for this correctness fix.

### F06 — Medium: directory UI disagreed with privilege identity rules

- **Location:** `DirectorySectionMixin._generate_directory_section`.
- **Reproduction:** membership in `CN=Readers,OU=Domain Admins,...` appeared in
  the Domain Admin groups field; `Domain Admins Archive` appeared privileged;
  a renamed actual Domain Admins group could be missed.
- **Root cause/impact:** substring checks in presentation bypassed the shared
  SID/role helpers. The UI could mislead users despite correct analyzer output.
- **Fix:** resolve direct membership by DN, use SID-aware role matching and
  security-group checks, and use the shared group classification for rows.
- **Validation:** a fixture checks the OU false positive, renamed group positive
  and namesake false positive together. These fields describe direct membership;
  full nested reachability remains the graph's responsibility.

### F07 — Medium: timezone stripping changed age thresholds and provenance

- **Locations:** computer enrichment, directory display, CISO password-age
  statistics, checkpoint and collection timestamps.
- **Reproduction:** represent the same instant in UTC and UTC+12 near a 90-day
  boundary. Previous age calculations discarded the offset, producing different
  counts/classifications. Checkpoint metadata omitted the UTC offset entirely.
- **Root cause/impact:** subtraction used local naive wall time instead of the
  represented instant. Offline replay and scans in different timezones could
  disagree, and checkpoint ordering/provenance was ambiguous across hosts.
- **Fix:** normalize ISO strings, datetimes and FILETIME through UTC where
  applicable, preserve CISO offsets, explicitly display UTC, and emit aware UTC
  checkpoint timestamps. Legacy naive directory dates are interpreted as UTC.
- **Validation:** offset-invariant computer and CISO boundary tests and aware
  checkpoint timestamp assertions; existing checkpoint and analysis tests pass.

### F08 — Medium: directory rendering repeatedly scanned every finding

- **Location:** `DirectorySectionMixin._generate_directory_section`.
- **Reproduction:** 3,000 users and 3,000 findings caused a full findings scan for
  each object. Groups/computers had the same repeated-search pattern.
- **Root cause/impact:** association cost grew as objects × findings, delaying
  report generation for larger inventories.
- **Fix:** build a findings-by-object index once and use it for all three object
  collections. Association now takes objects + findings work, apart from actual
  matching records and output generation.
- **Measurement:** same interpreter, host, fixture and five-run harness before
  and after: median **0.251959 s → 0.023687 s**. Output size was **7,388,782 bytes**
  in both runs. This is a synthetic section-rendering measurement, not an
  end-to-end scan/network or production-forest benchmark.
- **Validation:** per-object total/critical count regression and the existing
  reporting suites.

## Verification performed

- Baseline: `make test` **886 passed**, two ldap3/pyasn1 deprecation warnings;
  `make lint` passed. Existing mobile-navigation edits were included.
- New regression tests first reproduced **12 failures**, then **3 additional
  failures**, then the CISO offset failure. A separate count-preservation test
  protects the rendering optimization. There are **17 added test cases**.
- Final `make test`: **903 passed**, the same two dependency warnings.
- `make lint`, `git diff --check`, `bash -n install.sh run.sh`,
  `sh -n docker-entrypoint.sh`, ShellCheck, and Node syntax checks for the two
  report workspace scripts passed.
- `.venv/bin/python -m pip check`: no broken requirements.
- Built wheel with system Python and `pip wheel --no-deps --no-build-isolation`;
  no dependency installation or lockfile change. The runtime/test interpreter
  was Python **3.14.7**; the full supported-version CI matrix was not executed.
- `AtilKurt.py quality`: **49/49** labelled built-in fixtures passed. This is
  fixture coverage, not a measured production false-positive/false-negative rate.
- Full test suite includes offline replay, review/exception expiry, incomplete
  assessments, timeout/denial handling, scope budgets, atomic-file boundaries,
  history rollback, HTML/JSON/integration export and real DOCX/PDF generation.
  Network-dependent paths use fixtures/mocks in these tests.
- Headless Chromium: synthetic EN and TR reports, **40 tabs each**, desktop
  activation, real mobile menu clicks and typing after closing the overlay.
  No severe console errors or external resource requests. Mobile screenshots
  were inspected after the sidebar transition finished. The pre-existing mobile
  fix was preserved and verified, not counted as work authored in this review.
  The synthetic browser fixture has no password-hash tab; hash rendering/export
  is covered by tests, not this browser run.

Reproduction tests: `tests/test_full_audit_regressions.py` and the corrected
replication fixture in `tests/test_live_lab_regressions.py`.
Ignored local evidence is retained under `output/audit-20261013-full/`:
baseline/failure/final logs, quality output, build log, benchmark harness,
synthetic reports, browser results and mobile screenshots.

## Compatibility and remaining work

- Joint replication edges and collision-disambiguated node IDs intentionally
  change affected graph/edge identifiers. Regenerate saved remediation edge
  selections from a newly generated graph. Ordinary unique inventory IDs remain
  unchanged. Old offline graphs are not automatically rewritten without the
  evidence/review workflow that rebuilds them; use a fresh scan or explicit
  review/rebuild before relying on old derived paths.
- Replication aggregation is per resolved trustee/domain. Rights split across
  different groups in one effective token are not newly solved here. Other
  property-specific, conditional and cross-forest path semantics still need
  representative directory fixtures and independent validation; graph routes
  remain bounded and are not proof of executed takeover.
- No live LDAP/LDAPS/StartTLS, SYSVOL, DRS or actual account takeover was tested.
  Historical TLS failures in previous audit documents were not retested and are
  not claimed to be resolved. Live verification requires an authorized reachable
  lab and valid server-side TLS configuration.
- No full dependency-CVE audit, Windows/macOS execution, container build,
  large-forest memory/load study or exhaustive accessibility/localization audit
  was performed. Dependency compatibility checks do not establish absence of
  known vulnerabilities. Some minor untranslated report chrome remains.
- Remaining broad exception handling and duplicate legacy/modern rule paths are
  maintenance risks, not newly reproduced failures in this run. Prefer focused
  fixture-backed consolidation over a large rewrite. Report type/schema checks
  and exhaustive graph capability semantics deserve follow-up coverage.
- Existing scoring is a heuristic prioritization model. Current fixture coverage
  cannot establish calibration or error rates for an unknown production domain.
