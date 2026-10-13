# Non-admin Domain Admin footholds

- [x] List named non-admin accounts that can reach Domain Admin
- [x] Attach technique, reason, and finding evidence per foothold
- [x] Exclude already-privileged and broad principals
- [x] HTML block, tests, README

# Assessment-account Domain Admin paths

- [x] Resolve the bound LDAP account and collect its token groups
- [x] Enumerate all bounded Tier-0 routes and ESC enroll options from that account
- [x] Expand the DA map: extra catalog entries, uncategorized DA findings, full evidence, per-object options
- [x] HTML: assessment-account block plus all route options
- [x] `--sysvol` inspects the DC; CISO KPI trends from history-db
- [x] Tests, README, `make test`, `make lint`

# README

- [x] Align README with the current product (DA map, SYSVOL, CISO trends, pentest CLI, quality fixtures)
- [x] Fix heading hierarchy, stale counts, fast-profile skip list, and incomplete CLI reference

# False-positive and detection correctness

- [x] Do not treat disabled accounts, krbtgt, computers, or managed service accounts as active Kerberoast/AS-REP targets
- [x] Do not count domain-controller unconstrained delegation as a critical finding
- [x] Report privileged SPN and real delegation; stop the privileged-user x unconstrained-computer cartesian product
- [x] Drop evidence-free checklist placeholders and duplicate roast/delegation rows
- [x] Mark Kerberoast/AS-REP as Domain Admin equivalent only when the account is privileged
- [x] Stop describing whenChanged as a group-membership change
- [x] Match privileged SIDs by authority, not by RID alone
- [x] Keep CISO counts, Kerberoasting tabs, and grouped objects aligned with the scored findings
- [x] Keep a timed-out paged read, mark an unassessed collection, and refuse to overwrite a corrupt checkpoint
- [x] Do not treat a single replication right, a missing enrollment flag, or an unreadable descriptor as a clean result

## Review

Non-admin footholds: named users/computers (and non-privileged groups) with graph routes or trustee evidence are listed with technique, reason, and finding rows. Already-privileged identities and Everyone/Authenticated Users/Domain Users are excluded.

The Domain Admin map starts from the bind account: whoami + tokenGroups, bounded graph routes into Tier-0, confirmed ESC templates, findings that name the account, and authenticated-session starters. The catalog includes leftover `other_da` findings. `--sysvol` targets the DC. CISO score/critical/high KPIs trend against the previous `--history-db` scan.

README now matches that product: dedicated Domain Admin section, `--check-user` distinguished from the map, opt-in SYSVOL usage, complete pentest/review CLI, 49 labelled quality fixtures across nine families, `acl_legacy` on the fast profile, and a contents list.

Detection review: disabled, krbtgt, computer, and managed-service accounts are no longer active roast targets. Domain controller unconstrained delegation is expected and is excluded. Privileged SPN and real delegation are reported; the privileged-user by unconstrained-computer product is not. Checklist placeholders without evidence are gone. Kerberoast and AS-REP count as Domain Admin equivalent only with privileged evidence. `whenChanged` is labeled as an object change.

Second pass: a domain SID is privileged only when its authority and RID match a well-known domain group. Built-in groups match only `S-1-5-32-{rid}`. CISO narrative and charts skip findings that are not scored. AS-REP stays off the Kerberoasting tab. Grouped LAPS rows keep the named accounts. Replication shadow-admin permissions score as critical only when both replication rights are present. Empty or multi-row tokenGroups reads are unreadable or ambiguous, not a SID mismatch.

Collection review: an unlimited paged read uses a longer deadline, and a timeout keeps the pages already retrieved as an incomplete query instead of caching them as a finished inventory. A scope limit or GPO read error marks that collection unassessed. A corrupt checkpoint is not overwritten. ESC1 is still reported when the enrollment flag was not collected. An unreadable security descriptor is its own finding. A lone replication right does not open the DCSync path.

# Incomplete results and duplicate findings

- [x] Do not score an empty incomplete assessment as 100/100 or describe it as in good standing
- [x] Exit 2 when collection or an analysis step is explicitly incomplete
- [x] Score and CISO privileged counts use current group membership, not stale adminCount
- [x] Keep one password-never-expires finding for service accounts
- [x] Collapse a complete DCSync ACL pair when the DCSync finding names the same trustee
- [x] Report an unreadable RBCD descriptor instead of a confirmed grant
- [x] Record a failed GPO link lookup instead of an empty link list

# Remaining review items

- [x] Expand nested privileged membership for user-risk findings
- [x] Treat stale adminCount as current privilege only in the protected-account helper
- [x] Keep one constrained-delegation row when the broad finding already covers the computer
- [x] Do not call populated altSecurityIdentities a confirmed ESC14 path
- [x] Redact credential assignments in directory descriptions before reports and checkpoints
- [x] Clear the bind password when the LDAP connection closes
- [x] Stamp exports, checkpoints, and compliance records in UTC
- [x] Keep ESC1 unconfirmed when the enrollment flag was not collected


# Application audit and lab validation — 2026-10-12

- [x] Protect publication, checkpoint, identity and history boundaries; add regression tests.
- [x] Correct FILETIME/lockout semantics and prune unreachable route searches.
- [x] Retest optional LDAP containers and SCCM schema handling against the lab.
- [x] Separate existing membership, delegated administration, Tier-0 reachability and investigation options.
- [x] Preserve mixed supported/pending evidence and connect component graph SID aliases.
- [x] Add per-finding proof dossiers, read-only PoCs, retest contracts and command-substitution guards.
- [x] Verify EN/TR HTML and integration/client exports, desktop/mobile interactions and read-only ACL/membership evidence.
- [ ] Lab operator: restore a usable DC LDAPS/StartTLS endpoint, then rerun certificate-verified TLS tests. Current TLS failures are retained as failures.

Detailed findings and validation limits: `docs/AUDIT_2026-10-12.md`. Private live artifacts: `output/audit-20261012/`.

# Password hashes and report visibility — 2026-10-13

- [x] Add opt-in scoped DRS collection with process timeout, typed key parsing and explicit incomplete results.
- [x] Make scan report values visible by default and preserve an explicit `--redact-secrets` publishing option.
- [x] Add bilingual hash results and preserve their status in JSON, DOCX/PDF, checkpoints and offline reports.
- [x] Correct the missing query count in client reports; verify 880 tests, lint, wheel, exports and 41 browser tabs.
- [x] Report every returned LM/NTLM, NT history and Kerberos digest; skip DRS when the assessment token lacks both replication rights.
- [x] Lab rerun with a replication-capable account: 105/105 current digests, 10 NT history digests and 312 Kerberos keys are in HTML, JSON, DOCX and PDF. Domain Users remains `not_authorized`.
- [ ] Lab operator: restore LDAPS/StartTLS; current reset/unavailable results remain failed checks.

Follow-up details: `docs/AUDIT_2026-10-13.md`. Private evidence: `output/audit-20261013/`.

# Remediation simulation live check — 2026-10-13

- [x] Bind domain replication ACEs to the domain naming context and treat that node as Tier-0.
- [x] Confirm the lab report lists the control edge and that closing it changes the before/after counts.

## Review

The fast profile omits `attack_graph_v2`, so simulation stays empty there by design. A full lab scan now shows one exposed source. Removing that account's three domain replication edges drops exposure to zero; reset restores it.

# Full local review — 2026-10-13

- [x] Reproduce and fix domain capability, graph identity and explicit-DN matching defects.
- [x] Close redaction gaps in nested secret fields, report inputs and checkpoints.
- [x] Isolate cached LDAP evidence from mutable analysis/publication results.
- [x] Align directory privilege display and age calculations with shared identity/UTC rules.
- [x] Index directory risk associations and measure before/after rendering time.
- [x] Verify 903 tests, 49 labelled cases, lint, dependency consistency, wheel and EN/TR browser navigation.

Details, compatibility changes and untested live scenarios: `docs/AUDIT_2026-10-13_FULL.md`.
The earlier three independent replication edges are now one joint capability;
the prior single-right graph fixture overstated what its evidence established.
