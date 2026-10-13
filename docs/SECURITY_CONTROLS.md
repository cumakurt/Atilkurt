# Evidence-based security controls

AtilKurt remains a read-only assessment tool. These features collect or import
configuration and runtime observations; they do not change AD, enable policies,
rotate credentials or restore backups. The opt-in `--collect-password-hashes`
workflow additionally requests current account key material and NT password-history digests using read-only DRS
replication under the supplied credentials. It does not escalate privileges.

Scan reports/checkpoints expose collected secret values by default. Use
`--redact-secrets` to publish a redacted copy; identity masking is independent.
The bind password remains excluded from reports and logs. See the README's
password-hash section for transport, permission and scope limitations.

## Connection migration

LDAP on port 389 without TLS is the scan default, equivalent to `--insecure-ldap`.
Select `--ssl` for certificate-verified LDAPS. A failed explicit TLS connection
never falls back to LDAP.

```bash
Atilkurt -d example.com -u auditor --dc-ip dc.example.com --ssl --ca-certs-file company-ca.pem
Atilkurt -d example.com -u auditor --dc-ip dc.example.com --starttls --ca-certs-file company-ca.pem
```

`--starttls` opens port 389 and completes TLS before binding. An explicit
`--insecure-ldap` selects the same transport as the default; SIMPLE authentication
is rejected without TLS. `--auth-method simple` explicitly selects SIMPLE over
TLS, without automatic authentication fallback.

Kerberos uses the existing ticket cache and the supplied principal. Install the
optional backend with `pip install '.[kerberos]'`, acquire a ticket using your
normal enterprise workflow, and use a DC hostname matching its LDAP SPN:

```bash
Atilkurt -d example.com -u auditor@example.com --dc-ip dc.example.com --auth-method kerberos
```

Kerberos scans do not prompt for or consume a password. Kerberos LDAP credentials
are not reused for password-based SMB/SYSVOL reads; import offline shared files
for that workflow. Live ticket negotiation must be validated against your KDC.

## Common evidence contract

Import the local Windows collector output using `--security-evidence`, or use
`--validation-evidence` for the existing finding-review workflow. `--posture-file`
now requires the same target-bound observations for authoritative JSON evidence.
Flat historic registry/GPO exports remain evidence gaps; file modification time
is never treated as collection time.

```json
{
  "schema_version": 1,
  "domain": "example.com",
  "targets": [
    {"target": "dc.example.com", "controls": ["credential_guard", "wdigest", "advanced_audit_policy"]}
  ],
  "observations": [
    {
      "target": "dc.example.com",
      "name": "credential_guard",
      "value": {"configured": true, "running": true},
      "source": "Win32_DeviceGuard",
      "collected_at": "2026-10-12T09:00:00Z"
    }
  ]
}
```

Replace the illustrative timestamp with the actual collection time. Each record
inherits the document domain unless it explicitly supplies a domain. Wrong
domains, absent targets/sources, unsuccessful collection, stale timestamps and
timestamps more than five minutes in the future are unknown. The default age is
30 days, configurable using `--evidence-max-age-days`.

Every target/control has a separate state: `secure`, `insecure`, `unknown`,
`conflicting` or `not_applicable`. Missing controls on inventoried DCs stay
visible. A declared not-applicable control requires a reason; contradictory
observations produce `conflicting`, rather than silently hiding evidence.

Snapshot exports preserve the target/control manifest and declared exclusions.
Offline reports recheck saved posture timestamps. When evidence expires, earlier
weaknesses remain visible as requiring validation; expiration does not establish
remediation. Fresh secure observations can resolve the corresponding weakness.
Replaced endpoint evidence is rebuilt instead of being reintroduced from a saved
federated graph.

`--require-signed-evidence --trusted-key public.pem` rejects unsigned evidence.
Use the existing `Atilkurt sign` utility to sign collector/export documents.
Raw EVTX/XML/CSV logs cannot satisfy that policy: convert relevant observations
to this schema, preserve source information and sign the resulting document.
Signatures authenticate the supplier and integrity, not the factual truth of
the supplier's claims.

## Supported controls and value semantics

- `lsa_protection`, `credential_guard`, `remote_credential_guard`: objects with a
  boolean `running`; a `configured` flag alone remains unknown.
- `wdigest`: the explicit numeric UseLogonCredential value, 0 or 1. Missing
  registry values are unknown, not assumed disabled.
- `adcs_epa`, `adcs_rpc_signing`, `adcs_role_separation`: observed booleans.
  HTTPS availability alone is never EPA evidence.
- `adcs_ca_permissions`: `complete`, `dacl_present`, `grants` (SID/mask records)
  and a nonempty PKI-owner-supplied `approved_trustees` list. CA management,
  certificate officer, GenericAll, WriteDACL and WriteOwner grants to unapproved
  trustees are insecure. Denies and conditional ACEs need independent effective
  access evidence and remain unknown. A null DACL is insecure.
- `advanced_audit_policy`: `required_subcategories` contains subcategory GUIDs;
  `subcategories` maps GUIDs to numeric flags 0..3. Optional `required_flags`
  selects required success/failure bits per GUID; the default is both bits.
  The collector checks directory access/changes, group management and Kerberos.
  GPO display names never establish audit policy coverage.
- `entra_privileged_mfa` and `entra_conditional_access`: objects with `complete`,
  `total`, `covered` and `basis: "effective_enforcement"`. MFA registration or
  the existence of an enabled policy is not effective enforcement. Import an
  independently evaluated tenant export that includes all privileged identities
  and relevant exclusions/conditions. AtilKurt does not log in to Graph or infer
  effective Conditional Access from partial policy JSON.
- `hybrid_replication_permissions`: include `account`, `password_hash_sync`,
  `required_replication_only`, `has_replication` and/or `excessive_permissions`.
  Verified required PHS permissions are retained as a sensitive Tier-0
  capability, not scored as excessive rights to remove.
- `recovery_backup`: `last_success`, `max_age_days` (1..365), `system_state`.
- `recovery_isolation`: observed boolean confirming backup isolation.
- `recovery_dsrm_access`: boolean `vaulted` and `access_reviewed`. Never export
  DSRM passwords or recovery keys.
- `recovery_restore_test`: `successful`, `isolated`, `tested_at`; the successful
  isolated restore must be no older than 180 days.
- `recovery_plan`: `owner`, assessment `domain`, `reviewed_at`,
  `procedures_verified`; review must be no older than 180 days.

Recovery evidence is domain-scoped. Assess every forest domain and preserve the
separate results; a healthy backup job or one domain's recovery evidence does
not prove that the entire forest can be restored. The evidence importer does
not execute a recovery or certify application/data recovery.

## Native Windows collector

Generate the existing local read-only script using `--validation-script` or the
report's collector download. Run it on each explicitly assessed Windows host:

```powershell
.\collector.ps1 -OutputPath .\host-evidence.json
```

The script reads registry values, Device Guard runtime state, current-boot
Wininit PPL evidence, local administrator SIDs, bounded interactive sessions,
numeric audit subcategories, CA security/RPC/role-separation configuration and
the default certsrv IIS EPA setting. It also exports computer RSoP.
Unavailable services, missing permissions and non-default IIS topology are
recorded as collection errors. PKI owners must provide authorized CA trustees;
the collector deliberately does not guess that allowlist. It does not collect
passwords, tickets, certificate private keys or backup contents.

Remote Credential Guard runtime, cloud enforcement and recovery drills require
independent operational evidence. Those controls remain unknown until supplied.
This distinction prevents registry intent from becoming a false secure result.

## Policy semantics and OS behavior

LDAP signing, channel binding, inbound/outbound/domain NTLM restrictions and
SMB signing use separate legal values and meanings. Inbound NTLM value 1 denies
domain accounts; outbound value 1 only audits; full domain restrictions require
value 7 under this hardened baseline. Invalid enum values never increase verified
coverage.

Windows Server 2025 `LDAPServerEnforceIntegrity=1` overrides the legacy signing
setting only with fresh Windows Server build evidence (26100 or later).
Older server builds mark that enforcement policy not applicable. Missing OS or
policy evidence stays unknown; no new-install versus upgrade behavior is
guessed from the OS name alone.

## GPO content and actual application

Supply `--gpo-policy-file GPO_ID=PATH` with `--gpo-context`. Supported inputs are
Registry.pol (binary DWORD settings), GptTmpl.inf registry values and audit.csv
numeric subcategories. Every file is bounded, hashed and attached to an explicit
GPO ID. Contradictory settings fail preflight. Signed contexts must contain the
file digest in the GPO's `policy_sha256` array.

`--gpo-context` and live `--gpo-target` are alternative input sources and cannot
be combined. This prevents a live collection from silently replacing imported
policy content or target bindings. Invalid text encodings, malformed policy
values and ambiguous GPO identifiers fail input validation.

Set the GPO `collected_at` timestamp. Stale or missing content timestamps and
Registry.pol deletion/security directives make predicted results conditional.
Existing permission, WMI, inheritance, site/local and loopback limitations remain.
Bind RSoP to an explicit target. Its optional `settings` map produces a
per-setting `setting_comparison` against predictions; stale RSoP is labeled.
Parsed audit subcategories are retained in `content_evidence` for review;
effective host auditing still requires auditpol evidence.

## Endpoint relationships and privileged access

- `local_administrator`: `value.principal_sid`; creates `AdminTo`.
- `privileged_session`: `value.principal_sid`; creates conditional `HasSession`.
- `management_connection`: `value.principal_sid`; creates conditional
  `CanPSRemote` requiring effective endpoint access confirmation.
- `controls_identity_asset`: `value.controlled_target`; an explicitly verified
  management relationship. Hosts controlling a DC directly or transitively are
  Tier 0, as are evidenced local administrators of those assets.

Relations require fresh observations and unambiguous directory identities.
Unresolved identities are reported as gaps. A session never proves credential
theft. The attack planner keeps session/access prerequisites visible. Graph
exports disclose path depth and reporting limits; absent paths are not proof
that an attack is impossible. Domain Admins and Administrators are Tier 0;
renamed groups use well-known SIDs and nested membership is expanded.

## NTLM and RC4 retirement

Fresh target-bound Security events 4776 and RC4 4769 observations build a
client/account/service dependency inventory. Imported `legacy_protocol_usage`
observations can add protocol (`NTLM` or `RC4`), `client`, `account`, `service`,
positive `count`, `owner` and `expires_at`. Exceptions need an owner and future
expiry. Missing telemetry never produces a "ready to disable" claim.

Evidence confidence remains a heuristic strength score, displayed on a /100
scale and exported with `calibrated: false`; it is not a probability or a
production accuracy measurement. Offline fixtures measure only their labelled
scenarios.

## References

- [Microsoft LDAP signing and enforcement](https://learn.microsoft.com/en-us/windows-server/identity/manage-ldap-signing-group-policy)
- [Server 2025 registry baseline](https://learn.microsoft.com/en-us/azure/osconfig/server2025machineconfigdoc)
- [Audit subcategory GUIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/auditing-constants)
- [AD CS relay protections](https://support.microsoft.com/en-us/servicing/os/windows-server/2021/07/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs)
- [PHS required privileges](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-password-hash-synchronization)
- [Forest recovery](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-guide)
