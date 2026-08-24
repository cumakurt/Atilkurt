# AtilKurt

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

AtilKurt is a read-only Active Directory security assessment tool. It collects directory data through LDAP, runs a broad set of security analyzers, scores the findings, and generates a self-contained HTML report for offline review.

## Simplest Manual Usage

After completing either installation method below, a scan needs only the domain, username, and password. If `--dc-ip` is omitted, AtilKurt connects using the domain name:

```bash
ATILKURT_PASS='your-password' \
.venv/bin/atilkurt --domain example.com --username auditor
```

Replace the example values with the assessment account details. The password is passed through the environment instead of a command-line argument, so it is not exposed in the process argument list. If the domain name does not resolve to a reachable domain controller, add `--dc-ip 192.168.1.10`. Add `--ssl` when the domain controller provides LDAPS on port 636.

## Overview

The tool is designed for security assessments, internal red-team style reviews, and directory hygiene analysis. It does not modify Active Directory and is built around LDAP search operations only.

Core goals:

- Collect identity, group, computer, GPO, and ACL data from Active Directory
- Detect misconfigurations, weak controls, and known attack paths
- Consolidate findings into a severity-based risk model
- Produce offline-capable HTML, JSON, and optional checkpoint exports
- Support large environments with paging, caching, parallel collection, and incremental execution

## Key Capabilities

### Directory Inventory

- User, computer, group, and GPO collection
- Object SID collection for identity and ACL correlation
- Large-domain friendly paging and query caching

### Security Analysis

- User, computer, and group risk analysis
- Kerberos, delegation, privilege escalation, and ACL review
- Kerberoasting, AS-REP roasting, DCSync, GPP, LAPS, trust, and password policy checks
- AD CS analysis, including extended certificate abuse paths
- Extended LDAP checks for common privileged-object and configuration weaknesses
- Domain security, audit policy, stale object, gMSA, KRBTGT, machine quota, and replication metadata analysis

### Scoring and Prioritization

- Severity-based domain score
- Exploitability scoring
- Risk prioritization and remediation cost estimation
- Business impact and ROI-style remediation views

### Reporting

- Single-file HTML report with embedded assets
- JSON export for downstream processing
- Compliance reporting for CIS, NIST CSF, ISO 27001, and GDPR
- Executive summary and analysis summary tables
- Offline use without a separate `vendor/` directory

## How a Scan Works

AtilKurt follows a deterministic read-only assessment pipeline:

```text
CLI and environment validation
        ↓
LDAP or LDAPS bind
        ↓
Paged collection of users, computers, groups, and GPOs
        ↓
Registered security analysis modules
        ↓
Risk deduplication, exploitability assessment, and scoring
        ↓
Compliance mapping and remediation prioritization
        ↓
HTML report, optional JSON/export files, and optional checkpoint
```

The LDAP layer exposes search operations only. AtilKurt does not create, modify, or delete directory objects. Analysis modules consume normalized directory records and return findings; the scoring layer then applies object context and prevalence before sorting the findings. An unexpected analysis failure is surfaced and prevents the run from being reported as successful.

## Complete Analysis Catalog

The following tables describe every analysis step registered by the application. The value in the **Analysis key** column is also the value accepted by `--skip-analysis`. The option may be repeated when more than one module should be omitted.

### Identity, Endpoint, and Directory Hygiene

| Analysis key | What it evaluates |
| --- | --- |
| `user_risks` | Password-never-expires and password-not-required flags, disabled Kerberos pre-authentication, SPN-bearing users, protected-account indicators, inactive privileged users, disabled or locked accounts, old service-account passwords, recently created accounts, and recent group-membership changes. |
| `computer_risks` | End-of-life or legacy operating systems, unconstrained and constrained delegation, inactive computer accounts, and computer accounts that appear never to have been used. |
| `legacy_os` | Normalized operating-system names and versions, with separate end-of-life and legacy classifications so older but still supported versions are not reported as EOL. |
| `group_risks` | Excessive Domain Admin membership, nested privileged groups, and populated operator groups that can provide sensitive administrative capabilities. |
| `service_accounts` | Privileged service accounts, traditional service accounts that could use managed identities, and service-account password lifetime concerns. |
| `stale_objects` | Inactive users, ancient passwords, possible credential disclosure in descriptions, stale computers, and unresolved or orphaned SID references. |
| `honeypot` | Existing accounts that look like deception candidates and directory conditions where a controlled decoy account may improve detection. These are advisory findings, not proof that an account is malicious. |
| `tier_model` | Classification of users, groups, and computers into administrative tiers to expose high-value identities and cross-tier placement concerns. |

### Authentication, Password, and Credential Protection

| Analysis key | What it evaluates |
| --- | --- |
| `kerberos_delegation` | Unconstrained delegation, constrained delegation, broad service delegation, and delegation combinations that may enable impersonation or privilege escalation. |
| `kerberoasting` | Accounts with service principal names that can be Kerberoasted and accounts without Kerberos pre-authentication that may be AS-REP roastable. |
| `password_policy` | Domain password length, history, age, complexity, reversible encryption, and account-lockout policy attributes. |
| `password_spray` | Lockout threshold, duration and observation window, privileged accounts without smart-card requirements, password-age patterns, and an overall spray-readiness score. |
| `laps` | Presence of LAPS-related computer attributes, local administrator password coverage, and which principals may be able to read managed password data. |
| `gpp_passwords` | Group Policy Preference password material associated with collected GPOs, including recoverable `cpassword` exposure where available. |
| `gmsa` | gMSA configuration, principals allowed to retrieve managed passwords, and traditional service accounts that are candidates for migration to gMSA. |
| `golden_gmsa` | KDS root-key exposure and excessive gMSA password-reader conditions associated with Golden gMSA attack paths. |
| `krbtgt` | KRBTGT password age and encryption configuration indicators that affect Golden Ticket resilience. |

### Authorization, ACLs, and Attack Paths

| Analysis key | What it evaluates |
| --- | --- |
| `privilege_escalation` | Relationship-based escalation paths across users, groups, computers, SPNs, and delegation. |
| `acl_legacy` | Compatibility ACL checks for dangerous rights found on collected users, groups, and computers. |
| `acl_security` | Security-descriptor parsing, dangerous ACEs, inheritance concerns, shadow administrators, and multi-hop ACL privilege-escalation paths. |
| `dcsync` | Principals with directory replication rights that may permit DCSync-style credential extraction. |
| `gpo_abuse` | GPO modification rights and GPO placement or linkage that could affect privileged organizational units. |
| `backup_operators` | Membership in Backup Operators and other sensitive operator groups whose rights can bypass ordinary file or service controls. |
| `lateral_movement` | Unrestricted privileged logon opportunities, tier-boundary violations, and broad Remote Desktop exposure inferred from directory relationships. |
| `machine_quota` | `ms-DS-MachineAccountQuota`, account-creation exposure, and creator-SID concentration that can contribute to machine-account abuse paths. |
| `replication_metadata` | Recent sensitive-object changes and tombstone-lifetime settings relevant to change monitoring and recovery. |

### Domain, Trust, PKI, and Control-Plane Security

| Analysis key | What it evaluates |
| --- | --- |
| `trusts` | Domain trust direction, transitivity, SID-filtering-related indicators, and conditions that expand cross-domain attack scope. |
| `certificate_services` | Certificate-template attributes that directly indicate ESC1- or ESC2-like exposure. Other template conditions are reported only when the available LDAP attributes support them. |
| `adcs_extended` | Extended AD CS indicators for ESC5, ESC7, ESC9, ESC10/14, ESC11, ESC13, and Certifried-related conditions. Several CA-wide items are explicit review prompts and require manual confirmation. |
| `vulnerability_scan` | Directory-data heuristics for ZeroLogon, PrintNightmare, PetitPotam, Shadow Credentials, and NoPac exposure. This module does not send exploits or perform network vulnerability verification; patch state and service configuration must be confirmed independently. |
| `domain_security` | LDAP signing/channel-binding indicators, NTLM minimum-security settings, and SMB-signing policy evidence found in GPO metadata. |
| `extended_ldap` | RBCD, `msDS-KeyCredentialLink`, SID history, foreign security principals, fine-grained password policies, BitLocker recovery objects, AdminSDHolder, OU/GPO structure, empty or deeply nested groups, expired computers, printer and Exchange objects, DNS zones, and AD Recycle Bin state. |
| `audit_policy` | Audit-related GPO discovery, AdminSDHolder and domain-root SACL review guidance, and the critical Windows event IDs recommended for monitoring. |
| `coercion` | Print Spooler, DFS, and WebClient-related directory indicators that may expose authentication-coercion paths. No coercion request is sent. |
| `misconfiguration` | Cross-cutting checklist for password policy, administrative hygiene, delegation, ACL, trust, and tiering weaknesses based on the collected inventory. |

### Full and Fast Profiles

`--analysis-profile full` runs every registered analysis and is the default. `--analysis-profile fast` keeps the broad inventory and common risk checks but skips these query-heavy modules:

- `acl_security`
- `extended_ldap`
- `adcs_extended`
- `coercion`
- `replication_metadata`

Use `--skip-analysis KEY` for explicit control. Skipped modules produce empty result sections instead of breaking report generation, which keeps the JSON and HTML schemas predictable.

## Risk Scoring and Prioritization

Each consolidated finding receives:

- A base score derived from its risk type, or a severity-based fallback for new risk types
- An object-context multiplier for privileged users, domain controllers, groups, computers, and GPOs
- A prevalence multiplier when the same weakness affects multiple objects
- Combination bonuses when multiple related weaknesses affect the same object
- A final score from 0 to 100 and a normalized Critical, High, Medium, or Low severity
- A separate exploitability model with attack complexity, vector, required privileges, user interaction, known tooling, and a 0-to-10 exploitability score

The domain security score summarizes the scored findings. The risk-management section builds an impact-versus-likelihood heat map, estimates remediation effort, applies the configurable `--hourly-rate`, and calculates prioritization and ROI-style values. These business values are planning estimates, not financial guarantees.

## Compliance Coverage

The report maps applicable findings and LDAP-derived checks to:

- CIS Benchmark controls and CIS Controls v8 references
- NIST Cybersecurity Framework functions and categories
- ISO/IEC 27001 Annex A control families
- GDPR Article 32 security expectations

Compliance output is an assessment aid. It does not by itself establish certification or legal compliance; controls that cannot be verified from LDAP are marked for review or not assessed rather than treated as silently passing.

## Requirements

- Python 3.9 or later
- LDAP read access to the target domain
- Valid credentials for the target Active Directory environment

Recommended environment:

- A dedicated assessment workstation
- Network reachability to the domain controller
- Read-only credentials with the minimum permissions needed for the checks you want to run

## Installation

### Automatic Linux Setup

Clone the repository:

```bash
git clone https://github.com/cumakurt/AtilKurt.git
cd AtilKurt
```

The recommended launcher performs the following checks on every run and starts the application:

1. Confirms that the host is Linux and reads `/etc/os-release`.
2. Detects APT, DNF/YUM, Pacman, Zypper, or APK.
3. Verifies Python 3.9 or later and the system CA certificate store.
4. Creates or reuses the project virtual environment.
5. Verifies every version constraint in `requirements.txt` and runs `pip check`.
6. Installs only missing or incompatible system/Python dependencies.
7. Reads the supported `.env` keys as plain data, validates required inputs, and launches AtilKurt.

```bash
./run.sh --help
```

The launcher requests `sudo` only if a required system package is missing. Once the runtime and dependencies satisfy the declared requirements, subsequent runs print a skip message instead of reinstalling them. Override the default `.venv` or `.env` locations with `ATILKURT_VENV_DIR` and `ATILKURT_ENV_FILE`.

### Manual Setup

If you prefer to manage the environment yourself, create an isolated virtual environment and install the project with its runtime dependencies:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --editable .
```

Activate the environment if you want `python` and the installed `atilkurt` command to resolve from it:

```bash
source .venv/bin/activate
```

For development, install the test and lint tools as well:

```bash
.venv/bin/python -m pip install --editable ".[dev]"
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env`, restrict its permissions, and set the assessment values:

```bash
cp .env.example .env
chmod 600 .env
```

`run.sh` reads only the supported keys as data; it does not execute or source `.env`. Existing process environment variables take precedence over values in the file.

Supported environment variables:

- `ATILKURT_DOMAIN`: Target Active Directory DNS domain; equivalent to `--domain`
- `ATILKURT_USER`: Assessment username; equivalent to `--username`
- `ATILKURT_PASS`: Assessment password; consumed directly by the Python process
- `ATILKURT_DC_IP`: Optional domain controller IP address or hostname; equivalent to `--dc-ip`
- `ATILKURT_OUTPUT`: HTML output path; equivalent to `--output`

Launcher-only overrides:

- `ATILKURT_ENV_FILE`: Use a different environment file
- `ATILKURT_VENV_DIR`: Use a different virtual environment directory

Explicit CLI options take precedence over equivalent `.env` values. Existing process environment variables take precedence over `.env`. For passwords, `ATILKURT_PASS` takes precedence over the deprecated `--password` option; when neither is present, an interactive terminal receives a hidden password prompt.

### Authentication and Transport

A username may be supplied as `username`, `DOMAIN\username`, or `username@example.com`; the connection layer normalizes it for LDAP authentication.

- Without `--ssl`, AtilKurt connects to port 389 and attempts NTLM only. It never sends a SIMPLE bind password over plaintext LDAP.
- With `--ssl`, AtilKurt connects to port 636 and may use NTLM or SIMPLE inside the protected TLS connection.
- TLS certificate validation is enabled by default. A failed explicit LDAPS connection is reported and never downgraded to plaintext LDAP.
- `--no-validate-cert` is intended only for controlled labs with a certificate chain that cannot be validated.
- Connection and search failures use bounded retry and timeout settings; failed LDAP result codes are not cached as successful empty results.

### Certificate Validation

TLS certificate validation is enabled by default when `--ssl` is used. An explicit TLS connection never falls back to plaintext LDAP. Disable certificate validation only for controlled lab environments.

### Output Files

By default, the tool writes:

- HTML report
- Optional JSON export
- Optional Kerberoasting export
- Optional checkpoint file

Reports, exports, and checkpoints are written atomically with owner-only file permissions. The checkpoint directory is owner-accessible only.

Log files created with `--log-file` are also owner-readable and owner-writable only. Existing symbolic links are not followed for report, export, checkpoint, or log writes.

## Usage

### Basic Scan

```bash
./run.sh --ssl
```

Values from `.env` are added only when the equivalent CLI option is absent. You can also provide them directly through the process environment:

```bash
ATILKURT_DOMAIN=example.com \
ATILKURT_USER=auditor \
ATILKURT_PASS='use-a-secret-manager-in-automation' \
ATILKURT_DC_IP=192.168.1.10 \
./run.sh --ssl --output report.html
```

### Manual Python Usage

The launcher is optional. After completing the manual setup, invoke the Python entry point directly. `--domain` and `--username` are required; `--dc-ip` defaults to the domain name. When `ATILKURT_PASS` is not set and the command runs in an interactive terminal, AtilKurt prompts for the password without echoing it:

```bash
.venv/bin/python AtilKurt.py \
  --domain example.com \
  --username auditor \
  --dc-ip 192.168.1.10 \
  --ssl \
  --output report.html
```

For non-interactive use, pass the password through the environment instead of a CLI argument so it is not exposed in the process argument list:

```bash
ATILKURT_PASS='read-from-your-secret-manager' \
.venv/bin/python AtilKurt.py \
  --domain example.com \
  --username auditor \
  --dc-ip 192.168.1.10 \
  --ssl \
  --json-export assessment.json
```

When entering a command manually, a literal secret can still be retained by shell history even when it is an environment assignment. For recurring automation, populate `ATILKURT_PASS` from the platform's secret store or an already-exported protected environment value instead of typing the real password into the command line.

An editable installation also provides the equivalent `atilkurt` console command:

```bash
ATILKURT_PASS='read-from-your-secret-manager' \
.venv/bin/atilkurt \
  --domain example.com \
  --username auditor \
  --dc-ip 192.168.1.10 \
  --ssl
```

Use `--ssl` for LDAPS on port 636. Without it, the application uses LDAP on port 389 and restricts authentication to NTLM; it does not send SIMPLE credentials over plaintext LDAP. If `--output` is omitted, a timestamped HTML filename is generated for the target domain.

### Large Environment Scan

```bash
./run.sh \
  --page-size 1000 \
  --timeout 60 \
  --max-retries 3 \
  --parallel \
  --max-workers 4 \
  --analysis-profile fast
```

### Stealth-Oriented Scan

```bash
./run.sh \
  --stealth \
  --rate-limit 3.0 \
  --random-delay 1 5
```

### Skip a Specific Analysis

```bash
./run.sh \
  --skip-analysis acl_security
```

### Resume or Incremental Scan

```bash
./run.sh \
  --checkpoint scan_001
```

```bash
./run.sh \
  --resume scan_001
```

```bash
./run.sh \
  --incremental
```

`--checkpoint ID` stores the complete collection, analysis, scoring, and compliance state under `.atilkurt_checkpoints/ID.json`. `--resume ID` reuses a complete saved state and proceeds to report/export generation without recollecting the domain. If a checkpoint is incomplete or from an older partial format, AtilKurt safely performs a fresh scan.

`--incremental` still performs a current collection, then compares users by `sAMAccountName` and computers, groups, and GPOs by name against the newest checkpoint for the same domain. New, changed, and deleted records are attached to the analysis data. When no explicit checkpoint ID is supplied, an ID containing the domain and timestamp is created automatically.

### JSON Export

```bash
./run.sh \
  --json-export data.json
```

### Risk Management Tuning

```bash
./run.sh \
  --hourly-rate 150.0
```

### Baseline Drift Comparison

Create a machine-readable result and use it as the baseline for a later scan:

```bash
./run.sh --json-export baseline.json
./run.sh --baseline baseline.json --json-export current.json
```

The comparison matches findings by risk type and affected object, then reports new, resolved, unchanged, and net drift counts. Baseline comparison is independent from incremental directory-object comparison.

### Check One User's Escalation Path

```bash
./run.sh --check-user auditor
```

After the normal scan, this prints whether the named user has a computed path to Domain Admin, the shortest path depth, the path, and its estimated probability when a path exists.

### Diagnostic Logging

```bash
./run.sh --verbose --log-file assessment.log
```

Use `--verbose` for informational diagnostics or `--debug` for detailed troubleshooting. Console status output remains available independently of the Python logging level. Treat log files as sensitive assessment artifacts.

## CLI Reference

### Identity and Connection

- `-d, --domain`: Active Directory domain
- `-u, --username`: LDAP username
- `-p, --password`: LDAP password, deprecated in favor of `ATILKURT_PASS`
- `--dc-ip`: Domain controller IP address or hostname; defaults to the domain name
- `--ssl`: Use LDAPS on port 636
- `--validate-cert`: Backward-compatible certificate validation flag
- `--no-validate-cert`: Disable certificate validation

### Collection and Performance

- `--page-size`: LDAP page size, default 5000, valid range 1-5000
- `--timeout`: Base LDAP timeout in seconds, default 30, valid range 1-300
- `--max-retries`: Retry count for LDAP operations, default 3
- `--parallel`: Enable parallel top-level collection
- `--max-workers`: Maximum parallel workers, default 5, valid range 1-64
- `--no-progress`: Disable progress output

### Stealth and Timing

- `--stealth`: Enable stealth mode
- `--rate-limit`: Non-negative minimum seconds between LDAP network queries; default 0 or 0.5 with `--stealth`
- `--random-delay MIN MAX`: Non-negative random delay range between queries; MIN must not exceed MAX

### Analysis Control

- `--analysis-profile {full,fast}`: Select the scan profile
- `--skip-analysis KEY`: Skip a specific analysis step
- `--check-user USERNAME`: Evaluate whether a user can reach Domain Admin paths
- `--incremental`: Enable incremental scanning

### Export and Reporting

- `--output`: HTML report output path
- `--single-file-report`: Generate an offline-capable self-contained HTML report
- `--no-single-file-report`: Write a report that references a copied `vendor/` asset directory
- `--json-export`: JSON export output path
- `--kerberoasting-export`: Kerberoasting target export path
- `--checkpoint`: Save a checkpoint
- `--resume`: Resume from a checkpoint
- `--baseline`: Compare current findings with a prior `--json-export` file

### Risk Management

- `--hourly-rate`: Hourly remediation cost used for ROI calculations

### Logging

- `--verbose`: Informational logging
- `--debug`: Debug logging
- `--log-file`: Write logs to a file

## Report Output

### Interactive HTML Report

The HTML report includes:

- An executive dashboard with the domain score, critical/high counts, privileged-account and delegation KPIs, risk distribution, category breakdown, top risky objects, action priorities, password statistics, account activity, administrative-group membership, and account status
- Dedicated views for all risks, critical and high risks, privileged accounts, delegation, password issues, users, computers, groups, Kerberos findings, attack paths, service accounts, GPO abuse, DCSync, password policy, trusts, AD CS, GPP, LAPS, vulnerability indicators, legacy operating systems, and ACL security
- Finding cards with severity, affected object, technical description, business impact, attack scenario, mitigation guidance, MITRE ATT&CK references, and exploitability context when available
- Search, sorting, pagination, object-detail dialogs, and client-side CSV export for the relevant directory and risk tables
- Compliance views for CIS, NIST CSF, ISO 27001, and GDPR
- A risk-management heat map, remediation estimates, prioritized actions, and ROI-style planning values
- A Red Team playbook and Blue Team checklist derived from the actual findings, including suggested validation procedures and defensive Windows event IDs
- A complete analysis-count summary across all registered finding categories

The report is self-contained by default, so it can be copied to another machine and opened without a separate asset directory or network access.

Use `--no-single-file-report` when you prefer a smaller HTML file that references a copied `vendor/` directory next to the report. The default single-file mode embeds styles, scripts, icons, and fonts and does not require internet access.

### JSON Export

`--json-export FILE` writes the full collected directory inventory and analysis state, including:

- Users, computers, groups, and GPOs
- Consolidated and scored risks
- Domain score and executive summary
- All registered analysis result categories
- Compliance data and risk-management data
- Baseline comparison data when `--baseline` is used

JSON output is intended for downstream processing and contains substantially more sensitive directory data than the summary HTML views. Store and transmit it accordingly.

### Kerberoasting Target Export

`--kerberoasting-export FILE` writes a focused JSON list of identified SPN targets, privilege context, and prepared command templates supplied by the analyzer. The export does not request service tickets or crack credentials.

### Additional Export APIs

The `reporting.export_formats.ExportFormats` Python API also provides CSV risk export, simplified Nessus-compatible XML, newline-delimited SIEM JSON, and CEF output for integrations. These formats are library APIs and do not currently have dedicated CLI flags.

### Output Naming and File Safety

When `--output` is omitted or retains its default `report.html`, AtilKurt generates `AtilKurt_<domain>_<timestamp>.html`. Explicit output, JSON, and Kerberoasting paths are validated before use. Sensitive files are committed with atomic replacement and `0600` permissions so a partial write does not replace a previously valid artifact.

## Checkpoints, Incremental State, and Caching

- LDAP search results are cached in memory for a bounded lifetime to reduce duplicate queries during one process.
- Cache keys include the base DN, filter, attributes, size limit, page size, and paging state so semantically different searches do not collide.
- Paged search deduplicates entries and validates LDAP result codes before caching.
- Checkpoint IDs cannot contain path separators or resolve outside `.atilkurt_checkpoints`.
- The checkpoint directory uses `0700`; individual checkpoint files use `0600` and are atomically replaced.
- Incremental comparison uses deterministic SHA-256 identity hashes and reports new, changed, and deleted objects separately.
- Checkpoints and JSON baselines are not encrypted. Their filesystem permissions reduce accidental local disclosure but do not replace full-disk encryption or an organizational secrets/data handling policy.

## Performance and Scalability

AtilKurt includes several controls for large domains:

- LDAP paging for large result sets
- Query caching to reduce repeated lookups
- Parallel collection for top-level object sets
- Incremental checkpoint support
- Optional profile-based analysis selection
- Optional skipping of expensive modules

Practical guidance:

- Use `--parallel` on large domains
- Use `--analysis-profile fast` when you need a shorter scan window
- Use `--skip-analysis` to exclude a single expensive module
- Use `--stealth` only when you need controlled pacing for operational reasons

Parallel mode creates independent LDAP connections for the top-level collectors instead of sharing one mutable connection across workers. Rate limiting is applied to each connection; therefore `--stealth` or an explicit delay is still recommended when the directory has strict query-volume controls. Timeout and retry limits are bounded, and a timed-out paged search discards its partial result rather than reporting incomplete data as a successful collection.

No performance figure is universal across domains because directory size, DC limits, network latency, permissions, selected modules, and report size dominate runtime. Measure representative scans in your own environment before changing paging or worker settings.

## Docker Usage

Build the image and display CLI help:

```bash
docker build -t atilkurt:latest .
docker run --rm atilkurt:latest --help
```

Run a scan with only the three basic identity values and persist the report to `./output`:

```bash
mkdir -p output
docker run --rm \
  -e ATILKURT_DOMAIN=example.com \
  -e ATILKURT_USER=auditor \
  -e ATILKURT_PASS='your-password' \
  -e ATILKURT_OUTPUT=/output/report.html \
  -v "$PWD/output:/output" \
  atilkurt:latest
```

Add `-e ATILKURT_DC_IP=192.168.1.10` when the domain name does not resolve to a domain controller. Extra CLI arguments follow the image name, for example `atilkurt:latest --ssl --json-export /output/assessment.json`.

Docker Compose reads the same values from `.env`:

```bash
docker compose run --rm atilkurt --ssl
```

Container networking must be able to reach the domain controller on port 389 or 636. The bind-mounted output directory remains the operator's responsibility; review its host-side ownership and permissions after the run.

## Make Targets

The Makefile provides common development and container shortcuts:

- `make venv`: Ensure the selected virtual environment exists
- `make install`: Install the project in editable mode
- `make install-dev`: Install the project, pytest, and Ruff
- `make test`: Run the full test suite in the virtual environment
- `make lint`: Run Ruff without suppressing failures
- `make run DOMAIN=... USER=... PASS=...`: Run a local assessment; add `DC_IP=...` when DNS discovery is insufficient
- `make docker-build`, `make docker-run`, `make docker-shell`: Build, run, or inspect the container image
- `make clean`: Remove Python, pytest, and Ruff cache files

## Security Notes

- The tool performs read-only LDAP search operations only
- It does not modify Active Directory objects
- Passwords should be provided through `ATILKURT_PASS` or interactive input
- Prefer `--ssl`; plaintext LDAP does not attempt SIMPLE password authentication
- Explicit TLS failures are reported and never downgraded to plaintext LDAP
- Use `--no-validate-cert` only in lab environments
- Treat reports, JSON exports, and checkpoints as sensitive directory data
- Ensure you are authorized to scan the target domain before use

The report may include offensive validation commands in its Red Team playbook. They are generated for authorized assessment and purple-team workflows; AtilKurt itself does not execute them.

## Scope and Limitations

- Findings are based primarily on LDAP-visible state. Host-local settings, live service behavior, exact patch inventory, endpoint controls, and network segmentation may require separate verification.
- Vulnerability and coercion modules are passive heuristics. A finding is an investigation lead, not proof that exploitation will succeed.
- Some AD CS and audit-policy controls cannot be proven from the attributes available to an ordinary read-only account. Those modules deliberately emit review guidance when manual confirmation is required.
- A read-only account can receive incomplete results when ACLs hide attributes or containers. LDAP errors are reported, but the tool cannot infer data it is not authorized to read.
- Compliance percentages are technical mappings for prioritization and are not legal advice, an audit opinion, or certification evidence.
- Incremental comparison identifies directory-record drift; it is not continuous monitoring and does not replace event collection from domain controllers.
- The application does not rotate credentials, remediate findings, modify GPOs, or change Active Directory configuration.

## Testing

Run the full test suite with:

```bash
.venv/bin/python -m pytest
```

Run static analysis with:

```bash
.venv/bin/python -m ruff check .
```

Validate the launcher independently with:

```bash
bash -n run.sh
shellcheck run.sh
```

The repository includes tests for:

- Core analyzers
- LDAP escaping and caching
- Progress persistence
- Report generation
- HTML injection and embedded-data handling
- Secure atomic files, checkpoint traversal, and symbolic-link resistance
- CLI validation and launcher `.env` parsing
- Risk scoring, compliance mapping, and analysis deduplication
- Performance controls and representative analyzer edge cases

## Project Structure

```text
AtilKurt/
├── AtilKurt.py
├── run.sh
├── analysis/                 # Registered security and compliance analyzers
├── core/                     # LDAP, collection, validation, cache, and persistence
│   └── collectors/           # User, computer, group, GPO, and ACL collectors
├── reporting/                # HTML composition, report sections, and exporters
│   ├── report_sections/      # Dashboard, directory, risk, ACL, and compliance views
│   └── vendor/               # Offline report assets
├── risk/                     # Business impact, cost, heat map, and prioritization
├── scoring/                  # Finding and domain scoring
├── tests/                    # Unit, regression, security, and launcher tests
├── .github/workflows/ci.yml  # Python matrix, lint, tests, shell checks, and wheel build
├── requirements.txt
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── docker-entrypoint.sh
└── README.md
```

Main areas:

- `AtilKurt.py` owns CLI validation and orchestrates connection, collection, analysis, scoring, compliance, checkpointing, and report generation.
- `core/` owns external LDAP access, normalized collectors, input validation, query caching, bounded progress state, and secure file primitives.
- `analysis/registry.py` is the single ordered registry for analysis keys, profiles, result defaults, consolidation, and JSON export mappings.
- `analysis/` contains directory-data analyzers. Most analyzers are stateless; LDAP-aware modules receive the shared read-only connection boundary.
- `scoring/` converts findings to contextual 0-to-100 scores and a domain score.
- `risk/` adds heat-map placement, business-impact estimates, remediation effort, and prioritization.
- `reporting/` generates the offline HTML application, compliance views, dashboard, purple-team guidance, and integration exports.
- `tests/` covers the orchestration boundaries as well as individual analyzers and security regressions.

Runtime dependencies are intentionally small: `ldap3` provides LDAP protocol support and `pycryptodome` supports cryptographic parsing/decryption needed by specific analyses. Report UI assets are vendored for offline use; no CDN is required when opening the default report.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Author

**Cuma KURT**  
GitHub: https://github.com/cumakurt/AtilKurt
