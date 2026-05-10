# AtilKurt

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

AtilKurt is a read-only Active Directory security assessment tool. It collects directory data through LDAP, runs a broad set of security analyzers, scores the findings, and generates a self-contained HTML report for offline review.

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

## Requirements

- Python 3.9 or later
- LDAP read access to the target domain
- Valid credentials for the target Active Directory environment

Recommended environment:

- A dedicated assessment workstation
- Network reachability to the domain controller
- Read-only credentials with the minimum permissions needed for the checks you want to run

## Installation

Clone the repository:

```bash
git clone https://github.com/cumakurt/AtilKurt.git
cd AtilKurt
```

Install dependencies:

```bash
pip install -r requirements.txt
```

For local development:

```bash
pip install -e .
```

## Configuration

### Environment Variables

You can provide the password through `ATILKURT_PASS` instead of the command line.

Supported environment variables:

- `ATILKURT_DOMAIN`
- `ATILKURT_USER`
- `ATILKURT_PASS`
- `ATILKURT_DC_IP`

### Certificate Validation

TLS certificate validation is enabled by default when SSL/TLS is used. Disable it only for controlled lab environments.

### Output Files

By default, the tool writes:

- HTML report
- Optional JSON export
- Optional Kerberoasting export
- Optional checkpoint file

## Usage

### Basic Scan

```bash
python3 AtilKurt.py \
  --domain example.com \
  --username username \
  --password your_password \
  --dc-ip 192.168.1.10 \
  --output report.html
```

Short form:

```bash
python3 AtilKurt.py \
  -d example.com \
  -u username \
  -p your_password \
  --dc-ip 192.168.1.10 \
  --output report.html
```

### Large Environment Scan

```bash
python3 AtilKurt.py \
  -d corp.local \
  -u admin \
  -p SecurePass123 \
  --dc-ip 10.0.0.1 \
  --page-size 1000 \
  --timeout 60 \
  --max-retries 3 \
  --parallel \
  --max-workers 4 \
  --analysis-profile fast
```

### Stealth-Oriented Scan

```bash
python3 AtilKurt.py \
  -d corp.local \
  -u admin \
  -p SecurePass123 \
  --dc-ip 10.0.0.1 \
  --stealth \
  --rate-limit 3.0 \
  --random-delay 1 5
```

### Skip a Specific Analysis

```bash
python3 AtilKurt.py \
  -d corp.local \
  -u admin \
  -p SecurePass123 \
  --dc-ip 10.0.0.1 \
  --skip-analysis acl_security
```

### Resume or Incremental Scan

```bash
python3 AtilKurt.py \
  -d corp.local \
  -u admin \
  -p SecurePass123 \
  --dc-ip 10.0.0.1 \
  --checkpoint scan_001
```

```bash
python3 AtilKurt.py \
  -d corp.local \
  -u admin \
  -p SecurePass123 \
  --dc-ip 10.0.0.1 \
  --resume scan_001
```

```bash
python3 AtilKurt.py \
  -d corp.local \
  -u admin \
  -p SecurePass123 \
  --dc-ip 10.0.0.1 \
  --incremental
```

### JSON Export

```bash
python3 AtilKurt.py \
  -d corp.local \
  -u admin \
  -p SecurePass123 \
  --dc-ip 10.0.0.1 \
  --json-export data.json
```

### Risk Management Tuning

```bash
python3 AtilKurt.py \
  -d corp.local \
  -u admin \
  -p SecurePass123 \
  --dc-ip 10.0.0.1 \
  --hourly-rate 150.0
```

## CLI Reference

### Identity and Connection

- `-d, --domain`: Active Directory domain
- `-u, --username`: LDAP username
- `-p, --password`: LDAP password, deprecated in favor of `ATILKURT_PASS`
- `--dc-ip`: Domain controller IP address
- `--ssl`: Use SSL/TLS
- `--validate-cert`: Backward-compatible certificate validation flag
- `--no-validate-cert`: Disable certificate validation

### Collection and Performance

- `--page-size`: LDAP page size
- `--timeout`: Base LDAP timeout
- `--max-retries`: Retry count for LDAP operations
- `--parallel`: Enable parallel top-level collection
- `--max-workers`: Maximum parallel workers
- `--no-progress`: Disable progress output

### Stealth and Timing

- `--stealth`: Enable stealth mode
- `--rate-limit`: Minimum seconds between LDAP network queries
- `--random-delay MIN MAX`: Random delay range between queries

### Analysis Control

- `--analysis-profile {full,fast}`: Select the scan profile
- `--skip-analysis KEY`: Skip a specific analysis step
- `--check-user USERNAME`: Evaluate whether a user can reach Domain Admin paths
- `--incremental`: Enable incremental scanning

### Export and Reporting

- `--output`: HTML report output path
- `--single-file-report`: Generate an offline-capable self-contained HTML report
- `--json-export`: JSON export output path
- `--kerberoasting-export`: Kerberoasting target export path
- `--checkpoint`: Save a checkpoint
- `--resume`: Resume from a checkpoint

### Risk Management

- `--hourly-rate`: Hourly remediation cost used for ROI calculations

### Logging

- `--verbose`: Informational logging
- `--debug`: Debug logging
- `--log-file`: Write logs to a file

## Report Output

The HTML report includes:

- Executive summary and domain score
- Risk breakdown by severity and category
- Individual finding details with mitigation guidance
- Attack paths and exploitability scoring
- Compliance sections for supported frameworks
- Risk management summary with remediation prioritization
- Offline assets embedded directly in the report

The report is self-contained by default, so it can be copied to another machine and opened without a separate asset directory or network access.

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

## Security Notes

- The tool performs read-only LDAP search operations only
- It does not modify Active Directory objects
- Passwords should be provided through `ATILKURT_PASS` or interactive input
- Use `--no-validate-cert` only in lab environments
- Ensure you are authorized to scan the target domain before use

## Testing

Run the full test suite with:

```bash
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider
```

The repository includes tests for:

- Core analyzers
- LDAP escaping and caching
- Progress persistence
- Report generation
- New analysis modules
- Performance controls

## Project Structure

```text
AtilKurt/
├── AtilKurt.py
├── analysis/
├── core/
├── reporting/
├── risk/
├── scoring/
├── tests/
├── requirements.txt
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── README.md
```

Main areas:

- `core/`: LDAP connection, configuration, caching, validation, collectors, persistence
- `analysis/`: risk detectors, compliance logic, attack path analysis, and specialized checks
- `reporting/`: HTML, compliance, dashboard, and export generation
- `scoring/`: risk scoring and consolidation
- `risk/`: business impact and remediation prioritization
- `tests/`: unit and regression coverage

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Author

**Cuma KURT**  
GitHub: https://github.com/cumakurt/AtilKurt
*** End Patch
