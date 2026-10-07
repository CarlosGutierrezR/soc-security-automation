# SOC Security Automation

Vendor-neutral Security Automation / SOAR portfolio project built on a reusable SOC lab.

## Project status

SEC-AUTO-001 functional workflow implemented and validated.

Tested locally with Python 3.14.3.

Current automated test suite:

- 48 tests passing

## Operational problem

SOC analysts repeatedly perform alert normalization, process correlation, IOC extraction, enrichment, risk assessment and case-summary preparation for recurring alerts.

## Objective

Build a Python workflow that transforms SOC alert data into an auditable case-preparation output while preserving analyst approval for response decisions.

## Implemented workflow

Wazuh alert input
-> normalization
-> process parent-child correlation
-> IOC extraction
-> IOC deduplication
-> local enrichment
-> optional external enrichment context
-> explainable risk scoring
-> decision policy
-> case preparation
-> analyst approval

## Implemented components

- Wazuh alert normalization
- Parent-child process correlation
- SHA256, IPv4 and domain IOC extraction
- IOC false-positive tuning
- Local IPv4 classification
- VirusTotal API client with dry-run by default
- Mocked VirusTotal HTTP tests
- VirusTotal response normalization
- Explainable deterministic risk scoring
- Low / medium / high decision policy
- SOC case construction
- Audit trail
- End-to-end workflow tests
- Sanitized reproducible sample data

## Safety model

- Dry-run by default for external enrichment.
- No automatic containment.
- Analyst approval required for all response decisions.
- No secrets or raw sensitive SOC evidence in Git.
- Public evidence and sample data are sanitized.
- Risk scoring is transparent and auditable.

## VirusTotal integration

A VirusTotal API client is implemented and tested with mocked HTTP requests.

The current end-to-end workflow does not perform live VirusTotal requests. It accepts already-normalized external enrichment context when available.

No live API key is stored in the repository.

## Current limitations

The following capabilities are intentionally not claimed as implemented:

- Formal input schema validation.
- Live Wazuh historical lookups.
- Live Security Onion historical lookups.
- Live end-to-end VirusTotal enrichment.
- Automatic containment or remediation.

These are possible future extensions and are outside the current SEC-AUTO-001 scope.

## Repository structure

```text
src/soc_automation/   Python implementation
tests/                Automated tests
sample_data/          Sanitized SOC input samples
docs/                 Architecture and use-case documentation
evidence/sanitized/   Public sanitized evidence
