# SOC Security Automation

Vendor-neutral Security Automation / SOAR portfolio project built on a reusable SOC lab.

## Project status

Current phase: SEC-AUTO-001 baseline and workflow design.

## Operational problem

SOC analysts repeatedly perform IOC extraction, historical lookups, enrichment, normalization, risk assessment and case-summary preparation for similar alerts.

## Objective

Build a Python workflow for alert normalization, IOC extraction, internal lookups, enrichment, transparent risk scoring, case preparation and auditable analyst-approved response.

## Safety model

- Dry-run by default.
- No destructive containment without explicit analyst approval.
- Transparent scoring factors.
- Reproducible tests.
- No secrets or raw sensitive SOC evidence in Git.

## Current use case

SEC-AUTO-001 - Alert Enrichment and Case Preparation.

See docs/SEC-AUTO-001.md.

## Validation policy

A component is complete only after input, output, success case, failure behavior, reproducible testing, observed result and limitations are documented.
