# SEC-AUTO-001 - Alert Enrichment and Case Preparation

## Problem

Analysts manually repeat IOC extraction, historical lookups, enrichment and case-summary preparation for recurring alerts.

## Objective

Build a vendor-neutral Python workflow that collects evidence, enriches context, calculates an explainable risk score and prepares a case while keeping containment under analyst approval.

## Current Phase

Phase 1:
- alert input
- schema validation
- normalization
- reproducible sanitized sample data

## Initial normalized fields

- timestamp
- source
- agent_name
- rule_id
- rule_level
- description

The schema remains provisional until validated against real SOC alert data.

## Safety

No automatic containment is permitted in the initial implementation.
