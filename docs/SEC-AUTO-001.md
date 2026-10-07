# SEC-AUTO-001 - Alert Enrichment and Case Preparation

## Problem

Analysts manually repeat alert review, IOC extraction, process correlation, enrichment and case-summary preparation for recurring alerts.

## Objective

Build a vendor-neutral Python workflow that collects and normalizes evidence, extracts relevant IOCs, enriches context, calculates an explainable risk score and prepares a SOC case while keeping response decisions under analyst approval.

## Controlled activity

The source telemetry was generated from a benign controlled Windows Scheduled Task inside the authorized SOC lab.

The activity produced a process chain involving:

```text
Task Scheduler
-> svchost.exe
-> cmd.exe
-> conhost.exe
```

Two sanitized Wazuh alerts are used as reproducible project inputs:

- rule 92052
- rule 92032

## Implemented pipeline

```text
raw alerts
-> normalization
-> process correlation
-> IOC extraction
-> IOC deduplication
-> local enrichment
-> optional external context
-> explainable risk scoring
-> decision policy
-> case preparation
-> analyst approval
```

## Correlation

The workflow evaluates process parent-child relationships using:

- agent hostname
- process PID
- parent PID
- process GUID
- parent process GUID
- event timestamp window

## IOC extraction

Supported IOC types:

- SHA256
- IPv4
- domain

A workflow test identified a false-positive domain extraction from:

```text
SEC-AUTO-001-marker.txt
```

The extractor was tuned and a regression test was added.

## Enrichment

IPv4 indicators are first classified locally.

External enrichment is represented separately from local classification.

A VirusTotal client exists with dry-run enabled by default.

No live VirusTotal API request is required for the reproducible test suite.

## Risk scoring

Risk scoring is deterministic and explainable.

Signals currently include:

- process-chain correlation
- Wazuh rule level
- presence of IOCs
- optional VirusTotal malicious detections
- optional VirusTotal suspicious detections

Each contribution is preserved in the output as a reason with its assigned points.

## Decision policy

Current policy:

```text
0-29   LOW
30-69  MEDIUM
70-100 HIGH
```

Every result requires analyst approval.

No automatic containment is implemented.

## Validation

Observed final validation:

```text
48 tests passed
```

## Known limitations

Not implemented in the current version:

- formal schema validation
- live Wazuh historical lookup
- live Security Onion historical lookup
- live end-to-end VirusTotal request orchestration
- automated containment

## Security controls

- dry-run for external client by default
- API key excluded from Git
- raw evidence excluded from Git
- public samples sanitized
- no destructive response actions
- explicit analyst approval model
