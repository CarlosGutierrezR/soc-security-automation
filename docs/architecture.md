# Architecture

## Functional flow

```text
Sanitized Wazuh alerts
        |
        v
Alert normalization
        |
        v
Parent-child process correlation
        |
        v
IOC extraction
        |
        v
IOC deduplication
        |
        v
Local enrichment
        |
        +----------------------+
        |                      |
        v                      v
Local context          Optional external context
                               |
                               v
                       VirusTotal normalization
        |                      |
        +----------+-----------+
                   |
                   v
          Explainable risk score
                   |
                   v
            Decision policy
                   |
                   v
             Case builder
                   |
                   v
          Analyst approval
```

## Components

### normalizer.py

Transforms Wazuh alert structures into the project's vendor-neutral internal representation.

### correlation.py

Validates parent-child process relationships using:

- host
- PID
- process GUID
- timestamp window

### ioc_extractor.py

Extracts:

- SHA256 hashes
- IPv4 addresses
- domains

The domain extractor uses heuristic filename exclusions. It is not a Public Suffix List or authoritative DNS validator.

### enrichment.py

Classifies IPv4 indicators locally before deciding whether an external lookup is appropriate.

### virustotal_client.py

Provides VirusTotal API v3 lookup methods.

Security characteristics:

- dry-run by default
- API key obtained from argument or environment
- request timeout
- HTTP error propagation
- mocked tests for network behavior

### vt_normalizer.py

Converts VirusTotal response data into a provider-independent result structure.

It explicitly distinguishes unavailable analysis statistics from valid zero-valued statistics.

### risk_scoring.py

Calculates a deterministic and explainable risk score.

Each scoring contribution is preserved as an auditable reason.

### decision_policy.py

Maps scores into:

- low
- medium
- high

Every decision remains subject to analyst approval.

### case_builder.py

Builds the SOC case representation and records the workflow audit stages.

### workflow.py

Orchestrates the implemented pipeline from sanitized Wazuh input through case preparation.

## External integrations

### VirusTotal

Implemented:

- client
- dry-run
- request construction
- mocked HTTP behavior
- response normalization

Not currently claimed:

- live end-to-end enrichment in the main workflow

### Wazuh

Implemented:

- sanitized Wazuh alert ingestion
- Wazuh-specific normalization

Not currently implemented:

- live Wazuh API historical lookup

### Security Onion

No live integration is currently implemented or claimed.

## Response model

The workflow does not perform destructive response.

A high-risk result may propose containment, but execution requires explicit analyst approval and is outside the current implementation.
