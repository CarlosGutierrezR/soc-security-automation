# SEC-AUTO-001 — Manual vs Automated Execution Timing

## Purpose

Measure the analyst effort required to review the SEC-AUTO-001 alert pair manually and compare it with the execution time of the automated case-preparation workflow.

This is a controlled laboratory measurement. It is not presented as a production MTTR claim.

## Input

Both manual and automated runs used the same sanitized Wazuh alert pair:

- `sample_data/wazuh/92052_raw_sanitized.json`
- `sample_data/wazuh/92032_raw_sanitized.json`

The expected automated result was:

- correlated parent-child process chain: `true`
- correlated PID: `9632`
- IOC count: `2`
- maximum Wazuh level: `4`
- risk score: `45`
- decision: `analyst_review`

## Manual runs

Manual timing started when the analyst began reviewing the available alert evidence and ended when the analytical result was ready.

| Run | Duration (seconds) |
|---|---:|
| MANUAL-001 | 241.4374385 |
| MANUAL-002 | 163.4348003 |
| MANUAL-003 | 36.1617852 |

### Manual timing summary

- Minimum: `36.1617852 s`
- Median: `163.4348003 s`
- Maximum: `241.4374385 s`
- Range: `205.2756533 s`

## Automated end-to-end runs

Each automated run included:

1. Python interpreter startup.
2. Module imports.
3. Reading both JSON input files.
4. JSON parsing.
5. `run_workflow()` execution.
6. Validation of score, decision and IOC count.

| Run | Duration (seconds) |
|---|---:|
| AUTO-E2E-1 | 0.1338848 |
| AUTO-E2E-2 | 0.1255335 |
| AUTO-E2E-3 | 0.0936839 |

### Automated timing summary

- Minimum: `0.0936839 s`
- Median: `0.1255335 s`
- Maximum: `0.1338848 s`
- Range: `0.0402009 s`

All three automated runs produced:

- risk score: `45`
- decision: `analyst_review`
- IOC count: `2`

## Internal workflow benchmark

A separate measurement isolated only the execution of `run_workflow()` after imports and input loading.

| Run | Duration (seconds) |
|---|---:|
| AUTO-INTERNAL-1 | 0.004936100 |
| AUTO-INTERNAL-2 | 0.000215700 |
| AUTO-INTERNAL-3 | 0.000212600 |

Internal workflow median:

`0.000215700 s`

This benchmark is retained only as an implementation-performance observation and is not used for the manual-vs-automated operational comparison.

## Analyst observations

The first manual review contained interpretation errors that were corrected during validation:

- vendor ATT&CK mapping was initially treated as evidence of Account Discovery;
- available PID/GUID correlation fields were initially overlooked;
- only one Wazuh alert severity was initially considered.

Later runs became substantially faster as the analyst became familiar with the scenario.

This variability is part of the observed result and is not removed from the measurements.

## Methodological limitations

These measurements must not be generalized as production MTTR.

Important limitations:

- Only one controlled alert scenario was used.
- The same scenario was reviewed repeatedly.
- Manual runs were affected by analyst familiarity and learning.
- Automated timing ends when the case-preparation result is ready for analyst review.
- Human review and final disposition remain outside the automated execution time.
- No live VirusTotal request was performed.
- No live Wazuh or Security Onion historical lookup was performed.
- No automated containment was performed.
- The sample size is three runs per method.

For these reasons, no generalized percentage improvement or production speedup claim is made.

## Operational conclusion

Within this controlled SEC-AUTO-001 scenario, automation produced consistent structured case-preparation results while requiring substantially less machine execution time than the observed manual analysis time.

The intended benefit is not removal of the analyst. The workflow reduces repetitive normalization, correlation, IOC extraction and scoring work while preserving human review for interpretation and response decisions.