# Data Sanitization

## SEC-AUTO-001

The public sample alerts originate from controlled activity in the private SOC lab.

Before publication, the samples were sanitized while preserving the fields required for reproducible process correlation.

## Transformations

- Real endpoint IP replaced with RFC 5737 documentation address 192.0.2.22.
- Real endpoint hostname replaced with LAB-WIN11-01.
- Local username replaced with analyst1.
- Internal OpenSearch document identifiers removed.
- Wazuh manager name removed.
- Agent ID removed.
- Event record IDs and provider GUIDs removed.
- Logon identifiers removed.
- Full duplicated Windows event message removed.
- Process GUIDs replaced with synthetic GUIDs while preserving parent-child relationships.

## Preserved

- Event timestamps.
- Process and parent process IDs.
- Executable names.
- Controlled command line.
- Integrity levels.
- SHA256 values of standard Windows binaries.
- Wazuh rule IDs, levels and descriptions.
- Vendor-provided ATT&CK mappings.

Vendor ATT&CK mappings are preserved as source metadata and must not automatically be interpreted as analyst-validated behavior.
