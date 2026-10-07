import re
import ipaddress

SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")


def extract_sha256(text):
    matches = SHA256_PATTERN.findall(text)

    return [
        {
            "type": "sha256",
            "value": value.lower(),
        }
        for value in matches
    ]


IPV4_CANDIDATE_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ipv4(text):
    candidates = IPV4_CANDIDATE_PATTERN.findall(text)
    results = []

    for value in candidates:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue

        if ip.version != 4:
            continue

        results.append(
            {
                "type": "ipv4",
                "value": str(ip),
            }
        )

    return results


DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)


def extract_domains(text):
    matches = DOMAIN_PATTERN.findall(text)
    results = []

    for value in matches:
        normalized = value.lower()
        suffix = normalized.rsplit(".", 1)[-1]

        if suffix in NON_DOMAIN_SUFFIXES:
            continue

        results.append(
            {
                "type": "domain",
                "value": normalized,
            }
        )

    return results


def extract_iocs(text):
    return extract_sha256(text) + extract_ipv4(text) + extract_domains(text)


NON_DOMAIN_SUFFIXES = {
    "exe",
    "dll",
    "sys",
    "ps1",
    "bat",
    "cmd",
    "msi",
    "scr",
    "lnk",
    "txt",
}


def extract_iocs_from_alert(alert):
    text_parts = [
        alert["process"]["command_line"],
        alert["process"]["image"],
        alert["process"]["hashes"],
        alert["parent_process"]["command_line"],
        alert["parent_process"]["image"],
        alert["detection"]["description"],
    ]

    combined_text = " ".join(
        part for part in text_parts if isinstance(part, str) and part
    )

    return extract_iocs(combined_text)
