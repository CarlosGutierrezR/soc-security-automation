import ipaddress

DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def enrich_ipv4(value):
    ip = ipaddress.ip_address(value)

    if ip.version != 4:
        raise ValueError("Expected an IPv4 address")

    if any(ip in network for network in DOCUMENTATION_NETWORKS):
        scope = "documentation"
        external_lookup = False
    elif ip.is_loopback:
        scope = "loopback"
        external_lookup = False
    elif ip.is_link_local:
        scope = "link_local"
        external_lookup = False
    elif ip.is_private:
        scope = "private"
        external_lookup = False
    elif ip.is_multicast:
        scope = "multicast"
        external_lookup = False
    elif ip.is_unspecified:
        scope = "unspecified"
        external_lookup = False
    else:
        scope = "public"
        external_lookup = True

    return {
        "type": "ipv4",
        "value": str(ip),
        "scope": scope,
        "external_lookup": external_lookup,
    }


def enrich_ioc(ioc):
    ioc_type = ioc["type"]
    value = ioc["value"]

    if ioc_type == "ipv4":
        result = enrich_ipv4(value)
        result["enrichment_status"] = "local"
        return result

    if ioc_type in {"sha256", "domain"}:
        return {
            "type": ioc_type,
            "value": value,
            "enrichment_status": "pending_external",
            "external_lookup": True,
        }

    raise ValueError(f"Unsupported IOC type: {ioc_type}")


def enrich_iocs(iocs):
    return [enrich_ioc(ioc) for ioc in iocs]
