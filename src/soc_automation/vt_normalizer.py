def normalize_vt_success(ioc_type, value, payload):
    data = payload["data"]
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    return {
        "provider": "virustotal",
        "status": "success",
        "ioc": {
            "type": ioc_type,
            "value": value,
        },
        "stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
        },
    }
