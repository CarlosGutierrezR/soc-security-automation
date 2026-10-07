from datetime import datetime


def normalize_timestamp(timestamp):
    parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def normalize_wazuh_alert(alert):
    source = alert["_source"]
    eventdata = source["data"]["win"]["eventdata"]
    system = source["data"]["win"]["system"]
    rule = source["rule"]

    return {
        "source": "wazuh",
        "timestamp": normalize_timestamp(source["timestamp"]),
        "agent": {
            "ip": source["agent"]["ip"],
            "name": source["agent"]["name"],
        },
        "event": {
            "provider": system["providerName"],
            "channel": system["channel"],
            "event_id": int(system["eventID"]),
        },
        "process": {
            "pid": int(eventdata["processId"]),
            "guid": eventdata["processGuid"],
            "image": eventdata["image"],
            "command_line": eventdata["commandLine"],
            "user": eventdata["user"],
            "integrity_level": eventdata["integrityLevel"],
            "hashes": eventdata["hashes"],
        },
        "parent_process": {
            "pid": int(eventdata["parentProcessId"]),
            "guid": eventdata["parentProcessGuid"],
            "image": eventdata["parentImage"],
            "command_line": eventdata["parentCommandLine"],
            "user": eventdata["parentUser"],
        },
        "detection": {
            "rule_id": int(rule["id"]),
            "level": int(rule["level"]),
            "description": rule["description"],
        },
        "vendor_attack_mapping": {
            "ids": rule["mitre"]["id"],
            "techniques": rule["mitre"]["technique"],
            "tactics": rule["mitre"]["tactic"],
        },
    }
