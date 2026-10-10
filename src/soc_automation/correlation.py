from datetime import datetime


def parse_timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_parent_child_related(parent_alert, child_alert, max_seconds=5):
    same_host = parent_alert["agent"]["name"] == child_alert["agent"]["name"]

    pid_match = parent_alert["process"]["pid"] == child_alert["parent_process"]["pid"]

    guid_match = (
        parent_alert["process"]["guid"] == child_alert["parent_process"]["guid"]
    )

    parent_time = parse_timestamp(parent_alert["timestamp"])
    child_time = parse_timestamp(child_alert["timestamp"])

    delta_seconds = (child_time - parent_time).total_seconds()
    within_window = 0 <= delta_seconds <= max_seconds

    return same_host and pid_match and guid_match and within_window
