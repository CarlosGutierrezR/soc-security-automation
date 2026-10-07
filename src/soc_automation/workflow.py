from soc_automation.case_builder import build_case
from soc_automation.correlation import is_parent_child_related
from soc_automation.decision_policy import decide_action
from soc_automation.enrichment import enrich_iocs
from soc_automation.ioc_extractor import extract_iocs_from_alert
from soc_automation.normalizer import normalize_wazuh_alert
from soc_automation.risk_scoring import calculate_risk_score


def run_workflow(parent_raw, child_raw, vt_stats=None):
    parent = normalize_wazuh_alert(parent_raw)
    child = normalize_wazuh_alert(child_raw)

    alerts = [parent, child]

    related = is_parent_child_related(parent, child)

    iocs = []
    seen = set()

    for alert in alerts:
        for ioc in extract_iocs_from_alert(alert):
            key = (ioc["type"], ioc["value"])

            if key in seen:
                continue

            seen.add(key)
            iocs.append(ioc)

    enrichments = enrich_iocs(iocs)

    wazuh_level = max(alert["detection"]["level"] for alert in alerts)

    risk = calculate_risk_score(
        wazuh_level=wazuh_level,
        correlated_process_chain=related,
        ioc_count=len(iocs),
        vt_stats=vt_stats,
    )

    decision = decide_action(risk["score"])

    return build_case(
        alerts=alerts,
        correlation={
            "related": related,
            "type": "process_parent_child",
        },
        iocs=iocs,
        enrichments=enrichments,
        risk=risk,
        decision=decision,
    )
