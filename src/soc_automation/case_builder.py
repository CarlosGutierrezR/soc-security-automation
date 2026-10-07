def build_case(
    alerts,
    correlation,
    iocs,
    enrichments,
    risk,
    decision,
):
    return {
        "alerts": alerts,
        "correlation": correlation,
        "iocs": iocs,
        "enrichments": enrichments,
        "risk": risk,
        "decision": decision,
        "approval_required": decision["approval_required"],
        "audit": [
            "alerts_normalized",
            "correlation_evaluated",
            "iocs_extracted",
            "enrichment_evaluated",
            "risk_scored",
            "decision_generated",
        ],
    }
