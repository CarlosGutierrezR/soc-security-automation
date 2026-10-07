def decide_action(score):
    if not 0 <= score <= 100:
        raise ValueError("Risk score must be between 0 and 100")

    if score >= 70:
        return {
            "risk": "high",
            "action": "create_case_and_propose_containment",
            "approval_required": True,
        }

    if score >= 30:
        return {
            "risk": "medium",
            "action": "analyst_review",
            "approval_required": True,
        }

    return {
        "risk": "low",
        "action": "summary_close_candidate",
        "approval_required": True,
    }
