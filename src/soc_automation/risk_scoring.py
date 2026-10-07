def calculate_risk_score(
    wazuh_level,
    correlated_process_chain=False,
    ioc_count=0,
    vt_stats=None,
):
    score = 0
    reasons = []

    if correlated_process_chain:
        score += 20
        reasons.append(
            {
                "signal": "correlated_process_chain",
                "points": 20,
            }
        )

    if wazuh_level >= 7:
        score += 25
        reasons.append(
            {
                "signal": "wazuh_level_7_plus",
                "points": 25,
            }
        )
    elif wazuh_level >= 4:
        score += 15
        reasons.append(
            {
                "signal": "wazuh_level_4_6",
                "points": 15,
            }
        )
    elif wazuh_level >= 1:
        score += 5
        reasons.append(
            {
                "signal": "wazuh_level_1_3",
                "points": 5,
            }
        )

    if ioc_count > 0:
        score += 10
        reasons.append(
            {
                "signal": "ioc_present",
                "points": 10,
            }
        )

    vt_stats = vt_stats or {}

    malicious = vt_stats.get("malicious", 0)
    suspicious = vt_stats.get("suspicious", 0)

    if malicious >= 5:
        score += 30
        reasons.append(
            {
                "signal": "vt_malicious_5_plus",
                "points": 30,
            }
        )
    elif malicious >= 1:
        score += 15
        reasons.append(
            {
                "signal": "vt_malicious_1_4",
                "points": 15,
            }
        )

    if suspicious > 0:
        score += 10
        reasons.append(
            {
                "signal": "vt_suspicious_present",
                "points": 10,
            }
        )

    return {
        "score": min(score, 100),
        "reasons": reasons,
    }
