from typing import Dict, List, Any


RISK_LEVELS = {
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Critical",
}


def get_risk_level(score: int) -> str:
    score = max(0, min(100, int(score)))

    if score >= 86:
        return RISK_LEVELS["CRITICAL"]

    if score >= 61:
        return RISK_LEVELS["HIGH"]

    if score >= 31:
        return RISK_LEVELS["MEDIUM"]

    return RISK_LEVELS["LOW"]


def _contains(value: str, keywords: List[str]) -> bool:
    value = value.lower()
    return any(keyword.lower() in value for keyword in keywords)


def calculate_secret_score(secret: Dict[str, Any]) -> int:
    secret_type = str(secret.get("type", "")).lower()
    context = " ".join(
        [
            str(secret.get("file", "")),
            str(secret.get("line", "")),
            str(secret.get("maskedValue", "")),
            str(secret.get("value", "")),
            str(secret.get("context", "")),
        ]
    ).lower()

    score = 40

    if _contains(secret_type, ["private key", "rsa", "pem"]):
        score = max(score, 100)

    if _contains(secret_type, ["password", "passwd", "pwd"]):
        score = max(score, 95)

    if _contains(secret_type, ["bearer", "token", "access token", "refresh token", "jwt"]):
        score = max(score, 90)

    if _contains(secret_type, ["client secret", "secret"]):
        score = max(score, 85)

    if _contains(secret_type, ["api key", "apikey", "firebase", "google"]):
        score = max(score, 80)

    if "test" in context or "example" in context or "dummy" in context:
        score -= 15

    if "res/values/strings.xml" in context:
        score += 5

    return max(0, min(100, score))


def calculate_endpoint_score(endpoint: Dict[str, Any]) -> int:
    url = str(endpoint.get("url", ""))
    endpoint_type = str(endpoint.get("type", ""))
    protocol = str(endpoint.get("protocol", "")).upper()

    combined = f"{url} {endpoint_type}".lower()
    score = 20

    if protocol == "HTTP" or url.lower().startswith("http://"):
        score = max(score, 75)

    if _contains(combined, ["admin", "dashboard", "debug", "internal"]):
        score = max(score, 80)

    if _contains(combined, ["login", "auth", "token", "session", "oauth"]):
        score = max(score, 60)

    if _contains(combined, ["firebase", "firebasedatabase", "firebaseio"]):
        score = max(score, 60)

    if _contains(combined, ["192.168.", "10.", "172.16.", "localhost", "127.0.0.1"]):
        score = max(score, 70)

    if protocol == "HTTPS" and score < 60:
        score = max(score, 25)

    return max(0, min(100, score))


def enrich_findings_with_risk(findings: List[Dict[str, Any]], finding_type: str) -> List[Dict[str, Any]]:
    enriched = []

    for finding in findings or []:
        item = dict(finding)

        if finding_type == "secret":
            score = calculate_secret_score(item)
        else:
            score = calculate_endpoint_score(item)

        item["score"] = score
        item["risk"] = get_risk_level(score)

        enriched.append(item)

    return enriched


def calculate_global_score(secrets: List[Dict[str, Any]], endpoints: List[Dict[str, Any]]) -> int:
    all_scores = [
        int(item.get("score", 0))
        for item in [*(secrets or []), *(endpoints or [])]
    ]

    if not all_scores:
        return 0

    max_score = max(all_scores)
    average_score = sum(all_scores) / len(all_scores)

    global_score = int((max_score * 0.65) + (average_score * 0.35))

    return max(0, min(100, global_score))


def count_critical_findings(secrets: List[Dict[str, Any]], endpoints: List[Dict[str, Any]]) -> int:
    return sum(
        1
        for item in [*(secrets or []), *(endpoints or [])]
        if item.get("risk") == RISK_LEVELS["CRITICAL"]
    )


def build_risk_distribution(secrets: List[Dict[str, Any]], endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counters = {
        "Faible": 0,
        "Moyen": 0,
        "Élevé": 0,
        "Critique": 0,
    }

    mapping = {
        "Low": "Faible",
        "Medium": "Moyen",
        "High": "Élevé",
        "Critical": "Critique",
    }

    for item in [*(secrets or []), *(endpoints or [])]:
        label = mapping.get(item.get("risk"), "Faible")
        counters[label] += 1

    return [{"name": key, "value": value} for key, value in counters.items()]


def apply_risk_scoring(
    apk_name: str,
    files_analyzed: int,
    secrets: List[Dict[str, Any]],
    endpoints: List[Dict[str, Any]],
) -> Dict[str, Any]:
    scored_secrets = enrich_findings_with_risk(secrets, "secret")
    scored_endpoints = enrich_findings_with_risk(endpoints, "endpoint")

    global_score = calculate_global_score(scored_secrets, scored_endpoints)
    global_risk = get_risk_level(global_score)

    return {
        "apkName": apk_name,
        "globalRisk": global_risk,
        "globalScore": global_score,
        "filesAnalyzed": files_analyzed,
        "secretsCount": len(scored_secrets),
        "endpointsCount": len(scored_endpoints),
        "criticalFindings": count_critical_findings(scored_secrets, scored_endpoints),
        "secrets": scored_secrets,
        "endpoints": scored_endpoints,
        "riskDistribution": build_risk_distribution(scored_secrets, scored_endpoints),
    }