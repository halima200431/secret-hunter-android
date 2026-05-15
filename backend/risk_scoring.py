"""
SecretHunter Android — Risk Scoring Module (stub)
===================================================
Ce module reçoit les findings bruts du Secret Scanner et calcule
un score de risque global. Il est destiné à être enrichi par Halima
avec son modèle de scoring IA.

Fonctions publiques :
    compute_risk_score(scan_result: dict) -> dict
"""


# Poids de risque par niveau
RISK_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH":      5,
    "MEDIUM":    2,
    "LOW":       1,
}


def compute_risk_score(scan_result: dict) -> dict:
    """
    Calcule un score de risque global à partir des findings du Secret Scanner.

    Args:
        scan_result (dict): Résultat retourné par scan_secrets().

    Returns:
        dict: scan_result enrichi avec un champ 'global_risk_score' et 'risk_level'.
    """
    if scan_result.get("status") != "success":
        return scan_result

    findings = scan_result.get("findings", [])
    if not findings:
        scan_result["global_risk_score"] = 0
        scan_result["risk_level"]        = "SAFE"
        return scan_result

    # Score brut : somme pondérée des niveaux de risque
    raw_score = sum(RISK_WEIGHTS.get(f.get("risk", "LOW"), 1) for f in findings)

    # Normalisation sur 100
    max_score = len(findings) * RISK_WEIGHTS["CRITICAL"]
    normalized = min(100, round((raw_score / max_score) * 100)) if max_score > 0 else 0

    # Niveau de risque global
    if normalized >= 75:
        risk_level = "CRITICAL"
    elif normalized >= 50:
        risk_level = "HIGH"
    elif normalized >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    scan_result["global_risk_score"] = normalized
    scan_result["risk_level"]        = risk_level
    return scan_result