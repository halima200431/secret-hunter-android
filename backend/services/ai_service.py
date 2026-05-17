from typing import Any, Dict, List

try:
    from backend.services.ai_model_service import generate_ai_recommendations_with_model
except Exception:
    generate_ai_recommendations_with_model = None


def _risk_label(global_risk: str) -> str:
    value = str(global_risk or "").lower()

    if value in ["critical", "critique"]:
        return "critique"
    if value in ["high", "élevé", "eleve"]:
        return "élevé"
    if value in ["medium", "moyen"]:
        return "moyen"

    return "faible"


def _fallback_ai_analysis(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    apk_name = analysis_result.get("apkName", "APK analysé")
    secrets = analysis_result.get("secrets", [])
    endpoints = analysis_result.get("endpoints", [])

    if not isinstance(secrets, list):
        secrets = []

    if not isinstance(endpoints, list):
        endpoints = []

    secrets_count = analysis_result.get("secretsCount", len(secrets))
    endpoints_count = analysis_result.get("endpointsCount", len(endpoints))
    files_analyzed = analysis_result.get("filesAnalyzed", 0)
    global_score = analysis_result.get("globalScore", 0)
    global_risk = analysis_result.get("globalRisk", "Low")

    risk_fr = _risk_label(global_risk)

    ai_summary = (
        f"L'application {apk_name} contient {secrets_count} secret(s) potentiel(s) "
        f"et {endpoints_count} endpoint(s) détecté(s) sur {files_analyzed} fichier(s) analysé(s). "
        f"Le score global est de {global_score}/100, ce qui correspond à un risque {risk_fr}."
    )

    recommendations = []

    if secrets_count > 0:
        recommendations.append(
            {
                "priority": "Critical",
                "title": "Supprimer les secrets codés en dur",
                "description": (
                    "Les tokens, mots de passe, clés API et secrets clients ne doivent jamais être "
                    "stockés directement dans l'APK. Ils doivent être déplacés côté serveur ou gérés "
                    "avec un coffre de secrets."
                ),
            }
        )

    if endpoints_count > 0:
        recommendations.append(
            {
                "priority": "Medium",
                "title": "Valider les endpoints détectés",
                "description": (
                    "Les URLs, domaines et adresses IP détectés doivent être vérifiés afin de distinguer "
                    "les vrais endpoints backend des faux positifs comme les namespaces Android."
                ),
            }
        )

    if global_score >= 70:
        recommendations.append(
            {
                "priority": "High",
                "title": "Corriger les résultats critiques avant publication",
                "description": (
                    "Le score global indique un risque élevé. Les résultats critiques doivent être corrigés "
                    "avant toute mise en production de l'application."
                ),
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "priority": "Medium",
                "title": "Compléter par une analyse dynamique",
                "description": (
                    "Aucun secret critique n'a été détecté par l'analyse statique. Une analyse dynamique "
                    "est recommandée pour observer le comportement réel de l'application."
                ),
            }
        )

    return {
        "aiSummary": ai_summary,
        "recommendations": recommendations,
    }


def _enrich_findings(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    secrets = analysis_result.get("secrets", [])
    endpoints = analysis_result.get("endpoints", [])

    enriched_secrets = []
    for secret in secrets if isinstance(secrets, list) else []:
        if isinstance(secret, dict):
            item = dict(secret)
            item["aiRisk"] = item.get("risk", "High")
            item["explanation"] = item.get(
                "explanation",
                "Ce secret peut exposer des informations sensibles après décompilation de l'APK."
            )
            item["recommendation"] = item.get(
                "recommendation",
                "Supprimer ce secret du code client et le déplacer côté serveur."
            )
            enriched_secrets.append(item)

    enriched_endpoints = []
    for endpoint in endpoints if isinstance(endpoints, list) else []:
        if isinstance(endpoint, dict):
            item = dict(endpoint)
            item["aiRisk"] = item.get("risk", item.get("severity", "Low"))
            item["explanation"] = item.get(
                "explanation",
                "Cet endpoint ou domaine peut révéler une communication backend de l'application."
            )
            item["recommendation"] = item.get(
                "recommendation",
                "Vérifier que l'endpoint est légitime, protégé par HTTPS et soumis à un contrôle d'accès."
            )
            enriched_endpoints.append(item)

    return {
        "secrets": enriched_secrets,
        "endpoints": enriched_endpoints,
    }


def analyze_results_with_ai(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyse IA hybride :
    1. Essaie d'utiliser un modèle Hugging Face local.
    2. Si le modèle échoue, utilise un fallback basé sur règles.
    """

    model_result = None

    if generate_ai_recommendations_with_model is not None:
        model_result = generate_ai_recommendations_with_model(analysis_result)

    if model_result is None:
        model_result = _fallback_ai_analysis(analysis_result)

    enriched = _enrich_findings(analysis_result)

    return {
        "aiSummary": model_result.get("aiSummary", ""),
        "recommendations": model_result.get("recommendations", []),
        "secrets": enriched["secrets"],
        "endpoints": enriched["endpoints"],
    }