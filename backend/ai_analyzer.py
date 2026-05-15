from typing import Dict, List, Any


def _risk_label_fr(risk: str) -> str:
    mapping = {
        "Low": "faible",
        "Medium": "moyen",
        "High": "élevé",
        "Critical": "critique",
    }
    return mapping.get(risk, "inconnu")


def detect_false_positive(finding: Dict[str, Any]) -> bool:
    combined = " ".join(
        str(finding.get(key, ""))
        for key in ["type", "file", "maskedValue", "value", "url", "context"]
    ).lower()

    false_positive_markers = [
        "example",
        "sample",
        "dummy",
        "placeholder",
        "test_value",
        "changeme",
        "your_api_key",
    ]

    return any(marker in combined for marker in false_positive_markers)


def analyze_finding_with_ai(finding: Dict[str, Any], category: str) -> Dict[str, Any]:
    risk = finding.get("risk", "Low")
    risk_fr = _risk_label_fr(risk)

    if category == "secret":
        finding_type = str(finding.get("type", "Secret"))

        if "token" in finding_type.lower() or "bearer" in finding_type.lower():
            explanation = (
                "Un token d’authentification exposé dans une application Android "
                "peut permettre un accès non autorisé si le token est encore valide."
            )
            recommendation = (
                "Ne jamais stocker un token fixe dans le code client. "
                "Les tokens doivent être générés côté serveur et avoir une durée de vie limitée."
            )

        elif "password" in finding_type.lower():
            explanation = (
                "Un mot de passe codé en dur peut être récupéré après décompilation de l’APK."
            )
            recommendation = (
                "Supprimer le mot de passe du code et utiliser un mécanisme d’authentification sécurisé."
            )

        elif "api" in finding_type.lower() or "key" in finding_type.lower():
            explanation = (
                "Une clé API visible dans le code peut être réutilisée par un attaquant "
                "si elle n’est pas correctement restreinte."
            )
            recommendation = (
                "Restreindre la clé API par package name, signature SHA-1, domaine ou règles côté serveur."
            )

        else:
            explanation = (
                "Une information sensible semble être exposée dans le code ou les fichiers de configuration."
            )
            recommendation = (
                "Vérifier la validité de cette valeur et déplacer les secrets vers un backend sécurisé."
            )

    else:
        url = str(finding.get("url", ""))

        if url.lower().startswith("http://"):
            explanation = (
                "Un endpoint HTTP non chiffré expose le trafic à l’interception ou à la modification."
            )
            recommendation = (
                "Remplacer HTTP par HTTPS et appliquer une configuration réseau stricte."
            )

        elif any(word in url.lower() for word in ["admin", "debug", "internal"]):
            explanation = (
                "Un endpoint sensible est visible dans l’application, ce qui peut aider un attaquant à cartographier le backend."
            )
            recommendation = (
                "Éviter d’exposer des endpoints sensibles dans le code client et contrôler l’accès côté serveur."
            )

        else:
            explanation = (
                "L’endpoint détecté révèle une communication backend utilisée par l’application."
            )
            recommendation = (
                "Vérifier que l’endpoint est protégé par HTTPS, authentification et contrôle d’accès."
            )

    is_false_positive = detect_false_positive(finding)

    return {
        "aiRisk": risk,
        "aiRiskLabel": risk_fr,
        "explanation": explanation,
        "recommendation": recommendation,
        "falsePositiveProbability": "Medium" if is_false_positive else "Low",
    }


def enrich_findings_with_ai(findings: List[Dict[str, Any]], category: str) -> List[Dict[str, Any]]:
    enriched = []

    for finding in findings or []:
        ai_analysis = analyze_finding_with_ai(finding, category)
        enriched.append({**finding, **ai_analysis})

    return enriched


def generate_ai_summary(
    secrets: List[Dict[str, Any]],
    endpoints: List[Dict[str, Any]],
    global_score: int,
    global_risk: str,
) -> str:
    secrets_count = len(secrets or [])
    endpoints_count = len(endpoints or [])
    risk_fr = _risk_label_fr(global_risk)

    if secrets_count == 0 and endpoints_count == 0:
        return (
            "Aucun secret ni endpoint sensible n’a été détecté dans les fichiers analysés. "
            "Le niveau de risque global est faible, sous réserve que l’analyse statique soit complète."
        )

    return (
        f"L’application analysée contient {secrets_count} secret(s) potentiel(s) "
        f"et {endpoints_count} endpoint(s) détecté(s). "
        f"Le score global est de {global_score}/100, ce qui correspond à un risque {risk_fr}. "
        "Les éléments les plus sensibles doivent être corrigés en priorité afin de limiter "
        "l’exposition de données confidentielles dans l’APK."
    )


def generate_recommendations(secrets: List[Dict[str, Any]], endpoints: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    recommendations = []

    if any(item.get("risk") == "Critical" for item in secrets or []):
        recommendations.append(
            {
                "priority": "Critical",
                "title": "Supprimer les secrets critiques du code",
                "description": (
                    "Les tokens, mots de passe et clés privées ne doivent jamais être stockés "
                    "directement dans l’application Android."
                ),
            }
        )

    if any(str(item.get("url", "")).lower().startswith("http://") for item in endpoints or []):
        recommendations.append(
            {
                "priority": "High",
                "title": "Forcer l’utilisation de HTTPS",
                "description": (
                    "Tous les endpoints HTTP doivent être remplacés par HTTPS afin de protéger "
                    "les échanges réseau."
                ),
            }
        )

    if any("api" in str(item.get("type", "")).lower() for item in secrets or []):
        recommendations.append(
            {
                "priority": "High",
                "title": "Restreindre les clés API",
                "description": (
                    "Les clés API doivent être limitées par application, signature, domaine "
                    "ou contrôlées côté serveur."
                ),
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "priority": "Medium",
                "title": "Renforcer l’analyse de sécurité",
                "description": (
                    "Compléter l’analyse statique par une analyse dynamique afin de vérifier "
                    "le comportement réel de l’application."
                ),
            }
        )

    return recommendations


def build_ai_analysis(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    secrets = enrich_findings_with_ai(
        analysis_result.get("secrets", []),
        "secret",
    )

    endpoints = enrich_findings_with_ai(
        analysis_result.get("endpoints", []),
        "endpoint",
    )

    global_score = analysis_result.get("globalScore", 0)
    global_risk = analysis_result.get("globalRisk", "Low")

    return {
        "secrets": secrets,
        "endpoints": endpoints,
        "aiSummary": generate_ai_summary(
            secrets=secrets,
            endpoints=endpoints,
            global_score=global_score,
            global_risk=global_risk,
        ),
        "recommendations": generate_recommendations(secrets, endpoints),
    }