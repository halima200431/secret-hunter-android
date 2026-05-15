from typing import Dict, Any

from backend.ai_analyzer import build_ai_analysis


def analyze_results_with_ai(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Service IA.
    Actuellement, il utilise une IA basée sur des règles intelligentes.
    Plus tard, ce fichier peut être connecté à un vrai modèle LLM.
    """

    ai_output = build_ai_analysis(analysis_result)

    return {
        "secrets": ai_output["secrets"],
        "endpoints": ai_output["endpoints"],
        "aiSummary": ai_output["aiSummary"],
        "recommendations": ai_output["recommendations"],
    }