from typing import Any, Dict, List
import json

try:
    from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
except ImportError:
    AutoTokenizer = None
    AutoModelForSeq2SeqLM = None


MODEL_NAME = "google/flan-t5-base"

_tokenizer = None
_model = None


def load_ai_model():
    """
    Charge le modèle une seule fois.
    Si transformers n'est pas installé ou si le modèle ne se charge pas,
    la fonction retourne None.
    """

    global _tokenizer, _model

    if AutoTokenizer is None or AutoModelForSeq2SeqLM is None:
        return None, None

    if _tokenizer is not None and _model is not None:
        return _tokenizer, _model

    try:
        _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        _model = AutoModelForSeq2SeqLM.from_pretrained(MODEL_NAME)
        return _tokenizer, _model

    except Exception as error:
        print("[AI MODEL ERROR] Impossible de charger le modèle :", str(error))
        return None, None


def build_security_prompt(analysis_result: Dict[str, Any]) -> str:
    apk_name = analysis_result.get("apkName", "APK inconnu")
    global_score = analysis_result.get("globalScore", 0)
    global_risk = analysis_result.get("globalRisk", "Unknown")
    secrets_count = analysis_result.get("secretsCount", 0)
    endpoints_count = analysis_result.get("endpointsCount", 0)
    files_analyzed = analysis_result.get("filesAnalyzed", 0)

    secrets = analysis_result.get("secrets", [])
    endpoints = analysis_result.get("endpoints", [])

    sample_secrets = []
    for item in secrets[:5]:
        if isinstance(item, dict):
            sample_secrets.append(
                {
                    "type": item.get("type"),
                    "risk": item.get("risk"),
                    "file": item.get("file"),
                    "line": item.get("line"),
                }
            )

    sample_endpoints = []
    for item in endpoints[:5]:
        if isinstance(item, dict):
            sample_endpoints.append(
                {
                    "type": item.get("type"),
                    "value": item.get("url") or item.get("value"),
                    "risk": item.get("risk") or item.get("severity"),
                    "file": item.get("file"),
                }
            )

    data = {
        "apk_name": apk_name,
        "global_score": global_score,
        "global_risk": global_risk,
        "files_analyzed": files_analyzed,
        "secrets_count": secrets_count,
        "endpoints_count": endpoints_count,
        "sample_secrets": sample_secrets,
        "sample_endpoints": sample_endpoints,
    }

    return f"""
Tu es un assistant expert en sécurité Android.

Analyse les résultats suivants d'une analyse statique APK et génère :
1. Un résumé court en français.
2. Trois recommandations prioritaires.
3. Pour chaque recommandation, donne une priorité : Critical, High, Medium ou Low.

Résultats JSON :
{json.dumps(data, ensure_ascii=False, indent=2)}

Réponds uniquement en JSON valide avec ce format :
{{
  "aiSummary": "...",
  "recommendations": [
    {{
      "priority": "Critical",
      "title": "...",
      "description": "..."
    }}
  ]
}}
"""


def generate_ai_recommendations_with_model(
    analysis_result: Dict[str, Any],
) -> Dict[str, Any] | None:
    tokenizer, model = load_ai_model()

    if tokenizer is None or model is None:
        return None

    prompt = build_security_prompt(analysis_result)

    try:
        inputs = tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=1024,
        )

        outputs = model.generate(
            **inputs,
            max_new_tokens=512,
            temperature=0.3,
            do_sample=False,
        )

        generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)

        try:
            result = json.loads(generated_text)

            if not isinstance(result, dict):
                return None

            if "aiSummary" not in result or "recommendations" not in result:
                return None

            if not isinstance(result["recommendations"], list):
                return None

            return result

        except Exception:
            print("[AI MODEL WARNING] Réponse non JSON du modèle :")
            print(generated_text)
            return None

    except Exception as error:
        print("[AI MODEL ERROR] Génération impossible :", str(error))
        return None