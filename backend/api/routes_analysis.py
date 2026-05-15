import uuid
import zipfile
from pathlib import Path
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import secure_filename

from backend.jobs.job_manager import job_manager
from backend.scanners.risk_scoring import apply_risk_scoring
from backend.services.ai_service import analyze_results_with_ai
from backend.reports.report_generator import generate_reports


analysis_bp = Blueprint("analysis", __name__)


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()
    return extension in current_app.config.get("ALLOWED_EXTENSIONS", {"apk"})


def _save_uploaded_apk(file_storage):
    original_name = secure_filename(file_storage.filename or "")

    if not original_name:
        raise ValueError("Nom de fichier invalide.")

    if not _allowed_file(original_name):
        raise ValueError("Seuls les fichiers .apk sont acceptés.")

    analysis_id = str(uuid.uuid4())

    upload_dir = Path(current_app.config["UPLOAD_FOLDER"]) / analysis_id
    upload_dir.mkdir(parents=True, exist_ok=True)

    apk_path = upload_dir / original_name
    file_storage.save(apk_path)

    if not zipfile.is_zipfile(apk_path):
        apk_path.unlink(missing_ok=True)
        raise ValueError("Le fichier envoyé n’est pas un APK valide.")

    return analysis_id, apk_path, original_name


def _normalize_endpoint_result(endpoint_result):
    """
    Certains endpoint scanners retournent directement une liste.
    D'autres retournent un dictionnaire avec une clé 'findings'.
    Cette fonction normalise le résultat en liste propre.
    """

    if isinstance(endpoint_result, dict):
        findings = endpoint_result.get("findings", [])

        if isinstance(findings, list):
            return findings

        return []

    if isinstance(endpoint_result, list):
        return endpoint_result

    return []


def _run_analysis_pipeline(analysis_id: str, apk_path: str, apk_name: str):
    """
    Pipeline principal :
    1. Extraction APK
    2. Scan secrets
    3. Scan endpoints
    4. Scoring
    5. Analyse IA
    6. Génération rapport
    """

    apk_path = Path(apk_path)

    extracted_path = None
    files_analyzed = 0
    secrets = []
    endpoints = []
    extraction_errors = []

    print("\n========== START ANALYSIS PIPELINE ==========")
    print("ANALYSIS ID =", analysis_id)
    print("APK PATH =", apk_path)
    print("APK NAME =", apk_name)

    try:
        from backend.services.apk_service import extract_apk

        print("[1] Calling apk_service.extract_apk()...")

        extraction_result = extract_apk(
            apk_path=str(apk_path),
            analysis_id=analysis_id,
        )

        print("[1] EXTRACTION RESULT =", extraction_result)

        extracted_path = extraction_result.get("extracted_path")
        files_analyzed = extraction_result.get("files_count", 0)

        print("[1] EXTRACTED PATH =", extracted_path)
        print("[1] FILES ANALYZED =", files_analyzed)

    except Exception as error:
        print("[ERROR] APK SERVICE ERROR =", str(error))

        extraction_errors.append(
            {
                "module": "apk_service",
                "message": str(error),
            }
        )

    if extracted_path:
        try:
            from backend.scanners.secret_scanner import scan_secrets

            print("[2] Calling secret_scanner.scan_secrets()...")
            print("[2] SECRET SCAN PATH =", extracted_path)

            secret_result = scan_secrets(extracted_path)

            if isinstance(secret_result, list):
                secrets = secret_result
            else:
                secrets = []

            print("[2] SECRETS FOUND =", len(secrets))
            print("[2] SECRETS SAMPLE =", secrets[:3])

        except Exception as error:
            print("[ERROR] SECRET SCANNER ERROR =", str(error))

            extraction_errors.append(
                {
                    "module": "secret_scanner",
                    "message": str(error),
                }
            )

        try:
            from backend.scanners.endpoint_scanner import scan_endpoints

            print("[3] Calling endpoint_scanner.scan_endpoints()...")
            print("[3] ENDPOINT SCAN PATH =", extracted_path)

            endpoint_result = scan_endpoints(extracted_path)

            endpoints = _normalize_endpoint_result(endpoint_result)

            print("[3] ENDPOINTS FOUND =", len(endpoints))
            print("[3] ENDPOINTS SAMPLE =", endpoints[:3])

        except Exception as error:
            print("[ERROR] ENDPOINT SCANNER ERROR =", str(error))

            extraction_errors.append(
                {
                    "module": "endpoint_scanner",
                    "message": str(error),
                }
            )

    else:
        print("[ERROR] No extracted_path returned. Scan skipped.")

        extraction_errors.append(
            {
                "module": "pipeline",
                "message": "Aucun extracted_path retourné. Le scan secrets/endpoints n’a pas été exécuté.",
            }
        )

    try:
        print("[4] Calling risk scoring...")

        scored_result = apply_risk_scoring(
            apk_name=apk_name,
            files_analyzed=files_analyzed,
            secrets=secrets,
            endpoints=endpoints,
        )

        print("[4] SCORED RESULT =", scored_result)

    except Exception as error:
        print("[ERROR] RISK SCORING ERROR =", str(error))

        extraction_errors.append(
            {
                "module": "risk_scoring",
                "message": str(error),
            }
        )

        scored_result = {
            "apkName": apk_name,
            "globalRisk": "Low",
            "globalScore": 0,
            "filesAnalyzed": files_analyzed,
            "secretsCount": len(secrets),
            "endpointsCount": len(endpoints),
            "criticalFindings": 0,
            "secrets": secrets,
            "endpoints": endpoints,
            "riskDistribution": [
                {"name": "Faible", "value": 0},
                {"name": "Moyen", "value": 0},
                {"name": "Élevé", "value": 0},
                {"name": "Critique", "value": 0},
            ],
        }

    try:
        print("[5] Calling AI analyzer...")

        ai_result = analyze_results_with_ai(scored_result)

    except Exception as error:
        print("[ERROR] AI ANALYZER ERROR =", str(error))

        extraction_errors.append(
            {
                "module": "ai_analyzer",
                "message": str(error),
            }
        )

        ai_result = {
            "aiSummary": "L’analyse IA n’a pas pu être générée.",
            "recommendations": [],
        }

    final_result = {
        **scored_result,
        **ai_result,
        "analysisId": analysis_id,
        "analysisDate": _utc_now(),
        "status": "success" if not extraction_errors else "partial_success",
        "errors": extraction_errors,
    }

    try:
        print("[6] Calling report generator...")

        report_paths = generate_reports(
            analysis_result=final_result,
            analysis_id=analysis_id,
        )

        final_result["reports"] = report_paths

    except Exception as error:
        print("[ERROR] REPORT GENERATOR ERROR =", str(error))

        extraction_errors.append(
            {
                "module": "report_generator",
                "message": str(error),
            }
        )

        final_result["status"] = "partial_success"
        final_result["errors"] = extraction_errors
        final_result["reports"] = {}

    print("[7] FINAL RESULT =", final_result)
    print("========== END ANALYSIS PIPELINE ==========\n")

    return final_result


@analysis_bp.post("/analyze")
def analyze_apk():
    if "file" not in request.files:
        return jsonify(
            {
                "status": "error",
                "message": "Aucun fichier APK envoyé.",
            }
        ), 400

    file_storage = request.files["file"]

    try:
        analysis_id, apk_path, apk_name = _save_uploaded_apk(file_storage)

        job_manager.create_job(
            analysis_id=analysis_id,
            metadata={
                "apkName": apk_name,
                "createdAt": _utc_now(),
            },
        )

        job_manager.start_job(
            analysis_id=analysis_id,
            target=_run_analysis_pipeline,
            apk_path=str(apk_path),
            apk_name=apk_name,
        )

        return jsonify(
            {
                "status": "accepted",
                "message": "APK reçu. Analyse démarrée.",
                "analysisId": analysis_id,
                "apkName": apk_name,
            }
        ), 202

    except ValueError as error:
        return jsonify(
            {
                "status": "error",
                "message": str(error),
            }
        ), 400

    except Exception as error:
        print("[ERROR] UPLOAD ERROR =", str(error))

        return jsonify(
            {
                "status": "error",
                "message": "Erreur inattendue pendant l’upload de l’APK.",
            }
        ), 500


@analysis_bp.get("/analysis/<analysis_id>/status")
def get_analysis_status(analysis_id):
    job = job_manager.get_job(analysis_id)

    if job is None:
        return jsonify(
            {
                "status": "error",
                "message": "Analyse introuvable.",
            }
        ), 404

    return jsonify(job.to_public_dict())


@analysis_bp.get("/analysis/<analysis_id>/results")
def get_analysis_results(analysis_id):
    job = job_manager.get_job(analysis_id)

    if job is None:
        return jsonify(
            {
                "status": "error",
                "message": "Analyse introuvable.",
            }
        ), 404

    if job.status != "completed":
        return jsonify(
            {
                "status": job.status,
                "message": "Les résultats ne sont pas encore disponibles.",
                "progress": job.progress,
            }
        ), 202

    return jsonify(job.result)