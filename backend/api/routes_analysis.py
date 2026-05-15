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


def _run_analysis_pipeline(analysis_id: str, apk_path: str, apk_name: str):
    """
    Pipeline principal.
    Il est compatible avec les fichiers des collègues.
    Si leurs modules ne sont pas encore remplis, il retourne un résultat partiel propre.
    """

    apk_path = Path(apk_path)

    extracted_path = None
    files_analyzed = 0
    secrets = []
    endpoints = []
    extraction_errors = []

    try:
        from backend.services.apk_service import extract_apk

        extraction_result = extract_apk(
            apk_path=str(apk_path),
            analysis_id=analysis_id,
        )

        extracted_path = extraction_result.get("extracted_path")
        files_analyzed = extraction_result.get("files_count", 0)

    except Exception as error:
        extraction_errors.append(
            {
                "module": "apk_service",
                "message": str(error),
            }
        )

    if extracted_path:
        try:
            from backend.scanners.secret_scanner import scan_secrets

            secrets = scan_secrets(extracted_path)
        except Exception as error:
            extraction_errors.append(
                {
                    "module": "secret_scanner",
                    "message": str(error),
                }
            )

        try:
            from backend.scanners.endpoint_scanner import scan_endpoints

            endpoints = scan_endpoints(extracted_path)
        except Exception as error:
            extraction_errors.append(
                {
                    "module": "endpoint_scanner",
                    "message": str(error),
                }
            )

    scored_result = apply_risk_scoring(
        apk_name=apk_name,
        files_analyzed=files_analyzed,
        secrets=secrets,
        endpoints=endpoints,
    )

    ai_result = analyze_results_with_ai(scored_result)

    final_result = {
        **scored_result,
        **ai_result,
        "analysisId": analysis_id,
        "analysisDate": _utc_now(),
        "status": "success" if not extraction_errors else "partial_success",
        "errors": extraction_errors,
    }

    report_paths = generate_reports(
        analysis_result=final_result,
        analysis_id=analysis_id,
    )

    final_result["reports"] = report_paths

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

    except Exception:
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