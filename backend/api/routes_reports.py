from pathlib import Path

from flask import Blueprint, jsonify, request, send_file

try:
    from services.report_service import (
        generate_and_save_report,
        get_latest_report_id,
        get_report_html_path,
        load_report,
    )
except ImportError:
    from backend.services.report_service import (
        generate_and_save_report,
        get_latest_report_id,
        get_report_html_path,
        load_report,
    )


reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/api/reports/generate", methods=["POST"])
def generate_report_route():
    data = request.get_json(silent=True) or {}

    apk_name = data.get("apk_name", "unknown.apk")

    endpoint_scan_result = (
        data.get("endpoint_scan_result")
        or data.get("endpoint_result")
        or data.get("network_result")
        or {}
    )

    manifest_scan_result = (
        data.get("manifest_scan_result")
        or data.get("manifest_result")
        or {}
    )

    report = generate_and_save_report(
        apk_name=apk_name,
        endpoint_scan_result=endpoint_scan_result,
        manifest_scan_result=manifest_scan_result,
    )

    return jsonify(
        {
            "status": "success",
            "message": "Rapport généré avec succès.",
            "report_id": report["report_id"],
            "risk_score": report["risk_score"],
            "global_risk_level": report["global_risk_level"],
            "summary": report["summary"],
            "files": report["files"],
        }
    ), 201


@reports_bp.route("/api/reports/<report_id>/json", methods=["GET"])
def get_report_json_route(report_id):
    try:
        report = load_report(report_id)

        return jsonify(
            {
                "status": "success",
                "report": report,
            }
        ), 200

    except FileNotFoundError:
        return jsonify(
            {
                "status": "error",
                "message": "Rapport introuvable.",
            }
        ), 404


@reports_bp.route("/api/reports/<report_id>/html", methods=["GET"])
def get_report_html_route(report_id):
    html_path = get_report_html_path(report_id)

    if not html_path.exists():
        return jsonify(
            {
                "status": "error",
                "message": "Rapport HTML introuvable.",
            }
        ), 404

    return send_file(str(html_path), mimetype="text/html")


@reports_bp.route("/api/reports/latest/json", methods=["GET"])
def get_latest_report_json_route():
    report_id = get_latest_report_id()

    if not report_id:
        return jsonify(
            {
                "status": "error",
                "message": "Aucun rapport généré pour le moment.",
            }
        ), 404

    report = load_report(report_id)

    return jsonify(
        {
            "status": "success",
            "report": report,
        }
    ), 200


@reports_bp.route("/api/reports/latest/html", methods=["GET"])
def get_latest_report_html_route():
    report_id = get_latest_report_id()

    if not report_id:
        return jsonify(
            {
                "status": "error",
                "message": "Aucun rapport généré pour le moment.",
            }
        ), 404

    html_path = get_report_html_path(report_id)

    if not html_path.exists():
        return jsonify(
            {
                "status": "error",
                "message": "Rapport HTML introuvable.",
            }
        ), 404

    return send_file(str(html_path), mimetype="text/html")


@reports_bp.route("/report", methods=["GET"])
def open_latest_report_route():
    report_id = get_latest_report_id()

    if not report_id:
        return jsonify(
            {
                "status": "error",
                "message": "Aucun rapport disponible.",
            }
        ), 404

    html_path = get_report_html_path(report_id)

    return send_file(str(html_path), mimetype="text/html")