import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

try:
    from schemas.report_schema import build_report_schema
except ImportError:
    from backend.schemas.report_schema import build_report_schema


BASE_DIR = Path(__file__).resolve().parents[1]

REPORTS_DIR = BASE_DIR / "reports"
GENERATED_DIR = REPORTS_DIR / "generated"
TEMPLATES_DIR = REPORTS_DIR / "templates"

REPORT_TEMPLATE_NAME = "report_template.html"


def ensure_report_directories() -> None:
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)


def severity_rank(severity: str) -> int:
    order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    return order.get(str(severity).upper(), 4)


def sort_findings_by_risk(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        findings,
        key=lambda finding: severity_rank(finding.get("severity", "LOW")),
    )


def build_recommendations(findings: List[Dict[str, Any]]) -> List[str]:
    recommendations = []

    for finding in findings:
        recommendation = finding.get("recommendation", "")

        if recommendation and recommendation not in recommendations:
            recommendations.append(recommendation)

    return recommendations[:10]


def calculate_global_score(summary: Dict[str, int]) -> int:
    score = 0

    score += summary.get("critical", 0) * 30
    score += summary.get("high", 0) * 20
    score += summary.get("medium", 0) * 10
    score += summary.get("low", 0) * 3

    if score > 100:
        score = 100

    return score


def get_global_risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 25:
        return "MEDIUM"

    return "LOW"


def extract_findings(scan_result: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not scan_result:
        return []

    findings = scan_result.get("findings", [])

    if isinstance(findings, list):
        return findings

    return []


def generate_report(
    apk_name: str,
    endpoint_scan_result: Optional[Dict[str, Any]] = None,
    manifest_scan_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    endpoint_findings = extract_findings(endpoint_scan_result)
    manifest_findings = extract_findings(manifest_scan_result)

    report = build_report_schema(
        apk_name=apk_name,
        endpoint_findings=endpoint_findings,
        manifest_findings=manifest_findings,
    )

    report["findings"] = sort_findings_by_risk(report["findings"])
    report["top_10_risks"] = report["findings"][:10]
    report["recommendations"] = build_recommendations(report["findings"])

    global_score = calculate_global_score(report["summary"])

    report["risk_score"] = global_score
    report["global_risk_level"] = get_global_risk_level(global_score)

    return report


def render_report_html(report: Dict[str, Any]) -> str:
    ensure_report_directories()

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )

    template = env.get_template(REPORT_TEMPLATE_NAME)

    return template.render(report=report)


def save_json_report(report: Dict[str, Any], report_id: str) -> Path:
    ensure_report_directories()

    json_path = GENERATED_DIR / f"{report_id}.json"

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    return json_path


def save_html_report(report: Dict[str, Any], report_id: str) -> Path:
    ensure_report_directories()

    html_content = render_report_html(report)
    html_path = GENERATED_DIR / f"{report_id}.html"

    with open(html_path, "w", encoding="utf-8") as file:
        file.write(html_content)

    return html_path


def generate_and_save_report(
    apk_name: str,
    endpoint_scan_result: Optional[Dict[str, Any]] = None,
    manifest_scan_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    report_id = str(uuid.uuid4())[:8]

    report = generate_report(
        apk_name=apk_name,
        endpoint_scan_result=endpoint_scan_result,
        manifest_scan_result=manifest_scan_result,
    )

    report["report_id"] = report_id

    json_path = save_json_report(report, report_id)
    html_path = save_html_report(report, report_id)

    report["files"] = {
        "json": str(json_path).replace("\\", "/"),
        "html": str(html_path).replace("\\", "/"),
    }

    save_json_report(report, report_id)

    return report


def get_report_json_path(report_id: str) -> Path:
    return GENERATED_DIR / f"{report_id}.json"


def get_report_html_path(report_id: str) -> Path:
    return GENERATED_DIR / f"{report_id}.html"


def load_report(report_id: str) -> Dict[str, Any]:
    json_path = get_report_json_path(report_id)

    if not json_path.exists():
        raise FileNotFoundError(f"Rapport introuvable : {report_id}")

    with open(json_path, "r", encoding="utf-8") as file:
        return json.load(file)


def get_latest_report_id() -> Optional[str]:
    ensure_report_directories()

    json_files = list(GENERATED_DIR.glob("*.json"))

    if not json_files:
        return None

    latest_file = max(json_files, key=lambda file: file.stat().st_mtime)

    return latest_file.stem