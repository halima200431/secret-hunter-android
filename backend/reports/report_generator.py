import json
import html
from pathlib import Path
from typing import Dict, Any
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORTS_ROOT = PROJECT_ROOT / "reports"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _ensure_report_dir(analysis_id: str) -> Path:
    safe_id = "".join(char for char in analysis_id if char.isalnum() or char in ["-", "_"])
    report_dir = REPORTS_ROOT / safe_id
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


def generate_json_report(analysis_result: Dict[str, Any], report_dir: Path) -> str:
    json_path = report_dir / "report.json"

    safe_result = {
        **analysis_result,
        "generatedAt": _utc_now(),
    }

    with json_path.open("w", encoding="utf-8") as file:
        json.dump(safe_result, file, ensure_ascii=False, indent=2)

    return str(json_path)


def generate_html_report(analysis_result: Dict[str, Any], report_dir: Path) -> str:
    html_path = report_dir / "report.html"

    secrets_rows = []
    for secret in analysis_result.get("secrets", []):
        secrets_rows.append(
            f"""
            <tr>
                <td>{_safe_text(secret.get("type"))}</td>
                <td><code>{_safe_text(secret.get("maskedValue"))}</code></td>
                <td>{_safe_text(secret.get("file"))}</td>
                <td>{_safe_text(secret.get("line"))}</td>
                <td>{_safe_text(secret.get("risk"))}</td>
                <td>{_safe_text(secret.get("recommendation"))}</td>
            </tr>
            """
        )

    endpoints_rows = []
    for endpoint in analysis_result.get("endpoints", []):
        endpoints_rows.append(
            f"""
            <tr>
                <td><code>{_safe_text(endpoint.get("url"))}</code></td>
                <td>{_safe_text(endpoint.get("type"))}</td>
                <td>{_safe_text(endpoint.get("protocol"))}</td>
                <td>{_safe_text(endpoint.get("file"))}</td>
                <td>{_safe_text(endpoint.get("line"))}</td>
                <td>{_safe_text(endpoint.get("risk"))}</td>
            </tr>
            """
        )

    recommendations = []
    for recommendation in analysis_result.get("recommendations", []):
        recommendations.append(
            f"""
            <li>
                <strong>{_safe_text(recommendation.get("title"))}</strong>
                <p>{_safe_text(recommendation.get("description"))}</p>
            </li>
            """
        )

    content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>SecretHunter Android Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #111111;
                color: #f5f5f5;
                margin: 0;
                padding: 32px;
            }}

            .container {{
                max-width: 1100px;
                margin: auto;
                background: #1f1f1f;
                border: 1px solid #333333;
                border-radius: 18px;
                padding: 32px;
            }}

            h1, h2 {{
                color: #ffffff;
            }}

            .summary {{
                background: #171717;
                border: 1px solid #333333;
                border-radius: 14px;
                padding: 18px;
                margin-bottom: 24px;
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 12px;
                margin-bottom: 28px;
            }}

            th, td {{
                border-bottom: 1px solid #333333;
                padding: 12px;
                text-align: left;
                vertical-align: top;
            }}

            th {{
                color: #cccccc;
                background: #151515;
            }}

            code {{
                color: #ffb4b4;
            }}

            .risk {{
                font-size: 24px;
                font-weight: bold;
                color: #ff6b6b;
            }}

            p, li {{
                color: #d4d4d8;
                line-height: 1.6;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SecretHunter Android Report</h1>

            <div class="summary">
                <p><strong>APK :</strong> {_safe_text(analysis_result.get("apkName"))}</p>
                <p><strong>Date :</strong> {_safe_text(analysis_result.get("analysisDate"))}</p>
                <p><strong>Fichiers analysés :</strong> {_safe_text(analysis_result.get("filesAnalyzed"))}</p>
                <p><strong>Score global :</strong> {_safe_text(analysis_result.get("globalScore"))}/100</p>
                <p class="risk">Risque global : {_safe_text(analysis_result.get("globalRisk"))}</p>
            </div>

            <h2>Résumé IA</h2>
            <p>{_safe_text(analysis_result.get("aiSummary"))}</p>

            <h2>Secrets détectés</h2>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Valeur masquée</th>
                        <th>Fichier</th>
                        <th>Ligne</th>
                        <th>Risque</th>
                        <th>Recommandation</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(secrets_rows)}
                </tbody>
            </table>

            <h2>Endpoints détectés</h2>
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Type</th>
                        <th>Protocole</th>
                        <th>Fichier</th>
                        <th>Ligne</th>
                        <th>Risque</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(endpoints_rows)}
                </tbody>
            </table>

            <h2>Recommandations</h2>
            <ul>
                {''.join(recommendations)}
            </ul>
        </div>
    </body>
    </html>
    """

    with html_path.open("w", encoding="utf-8") as file:
        file.write(content)

    return str(html_path)


def generate_reports(analysis_result: Dict[str, Any], analysis_id: str) -> Dict[str, str]:
    report_dir = _ensure_report_dir(analysis_id)

    json_report = generate_json_report(
        analysis_result=analysis_result,
        report_dir=report_dir,
    )

    html_report = generate_html_report(
        analysis_result=analysis_result,
        report_dir=report_dir,
    )

    return {
        "json": json_report,
        "html": html_report,
    }