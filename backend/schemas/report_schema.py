from datetime import datetime
from typing import Any, Dict, List


SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def empty_summary() -> Dict[str, int]:
    return {
        "total_findings": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "urls": 0,
        "ips": 0,
        "domains": 0,
        "api_paths": 0,
        "manifest_issues": 0,
        "network_config_issues": 0,
        "false_positives": 0,
        "to_verify": 0,
        "confirmed": 0,
    }


def normalize_severity(severity: str) -> str:
    if not severity:
        return "LOW"

    severity = str(severity).upper().strip()

    if severity not in SEVERITIES:
        return "LOW"

    return severity


def normalize_classification(classification: str) -> str:
    if not classification:
        return "A_VERIFIER"

    classification = str(classification).upper().strip()

    allowed = ["VRAI_ENDPOINT", "A_VERIFIER", "FAUX_POSITIF"]

    if classification not in allowed:
        return "A_VERIFIER"

    return classification


def normalize_finding(finding: Dict[str, Any], source_module: str) -> Dict[str, Any]:
    severity = normalize_severity(finding.get("severity", "LOW"))
    classification = normalize_classification(finding.get("classification", "A_VERIFIER"))

    return {
        "source_module": source_module,
        "type": finding.get("type", "UNKNOWN"),
        "value": finding.get("value", ""),
        "file": finding.get("file", ""),
        "line": finding.get("line", 0),
        "context": finding.get("context", ""),
        "severity": severity,
        "classification": classification,
        "risk": finding.get("risk", "Risque non précisé."),
        "recommendation": finding.get("recommendation", "Vérification manuelle recommandée."),
    }


def update_summary_with_finding(summary: Dict[str, int], finding: Dict[str, Any]) -> None:
    summary["total_findings"] += 1

    severity = normalize_severity(finding.get("severity", "LOW"))

    if severity == "CRITICAL":
        summary["critical"] += 1
    elif severity == "HIGH":
        summary["high"] += 1
    elif severity == "MEDIUM":
        summary["medium"] += 1
    else:
        summary["low"] += 1

    finding_type = str(finding.get("type", "")).upper()

    if finding_type == "URL":
        summary["urls"] += 1
    elif finding_type == "IP_ADDRESS":
        summary["ips"] += 1
    elif finding_type == "DOMAIN":
        summary["domains"] += 1
    elif finding_type == "API_PATH":
        summary["api_paths"] += 1

    if finding_type in [
        "CLEAR_TEXT_TRAFFIC",
        "DEBUGGABLE_APP",
        "NETWORK_SECURITY_CONFIG_REFERENCE",
        "NETWORK_PERMISSION",
    ]:
        summary["manifest_issues"] += 1

    if finding_type in [
        "CLEAR_TEXT_PERMITTED_DOMAIN",
        "DEBUG_OVERRIDES",
        "USER_CERTIFICATES_TRUSTED",
        "TRUST_ANCHORS",
        "NETWORK_SECURITY_DOMAIN",
        "CLEAR_TEXT_BLOCKED_DOMAIN",
        "SYSTEM_CERTIFICATES_TRUSTED",
    ]:
        summary["network_config_issues"] += 1

    classification = normalize_classification(finding.get("classification", "A_VERIFIER"))

    if classification == "FAUX_POSITIF":
        summary["false_positives"] += 1
    elif classification == "VRAI_ENDPOINT":
        summary["confirmed"] += 1
    else:
        summary["to_verify"] += 1


def build_report_schema(
    apk_name: str,
    endpoint_findings: List[Dict[str, Any]],
    manifest_findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    summary = empty_summary()

    all_findings: List[Dict[str, Any]] = []

    for finding in endpoint_findings:
        normalized = normalize_finding(finding, "endpoint_scanner")
        all_findings.append(normalized)
        update_summary_with_finding(summary, normalized)

    for finding in manifest_findings:
        normalized = normalize_finding(finding, "manifest_analyzer")
        all_findings.append(normalized)
        update_summary_with_finding(summary, normalized)

    return {
        "schema_version": "1.0",
        "apk_name": apk_name,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": summary,
        "findings": all_findings,
        "top_10_risks": [],
        "recommendations": [],
    }