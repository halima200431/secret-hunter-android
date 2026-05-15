import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


Finding = Dict[str, Any]


NETWORK_PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
]

DANGEROUS_CONFIG_PATTERNS = [
    "usesCleartextTraffic",
    "cleartextTrafficPermitted",
    "debug-overrides",
    "certificates",
]


def safe_read_lines(file_path: Path) -> List[str]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            return file.readlines()
    except Exception:
        return []


def get_relative_path(file_path: Path, root_path: Path) -> str:
    try:
        return str(file_path.relative_to(root_path)).replace("\\", "/")
    except ValueError:
        return str(file_path).replace("\\", "/")


def build_finding(
    finding_type: str,
    value: str,
    file_path: Path,
    root_path: Path,
    line_number: int,
    context: str,
    severity: str,
    risk: str,
    recommendation: str,
    classification: str = "A_VERIFIER",
) -> Finding:
    return {
        "type": finding_type,
        "value": value,
        "file": get_relative_path(file_path, root_path),
        "line": line_number,
        "context": context.strip(),
        "severity": severity,
        "classification": classification,
        "risk": risk,
        "recommendation": recommendation,
    }


def find_android_manifest(decompiled_path: Path) -> Optional[Path]:
    direct_manifest = decompiled_path / "AndroidManifest.xml"

    if direct_manifest.exists():
        return direct_manifest

    for root, _, files in os.walk(decompiled_path):
        for file_name in files:
            if file_name == "AndroidManifest.xml":
                return Path(root) / file_name

    return None


def find_network_security_configs(decompiled_path: Path) -> List[Path]:
    configs = []

    possible_paths = [
        decompiled_path / "res" / "xml" / "network_security_config.xml",
        decompiled_path / "resources" / "res" / "xml" / "network_security_config.xml",
    ]

    for path in possible_paths:
        if path.exists():
            configs.append(path)

    for root, _, files in os.walk(decompiled_path):
        for file_name in files:
            lower_name = file_name.lower()
            if "network_security" in lower_name and lower_name.endswith(".xml"):
                path = Path(root) / file_name
                if path not in configs:
                    configs.append(path)

    return configs


def extract_network_security_config_reference(line: str) -> Optional[str]:
    match = re.search(r'android:networkSecurityConfig\s*=\s*["\']([^"\']+)["\']', line)
    if match:
        return match.group(1)

    return None


def analyze_manifest_file(manifest_path: Path, root_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    lines = safe_read_lines(manifest_path)

    for line_number, line in enumerate(lines, start=1):
        line_stripped = line.strip()
        line_lower = line.lower()

        for permission in NETWORK_PERMISSIONS:
            if permission.lower() in line_lower:
                severity = "LOW"
                risk = f"Permission réseau détectée : {permission}."
                recommendation = "Vérifier si cette permission est nécessaire au fonctionnement de l’application."

                if permission == "android.permission.INTERNET":
                    severity = "MEDIUM"
                    risk = "L’application possède la permission INTERNET et peut communiquer avec des serveurs externes."
                    recommendation = "Vérifier que toutes les communications réseau sont sécurisées avec HTTPS."

                findings.append(
                    build_finding(
                        finding_type="NETWORK_PERMISSION",
                        value=permission,
                        file_path=manifest_path,
                        root_path=root_path,
                        line_number=line_number,
                        context=line_stripped,
                        severity=severity,
                        classification="VRAI_ENDPOINT",
                        risk=risk,
                        recommendation=recommendation,
                    )
                )

        if "android:usescleartexttraffic" in line_lower:
            if "true" in line_lower:
                findings.append(
                    build_finding(
                        finding_type="CLEAR_TEXT_TRAFFIC",
                        value='android:usesCleartextTraffic="true"',
                        file_path=manifest_path,
                        root_path=root_path,
                        line_number=line_number,
                        context=line_stripped,
                        severity="HIGH",
                        classification="VRAI_ENDPOINT",
                        risk="L’application autorise le trafic HTTP non chiffré.",
                        recommendation="Mettre android:usesCleartextTraffic à false et forcer HTTPS.",
                    )
                )
            elif "false" in line_lower:
                findings.append(
                    build_finding(
                        finding_type="CLEAR_TEXT_TRAFFIC_DISABLED",
                        value='android:usesCleartextTraffic="false"',
                        file_path=manifest_path,
                        root_path=root_path,
                        line_number=line_number,
                        context=line_stripped,
                        severity="LOW",
                        classification="A_VERIFIER",
                        risk="Le trafic clair semble désactivé au niveau du Manifest.",
                        recommendation="Conserver cette configuration et vérifier aussi network_security_config.xml.",
                    )
                )

        network_config_ref = extract_network_security_config_reference(line)
        if network_config_ref:
            findings.append(
                build_finding(
                    finding_type="NETWORK_SECURITY_CONFIG_REFERENCE",
                    value=network_config_ref,
                    file_path=manifest_path,
                    root_path=root_path,
                    line_number=line_number,
                    context=line_stripped,
                    severity="MEDIUM",
                    classification="A_VERIFIER",
                    risk="L’application utilise un fichier network_security_config.",
                    recommendation="Analyser ce fichier pour vérifier les règles de cleartext, certificats utilisateur et debug-overrides.",
                )
            )

        if "android:debuggable" in line_lower and "true" in line_lower:
            findings.append(
                build_finding(
                    finding_type="DEBUGGABLE_APP",
                    value='android:debuggable="true"',
                    file_path=manifest_path,
                    root_path=root_path,
                    line_number=line_number,
                    context=line_stripped,
                    severity="HIGH",
                    classification="VRAI_ENDPOINT",
                    risk="L’application est marquée comme debuggable.",
                    recommendation="Désactiver android:debuggable en production.",
                )
            )

    return findings


def extract_domain_from_line(line: str) -> Optional[str]:
    match = re.search(r"<domain[^>]*>([^<]+)</domain>", line, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    return None


def analyze_network_security_config_file(config_path: Path, root_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    lines = safe_read_lines(config_path)

    current_domain = None

    for line_number, line in enumerate(lines, start=1):
        line_stripped = line.strip()
        line_lower = line.lower()

        domain = extract_domain_from_line(line)
        if domain:
            current_domain = domain
            findings.append(
                build_finding(
                    finding_type="NETWORK_SECURITY_DOMAIN",
                    value=domain,
                    file_path=config_path,
                    root_path=root_path,
                    line_number=line_number,
                    context=line_stripped,
                    severity="LOW",
                    classification="A_VERIFIER",
                    risk="Domaine déclaré dans network_security_config.xml.",
                    recommendation="Vérifier les règles de sécurité appliquées à ce domaine.",
                )
            )

        if "cleartexttrafficpermitted" in line_lower:
            if "true" in line_lower:
                value = "cleartextTrafficPermitted=true"
                if current_domain:
                    value = f"cleartextTrafficPermitted=true for {current_domain}"

                findings.append(
                    build_finding(
                        finding_type="CLEAR_TEXT_PERMITTED_DOMAIN",
                        value=value,
                        file_path=config_path,
                        root_path=root_path,
                        line_number=line_number,
                        context=line_stripped,
                        severity="HIGH",
                        classification="VRAI_ENDPOINT",
                        risk="Le fichier network_security_config autorise le trafic HTTP non chiffré.",
                        recommendation="Mettre cleartextTrafficPermitted à false et utiliser HTTPS pour tous les domaines.",
                    )
                )
            elif "false" in line_lower:
                findings.append(
                    build_finding(
                        finding_type="CLEAR_TEXT_BLOCKED_DOMAIN",
                        value="cleartextTrafficPermitted=false",
                        file_path=config_path,
                        root_path=root_path,
                        line_number=line_number,
                        context=line_stripped,
                        severity="LOW",
                        classification="A_VERIFIER",
                        risk="Le fichier network_security_config bloque le trafic HTTP clair pour certains domaines.",
                        recommendation="Conserver cette règle et vérifier qu’elle couvre tous les domaines sensibles.",
                    )
                )

        if "<debug-overrides" in line_lower or "</debug-overrides" in line_lower:
            findings.append(
                build_finding(
                    finding_type="DEBUG_OVERRIDES",
                    value="debug-overrides",
                    file_path=config_path,
                    root_path=root_path,
                    line_number=line_number,
                    context=line_stripped,
                    severity="HIGH",
                    classification="A_VERIFIER",
                    risk="Présence de debug-overrides dans network_security_config.xml.",
                    recommendation="Vérifier que cette configuration n’est pas active en production.",
                )
            )

        if 'certificates src="user"' in line_lower or "certificates src='user'" in line_lower:
            findings.append(
                build_finding(
                    finding_type="USER_CERTIFICATES_TRUSTED",
                    value='certificates src="user"',
                    file_path=config_path,
                    root_path=root_path,
                    line_number=line_number,
                    context=line_stripped,
                    severity="HIGH",
                    classification="VRAI_ENDPOINT",
                    risk="L’application fait confiance aux certificats installés par l’utilisateur.",
                    recommendation="Éviter de faire confiance aux certificats utilisateur en production sauf besoin justifié.",
                )
            )

        if 'certificates src="system"' in line_lower or "certificates src='system'" in line_lower:
            findings.append(
                build_finding(
                    finding_type="SYSTEM_CERTIFICATES_TRUSTED",
                    value='certificates src="system"',
                    file_path=config_path,
                    root_path=root_path,
                    line_number=line_number,
                    context=line_stripped,
                    severity="LOW",
                    classification="A_VERIFIER",
                    risk="L’application utilise les certificats système.",
                    recommendation="Configuration généralement normale, à vérifier selon le contexte de l’application.",
                )
            )

        if "<trust-anchors" in line_lower or "</trust-anchors" in line_lower:
            findings.append(
                build_finding(
                    finding_type="TRUST_ANCHORS",
                    value="trust-anchors",
                    file_path=config_path,
                    root_path=root_path,
                    line_number=line_number,
                    context=line_stripped,
                    severity="MEDIUM",
                    classification="A_VERIFIER",
                    risk="Configuration explicite des autorités de confiance TLS.",
                    recommendation="Vérifier que seules les autorités nécessaires sont autorisées.",
                )
            )

    return findings


def build_manifest_summary(findings: List[Finding]) -> Dict[str, int]:
    summary = {
        "total_findings": len(findings),
        "network_permissions": 0,
        "manifest_issues": 0,
        "network_security_config_issues": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for finding in findings:
        finding_type = finding.get("type", "")
        severity = finding.get("severity", "").upper()

        if finding_type == "NETWORK_PERMISSION":
            summary["network_permissions"] += 1

        if finding_type in [
            "CLEAR_TEXT_TRAFFIC",
            "DEBUGGABLE_APP",
            "NETWORK_SECURITY_CONFIG_REFERENCE",
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
            summary["network_security_config_issues"] += 1

        if severity == "CRITICAL":
            summary["critical"] += 1
        elif severity == "HIGH":
            summary["high"] += 1
        elif severity == "MEDIUM":
            summary["medium"] += 1
        elif severity == "LOW":
            summary["low"] += 1

    return summary


def sort_findings_by_severity(findings: List[Finding]) -> List[Finding]:
    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
    }

    return sorted(
        findings,
        key=lambda item: severity_order.get(item.get("severity", "LOW"), 4),
    )


def analyze_manifest(decompiled_path: str) -> Dict[str, Any]:
    root_path = Path(decompiled_path)

    if not root_path.exists():
        raise FileNotFoundError(f"Dossier décompilé introuvable : {root_path}")

    findings: List[Finding] = []

    manifest_path = find_android_manifest(root_path)
    network_security_configs = find_network_security_configs(root_path)

    if manifest_path:
        findings.extend(analyze_manifest_file(manifest_path, root_path))
    else:
        findings.append(
            {
                "type": "ANDROID_MANIFEST_NOT_FOUND",
                "value": "AndroidManifest.xml",
                "file": "",
                "line": 0,
                "context": "",
                "severity": "MEDIUM",
                "classification": "A_VERIFIER",
                "risk": "AndroidManifest.xml introuvable dans le dossier décompilé.",
                "recommendation": "Vérifier si la décompilation APK a été correctement réalisée.",
            }
        )

    for config_path in network_security_configs:
        findings.extend(analyze_network_security_config_file(config_path, root_path))

    findings = sort_findings_by_severity(findings)

    return {
        "module": "manifest_network_security_analyzer",
        "status": "success",
        "scanned_path": str(root_path).replace("\\", "/"),
        "manifest_found": manifest_path is not None,
        "network_security_config_files": [
            get_relative_path(path, root_path) for path in network_security_configs
        ],
        "summary": build_manifest_summary(findings),
        "findings": findings,
        "top_10_risks": findings[:10],
    }


def save_manifest_result(result: Dict[str, Any], output_path: str) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    test_path = "extracted/app_decompiled"

    result = analyze_manifest(test_path)

    print(json.dumps(result, indent=4, ensure_ascii=False))

    save_manifest_result(
        result=result,
        output_path="reports/manifest_scan_result.json",
    )