import json
import os
import re
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_PATTERNS_PATH = BASE_DIR / "rules" / "endpoint_patterns.json"


Finding = Dict[str, Any]


def load_patterns(patterns_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Charge les règles de détection depuis endpoint_patterns.json.
    """
    path = Path(patterns_path) if patterns_path else DEFAULT_PATTERNS_PATH

    if not path.exists():
        raise FileNotFoundError(f"Fichier de règles introuvable : {path}")

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def compile_regex_list(patterns: List[str]) -> List[Pattern[str]]:
    """
    Compile une liste de regex.
    """
    compiled = []

    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error as error:
            raise ValueError(f"Regex invalide : {pattern} | Erreur : {error}")

    return compiled


def should_scan_file(
    file_path: Path,
    allowed_extensions: List[str],
    ignored_directories: List[str],
    max_file_size_mb: int
) -> bool:
    """
    Vérifie si le fichier doit être analysé.
    """
    path_parts = {part.lower() for part in file_path.parts}

    for ignored_dir in ignored_directories:
        if ignored_dir.lower() in path_parts:
            return False

    if file_path.suffix.lower() not in allowed_extensions:
        return False

    try:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > max_file_size_mb:
            return False
    except OSError:
        return False

    return True


def safe_read_lines(file_path: Path) -> List[str]:
    """
    Lit un fichier sans bloquer si l'encodage est incorrect.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            return file.readlines()
    except Exception:
        return []


def get_relative_path(file_path: Path, root_path: Path) -> str:
    """
    Retourne un chemin lisible dans le rapport.
    """
    try:
        return str(file_path.relative_to(root_path)).replace("\\", "/")
    except ValueError:
        return str(file_path).replace("\\", "/")


def is_private_ip(ip_value: str) -> bool:
    """
    Vérifie si l'adresse IP est privée ou locale.
    """
    ip_without_port = ip_value.split(":")[0]

    try:
        ip = ipaddress.ip_address(ip_without_port)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


def is_valid_ip(ip_value: str) -> bool:
    """
    Vérifie si l'adresse IP est valide.
    """
    ip_without_port = ip_value.split(":")[0]

    try:
        ipaddress.ip_address(ip_without_port)
        return True
    except ValueError:
        return False


def contains_sensitive_keyword(value: str, keywords: List[str]) -> bool:
    """
    Vérifie si une valeur contient un mot sensible.
    """
    value_lower = value.lower()
    return any(keyword.lower() in value_lower for keyword in keywords)


def contains_high_risk_keyword(value: str, keywords: List[str]) -> bool:
    """
    Vérifie si une valeur contient un mot à haut risque.
    """
    value_lower = value.lower()
    return any(keyword.lower() in value_lower for keyword in keywords)


def is_false_positive(value: str, false_positive_domains: List[str]) -> bool:
    """
    Détecte les faux positifs fréquents.
    """
    value_lower = value.lower()

    false_positive_words = [
        "your_url",
        "your-api",
        "your_api",
        "your-domain",
        "placeholder",
        "sample",
        "demo",
        "test-url",
        "dummy",
        "changeme"
    ]

    if any(domain.lower() in value_lower for domain in false_positive_domains):
        return True

    if any(word in value_lower for word in false_positive_words):
        return True

    return False


def get_classification(value: str, false_positive_domains: List[str]) -> str:
    """
    Classe le résultat : vrai endpoint, faux positif ou à vérifier.
    """
    if is_false_positive(value, false_positive_domains):
        return "FAUX_POSITIF"

    return "A_VERIFIER"


def get_risk_analysis(
    finding_type: str,
    value: str,
    patterns_data: Dict[str, Any]
) -> Dict[str, str]:
    """
    Ajoute la gravité, le risque et la recommandation.
    """
    value_lower = value.lower()

    sensitive_keywords = patterns_data.get("sensitive_keywords", [])
    high_risk_keywords = patterns_data.get("high_risk_keywords", [])
    false_positive_domains = patterns_data.get("false_positive_domains", [])
    cloud_domains = patterns_data.get("cloud_domains", [])

    classification = get_classification(value, false_positive_domains)

    if classification == "FAUX_POSITIF":
        return {
            "severity": "LOW",
            "classification": "FAUX_POSITIF",
            "risk": "URL ou domaine probablement utilisé pour documentation, exemple ou configuration standard.",
            "recommendation": "Vérifier rapidement, mais ce résultat n’est généralement pas critique."
        }

    has_sensitive = contains_sensitive_keyword(value, sensitive_keywords)
    has_high_risk = contains_high_risk_keyword(value, high_risk_keywords)

    if finding_type == "URL":
        if value_lower.startswith("http://") and has_high_risk:
            return {
                "severity": "CRITICAL",
                "classification": "VRAI_ENDPOINT",
                "risk": "Endpoint sensible exposé via HTTP non chiffré.",
                "recommendation": "Remplacer HTTP par HTTPS, éviter les données sensibles dans l’URL et protéger l’endpoint côté serveur."
            }

        if value_lower.startswith("http://"):
            return {
                "severity": "HIGH",
                "classification": "VRAI_ENDPOINT",
                "risk": "Communication HTTP non chiffrée détectée.",
                "recommendation": "Utiliser HTTPS et désactiver le trafic en clair dans la configuration Android."
            }

        if value_lower.startswith("ws://"):
            return {
                "severity": "HIGH",
                "classification": "VRAI_ENDPOINT",
                "risk": "WebSocket non sécurisé détecté.",
                "recommendation": "Remplacer ws:// par wss:// afin de chiffrer les communications temps réel."
            }

        if has_sensitive:
            return {
                "severity": "MEDIUM",
                "classification": "VRAI_ENDPOINT",
                "risk": "Endpoint sensible détecté dans une URL.",
                "recommendation": "Vérifier les contrôles d’authentification et éviter d’exposer des informations sensibles côté client."
            }

        return {
            "severity": "LOW",
            "classification": "A_VERIFIER",
            "risk": "URL détectée dans l’application.",
            "recommendation": "Vérifier si cette URL doit être exposée dans l’APK."
        }

    if finding_type == "IP_ADDRESS":
        if is_private_ip(value):
            return {
                "severity": "HIGH",
                "classification": "VRAI_ENDPOINT",
                "risk": "Adresse IP privée ou locale codée en dur.",
                "recommendation": "Éviter les IP hardcodées et utiliser un nom de domaine ou une configuration sécurisée."
            }

        return {
            "severity": "MEDIUM",
            "classification": "A_VERIFIER",
            "risk": "Adresse IP publique détectée dans l’application.",
            "recommendation": "Vérifier si cette IP correspond à un serveur légitime et éviter l’exposition directe de l’infrastructure."
        }

    if finding_type == "DOMAIN":
        if any(domain in value_lower for domain in cloud_domains):
            return {
                "severity": "MEDIUM",
                "classification": "A_VERIFIER",
                "risk": "Domaine cloud ou service externe détecté.",
                "recommendation": "Vérifier les règles d’accès, les permissions et les restrictions associées à ce service."
            }

        if has_sensitive:
            return {
                "severity": "MEDIUM",
                "classification": "A_VERIFIER",
                "risk": "Domaine contenant un contexte potentiellement sensible.",
                "recommendation": "Vérifier si ce domaine correspond à un endpoint de production ou de test."
            }

        return {
            "severity": "LOW",
            "classification": "A_VERIFIER",
            "risk": "Domaine détecté dans l’application.",
            "recommendation": "Vérifier si ce domaine est nécessaire et s’il ne révèle pas d’environnement interne."
        }

    if finding_type == "API_PATH":
        if has_high_risk:
            return {
                "severity": "HIGH",
                "classification": "VRAI_ENDPOINT",
                "risk": "Endpoint API sensible détecté.",
                "recommendation": "Protéger cet endpoint avec authentification, contrôle d’accès et validation côté serveur."
            }

        return {
            "severity": "MEDIUM",
            "classification": "A_VERIFIER",
            "risk": "Chemin API détecté.",
            "recommendation": "Vérifier si ce chemin révèle une fonctionnalité sensible de l’application."
        }

    return {
        "severity": "LOW",
        "classification": "A_VERIFIER",
        "risk": "Information réseau détectée.",
        "recommendation": "Vérifier la pertinence de cette information dans l’APK."
    }


def clean_value(value: str) -> str:
    """
    Nettoie une valeur détectée.
    """
    return value.strip().strip(".,;)]}'\"")


def build_finding(
    finding_type: str,
    value: str,
    file_path: Path,
    root_path: Path,
    line_number: int,
    context: str,
    patterns_data: Dict[str, Any]
) -> Finding:
    """
    Construit un finding complet.
    """
    value = clean_value(value)

    risk_data = get_risk_analysis(
        finding_type=finding_type,
        value=value,
        patterns_data=patterns_data
    )

    return {
        "type": finding_type,
        "value": value,
        "file": get_relative_path(file_path, root_path),
        "line": line_number,
        "context": context.strip(),
        "severity": risk_data["severity"],
        "classification": risk_data["classification"],
        "risk": risk_data["risk"],
        "recommendation": risk_data["recommendation"]
    }


def scan_line(
    line: str,
    file_path: Path,
    root_path: Path,
    line_number: int,
    compiled_patterns: Dict[str, List[Pattern[str]]],
    patterns_data: Dict[str, Any]
) -> List[Finding]:
    """
    Analyse une seule ligne.
    """
    findings: List[Finding] = []
    seen: set[Tuple[str, str, int]] = set()

    url_spans: List[Tuple[int, int]] = []

    for pattern in compiled_patterns["url_patterns"]:
        for match in pattern.finditer(line):
            value = clean_value(match.group(0))
            url_spans.append(match.span())

            key = ("URL", value, line_number)
            if key in seen:
                continue

            seen.add(key)
            findings.append(
                build_finding(
                    finding_type="URL",
                    value=value,
                    file_path=file_path,
                    root_path=root_path,
                    line_number=line_number,
                    context=line,
                    patterns_data=patterns_data
                )
            )

    for pattern in compiled_patterns["ip_patterns"]:
        for match in pattern.finditer(line):
            value = clean_value(match.group(0))

            if not is_valid_ip(value):
                continue

            key = ("IP_ADDRESS", value, line_number)
            if key in seen:
                continue

            seen.add(key)
            findings.append(
                build_finding(
                    finding_type="IP_ADDRESS",
                    value=value,
                    file_path=file_path,
                    root_path=root_path,
                    line_number=line_number,
                    context=line,
                    patterns_data=patterns_data
                )
            )

    for pattern in compiled_patterns["domain_patterns"]:
        for match in pattern.finditer(line):
            value = clean_value(match.group(0))

            domain_inside_url = False
            for start, end in url_spans:
                if start <= match.start() and match.end() <= end:
                    domain_inside_url = True
                    break

            if domain_inside_url:
                continue

            key = ("DOMAIN", value, line_number)
            if key in seen:
                continue

            seen.add(key)
            findings.append(
                build_finding(
                    finding_type="DOMAIN",
                    value=value,
                    file_path=file_path,
                    root_path=root_path,
                    line_number=line_number,
                    context=line,
                    patterns_data=patterns_data
                )
            )

    for pattern in compiled_patterns["api_path_patterns"]:
        for match in pattern.finditer(line):
            value = match.group(1) if match.lastindex else match.group(0)
            value = clean_value(value)

            key = ("API_PATH", value, line_number)
            if key in seen:
                continue

            seen.add(key)
            findings.append(
                build_finding(
                    finding_type="API_PATH",
                    value=value,
                    file_path=file_path,
                    root_path=root_path,
                    line_number=line_number,
                    context=line,
                    patterns_data=patterns_data
                )
            )

    return findings


def build_summary(findings: List[Finding]) -> Dict[str, int]:
    """
    Génère un résumé des résultats.
    """
    summary = {
        "total_findings": len(findings),
        "urls": 0,
        "ips": 0,
        "domains": 0,
        "api_paths": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "false_positives": 0,
        "to_verify": 0,
        "confirmed_endpoints": 0
    }

    for finding in findings:
        finding_type = finding.get("type", "")
        severity = finding.get("severity", "").upper()
        classification = finding.get("classification", "")

        if finding_type == "URL":
            summary["urls"] += 1
        elif finding_type == "IP_ADDRESS":
            summary["ips"] += 1
        elif finding_type == "DOMAIN":
            summary["domains"] += 1
        elif finding_type == "API_PATH":
            summary["api_paths"] += 1

        if severity == "CRITICAL":
            summary["critical"] += 1
        elif severity == "HIGH":
            summary["high"] += 1
        elif severity == "MEDIUM":
            summary["medium"] += 1
        elif severity == "LOW":
            summary["low"] += 1

        if classification == "FAUX_POSITIF":
            summary["false_positives"] += 1
        elif classification == "A_VERIFIER":
            summary["to_verify"] += 1
        elif classification == "VRAI_ENDPOINT":
            summary["confirmed_endpoints"] += 1

    return summary


def sort_findings_by_risk(findings: List[Finding]) -> List[Finding]:
    """
    Trie les findings du plus critique au moins critique.
    """
    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3
    }

    return sorted(
        findings,
        key=lambda item: severity_order.get(item.get("severity", "LOW"), 4)
    )


def scan_endpoints(
    decompiled_path: str,
    patterns_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Fonction principale utilisée par le backend.

    Entrée :
        - chemin du dossier APK décompilé

    Sortie :
        - JSON avec résumé + findings
    """
    root_path = Path(decompiled_path)

    if not root_path.exists():
        raise FileNotFoundError(f"Dossier décompilé introuvable : {root_path}")

    patterns_data = load_patterns(patterns_path)

    allowed_extensions = patterns_data.get("allowed_extensions", [])
    ignored_directories = patterns_data.get("ignored_directories", [])
    max_file_size_mb = int(patterns_data.get("max_file_size_mb", 5))

    compiled_patterns = {
        "url_patterns": compile_regex_list(patterns_data.get("url_patterns", [])),
        "ip_patterns": compile_regex_list(patterns_data.get("ip_patterns", [])),
        "domain_patterns": compile_regex_list(patterns_data.get("domain_patterns", [])),
        "api_path_patterns": compile_regex_list(patterns_data.get("api_path_patterns", []))
    }

    findings: List[Finding] = []

    for current_root, _, files in os.walk(root_path):
        for file_name in files:
            file_path = Path(current_root) / file_name

            if not should_scan_file(
                file_path=file_path,
                allowed_extensions=allowed_extensions,
                ignored_directories=ignored_directories,
                max_file_size_mb=max_file_size_mb
            ):
                continue

            lines = safe_read_lines(file_path)

            for line_number, line in enumerate(lines, start=1):
                line_findings = scan_line(
                    line=line,
                    file_path=file_path,
                    root_path=root_path,
                    line_number=line_number,
                    compiled_patterns=compiled_patterns,
                    patterns_data=patterns_data
                )

                findings.extend(line_findings)

    findings = sort_findings_by_risk(findings)

    return {
        "module": "network_static_endpoint_scanner",
        "status": "success",
        "scanned_path": str(root_path).replace("\\", "/"),
        "summary": build_summary(findings),
        "findings": findings,
        "top_10_risks": findings[:10]
    }


def save_scan_result(result: Dict[str, Any], output_path: str) -> None:
    """
    Sauvegarde le résultat dans un fichier JSON.
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with open(output, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4, ensure_ascii=False)


if __name__ == "__main__":
    test_path = "extracted/app_decompiled"

    result = scan_endpoints(test_path)

    print(json.dumps(result, indent=4, ensure_ascii=False))

    save_scan_result(
        result=result,
        output_path="reports/endpoint_scan_result.json"
    )