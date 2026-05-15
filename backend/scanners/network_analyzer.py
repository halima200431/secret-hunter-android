import ipaddress
import re
from typing import Any, Dict, List
from urllib.parse import urlparse


Finding = Dict[str, Any]


SENSITIVE_KEYWORDS = [
    "login",
    "auth",
    "token",
    "admin",
    "password",
    "passwd",
    "pwd",
    "secret",
    "debug",
    "payment",
    "private",
    "session",
    "otp",
    "verify",
    "reset",
    "upload",
    "download",
    "profile",
    "account",
    "apikey",
    "api_key",
]

HIGH_RISK_KEYWORDS = [
    "login",
    "auth",
    "admin",
    "debug",
    "token",
    "password",
    "passwd",
    "pwd",
    "secret",
    "payment",
    "private",
    "otp",
    "reset",
]

FALSE_POSITIVE_DOMAINS = [
    "schemas.android.com",
    "developer.android.com",
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
]

CLOUD_DOMAINS = [
    "firebaseio.com",
    "googleapis.com",
    "amazonaws.com",
    "azurewebsites.net",
    "cloudfront.net",
    "herokuapp.com",
    "render.com",
    "vercel.app",
    "netlify.app",
    "ngrok.io",
]


def contains_keyword(value: str, keywords: List[str]) -> bool:
    value_lower = value.lower()
    return any(keyword.lower() in value_lower for keyword in keywords)


def is_false_positive(value: str) -> bool:
    value_lower = value.lower()

    false_positive_words = [
        "sample",
        "demo",
        "dummy",
        "placeholder",
        "changeme",
        "your_url",
        "your-api",
        "your_api",
        "your-domain",
        "test-url",
    ]

    if any(domain in value_lower for domain in FALSE_POSITIVE_DOMAINS):
        return True

    if any(word in value_lower for word in false_positive_words):
        return True

    return False


def remove_port_from_ip(value: str) -> str:
    if ":" in value:
        return value.split(":")[0]
    return value


def is_valid_ip(value: str) -> bool:
    ip_value = remove_port_from_ip(value)

    try:
        ipaddress.ip_address(ip_value)
        return True
    except ValueError:
        return False


def is_private_or_local_ip(value: str) -> bool:
    ip_value = remove_port_from_ip(value)

    try:
        ip = ipaddress.ip_address(ip_value)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def extract_host_from_url(value: str) -> str:
    try:
        parsed = urlparse(value)
        return parsed.hostname or ""
    except Exception:
        return ""


def url_contains_query_secret(value: str) -> bool:
    value_lower = value.lower()

    secret_query_patterns = [
        r"[?&]token=",
        r"[?&]access_token=",
        r"[?&]api_key=",
        r"[?&]apikey=",
        r"[?&]key=",
        r"[?&]secret=",
        r"[?&]password=",
        r"[?&]pwd=",
    ]

    return any(re.search(pattern, value_lower) for pattern in secret_query_patterns)


def detect_environment(value: str) -> str:
    value_lower = value.lower()

    if any(word in value_lower for word in ["dev", "debug", "test", "staging", "qa"]):
        return "TEST_OR_STAGING"

    if any(word in value_lower for word in ["prod", "production", "api"]):
        return "PRODUCTION_OR_API"

    return "UNKNOWN"


def classify_endpoint_type(value: str) -> str:
    value_lower = value.lower()

    if "login" in value_lower or "auth" in value_lower:
        return "AUTHENTICATION_ENDPOINT"

    if "admin" in value_lower:
        return "ADMIN_ENDPOINT"

    if "token" in value_lower:
        return "TOKEN_ENDPOINT"

    if "payment" in value_lower:
        return "PAYMENT_ENDPOINT"

    if "upload" in value_lower or "download" in value_lower:
        return "FILE_TRANSFER_ENDPOINT"

    if "debug" in value_lower:
        return "DEBUG_ENDPOINT"

    if "/api" in value_lower or "/v1" in value_lower or "/v2" in value_lower:
        return "API_ENDPOINT"

    return "NETWORK_ENDPOINT"


def analyze_url(value: str) -> Dict[str, str]:
    value_lower = value.lower()
    host = extract_host_from_url(value)
    has_sensitive = contains_keyword(value, SENSITIVE_KEYWORDS)
    has_high_risk = contains_keyword(value, HIGH_RISK_KEYWORDS)

    if is_false_positive(value):
        return {
            "severity": "LOW",
            "classification": "FAUX_POSITIF",
            "category": "DOCUMENTATION_OR_EXAMPLE",
            "risk": "URL probablement utilisée comme exemple, documentation ou configuration standard.",
            "recommendation": "Vérifier rapidement ce résultat, mais il n’est généralement pas critique.",
        }

    if url_contains_query_secret(value):
        return {
            "severity": "CRITICAL",
            "classification": "VRAI_ENDPOINT",
            "category": "SECRET_IN_URL",
            "risk": "La chaîne URL semble contenir un token, une clé API ou un mot de passe dans les paramètres.",
            "recommendation": "Ne jamais mettre de secrets dans l’URL. Révoquer le secret exposé et utiliser un mécanisme sécurisé côté serveur.",
        }

    if value_lower.startswith("http://") and has_high_risk:
        return {
            "severity": "CRITICAL",
            "classification": "VRAI_ENDPOINT",
            "category": classify_endpoint_type(value),
            "risk": "Endpoint sensible exposé via HTTP non chiffré.",
            "recommendation": "Remplacer HTTP par HTTPS, activer TLS et protéger cet endpoint côté serveur.",
        }

    if value_lower.startswith("http://"):
        return {
            "severity": "HIGH",
            "classification": "VRAI_ENDPOINT",
            "category": "INSECURE_HTTP_ENDPOINT",
            "risk": "Communication HTTP non chiffrée détectée.",
            "recommendation": "Remplacer HTTP par HTTPS et désactiver le trafic en clair dans Android.",
        }

    if value_lower.startswith("ws://"):
        return {
            "severity": "HIGH",
            "classification": "VRAI_ENDPOINT",
            "category": "INSECURE_WEBSOCKET",
            "risk": "WebSocket non sécurisé détecté.",
            "recommendation": "Remplacer ws:// par wss:// afin de chiffrer les communications temps réel.",
        }

    if host and is_private_or_local_ip(host):
        return {
            "severity": "HIGH",
            "classification": "VRAI_ENDPOINT",
            "category": "PRIVATE_IP_ENDPOINT",
            "risk": "URL contenant une adresse IP privée ou locale codée en dur.",
            "recommendation": "Éviter les IP hardcodées et utiliser un domaine ou une configuration d’environnement sécurisée.",
        }

    if has_sensitive:
        return {
            "severity": "MEDIUM",
            "classification": "VRAI_ENDPOINT",
            "category": classify_endpoint_type(value),
            "risk": "URL liée à une fonctionnalité sensible détectée.",
            "recommendation": "Vérifier l’authentification, l’autorisation et les contrôles côté serveur.",
        }

    if any(domain in value_lower for domain in CLOUD_DOMAINS):
        return {
            "severity": "MEDIUM",
            "classification": "A_VERIFIER",
            "category": "CLOUD_SERVICE_ENDPOINT",
            "risk": "Service cloud ou externe détecté dans l’application.",
            "recommendation": "Vérifier les restrictions d’accès et les permissions associées à ce service.",
        }

    return {
        "severity": "LOW",
        "classification": "A_VERIFIER",
        "category": "URL",
        "risk": "URL détectée dans l’application.",
        "recommendation": "Vérifier si cette URL doit être exposée dans l’APK.",
    }


def analyze_ip(value: str) -> Dict[str, str]:
    if not is_valid_ip(value):
        return {
            "severity": "LOW",
            "classification": "FAUX_POSITIF",
            "category": "INVALID_IP",
            "risk": "La valeur ressemble à une IP mais n’est pas valide.",
            "recommendation": "Ignorer ce résultat ou vérifier manuellement.",
        }

    if is_private_or_local_ip(value):
        return {
            "severity": "HIGH",
            "classification": "VRAI_ENDPOINT",
            "category": "PRIVATE_IP_HARDCODED",
            "risk": "Adresse IP privée ou locale codée en dur.",
            "recommendation": "Éviter les IP hardcodées et utiliser un nom de domaine ou une configuration sécurisée.",
        }

    return {
        "severity": "MEDIUM",
        "classification": "A_VERIFIER",
        "category": "PUBLIC_IP_HARDCODED",
        "risk": "Adresse IP publique détectée dans l’application.",
        "recommendation": "Vérifier si cette IP correspond à un serveur légitime et éviter l’exposition directe de l’infrastructure.",
    }


def analyze_domain(value: str) -> Dict[str, str]:
    value_lower = value.lower()

    if is_false_positive(value):
        return {
            "severity": "LOW",
            "classification": "FAUX_POSITIF",
            "category": "DOCUMENTATION_OR_EXAMPLE",
            "risk": "Domaine probablement utilisé pour documentation ou exemple.",
            "recommendation": "Vérifier rapidement, mais ce résultat n’est généralement pas critique.",
        }

    if any(domain in value_lower for domain in CLOUD_DOMAINS):
        return {
            "severity": "MEDIUM",
            "classification": "A_VERIFIER",
            "category": "CLOUD_DOMAIN",
            "risk": "Domaine cloud ou service externe détecté.",
            "recommendation": "Vérifier les règles d’accès, les restrictions et les permissions du service.",
        }

    if contains_keyword(value, SENSITIVE_KEYWORDS):
        return {
            "severity": "MEDIUM",
            "classification": "A_VERIFIER",
            "category": "SENSITIVE_DOMAIN",
            "risk": "Domaine contenant un contexte potentiellement sensible.",
            "recommendation": "Vérifier si ce domaine correspond à un environnement de production, test ou administration.",
        }

    return {
        "severity": "LOW",
        "classification": "A_VERIFIER",
        "category": "DOMAIN",
        "risk": "Domaine détecté dans l’application.",
        "recommendation": "Vérifier si ce domaine est nécessaire et s’il ne révèle pas une infrastructure interne.",
    }


def analyze_api_path(value: str) -> Dict[str, str]:
    if is_false_positive(value):
        return {
            "severity": "LOW",
            "classification": "FAUX_POSITIF",
            "category": "DOCUMENTATION_OR_EXAMPLE",
            "risk": "Chemin probablement utilisé comme exemple ou documentation.",
            "recommendation": "Vérifier rapidement, mais ce résultat n’est généralement pas critique.",
        }

    if contains_keyword(value, HIGH_RISK_KEYWORDS):
        return {
            "severity": "HIGH",
            "classification": "VRAI_ENDPOINT",
            "category": classify_endpoint_type(value),
            "risk": "Endpoint API sensible détecté.",
            "recommendation": "Protéger cet endpoint avec authentification, contrôle d’accès, validation côté serveur et journalisation.",
        }

    if contains_keyword(value, SENSITIVE_KEYWORDS):
        return {
            "severity": "MEDIUM",
            "classification": "A_VERIFIER",
            "category": classify_endpoint_type(value),
            "risk": "Chemin API potentiellement sensible détecté.",
            "recommendation": "Vérifier si ce chemin expose une fonctionnalité sensible.",
        }

    return {
        "severity": "MEDIUM",
        "classification": "A_VERIFIER",
        "category": "API_PATH",
        "risk": "Chemin API détecté dans le code.",
        "recommendation": "Vérifier si ce chemin révèle une fonctionnalité interne de l’application.",
    }


def analyze_single_finding(finding: Finding) -> Finding:
    finding_type = finding.get("type", "").upper()
    value = str(finding.get("value", ""))

    if finding_type == "URL":
        risk_data = analyze_url(value)
    elif finding_type == "IP_ADDRESS":
        risk_data = analyze_ip(value)
    elif finding_type == "DOMAIN":
        risk_data = analyze_domain(value)
    elif finding_type == "API_PATH":
        risk_data = analyze_api_path(value)
    else:
        risk_data = {
            "severity": "LOW",
            "classification": "A_VERIFIER",
            "category": "NETWORK_INFORMATION",
            "risk": "Information réseau détectée.",
            "recommendation": "Vérifier la pertinence de cette information.",
        }

    enriched_finding = dict(finding)
    enriched_finding.update(risk_data)
    enriched_finding["environment"] = detect_environment(value)

    return enriched_finding


def build_network_summary(findings: List[Finding]) -> Dict[str, int]:
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
        "confirmed_endpoints": 0,
    }

    for finding in findings:
        finding_type = finding.get("type", "").upper()
        severity = finding.get("severity", "").upper()
        classification = finding.get("classification", "").upper()

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


def analyze_network_findings(findings: List[Finding]) -> Dict[str, Any]:
    analyzed_findings = [analyze_single_finding(finding) for finding in findings]
    analyzed_findings = sort_findings_by_severity(analyzed_findings)

    return {
        "module": "network_analyzer",
        "status": "success",
        "summary": build_network_summary(analyzed_findings),
        "findings": analyzed_findings,
        "top_10_risks": analyzed_findings[:10],
    }


def merge_endpoint_scan_with_network_analysis(endpoint_scan_result: Dict[str, Any]) -> Dict[str, Any]:
    findings = endpoint_scan_result.get("findings", [])
    network_result = analyze_network_findings(findings)

    return {
        "module": "network_static_analysis",
        "status": "success",
        "scanned_path": endpoint_scan_result.get("scanned_path", ""),
        "summary": network_result["summary"],
        "findings": network_result["findings"],
        "top_10_risks": network_result["top_10_risks"],
    }


if __name__ == "__main__":
    sample_findings = [
        {
            "type": "URL",
            "value": "http://192.168.1.10:8080/api/login",
            "file": "sources/com/example/LoginActivity.java",
            "line": 5,
            "context": "String url = \"http://192.168.1.10:8080/api/login\";",
        },
        {
            "type": "API_PATH",
            "value": "/admin/debug",
            "file": "sources/com/example/LoginActivity.java",
            "line": 6,
            "context": "String admin = \"/admin/debug\";",
        },
    ]

    result = analyze_network_findings(sample_findings)

    import json
    print(json.dumps(result, indent=4, ensure_ascii=False))