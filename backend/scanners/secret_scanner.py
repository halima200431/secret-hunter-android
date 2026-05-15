"""
backend/scanners/secret_scanner.py
------------------------------------
Module principal de détection des secrets dans les fichiers extraits d'un APK Android.

Ce scanner parcourt récursivement un dossier extrait, applique des expressions
régulières sur les fichiers texte supportés, et retourne une liste structurée
de secrets détectés avec masquage systématique des valeurs sensibles.

Aucun secret complet n'est jamais retourné dans les résultats.
"""

import re
import uuid
from pathlib import Path
from typing import Any

from backend.core.exceptions import ConfigurationError, SecretScanError
from backend.utils.json_utils import read_json_file
from backend.utils.mask_utils import (
    calculate_entropy,
    is_value_too_short,
    mask_secret,
    mask_token,
)

# Chemin par défaut vers le fichier de patterns
DEFAULT_PATTERNS_PATH = Path(__file__).parent.parent / "rules" / "secret_patterns.json"

# Entropie minimale pour qu'une valeur soit considérée comme un secret réel
MINIMUM_ENTROPY = 3.0

# Niveau de confiance de base par type de pattern
CONFIDENCE_BY_TYPE: dict[str, float] = {
    "Google API Key": 0.97,
    "Firebase URL": 0.92,
    "Firebase API Key": 0.88,
    "Bearer Token": 0.93,
    "JWT Token": 0.96,
    "AWS Access Key": 0.98,
    "GitHub Token": 0.97,
    "Generic API Key": 0.75,
    "Password Assignment": 0.85,
    "Client Secret": 0.82,
    "Access Token": 0.78,
    "Refresh Token": 0.78,
    "Private Key Block": 0.99,
    "Authorization Header": 0.94,
    "Slack Token": 0.96,
}

# Risque initial par type de secret
RISK_BY_TYPE: dict[str, str] = {
    "Password": "Critical",
    "Private Key": "Critical",
    "Bearer Token": "Critical",
    "JWT Token": "Critical",
    "API Key": "High",
    "Firebase Key": "High",
    "Access Token": "High",
    "Refresh Token": "High",
    "Client Secret": "High",
    "Generic Secret": "Medium",
}

# Taille maximale d'un fichier à analyser (5 Mo) pour éviter les fichiers binaires massifs
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


def load_secret_patterns(patterns_path: str | Path | None = None) -> dict:
    """
    Charge les patterns de détection depuis le fichier JSON de règles.

    Args:
        patterns_path: Chemin vers le fichier JSON. Utilise le chemin par défaut si None.

    Returns:
        Dictionnaire contenant 'patterns', 'supported_extensions' et 'ignored_keywords'.

    Raises:
        ConfigurationError: Si le fichier est absent ou malformé.
    """
    path = Path(patterns_path) if patterns_path else DEFAULT_PATTERNS_PATH

    if not path.exists():
        raise ConfigurationError(
            f"Fichier de patterns introuvable : {path}. "
            "Vérifiez que backend/rules/secret_patterns.json existe."
        )

    data = read_json_file(path)

    if not data or "patterns" not in data:
        raise ConfigurationError(
            f"Le fichier de patterns est vide ou mal structuré : {path}"
        )

    return data


def is_text_file(file_path: Path) -> bool:
    """
    Vérifie si un fichier est lisible comme texte (non binaire).
    Lit les 512 premiers octets pour détecter les octets nuls caractéristiques
    des fichiers binaires.

    Args:
        file_path: Chemin vers le fichier à tester.

    Returns:
        True si le fichier est lisible comme texte, False sinon.
    """
    try:
        # Vérification de la taille
        if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
            return False

        with open(file_path, "rb") as f:
            sample = f.read(512)

        # Un fichier binaire contient généralement des octets nuls
        return b"\x00" not in sample

    except OSError:
        return False


def iter_supported_files(extracted_path: str | Path, supported_extensions: list[str]):
    """
    Itère récursivement sur les fichiers supportés dans le dossier extrait.

    Args:
        extracted_path: Chemin racine du dossier APK extrait.
        supported_extensions: Liste des extensions de fichiers à analyser.

    Yields:
        Path: Chemin de chaque fichier texte supporté trouvé.
    """
    root = Path(extracted_path)

    if not root.exists() or not root.is_dir():
        raise SecretScanError(
            f"Le dossier extrait est introuvable ou invalide : {root}"
        )

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue

        if file_path.suffix.lower() not in supported_extensions:
            continue

        if is_text_file(file_path):
            yield file_path


def is_false_positive(value: str, ignored_keywords: list[str]) -> bool:
    """
    Détermine si une valeur détectée est un faux positif évident.

    Critères d'exclusion :
    - Valeur trop courte (moins de 8 caractères)
    - Valeur contenant un mot-clé ignoré (placeholder, test, example...)
    - Entropie trop faible (valeur répétitive ou prévisible)

    Args:
        value: Valeur extraite par le pattern regex.
        ignored_keywords: Liste de mots-clés à ignorer.

    Returns:
        True si la valeur est un faux positif, False sinon.
    """
    if not value or is_value_too_short(value):
        return True

    value_lower = value.lower().strip()

    for keyword in ignored_keywords:
        if keyword.lower() in value_lower:
            return True

    # Vérification de l'entropie : une valeur avec trop peu de variété n'est pas un secret
    entropy = calculate_entropy(value)
    if entropy < MINIMUM_ENTROPY:
        return True

    return False


def normalize_context(line_content: str) -> str:
    """
    Nettoie et normalise une ligne de contexte pour l'affichage.
    Retire les espaces superflus et tronque les lignes trop longues.

    Args:
        line_content: Contenu brut d'une ligne.

    Returns:
        Ligne normalisée et tronquée si nécessaire.
    """
    cleaned = line_content.strip()
    max_display_length = 120

    if len(cleaned) > max_display_length:
        return cleaned[:max_display_length] + "..."

    return cleaned


def get_line_context(lines: list[str], line_number: int, context_size: int = 1) -> str:
    """
    Retourne les lignes de contexte autour d'une ligne donnée.
    Utile pour aider le développeur à localiser le problème.

    Args:
        lines: Liste de toutes les lignes du fichier.
        line_number: Numéro de la ligne (1-indexé).
        context_size: Nombre de lignes de contexte avant et après.

    Returns:
        Contexte textuel normalisé autour de la ligne.
    """
    total_lines = len(lines)
    index = line_number - 1  # Conversion en index 0-based

    start = max(0, index - context_size)
    end = min(total_lines, index + context_size + 1)

    context_lines = []
    for i in range(start, end):
        prefix = ">>> " if i == index else "    "
        context_lines.append(f"{prefix}{i + 1}: {normalize_context(lines[i])}")

    return "\n".join(context_lines)


def classify_secret_type(match_name: str) -> str:
    """
    Détermine le type normalisé d'un secret à partir du nom du pattern.

    Args:
        match_name: Nom du pattern regex (ex: "Google API Key").

    Returns:
        Type normalisé du secret (ex: "API Key", "Bearer Token").
    """
    name_lower = match_name.lower()

    if "private key" in name_lower:
        return "Private Key"
    if "jwt" in name_lower:
        return "JWT Token"
    if "bearer" in name_lower or "authorization" in name_lower:
        return "Bearer Token"
    if "password" in name_lower or "passwd" in name_lower:
        return "Password"
    if "client secret" in name_lower:
        return "Client Secret"
    if "access token" in name_lower:
        return "Access Token"
    if "refresh token" in name_lower:
        return "Refresh Token"
    if "firebase" in name_lower:
        return "Firebase Key"
    if "aws" in name_lower:
        return "API Key"
    if "github" in name_lower or "slack" in name_lower:
        return "API Key"
    if "api key" in name_lower or "apikey" in name_lower:
        return "API Key"

    return "Generic Secret"


def _mask_value_by_type(secret_type: str, raw_value: str) -> str:
    """
    Applique le masquage adapté selon le type de secret.

    Args:
        secret_type: Type normalisé du secret.
        raw_value: Valeur brute à masquer.

    Returns:
        Valeur masquée appropriée au type.
    """
    token_types = {"JWT Token", "Bearer Token", "Access Token", "Refresh Token"}

    if secret_type in token_types:
        return mask_token(raw_value)

    return mask_secret(raw_value)


def build_secret_finding(
    pattern: dict,
    raw_value: str,
    file_path: Path,
    line_number: int,
    extracted_root: Path,
    finding_index: int,
) -> dict[str, Any]:
    """
    Construit un dictionnaire structuré représentant un secret détecté.

    Args:
        pattern: Dictionnaire du pattern regex (nom, type, risque, recommendation).
        raw_value: Valeur brute extraite par le regex (sera masquée).
        file_path: Chemin absolu du fichier contenant le secret.
        line_number: Numéro de ligne (1-indexé) du secret.
        extracted_root: Chemin racine du dossier extrait (pour chemin relatif).
        finding_index: Index du résultat pour la génération de l'ID.

    Returns:
        Dictionnaire JSON-sérialisable représentant le secret détecté.
    """
    secret_type = classify_secret_type(pattern["name"])
    masked_value = _mask_value_by_type(secret_type, raw_value)

    # Chemin relatif par rapport au dossier extrait (compatible Windows/Linux)
    try:
        relative_file = str(file_path.relative_to(extracted_root))
    except ValueError:
        relative_file = str(file_path)

    # Normalisation du séparateur de chemin pour la cohérence
    relative_file = relative_file.replace("\\", "/")

    risk = pattern.get("risk") or RISK_BY_TYPE.get(secret_type, "Medium")
    confidence = CONFIDENCE_BY_TYPE.get(pattern["name"], 0.75)
    entropy = calculate_entropy(raw_value)

    # Ajustement du score de confiance selon l'entropie
    if entropy >= 4.5:
        confidence = min(confidence + 0.03, 1.0)
    elif entropy < 3.5:
        confidence = max(confidence - 0.10, 0.50)

    finding_id = f"secret-{finding_index:03d}"

    return {
        "id": finding_id,
        "type": secret_type,
        "maskedValue": masked_value,
        "file": relative_file,
        "line": line_number,
        "risk": risk,
        "confidence": round(confidence, 2),
        "explanation": pattern.get(
            "description",
            f"Un secret de type '{secret_type}' a été détecté dans ce fichier."
        ),
        "recommendation": pattern.get(
            "recommendation",
            "Retirer ce secret du code source et le stocker dans un gestionnaire de secrets."
        ),
        "source": f"regex: {pattern['name']}",
        "category": "secret",
    }


def scan_file_for_secrets(
    file_path: Path,
    patterns: list[dict],
    ignored_keywords: list[str],
    extracted_root: Path,
    finding_counter: list[int],
) -> list[dict[str, Any]]:
    """
    Analyse un fichier texte et retourne tous les secrets détectés.

    Args:
        file_path: Chemin absolu du fichier à analyser.
        patterns: Liste des patterns regex à appliquer.
        ignored_keywords: Mots-clés indiquant un faux positif.
        extracted_root: Chemin racine pour le calcul du chemin relatif.
        finding_counter: Liste à un élément [int] partagée pour l'incrémentation des IDs.

    Returns:
        Liste de dictionnaires représentant les secrets détectés dans ce fichier.
    """
    findings: list[dict] = []

    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
            lines = content.splitlines()

    except OSError:
        # Fichier inaccessible en lecture : on l'ignore silencieusement
        return findings

    for pattern in patterns:
        regex_str = pattern.get("regex", "")
        if not regex_str:
            continue

        try:
            compiled = re.compile(regex_str, re.IGNORECASE)
        except re.error:
            # Pattern regex invalide : on l'ignore
            continue

        for match in compiled.finditer(content):
            # Extraire la valeur du secret : groupe 2 si disponible, sinon groupe 1, sinon tout le match
            if match.lastindex and match.lastindex >= 2:
                raw_value = match.group(2)
            elif match.lastindex and match.lastindex >= 1:
                raw_value = match.group(1)
            else:
                raw_value = match.group(0)

            if not raw_value:
                continue

            # Filtrage des faux positifs
            if is_false_positive(raw_value, ignored_keywords):
                continue

            # Calcul du numéro de ligne (1-indexé)
            line_start = content[: match.start()].count("\n") + 1

            finding_counter[0] += 1

            finding = build_secret_finding(
                pattern=pattern,
                raw_value=raw_value,
                file_path=file_path,
                line_number=line_start,
                extracted_root=extracted_root,
                finding_index=finding_counter[0],
            )

            findings.append(finding)

    return findings


def scan_secrets(
    extracted_path: str | Path,
    patterns_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """
    Point d'entrée principal du scanner de secrets.

    Parcourt récursivement le dossier APK extrait, analyse chaque fichier
    texte supporté et retourne une liste de secrets détectés.

    Args:
        extracted_path: Chemin du dossier APK extrait (ex: "extracted/demo_app/").
        patterns_path: Chemin optionnel vers le fichier de patterns JSON.

    Returns:
        Liste de dictionnaires JSON-sérialisables représentant les secrets trouvés.

    Raises:
        SecretScanError: En cas d'erreur critique pendant le scan.
        ConfigurationError: Si les patterns ne peuvent pas être chargés.
    """
    extracted_root = Path(extracted_path).resolve()

    # Chargement des patterns de détection
    config = load_secret_patterns(patterns_path)
    patterns: list[dict] = config.get("patterns", [])
    supported_extensions: list[str] = config.get("supported_extensions", [])
    ignored_keywords: list[str] = config.get("ignored_keywords", [])

    if not patterns:
        raise ConfigurationError("Aucun pattern de détection chargé. Vérifiez secret_patterns.json.")

    all_findings: list[dict] = []

    # Compteur partagé pour les IDs uniques (liste pour mutabilité)
    finding_counter = [0]

    # Suivi des doublons : même fichier + même ligne + même type
    seen_signatures: set[str] = set()

    try:
        for file_path in iter_supported_files(extracted_root, supported_extensions):
            file_findings = scan_file_for_secrets(
                file_path=file_path,
                patterns=patterns,
                ignored_keywords=ignored_keywords,
                extracted_root=extracted_root,
                finding_counter=finding_counter,
            )

            for finding in file_findings:
                # Dédoublonnage : on évite les mêmes secrets détectés par plusieurs patterns
                signature = f"{finding['file']}:{finding['line']}:{finding['type']}"
                if signature in seen_signatures:
                    continue
                seen_signatures.add(signature)
                all_findings.append(finding)

    except SecretScanError:
        raise
    except Exception as e:
        raise SecretScanError(
            f"Erreur inattendue pendant le scan du dossier '{extracted_root}' : {e}"
        ) from e

    return all_findings