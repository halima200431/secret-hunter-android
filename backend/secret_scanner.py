"""
SecretHunter Android - Secret Scanner Module
=============================================
Module d'analyse statique pour détecter les secrets exposés dans les APKs Android décompilés.
Auteur : Module développé pour le projet académique SecretHunter Android
Usage  : scan_secrets(extracted_apk_path: str) -> dict
"""

import os
import re
import json
import math
import time
import logging
from pathlib import Path
from typing import Optional

# ─── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger("SecretScanner")

# ─── Constantes ─────────────────────────────────────────────────────────────
SUPPORTED_EXTENSIONS = {".java", ".kt", ".xml", ".json", ".properties", ".txt", ".smali", ".gradle", ".yaml", ".yml"}
MAX_FILE_SIZE_BYTES   = 5 * 1024 * 1024   # 5 Mo max par fichier
ENTROPY_THRESHOLD     = 3.5               # seuil d'entropie de Shannon
MASK_KEEP_CHARS       = 6                 # nb de caractères visibles après masquage

# Valeurs génériques à ignorer (faux positifs fréquents)
IGNORED_VALUES = {
    "test", "demo", "example", "null", "none", "password", "changeme",
    "secret", "your_key_here", "insert_key", "api_key", "xxx", "yyy",
    "1234567890", "abcdefgh", "placeholder", "replace_me", "todo",
    "dummy", "fake", "sample", "your_token_here", "xxxxxxxx",
    "0000000000", "enter_key_here",
}

# ─── Chargement des patterns depuis le fichier JSON ─────────────────────────
RULES_PATH = Path(__file__).parent.parent / "rules" / "secret_patterns.json"

def load_patterns() -> list[dict]:
    """Charge les patterns de détection depuis le fichier JSON de règles."""
    if not RULES_PATH.exists():
        logger.warning(f"Fichier de règles introuvable : {RULES_PATH}. Utilisation des patterns intégrés.")
        return []
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("patterns", [])


# ─── Utilitaires ────────────────────────────────────────────────────────────

def mask_secret(value: str, keep: int = MASK_KEEP_CHARS) -> str:
    """
    Masque un secret en ne laissant apparaître que les premiers caractères.
    Exemple : "AIzaSyABCDEF1234" -> "AIzaSy**********"
    """
    if not value or len(value) <= keep:
        return "*" * len(value)
    visible = value[:keep]
    masked  = "*" * (len(value) - keep)
    return visible + masked


def shannon_entropy(text: str) -> float:
    """
    Calcule l'entropie de Shannon d'une chaîne de caractères.
    Une entropie élevée (> 3.5) indique une chaîne potentiellement aléatoire (token, clé...).
    """
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())
    return round(entropy, 4)


def is_ignored_value(value: str) -> bool:
    """Retourne True si la valeur est un faux positif connu (valeur générique)."""
    cleaned = value.strip().lower()
    if cleaned in IGNORED_VALUES:
        return True
    # Ignorer les chaînes trop courtes ou ne contenant que des répétitions
    if len(cleaned) < 6:
        return True
    if len(set(cleaned)) <= 2:   # ex: "aaaaaaa", "0000000"
        return True
    return False


def is_binary_file(filepath: Path) -> bool:
    """Détecte rapidement si un fichier est binaire (heuristique sur les 1024 premiers octets)."""
    try:
        with open(filepath, "rb") as f:
            chunk = f.read(1024)
        # Les fichiers texte ne contiennent pas d'octets nuls
        return b"\x00" in chunk
    except Exception:
        return True


def get_context_line(lines: list[str], line_number: int, window: int = 0) -> str:
    """Retourne la ligne de contexte (la ligne elle-même, épurée)."""
    if 0 <= line_number < len(lines):
        return lines[line_number].strip()[:200]   # max 200 chars pour le contexte
    return ""


# ─── Analyse d'un fichier ───────────────────────────────────────────────────

def scan_file(filepath: Path, patterns: list[dict], relative_base: Path) -> list[dict]:
    """
    Analyse un fichier unique à la recherche de secrets.
    Retourne une liste de findings.
    """
    findings = []

    # Vérifications préliminaires
    if filepath.stat().st_size > MAX_FILE_SIZE_BYTES:
        logger.debug(f"Fichier ignoré (trop volumineux) : {filepath}")
        return findings

    if is_binary_file(filepath):
        logger.debug(f"Fichier ignoré (binaire) : {filepath}")
        return findings

    # Lecture du fichier
    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        logger.warning(f"Impossible de lire {filepath} : {e}")
        return findings

    lines = content.splitlines()
    relative_path = str(filepath.relative_to(relative_base))

    for pattern_def in patterns:
        pattern_name = pattern_def.get("name", "Unknown")
        regex_str    = pattern_def.get("regex", "")
        risk_level   = pattern_def.get("risk", "MEDIUM")
        description  = pattern_def.get("description", "Secret potentiellement exposé.")

        if not regex_str:
            continue

        try:
            regex = re.compile(regex_str, re.IGNORECASE | re.MULTILINE)
        except re.error as e:
            logger.warning(f"Regex invalide pour '{pattern_name}' : {e}")
            continue

        for match in regex.finditer(content):
            # Extraire la valeur capturée (groupe 1 si disponible, sinon match complet)
            raw_value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            raw_value = raw_value.strip()

            # Filtrer les faux positifs
            if is_ignored_value(raw_value):
                continue

            # Calcul d'entropie pour les patterns qui bénéficient de cette vérification
            if pattern_def.get("check_entropy", False):
                entropy = shannon_entropy(raw_value)
                if entropy < ENTROPY_THRESHOLD:
                    continue   # Chaîne pas assez aléatoire → probablement pas un secret réel

            # Numéro de ligne (1-based)
            line_number = content[:match.start()].count("\n")
            context_line = get_context_line(lines, line_number)

            # Masquage du secret
            masked = mask_secret(raw_value)

            # Remplacer la valeur brute par la valeur masquée dans le contexte
            context_masked = context_line.replace(raw_value, masked) if raw_value in context_line else context_line

            finding = {
                "type":         pattern_name,
                "masked_value": masked,
                "file":         relative_path,
                "line":         line_number + 1,
                "risk":         risk_level,
                "entropy":      shannon_entropy(raw_value),
                "context":      context_masked,
                "description":  description,
            }
            findings.append(finding)

    return findings


# ─── Fonction principale ─────────────────────────────────────────────────────

def scan_secrets(extracted_apk_path: str) -> dict:
    """
    Parcourt récursivement un dossier d'APK décompilé et détecte les secrets exposés.

    Args:
        extracted_apk_path (str): Chemin vers le dossier contenant les fichiers extraits.

    Returns:
        dict: Résultat structuré contenant les findings, statistiques et métadonnées.
    """
    start_time = time.time()
    base_path  = Path(extracted_apk_path)

    # Validation du dossier
    if not base_path.exists() or not base_path.is_dir():
        return {
            "status":  "error",
            "message": f"Le dossier spécifié n'existe pas ou n'est pas un dossier : {extracted_apk_path}",
        }

    # Chargement des patterns de détection
    patterns = load_patterns()
    if not patterns:
        return {
            "status":  "error",
            "message": "Aucun pattern de détection disponible. Vérifiez rules/secret_patterns.json.",
        }

    logger.info(f"Démarrage du scan de : {base_path}")
    logger.info(f"Patterns chargés : {len(patterns)}")

    all_findings    = []
    files_scanned   = 0
    files_skipped   = 0

    # Parcours récursif
    for filepath in sorted(base_path.rglob("*")):
        if not filepath.is_file():
            continue
        if filepath.suffix.lower() not in SUPPORTED_EXTENSIONS:
            files_skipped += 1
            continue

        files_scanned += 1
        file_findings = scan_file(filepath, patterns, base_path)
        all_findings.extend(file_findings)

    # Déduplication (même fichier + même ligne + même type)
    seen      = set()
    unique_findings = []
    for f in all_findings:
        key = (f["file"], f["line"], f["type"], f["masked_value"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Tri par niveau de risque décroissant
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    unique_findings.sort(key=lambda x: risk_order.get(x["risk"], 99))

    elapsed = round(time.time() - start_time, 2)

    # Statistiques par niveau de risque
    risk_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in unique_findings:
        risk_summary[f["risk"]] = risk_summary.get(f["risk"], 0) + 1

    result = {
        "status":              "success",
        "scanned_path":        str(base_path),
        "total_files_scanned": files_scanned,
        "total_files_skipped": files_skipped,
        "total_secrets_found": len(unique_findings),
        "scan_duration_sec":   elapsed,
        "risk_summary":        risk_summary,
        "findings":            unique_findings,
    }

    logger.info(f"Scan terminé en {elapsed}s | Fichiers : {files_scanned} | Secrets : {len(unique_findings)}")
    return result


# ─── Point d'entrée CLI ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage : python secret_scanner.py <chemin_dossier_apk_extrait>")
        sys.exit(1)

    apk_path = sys.argv[1]
    result   = scan_secrets(apk_path)

    output_path = Path("reports") / "secrets_result.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\n✅ Rapport sauvegardé dans : {output_path}")