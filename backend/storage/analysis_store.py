"""
backend/storage/analysis_store.py
-----------------------------------
Module de stockage JSON pour la persistance des résultats d'analyse SecretHunter.
Utilise des fichiers JSON locaux (pas de base de données) pour rester simple
et portable. Chaque analyse est sauvegardée dans un fichier distinct.

Format : reports/{analysis_id}.json
"""

import json
from pathlib import Path
from typing import Any

from backend.core.exceptions import StorageError
from backend.utils.json_utils import ensure_json_serializable, read_json_file, write_json_file


def _get_analysis_path(analysis_id: str, storage_dir: str | Path) -> Path:
    """
    Construit le chemin du fichier JSON correspondant à un identifiant d'analyse.

    Args:
        analysis_id: Identifiant unique de l'analyse.
        storage_dir: Répertoire de stockage des rapports.

    Returns:
        Chemin complet vers le fichier JSON de l'analyse.
    """
    return Path(storage_dir) / f"{analysis_id}.json"


def save_analysis_result(
    analysis_id: str,
    data: dict[str, Any],
    storage_dir: str | Path = "reports",
) -> Path:
    """
    Sauvegarde le résultat d'une analyse dans un fichier JSON.
    Crée le répertoire de stockage s'il n'existe pas encore.

    Args:
        analysis_id: Identifiant unique de l'analyse (utilisé comme nom de fichier).
        data: Dictionnaire contenant les résultats à sauvegarder.
        storage_dir: Répertoire de destination (par défaut "reports").

    Returns:
        Chemin du fichier créé.

    Raises:
        StorageError: Si la sauvegarde échoue.
    """
    if not analysis_id or not analysis_id.strip():
        raise StorageError("L'identifiant d'analyse ne peut pas être vide.")

    output_path = _get_analysis_path(analysis_id.strip(), storage_dir)

    try:
        serializable_data = ensure_json_serializable(data)
        write_json_file(output_path, serializable_data)
    except StorageError:
        raise
    except Exception as e:
        raise StorageError(
            f"Impossible de sauvegarder l'analyse '{analysis_id}' : {e}"
        ) from e

    return output_path


def load_analysis_result(
    analysis_id: str,
    storage_dir: str | Path = "reports",
) -> dict[str, Any] | None:
    """
    Charge le résultat d'une analyse depuis son fichier JSON.

    Args:
        analysis_id: Identifiant unique de l'analyse à charger.
        storage_dir: Répertoire de stockage (par défaut "reports").

    Returns:
        Dictionnaire des résultats, ou None si l'analyse n'existe pas.

    Raises:
        StorageError: Si le fichier existe mais est corrompu ou illisible.
    """
    file_path = _get_analysis_path(analysis_id, storage_dir)

    if not file_path.exists():
        return None

    try:
        data = read_json_file(file_path)
    except StorageError:
        raise
    except Exception as e:
        raise StorageError(
            f"Erreur lors du chargement de l'analyse '{analysis_id}' : {e}"
        ) from e

    return data


def analysis_exists(
    analysis_id: str,
    storage_dir: str | Path = "reports",
) -> bool:
    """
    Vérifie si un fichier d'analyse existe pour un identifiant donné.

    Args:
        analysis_id: Identifiant de l'analyse à rechercher.
        storage_dir: Répertoire de stockage (par défaut "reports").

    Returns:
        True si le fichier d'analyse existe, False sinon.
    """
    file_path = _get_analysis_path(analysis_id, storage_dir)
    return file_path.exists() and file_path.is_file()


def list_analysis_results(
    storage_dir: str | Path = "reports",
) -> list[dict[str, Any]]:
    """
    Liste toutes les analyses disponibles dans le répertoire de stockage.
    Retourne les métadonnées de base de chaque analyse sans charger tous les secrets.

    Args:
        storage_dir: Répertoire de stockage (par défaut "reports").

    Returns:
        Liste de dictionnaires contenant les métadonnées de chaque analyse
        (analysisId, status, secretsCount, timestamp si disponibles).
        Retourne une liste vide si le répertoire est absent ou vide.
    """
    storage_path = Path(storage_dir)

    if not storage_path.exists() or not storage_path.is_dir():
        return []

    results: list[dict[str, Any]] = []

    for json_file in sorted(storage_path.glob("*.json")):
        try:
            data = read_json_file(json_file)

            if not isinstance(data, dict):
                continue

            # Extraction des métadonnées de base uniquement (sans les secrets complets)
            summary = {
                "analysisId": data.get("analysisId", json_file.stem),
                "status": data.get("status", "unknown"),
                "secretsCount": data.get("secretsCount", 0),
                "criticalFindings": data.get("criticalFindings", 0),
                "highFindings": data.get("highFindings", 0),
                "mediumFindings": data.get("mediumFindings", 0),
                "lowFindings": data.get("lowFindings", 0),
                "filePath": str(json_file),
            }

            results.append(summary)

        except (StorageError, json.JSONDecodeError):
            # Fichier corrompu : on l'ignore et on continue
            continue

    return results


def delete_analysis_result(
    analysis_id: str,
    storage_dir: str | Path = "reports",
) -> bool:
    """
    Supprime le fichier d'analyse correspondant à un identifiant.

    Args:
        analysis_id: Identifiant de l'analyse à supprimer.
        storage_dir: Répertoire de stockage (par défaut "reports").

    Returns:
        True si le fichier a été supprimé, False s'il n'existait pas.

    Raises:
        StorageError: Si la suppression échoue pour une raison inattendue.
    """
    file_path = _get_analysis_path(analysis_id, storage_dir)

    if not file_path.exists():
        return False

    try:
        file_path.unlink()
        return True
    except OSError as e:
        raise StorageError(
            f"Impossible de supprimer l'analyse '{analysis_id}' : {e}"
        ) from e