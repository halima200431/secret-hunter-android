"""
backend/utils/json_utils.py
----------------------------
Fonctions utilitaires pour la lecture, l'écriture et la manipulation
de données JSON dans le projet SecretHunter Android.
"""

import json
import math
from pathlib import Path
from typing import Any

from backend.core.exceptions import StorageError


def read_json_file(path: str | Path, default: Any = None) -> Any:
    """
    Lit et retourne le contenu d'un fichier JSON.

    Args:
        path: Chemin vers le fichier JSON à lire.
        default: Valeur retournée si le fichier est absent ou illisible.

    Returns:
        Contenu JSON désérialisé, ou `default` en cas d'erreur.
    """
    file_path = Path(path)

    if not file_path.exists():
        return default

    try:
        with open(file_path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise StorageError(f"Fichier JSON invalide : {file_path} — {e}") from e
    except OSError as e:
        raise StorageError(f"Impossible de lire le fichier : {file_path} — {e}") from e


def write_json_file(path: str | Path, data: Any) -> None:
    """
    Sérialise et écrit des données dans un fichier JSON.
    Crée les répertoires parents si nécessaire.

    Args:
        path: Chemin de destination du fichier JSON.
        data: Données à sérialiser et sauvegarder.

    Raises:
        StorageError: Si l'écriture échoue.
    """
    file_path = Path(path)

    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except (OSError, TypeError) as e:
        raise StorageError(f"Impossible d'écrire le fichier JSON : {file_path} — {e}") from e


def ensure_json_serializable(data: Any) -> Any:
    """
    Convertit récursivement les types non sérialisables en types compatibles JSON.
    Gère les Path, sets, et valeurs float spéciales (inf, nan).

    Args:
        data: Données à nettoyer pour la sérialisation JSON.

    Returns:
        Données converties en types JSON natifs.
    """
    if isinstance(data, dict):
        return {k: ensure_json_serializable(v) for k, v in data.items()}

    if isinstance(data, (list, tuple)):
        return [ensure_json_serializable(item) for item in data]

    if isinstance(data, set):
        return [ensure_json_serializable(item) for item in sorted(data)]

    if isinstance(data, Path):
        return str(data)

    if isinstance(data, float):
        if math.isnan(data) or math.isinf(data):
            return None
        return data

    # Types natifs JSON : str, int, bool, None
    return data


def create_success_response(data: Any, message: str = "success") -> dict:
    """
    Construit une réponse JSON standardisée pour un succès.

    Args:
        data: Données à inclure dans la réponse.
        message: Message descriptif (par défaut "success").

    Returns:
        Dictionnaire structuré avec statut, message et données.
    """
    return {
        "status": "success",
        "message": message,
        "data": ensure_json_serializable(data),
    }


def create_error_response(error: Exception | str, message: str = "error") -> dict:
    """
    Construit une réponse JSON standardisée pour une erreur.

    Args:
        error: Exception levée ou message d'erreur sous forme de chaîne.
        message: Libellé général de l'erreur (par défaut "error").

    Returns:
        Dictionnaire structuré avec statut, message et détail de l'erreur.
    """
    error_detail = str(error) if isinstance(error, Exception) else error

    return {
        "status": "error",
        "message": message,
        "error": error_detail,
    }