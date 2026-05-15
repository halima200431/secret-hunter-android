from pathlib import Path

from backend.scanners.apk_extractor import extract_apk_file


PROJECT_ROOT = Path(__file__).resolve().parents[2]
UPLOADS_DIR = PROJECT_ROOT / "uploads"
EXTRACTED_DIR = PROJECT_ROOT / "extracted"


def extract_apk(apk_path, analysis_id=None):
    """
    Service principal d'extraction APK.

    Cette fonction est appelée par routes_analysis.py.
    Elle utilise le scanner ApkExtractor, puis retourne un résultat
    normalisé pour les autres modules du backend.
    """

    apk_path = Path(apk_path)

    if not apk_path.exists():
        raise FileNotFoundError(f"APK introuvable : {apk_path}")

    result = extract_apk_file(
        apk_path=apk_path,
        uploads_dir=UPLOADS_DIR,
        extracted_dir=EXTRACTED_DIR
    )

    if result.get("status") == "error":
        raise RuntimeError(result.get("message", "Erreur pendant l'extraction APK."))

    return {
        "status": result.get("status", "success"),
        "message": result.get("message", ""),
        "apk_name": result.get("apk_name", apk_path.name),
        "analysis_id": analysis_id,
        "extracted_path": result.get("extracted_path") or result.get("analysis_folder"),
        "analysis_folder": result.get("analysis_folder"),
        "files_count": result.get("files_count", 0),
        "important_files": result.get("important_files", {}),
        "sample_files": result.get("sample_files", []),
        "errors": result.get("errors", [])
    }