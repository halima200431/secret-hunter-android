"""
SecretHunter Android — Backend Flask
=====================================
Point d'entrée de l'API REST.
Endpoint principal : POST /scan
"""

import os
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from flask import Flask, request, jsonify
from secret_scanner import scan_secrets

app = Flask(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────
UPLOAD_FOLDER  = Path("uploads")
EXTRACT_FOLDER = Path("extracted")
REPORTS_FOLDER = Path("reports")
ALLOWED_EXTENSIONS = {"apk"}

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
EXTRACT_FOLDER.mkdir(parents=True, exist_ok=True)
REPORTS_FOLDER.mkdir(parents=True, exist_ok=True)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def decompile_apk(apk_path: Path, output_dir: Path) -> bool:
    """
    Décompile un APK avec JADX (si disponible) ou Apktool en fallback.
    Retourne True si la décompilation a réussi.
    """
    try:
        # Tentative avec JADX
        result = subprocess.run(
            ["jadx", "-d", str(output_dir), str(apk_path)],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        # Fallback avec Apktool
        result = subprocess.run(
            ["apktool", "d", str(apk_path), "-o", str(output_dir), "-f"],
            capture_output=True, text=True, timeout=120
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ─── Route principale : scan d'un APK uploadé ────────────────────────────────
@app.route("/scan", methods=["POST"])
def scan_apk():
    """
    Endpoint principal : reçoit un fichier APK, le décompile et lance le scan de secrets.

    Body : multipart/form-data
        - file : fichier .apk

    Retourne : JSON avec les secrets détectés
    """
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "Aucun fichier fourni (clé 'file' manquante)."}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"status": "error", "message": "Nom de fichier vide."}), 400

    if not allowed_file(file.filename):
        return jsonify({"status": "error", "message": "Extension non autorisée. Seuls les fichiers .apk sont acceptés."}), 400

    # Sauvegarde temporaire de l'APK uploadé
    apk_filename = Path(file.filename).name
    apk_save_path = UPLOAD_FOLDER / apk_filename
    file.save(str(apk_save_path))

    # Dossier de décompilation
    app_name    = apk_save_path.stem
    extract_dir = EXTRACT_FOLDER / app_name

    # Nettoyage si déjà extrait
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True)

    # Décompilation
    success = decompile_apk(apk_save_path, extract_dir)
    if not success:
        return jsonify({
            "status":  "error",
            "message": "La décompilation a échoué. Vérifiez que JADX ou Apktool est installé.",
        }), 500

    # Lancement du scan de secrets
    result = scan_secrets(str(extract_dir))

    # Sauvegarde du rapport JSON
    report_path = REPORTS_FOLDER / f"{app_name}_secrets.json"
    report_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    return jsonify(result), 200


# ─── Route : scan d'un dossier déjà extrait (test / dev) ─────────────────────
@app.route("/scan/folder", methods=["POST"])
def scan_folder():
    """
    Endpoint de développement : lance le scan sur un dossier déjà décompilé.

    Body JSON :
        { "path": "/chemin/vers/dossier/extrait" }

    Retourne : JSON avec les secrets détectés
    """
    data = request.get_json(silent=True)
    if not data or "path" not in data:
        return jsonify({"status": "error", "message": "Body JSON requis avec le champ 'path'."}), 400

    folder_path = data["path"]
    result      = scan_secrets(folder_path)
    return jsonify(result), 200


# ─── Route : santé de l'API ───────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "SecretHunter Android API"}), 200


# ─── Lancement ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)