from pathlib import Path
import os

from flask import Flask, jsonify

try:
    from flask_cors import CORS
except ImportError:
    CORS = None

from backend.api.routes_analysis import analysis_bp


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent


def create_app() -> Flask:
    app = Flask(__name__)

    app.config["PROJECT_ROOT"] = str(PROJECT_ROOT)
    app.config["UPLOAD_FOLDER"] = str(PROJECT_ROOT / "uploads")
    app.config["EXTRACTED_FOLDER"] = str(PROJECT_ROOT / "extracted")
    app.config["REPORTS_FOLDER"] = str(PROJECT_ROOT / "reports")
    app.config["LOGS_FOLDER"] = str(PROJECT_ROOT / "logs")

    app.config["MAX_CONTENT_LENGTH"] = int(
        os.getenv("MAX_APK_SIZE_MB", "80")
    ) * 1024 * 1024

    app.config["ALLOWED_EXTENSIONS"] = {"apk"}

    for folder_key in [
        "UPLOAD_FOLDER",
        "EXTRACTED_FOLDER",
        "REPORTS_FOLDER",
        "LOGS_FOLDER",
    ]:
        Path(app.config[folder_key]).mkdir(parents=True, exist_ok=True)

    if CORS is not None:
        allowed_origin = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
        CORS(
            app,
            resources={r"/api/*": {"origins": allowed_origin}},
            supports_credentials=False,
        )

    app.register_blueprint(analysis_bp, url_prefix="/api")

    @app.get("/")
    def index():
        return jsonify(
            {
                "app": "SecretHunter Android Backend",
                "status": "running",
                "version": "1.0.0",
                "message": "Backend prêt pour l’analyse statique des APK Android.",
            }
        )

    @app.errorhandler(413)
    def file_too_large(_error):
        return jsonify(
            {
                "status": "error",
                "message": "Le fichier APK dépasse la taille maximale autorisée.",
            }
        ), 413

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify(
            {
                "status": "error",
                "message": "Route introuvable.",
            }
        ), 404

    @app.errorhandler(500)
    def internal_error(_error):
        return jsonify(
            {
                "status": "error",
                "message": "Erreur interne du serveur.",
            }
        ), 500

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.getenv("BACKEND_HOST", "127.0.0.1"),
        port=int(os.getenv("BACKEND_PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true",
    )