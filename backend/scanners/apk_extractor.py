import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from datetime import datetime


class ApkExtractor:
    """
    Module responsable de la validation et de l'extraction d'un fichier APK.
    """

    def __init__(self, uploads_dir="uploads", extracted_dir="extracted"):
        self.uploads_dir = Path(uploads_dir)
        self.extracted_dir = Path(extracted_dir)

        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.extracted_dir.mkdir(parents=True, exist_ok=True)

    def is_valid_apk(self, apk_path):
        """
        Vérifie que le fichier fourni est un APK valide.
        """

        apk_path = Path(apk_path)

        if not apk_path.exists():
            return False, "Le fichier n'existe pas."

        if not apk_path.is_file():
            return False, "Le chemin fourni n'est pas un fichier."

        if apk_path.suffix.lower() != ".apk":
            return False, "Le fichier doit avoir l'extension .apk."

        if apk_path.stat().st_size == 0:
            return False, "Le fichier APK est vide."

        if not zipfile.is_zipfile(apk_path):
            return False, "Le fichier n'est pas une archive APK valide."

        try:
            with zipfile.ZipFile(apk_path, "r") as apk_zip:
                files = apk_zip.namelist()

                if "AndroidManifest.xml" not in files:
                    return False, "AndroidManifest.xml est introuvable dans l'APK."

                dex_files = [
                    file for file in files
                    if file.startswith("classes") and file.endswith(".dex")
                ]

                if not dex_files:
                    return False, "Aucun fichier classes.dex trouvé dans l'APK."

        except Exception as error:
            return False, f"Erreur lors de la lecture de l'APK : {error}"

        return True, "APK valide."

    def get_tool_path(self, tool_name):
        """
        Retourne le chemin exact de l'outil.
        Sous Windows avec Scoop, les outils sont souvent disponibles en .cmd.
        """

        if os.name == "nt":
            possible_names = [
                f"{tool_name}.cmd",
                f"{tool_name}.bat",
                tool_name
            ]
        else:
            possible_names = [tool_name]

        for name in possible_names:
            tool_path = shutil.which(name)
            if tool_path:
                return tool_path

        return None

    def check_tool_exists(self, tool_name):
        """
        Vérifie si un outil externe est installé et accessible depuis le terminal.
        """

        tool_path = self.get_tool_path(tool_name)

        if tool_path is None:
            return False, f"L'outil {tool_name} n'est pas installé ou n'est pas dans le PATH."

        return True, f"L'outil {tool_name} est disponible : {tool_path}"

    def create_analysis_folder(self, apk_path):
        """
        Crée un dossier unique pour chaque analyse APK.
        """

        apk_name = Path(apk_path).stem.replace(" ", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        analysis_folder = self.extracted_dir / f"{apk_name}_{timestamp}"
        jadx_folder = analysis_folder / "jadx_output"
        apktool_folder = analysis_folder / "apktool_output"

        jadx_folder.mkdir(parents=True, exist_ok=True)
        apktool_folder.mkdir(parents=True, exist_ok=True)

        return analysis_folder, jadx_folder, apktool_folder

    def decompile_with_jadx(self, apk_path, output_dir):
        """
        Décompile l'APK avec JADX.
        """

        jadx_path = self.get_tool_path("jadx")

        if jadx_path is None:
            raise RuntimeError("JADX est introuvable dans le PATH.")

        command = [
            jadx_path,
            "-d",
            str(output_dir),
            str(apk_path)
        ]

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            raise RuntimeError(f"Erreur JADX : {result.stderr}")

        return {
            "status": "success",
            "message": "Décompilation JADX terminée avec succès.",
            "output_dir": str(output_dir)
        }

    def decompile_with_apktool(self, apk_path, output_dir):
        """
        Décompile l'APK avec Apktool.
        """

        apktool_path = self.get_tool_path("apktool")

        if apktool_path is None:
            raise RuntimeError("Apktool est introuvable dans le PATH.")

        command = [
            apktool_path,
            "d",
            str(apk_path),
            "-o",
            str(output_dir),
            "-f"
        ]

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            raise RuntimeError(f"Erreur Apktool : {result.stderr}")

        return {
            "status": "success",
            "message": "Décompilation Apktool terminée avec succès.",
            "output_dir": str(output_dir)
        }

    def list_all_files(self, folder):
        """
        Liste tous les fichiers extraits après décompilation.
        """

        folder = Path(folder)
        files = []

        for root, dirs, filenames in os.walk(folder):
            for filename in filenames:
                full_path = Path(root) / filename
                files.append(str(full_path))

        return files

    def find_important_files(self, analysis_folder):
        """
        Identifie les fichiers utiles pour les autres modules.
        """

        analysis_folder = Path(analysis_folder)

        important_files = {
            "android_manifest": [],
            "dex_files": [],
            "strings_xml": [],
            "assets": [],
            "json_files": [],
            "xml_files": [],
            "properties_files": [],
            "other_config_files": []
        }

        for root, dirs, files in os.walk(analysis_folder):
            root_path = Path(root)

            for directory in dirs:
                if directory.lower() == "assets":
                    important_files["assets"].append(str(root_path / directory))

            for file in files:
                file_path = root_path / file
                file_name = file.lower()

                if file_name == "androidmanifest.xml":
                    important_files["android_manifest"].append(str(file_path))

                elif file_name.startswith("classes") and file_name.endswith(".dex"):
                    important_files["dex_files"].append(str(file_path))

                elif file_name == "strings.xml":
                    important_files["strings_xml"].append(str(file_path))

                elif file_name.endswith(".json"):
                    important_files["json_files"].append(str(file_path))

                elif file_name.endswith(".xml"):
                    important_files["xml_files"].append(str(file_path))

                elif file_name.endswith(".properties"):
                    important_files["properties_files"].append(str(file_path))

                elif file_name.endswith((".conf", ".config", ".ini", ".env")):
                    important_files["other_config_files"].append(str(file_path))

        return important_files

    def save_original_apk(self, apk_path, analysis_folder):
        """
        Copie l'APK original dans le dossier d'analyse.
        """

        apk_path = Path(apk_path)
        destination = Path(analysis_folder) / apk_path.name

        shutil.copy2(apk_path, destination)

        return str(destination)

    def extract_apk(self, apk_path):
        """
        Fonction principale :
        1. Valider l'APK
        2. Vérifier JADX et Apktool
        3. Créer le dossier d'analyse
        4. Décompiler avec JADX
        5. Décompiler avec Apktool
        6. Retourner les fichiers importants
        """

        apk_path = Path(apk_path)

        validation_status, validation_message = self.is_valid_apk(apk_path)

        if not validation_status:
            return {
                "status": "error",
                "step": "apk_validation",
                "message": validation_message
            }

        jadx_status, jadx_message = self.check_tool_exists("jadx")
        apktool_status, apktool_message = self.check_tool_exists("apktool")

        if not jadx_status:
            return {
                "status": "error",
                "step": "tool_check",
                "message": jadx_message
            }

        if not apktool_status:
            return {
                "status": "error",
                "step": "tool_check",
                "message": apktool_message
            }

        analysis_folder, jadx_folder, apktool_folder = self.create_analysis_folder(apk_path)

        result = {
            "status": "success",
            "message": "Extraction APK terminée avec succès.",
            "apk_name": apk_path.name,
            "analysis_folder": str(analysis_folder),
            "original_apk": None,
            "jadx": None,
            "apktool": None,
            "files_count": 0,
            "important_files": {},
            "errors": []
        }

        try:
            result["original_apk"] = self.save_original_apk(apk_path, analysis_folder)
            result["jadx"] = self.decompile_with_jadx(apk_path, jadx_folder)

        except Exception as error:
            result["errors"].append({
                "tool": "jadx",
                "message": str(error)
            })

        try:
            result["apktool"] = self.decompile_with_apktool(apk_path, apktool_folder)

        except Exception as error:
            result["errors"].append({
                "tool": "apktool",
                "message": str(error)
            })

        all_files = self.list_all_files(analysis_folder)
        important_files = self.find_important_files(analysis_folder)

        result["files_count"] = len(all_files)
        result["important_files"] = important_files
        result["sample_files"] = all_files[:50]

        if result["errors"]:
            result["status"] = "partial_success"
            result["message"] = "L'extraction est partiellement terminée. Certains outils ont échoué."

        return result
    
def extract_apk_file(apk_path, uploads_dir="uploads", extracted_dir="extracted"):
    """
    Fonction wrapper utilisée par les services backend.

    Elle permet d'utiliser la classe ApkExtractor sans créer l'objet
    manuellement dans chaque fichier du projet.
    """

    extractor = ApkExtractor(
        uploads_dir=uploads_dir,
        extracted_dir=extracted_dir
    )

    result = extractor.extract_apk(apk_path)

    if "analysis_folder" in result:
        result["extracted_path"] = result["analysis_folder"]

    return result    