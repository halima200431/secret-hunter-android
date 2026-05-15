"""
backend/core/exceptions.py
--------------------------
Exceptions personnalisées pour le projet SecretHunter Android.
Chaque exception hérite de SecretHunterError pour faciliter
la gestion globale des erreurs dans le projet.
"""


class SecretHunterError(Exception):
    """
    Classe de base pour toutes les exceptions du projet SecretHunter.
    Toutes les exceptions spécifiques héritent de cette classe.
    """

    def __init__(self, message: str = "Une erreur SecretHunter s'est produite."):
        self.message = message
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"[SecretHunterError] {self.message}"


class InvalidAPKError(SecretHunterError):
    """
    Levée lorsqu'un fichier APK fourni est invalide, corrompu
    ou ne correspond pas au format attendu.
    """

    def __init__(self, message: str = "Le fichier APK fourni est invalide ou corrompu."):
        super().__init__(message)

    def __str__(self) -> str:
        return f"[InvalidAPKError] {self.message}"


class ExtractionError(SecretHunterError):
    """
    Levée lorsque l'extraction du contenu d'un APK échoue,
    par exemple si le fichier est protégé ou incomplet.
    """

    def __init__(self, message: str = "L'extraction du fichier APK a échoué."):
        super().__init__(message)

    def __str__(self) -> str:
        return f"[ExtractionError] {self.message}"


class SecretScanError(SecretHunterError):
    """
    Levée lors d'une erreur survenant pendant le scan
    des secrets dans les fichiers extraits.
    """

    def __init__(self, message: str = "Une erreur s'est produite pendant le scan des secrets."):
        super().__init__(message)

    def __str__(self) -> str:
        return f"[SecretScanError] {self.message}"


class StorageError(SecretHunterError):
    """
    Levée lors d'une erreur de lecture ou d'écriture
    dans le stockage JSON des résultats d'analyse.
    """

    def __init__(self, message: str = "Une erreur de stockage s'est produite."):
        super().__init__(message)

    def __str__(self) -> str:
        return f"[StorageError] {self.message}"


class ConfigurationError(SecretHunterError):
    """
    Levée lorsque la configuration du projet est manquante,
    incorrecte ou incompatible.
    """

    def __init__(self, message: str = "La configuration du projet est invalide ou manquante."):
        super().__init__(message)

    def __str__(self) -> str:
        return f"[ConfigurationError] {self.message}"