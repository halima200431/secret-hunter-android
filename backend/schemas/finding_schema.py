"""
backend/schemas/finding_schema.py
----------------------------------
Schéma de données représentant une vulnérabilité de type "secret"
détectée lors de l'analyse d'un APK Android.

Utilise dataclass pour une structure claire, typée et sérialisable.
"""

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    """
    Représente un secret ou une vulnérabilité détectée dans un fichier extrait d'un APK.

    Champs obligatoires:
        id (str): Identifiant unique du résultat (ex: "secret-001").
        type (str): Type du secret détecté (ex: "API Key", "Bearer Token").
        maskedValue (str): Valeur masquée du secret (jamais la valeur complète).
        file (str): Chemin relatif du fichier contenant le secret.
        line (int): Numéro de la ligne où le secret a été trouvé.
        risk (str): Niveau de risque : "Critical", "High", "Medium", "Low".
        confidence (float): Score de confiance entre 0.0 et 1.0.
        explanation (str): Explication lisible du problème détecté.
        recommendation (str): Conseil pour corriger la vulnérabilité.
        source (str): Source de détection (ex: "regex: Google API Key").

    Champs optionnels:
        category (str): Catégorie de la vulnérabilité (par défaut "secret").
    """

    id: str
    type: str
    maskedValue: str
    file: str
    line: int
    risk: str
    confidence: float
    explanation: str
    recommendation: str
    source: str
    category: str = field(default="secret")

    def to_dict(self) -> dict[str, Any]:
        """
        Convertit l'objet Finding en dictionnaire JSON-sérialisable.

        Returns:
            Dictionnaire avec tous les champs du Finding.
        """
        result = asdict(self)

        # Arrondir le score de confiance à 2 décimales pour la lisibilité
        result["confidence"] = round(result["confidence"], 2)

        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """
        Crée un objet Finding à partir d'un dictionnaire (ex: chargé depuis JSON).

        Args:
            data: Dictionnaire contenant les champs du Finding.

        Returns:
            Instance de Finding reconstituée.

        Raises:
            KeyError: Si un champ obligatoire est absent du dictionnaire.
            ValueError: Si le type de données d'un champ est incorrect.
        """
        required_fields = [
            "id", "type", "maskedValue", "file",
            "line", "risk", "confidence",
            "explanation", "recommendation", "source"
        ]

        for field_name in required_fields:
            if field_name not in data:
                raise KeyError(
                    f"Champ obligatoire manquant dans le dictionnaire Finding : '{field_name}'"
                )

        return cls(
            id=str(data["id"]),
            type=str(data["type"]),
            maskedValue=str(data["maskedValue"]),
            file=str(data["file"]),
            line=int(data["line"]),
            risk=str(data["risk"]),
            confidence=float(data["confidence"]),
            explanation=str(data["explanation"]),
            recommendation=str(data["recommendation"]),
            source=str(data["source"]),
            category=str(data.get("category", "secret")),
        )

    def is_critical(self) -> bool:
        """Retourne True si le niveau de risque est Critical."""
        return self.risk.lower() == "critical"

    def is_high(self) -> bool:
        """Retourne True si le niveau de risque est High."""
        return self.risk.lower() == "high"

    def is_medium(self) -> bool:
        """Retourne True si le niveau de risque est Medium."""
        return self.risk.lower() == "medium"

    def __repr__(self) -> str:
        return (
            f"Finding(id={self.id!r}, type={self.type!r}, "
            f"risk={self.risk!r}, file={self.file!r}, line={self.line})"
        )