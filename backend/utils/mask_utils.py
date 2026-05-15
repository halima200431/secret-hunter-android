"""
backend/utils/mask_utils.py
----------------------------
Fonctions de masquage pour les secrets détectés dans les fichiers APK.
Garantit qu'aucun secret complet n'est jamais exposé dans les résultats.
"""

import math
import re


# Longueur minimale en dessous de laquelle une valeur n'est pas masquée
# mais simplement ignorée (trop courte pour être un vrai secret).
MINIMUM_SECRET_LENGTH = 8

# Caractère utilisé pour masquer la partie centrale du secret.
MASK_CHAR = "*"


def is_value_too_short(value: str) -> bool:
    """
    Vérifie si une valeur est trop courte pour être un secret réel.

    Args:
        value: Valeur à évaluer.

    Returns:
        True si la valeur est trop courte, False sinon.
    """
    return len(value.strip()) < MINIMUM_SECRET_LENGTH


def calculate_entropy(value: str) -> float:
    """
    Calcule l'entropie de Shannon d'une chaîne de caractères.
    Une entropie élevée (> 3.5) indique une valeur potentiellement secrète.

    Args:
        value: Chaîne dont l'entropie doit être calculée.

    Returns:
        Valeur d'entropie (float). Retourne 0.0 si la chaîne est vide.

    Exemple:
        "aaaa"           → ~0.0  (faible entropie, répétitif)
        "AIzaSy1Abc..."  → ~4.5  (haute entropie, secret probable)
    """
    if not value:
        return 0.0

    # Comptage des fréquences de chaque caractère
    frequencies: dict[str, int] = {}
    for char in value:
        frequencies[char] = frequencies.get(char, 0) + 1

    length = len(value)
    entropy = 0.0

    for count in frequencies.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def mask_secret(value: str, visible_start: int = 6, visible_end: int = 2) -> str:
    """
    Masque la partie centrale d'un secret en conservant uniquement
    les premiers et derniers caractères visibles.

    Args:
        value: Valeur secrète à masquer.
        visible_start: Nombre de caractères visibles au début.
        visible_end: Nombre de caractères visibles à la fin.

    Returns:
        Valeur masquée. Ex: "AIzaSyFakeKey123456789" → "AIzaSy********89"

    Note:
        Si la valeur est trop courte, le masquage total est appliqué.
    """
    value = value.strip()

    if is_value_too_short(value):
        return MASK_CHAR * 8

    total = len(value)

    # Si la valeur est très courte, on réduit les parties visibles
    if total <= visible_start + visible_end + 2:
        visible_start = 2
        visible_end = 1

    start_part = value[:visible_start]
    end_part = value[total - visible_end:] if visible_end > 0 else ""
    masked_middle = MASK_CHAR * 8

    return f"{start_part}{masked_middle}{end_part}"


def mask_token(value: str) -> str:
    """
    Masque spécifiquement les tokens (Bearer, JWT, access tokens, etc.).
    Conserve un préfixe légèrement plus long pour l'identification.

    Args:
        value: Token à masquer.

    Returns:
        Token masqué. Ex: "eyJhbGciOiJIUzI1NiIs..." → "eyJhbG********"

    Note:
        Le préfixe "eyJ" est caractéristique des tokens JWT encodés en Base64.
    """
    value = value.strip()

    if is_value_too_short(value):
        return MASK_CHAR * 8

    # Conserver les 7 premiers caractères pour permettre l'identification du type
    return mask_secret(value, visible_start=7, visible_end=0)


def safe_preview(value: str) -> str:
    """
    Retourne un aperçu sécurisé et court d'une valeur sensible,
    adapté pour les logs ou les messages d'information.

    Args:
        value: Valeur dont on veut un aperçu sécurisé.

    Returns:
        Aperçu tronqué. Ex: "password123456" → "passwo..."
    """
    value = value.strip()

    if not value:
        return "[vide]"

    if is_value_too_short(value):
        return "[valeur trop courte]"

    preview_length = min(6, len(value))
    return value[:preview_length] + "..."


def mask_bearer_line(line: str) -> str:
    """
    Masque un token Bearer dans une ligne de texte complète.
    Utile pour afficher une ligne de contexte sans exposer le token.

    Args:
        line: Ligne contenant potentiellement un token Bearer.

    Returns:
        Ligne avec le token Bearer masqué.
    """
    pattern = re.compile(
        r'(Bearer\s+)([A-Za-z0-9\-_\.]+)',
        re.IGNORECASE
    )

    def replace_token(match: re.Match) -> str:
        prefix = match.group(1)
        token = match.group(2)
        return prefix + mask_token(token)

    return pattern.sub(replace_token, line)