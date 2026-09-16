"""
security.py — Validation, anonymisation, limitation d'usage et services d'audit.

Ce module regroupe tout ce qui touche à la sécurité de l'application :

* **validation et nettoyage** des entrées utilisateur ;
* **échappement HTML** de toute donnée d'origine externe (flux RSS, API) avant
  affichage — indispensable puisque l'interface utilise `unsafe_allow_html` ;
* **filtrage des URL** : seuls les schémas http(s) sont acceptés, ce qui bloque
  les liens `javascript:` qu'un flux compromis pourrait injecter ;
* **anonymisation** : aucune donnée personnelle n'est stockée en clair, les
  empreintes sont hachées avec un sel propre au processus ;
* **limitation d'usage** : les API publiques gratuites (Pwned Passwords,
  xposedornot) sont partagées, une limite par session évite de les saturer ;
* **services d'audit** : robustesse d'un mot de passe et exposition d'un e-mail.
"""
import hashlib
import html
import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

logger = logging.getLogger("CyberShield.security")

# --------------------------------------------------------------------------
# Limites de saisie
# --------------------------------------------------------------------------
MAX_PASSWORD_LENGTH = 256      # au-delà, on tronque : évite un hachage abusif
MAX_EMAIL_LENGTH = 254         # longueur maximale d'une adresse e-mail
MAX_QUERY_LENGTH = 120         # champs de recherche / filtre

# Sel aléatoire régénéré à chaque démarrage : les empreintes stockées ne
# permettent pas de remonter à la valeur d'origine (pas de table de hachage
# réutilisable d'une exécution à l'autre).
_PROCESS_SALT = secrets.token_bytes(16)

# Expression de validation d'adresse e-mail : volontairement stricte mais
# lisible, et surtout ancrée (re.fullmatch) pour éviter les chaînes partielles.
EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
)

# Séparateurs de la réponse de l'API Pwned Passwords
_HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_XPOSED_URL = "https://api.xposedornot.com/v1/check-email/{email}"
_USER_AGENT = "CyberShield/3.0 (outil pedagogique d'audit)"


# ==========================================================================
# 1. Échappement et validation
# ==========================================================================
def escape(value) -> str:
    """
    Échappe une donnée d'origine externe avant insertion dans du HTML.

    Indispensable : un flux RSS compromis pourrait injecter du balisage
    (faux bouton de connexion, iframe, etc.) dans l'interface.
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def safe_url(url: Optional[str]) -> str:
    """
    Retourne l'URL si son schéma est http(s), sinon '#'.

    Bloque notamment `javascript:`, `data:` et `file:`, qui permettraient une
    exécution de code ou une fuite locale si un lien provient d'une source
    non fiable.
    """
    if not url:
        return "#"
    try:
        parsed = urlparse(str(url).strip())
    except ValueError:
        return "#"
    if parsed.scheme.lower() not in ("http", "https"):
        return "#"
    if not parsed.netloc:
        return "#"
    return str(url).strip()


def clean_query(text: Optional[str], max_length: int = MAX_QUERY_LENGTH) -> str:
    """Nettoie un champ de recherche : supprime les caractères de contrôle."""
    if not text:
        return ""
    # Les caractères de contrôle (dont les retours à la ligne) n'ont rien à
    # faire dans un filtre et peuvent perturber l'affichage.
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", str(text))
    return cleaned.strip()[:max_length]


def truncate_password(password: Optional[str]) -> str:
    """Borne la longueur du mot de passe traité (protection contre l'abus)."""
    if not password:
        return ""
    return password[:MAX_PASSWORD_LENGTH]


def is_valid_email(email: Optional[str]) -> bool:
    """Valide une adresse e-mail par correspondance complète (ancrée)."""
    if not email or len(email) > MAX_EMAIL_LENGTH:
        return False
    return EMAIL_PATTERN.fullmatch(email.strip()) is not None


def anonymize(value: Optional[str], length: int = 12) -> str:
    """
    Retourne une empreinte non réversible d'une donnée personnelle.

    Utilisé pour le User-Agent : on conserve la possibilité de compter des
    navigateurs distincts sans stocker de donnée identifiante.
    """
    if not value:
        return "anon"
    digest = hashlib.sha256(_PROCESS_SALT + str(value).encode("utf-8", "replace"))
    return digest.hexdigest()[:length]


# ==========================================================================
# 2. Limitation d'usage (protège les API publiques et la plateforme)
# ==========================================================================
@dataclass
class _Bucket:
    tokens: List[float]
    limit: int
    window_seconds: int


class RateLimiter:
    """
    Limiteur par fenêtre glissante, en mémoire.

    Objectif : les API utilisées sont gratuites et partagées. Sans limite, une
    seule personne peut épuiser le quota pour tout le monde (et faire bloquer
    l'application par l'API).
    """

    def __init__(self) -> None:
        self._buckets: Dict[str, _Bucket] = {}

    def allow(self, key: str, limit: int, window_seconds: int) -> Tuple[bool, int]:
        """
        Enregistre une utilisation si la limite n'est pas atteinte.

        Retourne (autorisé, secondes_avant_nouvelle_tentative).
        """
        now = time.monotonic()
        bucket = self._buckets.get(key)
        if bucket is None or bucket.limit != limit or bucket.window_seconds != window_seconds:
            bucket = _Bucket(tokens=[], limit=limit, window_seconds=window_seconds)
            self._buckets[key] = bucket

        # On ne garde que les événements de la fenêtre courante.
        bucket.tokens = [t for t in bucket.tokens if now - t < bucket.window_seconds]
        if len(bucket.tokens) >= bucket.limit:
            oldest = min(bucket.tokens)
            retry_after = int(bucket.window_seconds - (now - oldest)) + 1
            return False, max(retry_after, 1)

        bucket.tokens.append(now)
        return True, 0


rate_limiter = RateLimiter()


# ==========================================================================
# 3. Service d'audit de mot de passe
# ==========================================================================
@dataclass
class PasswordCriterion:
    """Un critère de complexité et la recommandation associée s'il n'est pas rempli."""

    description: str
    is_met: bool
    recommendation: str


class PasswordSecurityEvaluator:
    """Évalue la robustesse d'un mot de passe, sans jamais le transmettre."""

    # Suites évidentes : très fréquentes dans les dictionnaires d'attaque.
    # On teste des fenêtres de 4 caractères, sinon la comparaison ne peut jamais
    # correspondre (aucun mot de passe ne contient l'alphabet entier).
    _SEQUENCES = (
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiop",
        "azertyuiop",
    )
    _SEQUENCE_WINDOW = 4

    @staticmethod
    def _has_sequence(lowered_password: str) -> bool:
        """Vrai si le mot de passe contient une suite de 4+ caractères consécutifs."""
        for sequence in PasswordSecurityEvaluator._SEQUENCES:
            for index in range(len(sequence) - PasswordSecurityEvaluator._SEQUENCE_WINDOW + 1):
                if sequence[index:index + PasswordSecurityEvaluator._SEQUENCE_WINDOW] in lowered_password:
                    return True
        return False

    @staticmethod
    def evaluate(
        password: str, lang_dict: dict
    ) -> Tuple[str, float, List[PasswordCriterion], List[str]]:
        """
        Retourne (niveau, pourcentage, critères, avertissements).

        Les avertissements signalent des schémas faibles que la seule présence
        de majuscules ou de chiffres ne suffit pas à rattraper.
        """
        password = truncate_password(password)

        criteria = [
            PasswordCriterion(lang_dict["c_len"], len(password) >= 12, lang_dict["c_len_rec"]),
            PasswordCriterion(lang_dict["c_upper"], bool(re.search(r"[A-Z]", password)), lang_dict["c_upper_rec"]),
            PasswordCriterion(lang_dict["c_lower"], bool(re.search(r"[a-z]", password)), lang_dict["c_lower_rec"]),
            PasswordCriterion(lang_dict["c_num"], bool(re.search(r"[0-9]", password)), lang_dict["c_num_rec"]),
            PasswordCriterion(
                lang_dict["c_sym"],
                bool(re.search(r"[^A-Za-z0-9]", password)),
                lang_dict["c_sym_rec"],
            ),
        ]

        score = sum(1 for c in criteria if c.is_met)
        percentage = (score / len(criteria)) * 100

        if score >= 5:
            level = lang_dict["pwd_strong"]
        elif score >= 3:
            level = lang_dict["pwd_medium"]
        else:
            level = lang_dict["pwd_weak"]

        return level, percentage, criteria, PasswordSecurityEvaluator._warnings(password)

    @staticmethod
    def _warnings(password: str) -> List[str]:
        """Détecte les schémas faibles que les critères de base laissent passer."""
        warnings: List[str] = []
        lowered = password.lower()

        if len(set(password)) <= 4 and len(password) >= 8:
            warnings.append("Jeu de caractères très limité : le mot de passe se devine par répétition.")
        if re.search(r"(.)\1{2,}", password):
            warnings.append("Répétitions de caractères consécutives (ex. « aaa »).")
        if PasswordSecurityEvaluator._has_sequence(lowered):
            warnings.append("Suite connue du clavier ou de l'alphabet (ex. « abc », « 1234 »).")
        if re.match(r"^[A-Z][a-z]+[0-9]{1,4}[!@#$%^&*]?$", password):
            warnings.append("Structure très courante (Majuscule + mot + chiffres) : c'est le premier schéma testé par les outils de cassage.")
        if re.search(r"(19|20)\d{2}", password):
            warnings.append("Contient une année : information souvent devinable.")
        return warnings

    @staticmethod
    def check_breach(password: str, timeout: float = 6.0) -> Optional[int]:
        """
        Vérifie l'exposition d'un mot de passe via le k-anonymat.

        Seuls les **5 premiers caractères** de l'empreinte SHA-1 sont envoyés à
        l'API ; celle-ci renvoie ensuite tous les suffixes correspondants, et la
        comparaison finale se fait localement. Le mot de passe n'est donc jamais
        transmis, ni même son empreinte complète.

        Retourne le nombre d'occurrences connues, 0 si absent, None si l'API est
        injoignable.
        """
        password = truncate_password(password)
        if not password:
            return 0

        # `usedforsecurity=False` : SHA-1 est imposé par le protocole de l'API,
        # il ne sert pas à protéger une donnée mais à interroger un index public.
        digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]

        try:
            response = requests.get(
                _HIBP_URL.format(prefix=prefix),
                headers={"User-Agent": _USER_AGENT, "Add-Padding": "true"},
                timeout=timeout,
            )
        except requests.RequestException as exc:
            logger.warning("API Pwned Passwords injoignable : %s", exc)
            return None

        if response.status_code != 200:
            logger.warning("API Pwned Passwords a répondu %s", response.status_code)
            return None

        for line in response.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip().upper() == suffix:
                try:
                    return int(parts[1])
                except ValueError:
                    return None

        return 0


# ==========================================================================
# 4. Service d'audit d'exposition d'e-mail
# ==========================================================================
class EmailBreachEvaluator:
    """Recherche une adresse e-mail dans les violations de données publiques."""

    @staticmethod
    def check_breaches(email: str, timeout: float = 8.0) -> Tuple[Optional[bool], List[str], Optional[str]]:
        """
        Retourne (compromis, services, erreur).

        Le premier élément vaut True, False ou None (vérification impossible).
        """
        if not is_valid_email(email):
            return None, [], "invalid_email"

        try:
            response = requests.get(
                _XPOSED_URL.format(email=email.strip()),
                headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
                timeout=timeout,
            )
        except requests.RequestException as exc:
            logger.warning("API xposedornot injoignable : %s", exc)
            return None, [], "network"

        if response.status_code == 404:
            return False, [], None
        if response.status_code == 429:
            return None, [], "rate_limited"
        if response.status_code != 200:
            return None, [], f"http_{response.status_code}"

        try:
            data = response.json()
        except ValueError:
            return None, [], "bad_payload"

        breaches_raw = data.get("breaches") or []
        # L'API peut renvoyer une liste de listes ; on remet à plat.
        names: List[str] = []
        for item in breaches_raw:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, (list, tuple)):
                names.extend(str(x) for x in item if x)

        if names:
            return True, names, None
        return False, [], None
