"""
threat_intel.py — Veille sécurité en temps réel.

Deux sources complémentaires :

* **Catalogue CISA KEV** (Known Exploited Vulnerabilities) : la liste officielle
  des vulnérabilités dont l'exploitation a été observée dans la nature. Publiée
  en JSON par la CISA, mise à jour en continu, sans clé d'API.
* **Flux RSS** d'actualité sécurité : The Hacker News, BleepingComputer,
  CERT-FR (ANSSI) et les avis de la CISA.

Ce module est volontairement pur Python (aucune dépendance à Streamlit) : il est
donc directement testable, et la mise en cache est gérée par l'appelant.
"""
import logging
import re
from dataclasses import dataclass, field
from datetime import date, timezone
from typing import Dict, List, Optional, Tuple

import feedparser
import requests

logger = logging.getLogger("CyberShield.threat_intel")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

NEWS_SOURCES: Dict[str, str] = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "CERT-FR (ANSSI)": "https://www.cert.ssi.gouv.fr/feed/",
}

_USER_AGENT = "CyberShield/3.0 (outil pedagogique d'audit)"
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass
class Vulnerability:
    """Une entrée du catalogue KEV."""

    cve: str
    vendor: str
    product: str
    name: str
    description: str
    action: str
    date_added: str
    due_date: str
    ransomware: bool

    @property
    def date_added_iso(self) -> str:
        return self.date_added

    def matches(self, query: str) -> bool:
        """Recherche insensible à la casse dans les champs utiles."""
        if not query:
            return True
        needle = query.casefold()
        haystack = " ".join(
            (self.cve, self.vendor, self.product, self.name)
        ).casefold()
        return needle in haystack


@dataclass
class NewsArticle:
    """Un article issu d'un flux RSS."""

    source: str
    title: str
    link: str
    published: str
    summary: str = ""


@dataclass
class IntelResult:
    """Résultat complet d'une collecte, avec les erreurs par source."""

    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    articles: List[NewsArticle] = field(default_factory=list)
    catalog_version: str = ""
    catalog_date: str = ""
    errors: Dict[str, str] = field(default_factory=dict)


# ==========================================================================
# Catalogue CISA KEV
# ==========================================================================
def fetch_kev_catalog(timeout: float = 20.0) -> Tuple[List[Vulnerability], str, str, Optional[str]]:
    """
    Télécharge et convertit le catalogue KEV.

    Retourne (vulnérabilités, version du catalogue, date de publication, erreur).
    Ne lève jamais : en cas d'échec, la liste est vide et l'erreur est renvoyée
    pour être affichée à l'utilisateur.
    """
    try:
        response = requests.get(
            KEV_URL,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        message = f"Réseau indisponible ({type(exc).__name__})"
        logger.warning("Catalogue KEV injoignable : %s", exc)
        return [], "", "", message

    if response.status_code != 200:
        message = f"HTTP {response.status_code}"
        logger.warning("Catalogue KEV : %s", message)
        return [], "", "", message

    try:
        payload = response.json()
    except ValueError as exc:
        logger.warning("Catalogue KEV illisible : %s", exc)
        return [], "", "", "Réponse JSON illisible"

    vulnerabilities: List[Vulnerability] = []
    for item in payload.get("vulnerabilities", []):
        try:
            vulnerabilities.append(
                Vulnerability(
                    cve=str(item.get("cveID", "")),
                    vendor=str(item.get("vendorProject", "")),
                    product=str(item.get("product", "")),
                    name=str(item.get("vulnerabilityName", "")),
                    description=str(item.get("shortDescription", "")),
                    action=str(item.get("requiredAction", "")),
                    date_added=str(item.get("dateAdded", "")),
                    due_date=str(item.get("dueDate", "")),
                    ransomware=str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
                )
            )
        except (AttributeError, TypeError):
            continue

    return (
        vulnerabilities,
        str(payload.get("catalogVersion", "")),
        str(payload.get("dateReleased", "")),
        None,
    )


def recent_vulnerabilities(vulnerabilities: List[Vulnerability], limit: int = 12) -> List[Vulnerability]:
    """Les `limit` vulnérabilités ajoutées le plus récemment."""
    ordered = sorted(vulnerabilities, key=lambda v: v.date_added, reverse=True)
    return ordered[:limit]


def search_vulnerabilities(
    vulnerabilities: List[Vulnerability], query: str, limit: int = 40
) -> List[Vulnerability]:
    """Filtre le catalogue ; les résultats sont triés du plus récent au plus ancien."""
    matching = [v for v in vulnerabilities if v.matches(query)]
    matching.sort(key=lambda v: v.date_added, reverse=True)
    return matching[:limit]


def catalog_statistics(vulnerabilities: List[Vulnerability]) -> Dict[str, object]:
    """Quelques indicateurs affichables en tête de l'onglet Menaces."""
    if not vulnerabilities:
        return {"total": 0, "ransomware": 0, "vendors": 0, "latest": "", "this_year": 0}

    ransomware = sum(1 for v in vulnerabilities if v.ransomware)
    vendors = {v.vendor for v in vulnerabilities if v.vendor}
    latest = max((v.date_added for v in vulnerabilities), default="")
    current_year = str(date.today().year)
    this_year = sum(1 for v in vulnerabilities if v.date_added.startswith(current_year))

    return {
        "total": len(vulnerabilities),
        "ransomware": ransomware,
        "vendors": len(vendors),
        "latest": latest,
        "this_year": this_year,
    }


# ==========================================================================
# Flux RSS d'actualité
# ==========================================================================
def _clean_summary(raw: str, max_length: int = 220) -> str:
    """Retire le balisage HTML d'un résumé de flux et borne sa longueur."""
    if not raw:
        return ""
    without_tags = re.sub(r"<[^>]+>", " ", raw)
    collapsed = re.sub(r"\s+", " ", without_tags).strip()
    if len(collapsed) <= max_length:
        return collapsed
    return collapsed[:max_length].rsplit(" ", 1)[0] + "…"


def fetch_news(timeout: float = 10.0, per_source: int = 5) -> Tuple[List[NewsArticle], Dict[str, str]]:
    """
    Récupère les derniers articles de chaque source.

    Retourne (articles, erreurs) — une source en panne n'empêche pas les autres
    de remonter, et l'erreur est rapportée telle quelle.
    """
    articles: List[NewsArticle] = []
    errors: Dict[str, str] = {}

    for source, url in NEWS_SOURCES.items():
        try:
            # On passe par requests pour maîtriser le délai et l'en-tête :
            # feedparser.parse(url) n'expose ni timeout explicite ni User-Agent.
            response = requests.get(
                url,
                headers={"User-Agent": _USER_AGENT, "Accept": "application/rss+xml, application/xml, text/xml"},
                timeout=timeout,
            )
            if response.status_code != 200:
                errors[source] = f"HTTP {response.status_code}"
                continue
            feed = feedparser.parse(response.content)
        except requests.RequestException as exc:
            errors[source] = f"{type(exc).__name__}"
            logger.warning("Flux %s injoignable : %s", source, exc)
            continue

        for entry in feed.entries[:per_source]:
            published = ""
            for key in ("published", "updated", "created"):
                value = entry.get(key)
                if value:
                    published = _format_feed_date(value)
                    break
            articles.append(
                NewsArticle(
                    source=source,
                    title=str(entry.get("title", "")).strip(),
                    link=str(entry.get("link", "")).strip(),
                    published=published,
                    summary=_clean_summary(str(entry.get("summary", ""))),
                )
            )

    return articles, errors


def _format_feed_date(value: str) -> str:
    """
    Convertit une date de flux RSS en libellé court lisible.

    Les flux utilisent le format RFC 822 (« Wed, 16 Sep 2026 11:18:20 +0000 »),
    que `email.utils` sait analyser nativement — inutile de passer par une
    fonction interne de feedparser.
    """
    try:
        from email.utils import parsedate_to_datetime

        parsed = parsedate_to_datetime(str(value))
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).strftime("%d/%m/%Y %H:%M")
    except (TypeError, ValueError, IndexError):
        pass
    except Exception:                                          # noqa: BLE001
        pass
    return str(value)[:24]


def collect(kev_timeout: float = 20.0, news_timeout: float = 10.0) -> IntelResult:
    """Collecte l'ensemble des sources et agrège les erreurs."""
    result = IntelResult()

    vulnerabilities, version, released, error = fetch_kev_catalog(timeout=kev_timeout)
    result.vulnerabilities = vulnerabilities
    result.catalog_version = version
    result.catalog_date = released
    if error:
        result.errors["CISA KEV"] = error

    articles, news_errors = fetch_news(timeout=news_timeout)
    result.articles = articles
    result.errors.update(news_errors)

    return result


def is_cve(value: str) -> bool:
    """Vrai si la chaîne est un identifiant CVE valide (utilisé pour les liens)."""
    return bool(_CVE_PATTERN.match(value.strip()))
