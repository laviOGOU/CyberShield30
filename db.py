"""
db.py — Télémétrie anonymisée (SQLite).

Principes retenus :

* **Toutes les requêtes sont paramétrées** (`?`) : aucune valeur utilisateur n'est
  concaténée dans du SQL.
* **Aucune donnée personnelle** n'est stockée : ni mot de passe, ni adresse
  e-mail, ni adresse IP. L'empreinte du navigateur est hachée avant écriture.
* **Journal borné** : la table `telemetry` est élaguée pour que la base ne
  grossisse pas indéfiniment.
* **Dégradation propre** : si le disque est en lecture seule (certaines
  plateformes d'hébergement), les fonctions renvoient des valeurs neutres au
  lieu de faire planter l'application.
"""
import logging
import sqlite3
import threading
from contextlib import contextmanager
from typing import Dict, Iterator, List, Optional, Tuple

logger = logging.getLogger("CyberShield.db")

DB_PATH = "cybershield_data.db"
MAX_TELEMETRY_ROWS = 5000
_LOCK = threading.Lock()

METRIC_KEYS = (
    "visites_totales",
    "tests_mdp",
    "mdp_forts",
    "mdp_moyens",
    "mdp_faibles",
    "mdp_compromis",
    "tests_email",
    "emails_compromis",
)


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    """
    Ouvre une connexion configurée et la ferme systématiquement.

    `timeout` + WAL : Streamlit exécute plusieurs sessions en parallèle, une
    écriture concurrente peut sinon échouer immédiatement avec « database is
    locked ».
    """
    connection = sqlite3.connect(DB_PATH, timeout=10.0)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db() -> bool:
    """Crée les tables si nécessaire. Retourne False si la base est inutilisable."""
    try:
        with _LOCK, _connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    detail TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metrics (
                    metric_key TEXT PRIMARY KEY,
                    metric_value INTEGER DEFAULT 0
                )
                """
            )
            conn.executemany(
                "INSERT OR IGNORE INTO metrics (metric_key, metric_value) VALUES (?, 0)",
                [(key,) for key in METRIC_KEYS],
            )
        return True
    except sqlite3.Error as exc:
        logger.error("Initialisation de la base impossible : %s", exc)
        return False


def increment_metric(key: str, amount: int = 1) -> None:
    """Incrémente un compteur. La clé est validée contre la liste connue."""
    if key not in METRIC_KEYS:
        logger.warning("Compteur inconnu ignoré : %r", key)
        return
    try:
        with _LOCK, _connect() as conn:
            conn.execute(
                "UPDATE metrics SET metric_value = metric_value + ? WHERE metric_key = ?",
                (int(amount), key),
            )
    except (sqlite3.Error, ValueError) as exc:
        logger.error("Mise à jour du compteur %s impossible : %s", key, exc)


def get_all_metrics() -> Dict[str, int]:
    """Retourne tous les compteurs, à zéro si la base est illisible."""
    empty = {key: 0 for key in METRIC_KEYS}
    try:
        with _connect() as conn:
            rows = conn.execute("SELECT metric_key, metric_value FROM metrics").fetchall()
        empty.update({str(k): int(v) for k, v in rows})
    except (sqlite3.Error, TypeError, ValueError) as exc:
        logger.error("Lecture des compteurs impossible : %s", exc)
    return empty


def log_event(event_type: str, detail: str = "", max_detail: int = 300) -> None:
    """
    Enregistre un événement.

    `detail` doit déjà être anonymisé par l'appelant (voir security.anonymize) :
    cette fonction ne fait que stocker ce qu'on lui donne.
    """
    if not event_type:
        return
    try:
        with _LOCK, _connect() as conn:
            conn.execute(
                "INSERT INTO telemetry (event_type, detail) VALUES (?, ?)",
                (str(event_type)[:60], str(detail)[:max_detail]),
            )
            # Élagage : on ne conserve que les MAX_TELEMETRY_ROWS plus récents.
            conn.execute(
                """
                DELETE FROM telemetry
                WHERE id <= (
                    SELECT MAX(id) FROM telemetry
                ) - ?
                """,
                (MAX_TELEMETRY_ROWS,),
            )
    except sqlite3.Error as exc:
        logger.error("Écriture du journal impossible : %s", exc)


def recent_events(limit: int = 8) -> List[Tuple[str, str, str]]:
    """Derniers événements, du plus récent au plus ancien."""
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT timestamp, event_type, detail FROM telemetry ORDER BY id DESC LIMIT ?",
                (max(1, min(int(limit), 100)),),
            ).fetchall()
        return [(str(a), str(b), str(c or "")) for a, b, c in rows]
    except (sqlite3.Error, ValueError) as exc:
        logger.error("Lecture du journal impossible : %s", exc)
        return []


def password_distribution() -> Dict[str, int]:
    """Répartition des mots de passe évalués (forts / moyens / faibles)."""
    metrics = get_all_metrics()
    return {
        "strong": metrics.get("mdp_forts", 0),
        "medium": metrics.get("mdp_moyens", 0),
        "weak": metrics.get("mdp_faibles", 0),
    }


def is_available() -> bool:
    """Indique si la persistance fonctionne (base créée et accessible)."""
    try:
        with _connect() as conn:
            conn.execute("SELECT 1 FROM metrics LIMIT 1")
        return True
    except sqlite3.Error:
        return False
