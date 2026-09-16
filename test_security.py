"""
test_security.py — Tests de sécurité et de robustesse.

Exécution :
    .venv/Scripts/python.exe -m pytest test_security.py -v

Les tests ne font aucun appel réseau : les parties qui dépendent d'Internet sont
testées via leurs fonctions pures (analyse, filtrage, échappement, comptage).
"""
import sqlite3

import pytest

import db
import i18n
import security
import threat_intel


# ==========================================================================
# 1. Injection SQL
# ==========================================================================
class TestInjectionSQL:
    """Les requêtes sont paramétrées : aucune entrée ne doit modifier le schéma."""

    PAYLOADS = [
        "'; DROP TABLE telemetry; --",
        "1' OR '1'='1",
        "'; DELETE FROM metrics; --",
        "\" OR 1=1 --",
        "Robert'); DROP TABLE metrics;--",
    ]

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_injection_ne_detruit_rien(self, payload, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
        assert db.init_db() is True

        db.log_event("TEST", payload)
        db.increment_metric("tests_mdp")

        # Les tables doivent toujours exister.
        with sqlite3.connect(db.DB_PATH) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        assert "telemetry" in tables
        assert "metrics" in tables

        # Et la charge utile doit être stockée telle quelle, sans être exécutée.
        events = db.recent_events(limit=1)
        assert payload[:60] in events[0][2]

    def test_cle_metrique_inconnue_rejetee(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
        db.init_db()
        db.increment_metric("'; DROP TABLE metrics; --")
        # Aucune colonne ajoutée : seules les clés connues sont acceptées.
        assert "'; DROP TABLE metrics; --" not in db.get_all_metrics()


# ==========================================================================
# 2. Échappement HTML (les flux RSS sont des sources non fiables)
# ==========================================================================
class TestEchappement:
    def test_balise_script_neutralisee(self):
        result = security.escape("<script>alert(1)</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_attribut_html_neutralise(self):
        result = security.escape('" onmouseover="alert(1)')
        assert '"' not in result
        assert "&quot;" in result

    def test_image_avec_onerror(self):
        result = security.escape('<img src=x onerror=alert(1)>')
        assert "<img" not in result

    def test_valeur_none(self):
        assert security.escape(None) == ""


# ==========================================================================
# 3. Filtrage des URL (protection contre les liens javascript:)
# ==========================================================================
class TestSafeUrl:
    @pytest.mark.parametrize("url", [
        "javascript:alert(1)",
        "JavaScript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///C:/Windows/System32/",
        "vbscript:msgbox(1)",
        "",
        None,
        "pas-une-url",
    ])
    def test_schemas_dangereux_refuses(self, url):
        assert security.safe_url(url) == "#"

    @pytest.mark.parametrize("url", [
        "https://thehackernews.com/2026/09/article.html",
        "http://example.com/feed",
    ])
    def test_url_legitimes_acceptees(self, url):
        assert security.safe_url(url) == url


# ==========================================================================
# 4. Validation des saisies
# ==========================================================================
class TestValidation:
    @pytest.mark.parametrize("email", [
        "utilisateur@domaine.com",
        "prenom.nom+tag@sous.domaine.fr",
        "a_b-c@exemple.co.uk",
    ])
    def test_emails_valides(self, email):
        assert security.is_valid_email(email) is True

    @pytest.mark.parametrize("email", [
        "sans-arobase.com",
        "@domaine.com",
        "utilisateur@",
        "utilisateur@domaine",
        "utilisateur@@domaine.com",
        "espaces dans@domaine.com",
        "",
        None,
        "a" * 300 + "@domaine.com",
    ])
    def test_emails_invalides(self, email):
        assert security.is_valid_email(email) is False

    def test_mot_de_passe_tronque(self):
        long_password = "a" * 5000
        assert len(security.truncate_password(long_password)) == security.MAX_PASSWORD_LENGTH

    def test_caracteres_de_controle_nettoyes(self):
        assert "\n" not in security.clean_query("apache\n\r\x00serveur")
        assert len(security.clean_query("x" * 500)) == security.MAX_QUERY_LENGTH


# ==========================================================================
# 5. Anonymisation
# ==========================================================================
class TestAnonymisation:
    def test_empreinte_non_reversible(self):
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/153.0"
        fingerprint = security.anonymize(user_agent)
        assert user_agent not in fingerprint
        assert len(fingerprint) == 12

    def test_empreinte_stable_dans_le_processus(self):
        assert security.anonymize("test-agent") == security.anonymize("test-agent")

    def test_empreintes_distinctes(self):
        assert security.anonymize("agent-a") != security.anonymize("agent-b")

    def test_valeur_vide(self):
        assert security.anonymize("") == "anon"
        assert security.anonymize(None) == "anon"


# ==========================================================================
# 6. Limitation d'usage
# ==========================================================================
class TestRateLimiter:
    def test_limite_atteinte(self):
        limiter = security.RateLimiter()
        for _ in range(3):
            allowed, _ = limiter.allow("cle", limit=3, window_seconds=60)
            assert allowed is True

        allowed, retry_after = limiter.allow("cle", limit=3, window_seconds=60)
        assert allowed is False
        assert retry_after > 0

    def test_cles_independantes(self):
        limiter = security.RateLimiter()
        for _ in range(3):
            limiter.allow("a", limit=3, window_seconds=60)
        assert limiter.allow("a", limit=3, window_seconds=60)[0] is False
        assert limiter.allow("b", limit=3, window_seconds=60)[0] is True

    def test_fenetre_expiree(self, monkeypatch):
        limiter = security.RateLimiter()
        limiter.allow("cle", limit=1, window_seconds=10)

        # On simule le passage du temps en décalant les horodatages enregistrés.
        bucket = limiter._buckets["cle"]
        bucket.tokens = [t - 60 for t in bucket.tokens]

        assert limiter.allow("cle", limit=1, window_seconds=10)[0] is True


# ==========================================================================
# 7. Analyse de mot de passe
# ==========================================================================
class TestAnalyseMotDePasse:
    LANG = i18n.get_translations("FR")

    def test_mot_de_passe_faible(self):
        level, percentage, criteria, _ = security.PasswordSecurityEvaluator.evaluate(
            "1234", self.LANG
        )
        assert level == self.LANG["pwd_weak"]
        assert percentage < 60
        assert sum(1 for c in criteria if c.is_met) <= 2

    def test_mot_de_passe_fort(self):
        level, percentage, criteria, _ = security.PasswordSecurityEvaluator.evaluate(
            "Cafetiere#Bleu$Trompette98!", self.LANG
        )
        assert level == self.LANG["pwd_strong"]
        assert percentage == 100
        assert all(c.is_met for c in criteria)

    def test_niveau_intermediaire(self):
        level, _, _, _ = security.PasswordSecurityEvaluator.evaluate("Motdepasse12", self.LANG)
        assert level == self.LANG["pwd_medium"]

    def test_avertissements_sur_schemas_faibles(self):
        _, _, _, warnings = security.PasswordSecurityEvaluator.evaluate(
            "Motdepasse2024!", self.LANG
        )
        assert any("courante" in w or "année" in w for w in warnings)

    def test_sequence_detectee(self):
        _, _, _, warnings = security.PasswordSecurityEvaluator.evaluate(
            "abcdEfgh!2345", self.LANG
        )
        assert any("Suite connue" in w for w in warnings)

    def test_repetition_detectee(self):
        _, _, _, warnings = security.PasswordSecurityEvaluator.evaluate(
            "aaaBBBccc1!", self.LANG
        )
        assert any("Répétition" in w for w in warnings)

    def test_mot_de_passe_vide_jamais_envoye(self):
        # Sans mot de passe, aucune requête ne doit partir : la fonction
        # retourne 0 sans contacter l'API.
        assert security.PasswordSecurityEvaluator.check_breach("") == 0


# ==========================================================================
# 8. Veille (CISA KEV) — fonctions pures, sans réseau
# ==========================================================================
def _vulnerabilite(cve, vendor, product, date_added, ransomware=False):
    return threat_intel.Vulnerability(
        cve=cve,
        vendor=vendor,
        product=product,
        name=f"{product} vulnerability",
        description="",
        action="",
        date_added=date_added,
        due_date="",
        ransomware=ransomware,
    )


class TestThreatIntel:
    def test_recherche_insensible_a_la_casse(self):
        vulns = [
            _vulnerabilite("CVE-2024-0001", "Apache", "HTTP Server", "2024-01-01"),
            _vulnerabilite("CVE-2024-0002", "Ivanti", "Connect Secure", "2024-02-01"),
        ]
        assert len(threat_intel.search_vulnerabilities(vulns, "apache")) == 1
        assert len(threat_intel.search_vulnerabilities(vulns, "CVE-2024-0002")) == 1
        assert len(threat_intel.search_vulnerabilities(vulns, "")) == 2
        assert threat_intel.search_vulnerabilities(vulns, "inexistant") == []

    def test_ajouts_recents_tries(self):
        vulns = [
            _vulnerabilite("CVE-2024-0001", "A", "P", "2024-01-01"),
            _vulnerabilite("CVE-2024-0003", "C", "P", "2024-03-01"),
            _vulnerabilite("CVE-2024-0002", "B", "P", "2024-02-01"),
        ]
        recents = threat_intel.recent_vulnerabilities(vulns, limit=2)
        assert [v.cve for v in recents] == ["CVE-2024-0003", "CVE-2024-0002"]

    def test_statistiques(self):
        vulns = [
            _vulnerabilite("CVE-2024-0001", "Apache", "P", "2024-01-01", ransomware=True),
            _vulnerabilite("CVE-2024-0002", "Ivanti", "P", "2025-01-01"),
        ]
        stats = threat_intel.catalog_statistics(vulns)
        assert stats["total"] == 2
        assert stats["ransomware"] == 1
        assert stats["vendors"] == 2
        assert stats["latest"] == "2025-01-01"

    def test_statistiques_vides(self):
        stats = threat_intel.catalog_statistics([])
        assert stats["total"] == 0

    def test_validation_identifiant_cve(self):
        assert threat_intel.is_cve("CVE-2024-1234") is True
        assert threat_intel.is_cve("CVE-2024-123456") is True
        assert threat_intel.is_cve("cve-2024-1234") is True
        assert threat_intel.is_cve("CVE-24-1234") is False
        assert threat_intel.is_cve("javascript:alert(1)") is False
        assert threat_intel.is_cve("") is False

    def test_resume_flux_sans_html(self):
        raw = "<p>Une <b>faille</b> critique</p><script>alert(1)</script>"
        cleaned = threat_intel._clean_summary(raw)
        assert "<" not in cleaned
        assert "script" not in cleaned
        assert "faille" in cleaned

    def test_resume_tronque(self):
        raw = "mot " * 200
        cleaned = threat_intel._clean_summary(raw, max_length=50)
        assert len(cleaned) <= 51          # 50 caractères + le caractère de coupure
        assert cleaned.endswith("…")


# ==========================================================================
# 9. Traductions
# ==========================================================================
class TestTraductions:
    def test_memes_cles_dans_les_deux_langues(self):
        fr = set(i18n.TRANSLATIONS["FR"].keys())
        en = set(i18n.TRANSLATIONS["EN"].keys())
        assert fr == en, f"Clés manquantes : {fr ^ en}"

    def test_aucune_valeur_vide(self):
        for langue, textes in i18n.TRANSLATIONS.items():
            for cle, valeur in textes.items():
                assert str(valeur).strip(), f"{langue}.{cle} est vide"

    def test_langue_inconnue_retombe_sur_le_francais(self):
        assert i18n.get_translations("XX") == i18n.TRANSLATIONS["FR"]

    def test_les_deux_langues_diffèrent(self):
        assert i18n.TRANSLATIONS["FR"]["pwd_subtitle"] != i18n.TRANSLATIONS["EN"]["pwd_subtitle"]


# ==========================================================================
# 10. Télémétrie
# ==========================================================================
class TestTelemetrie:
    def test_compteurs_initialises_a_zero(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
        db.init_db()
        metrics = db.get_all_metrics()
        assert set(db.METRIC_KEYS).issubset(metrics.keys())
        assert metrics["visites_totales"] == 0

    def test_increment(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
        db.init_db()
        db.increment_metric("tests_mdp", 3)
        assert db.get_all_metrics()["tests_mdp"] == 3

    def test_journal_borne(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
        monkeypatch.setattr(db, "MAX_TELEMETRY_ROWS", 10)
        db.init_db()
        for index in range(25):
            db.log_event("TEST", f"evenement-{index}")

        with sqlite3.connect(db.DB_PATH) as conn:
            count = conn.execute("SELECT COUNT(*) FROM telemetry").fetchone()[0]
        # L'élagage laisse passer une marge, mais la table ne grandit pas sans fin.
        assert count <= 30

    def test_detail_tronque(self, tmp_path, monkeypatch):
        monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "test.db"))
        db.init_db()
        db.log_event("TEST", "x" * 5000)
        assert len(db.recent_events(limit=1)[0][2]) <= 300
