"""
test_app.py — Tests de l'application elle-même, via l'API de test de Streamlit.

`AppTest` exécute réellement app.py dans un processus isolé : on peut saisir des
valeurs, relancer le script et inspecter ce qui a été produit. C'est la façon
fiable de vérifier le comportement sans navigateur.

Deux fixtures :
  * `app`        — instance de lecture seule, partagée (démarrage coûteux)
  * `fresh_app`  — instance neuve par test, pour tout ce qui modifie l'état

Exécution :
    .venv/Scripts/python.exe -m pytest test_app.py -v
"""
import pytest
from streamlit.testing.v1 import AppTest

TIMEOUT = 120


@pytest.fixture(scope="module")
def app():
    instance = AppTest.from_file("app.py", default_timeout=TIMEOUT)
    instance.run()
    return instance


@pytest.fixture
def fresh_app():
    instance = AppTest.from_file("app.py", default_timeout=TIMEOUT)
    instance.run()
    return instance


# --------------------------------------------------------------------------
# Utilitaires d'inspection
# --------------------------------------------------------------------------
def markdown_of(instance) -> str:
    """Tout le balisage produit par st.markdown()."""
    return "\n".join(element.value for element in instance.markdown)


def text_of(instance) -> str:
    """Tout le texte visible, quelle que soit la fonction d'affichage."""
    parts = [markdown_of(instance)]
    parts += [element.value for element in instance.caption]
    parts += [element.value for element in instance.error]
    parts += [element.value for element in instance.warning]
    parts += [element.value for element in instance.success]
    parts += [element.value for element in instance.info]
    parts += [element.label for element in instance.text_input]
    return "\n".join(str(part) for part in parts)


def indented_markup(instance) -> list:
    """
    Repère les fragments de balisage qui seraient affichés en texte brut.

    Le markdown de Streamlit traite toute ligne indentée de 4 espaces — ou qui
    suit une ligne vide — comme un bloc de code : le HTML apparaît alors en
    clair dans la page. C'est exactement le défaut corrigé pendant la mise au
    point, d'où ce test de non-régression.
    """
    suspects = []
    for value in [element.value for element in instance.markdown]:
        for line in str(value).splitlines():
            if line.startswith(("    ", "\t")) and '<div class="cs-' in line:
                suspects.append(line.strip()[:80])
    return suspects


# ==========================================================================
# Démarrage
# ==========================================================================
class TestDemarrage:
    def test_aucune_exception(self, app):
        assert not app.exception, [str(e.value) for e in app.exception]

    def test_quatre_onglets(self, app):
        assert len(app.tabs) == 4

    def test_les_polices_du_theme_sont_chargees(self, app):
        html = markdown_of(app)
        assert "Space+Grotesk" in html
        assert "Figtree" in html
        assert "Instrument+Serif" in html

    def test_palette_sombre_appliquee(self, app):
        html = markdown_of(app)
        assert "#0a0e1a" in html
        assert "--cyan" in html

    def test_aucun_balisage_indente(self, app):
        assert indented_markup(app) == []

    def test_aucune_erreur_serveur_affichee(self, app):
        messages = [element.value for element in app.error]
        assert not any("Traceback" in str(m) for m in messages)


# ==========================================================================
# Onglet mot de passe et encart 1Password
# ==========================================================================
class TestOngletMotDePasse:
    def test_champ_vide_affiche_l_invite(self, app):
        assert "Saisissez un mot de passe" in text_of(app)

    def test_encart_1password_absent_avant_analyse(self, app):
        assert "1password.com" not in markdown_of(app)

    def test_encart_1password_apres_analyse(self, fresh_app):
        fresh_app.text_input(key="password_input").set_value("Cafetiere#Bleu$Trompette98!")
        fresh_app.run()

        assert not fresh_app.exception, [str(e.value) for e in fresh_app.exception]
        html = markdown_of(fresh_app)

        assert "1password.com" in html, "l'encart de redirection vers 1Password n'est pas rendu"
        assert "cs-cta" in html
        # Un lien sortant doit toujours s'ouvrir dans un nouvel onglet et sans
        # transmettre la page d'origine (rel=noopener noreferrer).
        assert 'rel="noopener noreferrer"' in html
        assert 'target="_blank"' in html

    def test_encart_1password_present_meme_si_mot_de_passe_faible(self, fresh_app):
        fresh_app.text_input(key="password_input").set_value("1234")
        fresh_app.run()
        assert "1password.com" in markdown_of(fresh_app)

    def test_verdict_fort_pour_un_mot_de_passe_robuste(self, fresh_app):
        fresh_app.text_input(key="password_input").set_value("Cafetiere#Bleu$Trompette98!")
        fresh_app.run()
        assert "Fort" in markdown_of(fresh_app)

    def test_verdict_faible_pour_un_mot_de_passe_court(self, fresh_app):
        fresh_app.text_input(key="password_input").set_value("1234")
        fresh_app.run()
        assert "Faible" in markdown_of(fresh_app)

    def test_les_cinq_criteres_sont_affiches(self, fresh_app):
        fresh_app.text_input(key="password_input").set_value("Motdepasse12")
        fresh_app.run()
        assert markdown_of(fresh_app).count('class="cs-criterion"') >= 5

    def test_mention_du_k_anonymat(self, fresh_app):
        fresh_app.text_input(key="password_input").set_value("Motdepasse12")
        fresh_app.run()
        captions = " ".join(str(c.value) for c in fresh_app.caption)
        assert "k-anonymat" in captions or "SHA-1" in captions


# ==========================================================================
# Onglet e-mail
# ==========================================================================
class TestOngletEmail:
    def test_adresse_invalide_rejetee(self, fresh_app):
        fresh_app.text_input(key="email_input").set_value("pas-une-adresse")
        fresh_app.button(key="email_button").click()
        fresh_app.run()
        assert not fresh_app.exception
        assert any("invalide" in str(e.value).lower() for e in fresh_app.error)

    def test_injection_html_dans_le_champ_email(self, fresh_app):
        fresh_app.text_input(key="email_input").set_value("<script>alert(1)</script>@x.com")
        fresh_app.button(key="email_button").click()
        fresh_app.run()
        assert not fresh_app.exception
        # La chaîne ne doit jamais ressortir telle quelle dans le balisage produit.
        assert "<script>alert(1)</script>" not in markdown_of(fresh_app)


# ==========================================================================
# Onglet menaces
# ==========================================================================
class TestOngletMenaces:
    def test_catalogue_kev_ou_erreur_explicite(self, app):
        """Selon la disponibilité réseau : soit les données, soit un message clair."""
        text = text_of(app)
        assert ("Vulnérabilités KEV" in text) or ("injoignable" in text.lower())

    def test_aucun_balisage_indente(self, app):
        assert indented_markup(app) == []

    def test_recherche_sans_resultat(self, fresh_app):
        fresh_app.text_input(key="kev_search").set_value("zzzz-domaine-inexistant-zzzz")
        fresh_app.run()
        assert not fresh_app.exception
        assert "Aucun résultat" in text_of(fresh_app) or "injoignable" in text_of(fresh_app).lower()

    def test_caracteres_dangereux_dans_la_recherche(self, fresh_app):
        fresh_app.text_input(key="kev_search").set_value('<img src=x onerror=alert(1)>')
        fresh_app.run()
        assert not fresh_app.exception
        assert "<img src=x" not in markdown_of(fresh_app)


# ==========================================================================
# Onglet télémétrie
# ==========================================================================
class TestOngletTelemetrie:
    def test_indicateurs_affiches(self, app):
        assert "cs-kpi" in markdown_of(app)

    def test_note_de_confidentialite(self, app):
        captions = " ".join(str(c.value) for c in app.caption).lower()
        assert "anonyme" in captions or "anonymous" in captions


# ==========================================================================
# Langue
# ==========================================================================
class TestLangue:
    def test_bascule_en_anglais(self, fresh_app):
        fresh_app.selectbox(key="language_selector").select("English 🇬🇧")
        fresh_app.run()
        assert not fresh_app.exception

        captions = " ".join(str(c.value) for c in fresh_app.caption)
        labels = " ".join(str(c.label) for c in fresh_app.text_input)
        assert "Passwords never leave your browser" in captions
        assert "Enter the password" in labels

    def test_langue_par_defaut_en_francais(self, fresh_app):
        captions = " ".join(str(c.value) for c in fresh_app.caption)
        assert "Les mots de passe ne quittent jamais" in captions
