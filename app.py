import hashlib
import logging
import re
import sqlite3
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import feedparser
import requests
import streamlit as st

# ==========================================
# 1. CONFIGURATION & LOGGING
# ==========================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CyberShield")

DB_PATH = "cybershield_data.db"

# ==========================================
# 2. COUCHE DE PERSISTANCE (SQLITE)
# ==========================================


def init_db() -> None:
    """Initialise la base de données SQLite pour la télémétrie."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    detail TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    metric_key TEXT PRIMARY KEY,
                    metric_value INTEGER DEFAULT 0
                )
            """)
            keys = [
                "visites_totales",
                "tests_mdp",
                "mdp_forts",
                "mdp_moyens",
                "mdp_faibles",
                "mdp_compromis",
                "tests_email",
                "emails_compromis",
            ]
            for key in keys:
                cursor.execute(
                    "INSERT OR IGNORE INTO metrics (metric_key, metric_value) VALUES (?, 0)",
                    (key,),
                )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Erreur DB : {str(e)}")


def increment_metric(key: str, amount: int = 1) -> None:
    """Incrémente une valeur métrique spécifique."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE metrics SET metric_value = metric_value + ? WHERE metric_key = ?",
                (amount, key),
            )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Erreur mise à jour métrique {key} : {str(e)}")


def get_all_metrics() -> Dict[str, int]:
    """Récupère les métriques enregistrées."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT metric_key, metric_value FROM metrics")
            return dict(cursor.fetchall())
    except sqlite3.Error as e:
        logger.error(f"Erreur lecture métriques : {str(e)}")
        return {}


def log_event(event_type: str, detail: str = "") -> None:
    """Enregistre un événement dans la télémétrie."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO telemetry (event_type, detail) VALUES (?, ?)",
                (event_type, detail),
            )
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Erreur log : {str(e)}")


init_db()

# ==========================================
# 3. TRADUCTIONS (LANGUAGES)
# ==========================================
TRANSLATIONS = {
    "FR": {
        "title": "🛡️ CYBERSHIELD SECURITY AUDITOR",
        "subtitle": "Plateforme d'évaluation des vulnérabilités et télémétrie anonymisée",
        "welcome_title": "👋 Bienvenue sur votre centre de contrôle de sécurité",
        "welcome_text": "Sélectionnez un onglet ci-dessous pour démarrer : <b>🔑 Valider la robustesse d'un mot de passe</b>, <b>📧 Vérifier si votre e-mail a été compromis</b> ou <b>📊 Consulter les statistiques en temps réel</b>.",
        "sidebar_config": "⚙️ Configuration",
        "sidebar_lang": "🌐 Langue / Language",
        "sidebar_about": "Ce système d'audit utilise le principe de k-anonymat via l'API HaveIBeenPwned. Vos mots de passe ne transitent **jamais** en clair.",
        "sidebar_news": "📢 Actualités Cyber (Temps Réel)",
        "sidebar_refresh": "🔄 Rafraîchir l'actualité",
        "sidebar_no_news": "Aucune actualité disponible pour le moment.",
        "tab_pwd": "🔑 Audit Mot de Passe",
        "tab_email": "📧 Analyse de Fuite E-mail",
        "tab_stats": "📊 Télémétrie & Métriques",
        "pwd_subtitle": "Analyse de la robustesse des identifiants",
        "pwd_label": "Saisissez le mot de passe à évaluer :",
        "pwd_diag": "Diagnostic",
        "pwd_level": "Niveau de sécurité :",
        "pwd_strong": "Fort",
        "pwd_medium": "Moyen",
        "pwd_weak": "Faible",
        "pwd_criteria_title": "Détail des critères d'évaluation",
        "pwd_breach_title": "Vérification dans les fuites publiques",
        "pwd_breach_danger": "🚨 DANGER : Présent {count:,} fois dans des fuites de données !",
        "pwd_breach_safe": "✅ Aucune fuite détectée pour ce mot de passe.",
        "pwd_breach_error": "⚠️ Impossible de vérifier la présence (Erreur API).",
        "pwd_recom_title": "🛠️ Recommandations de sécurité",
        "pwd_actions_req": "Action(s) requise(s) sur la structure :",
        "pwd_structure_ok": "🎉 La structure de votre mot de passe valide tous les critères de complexité.",
        "pwd_critical_alert": "🚨 Recommandation critique : Ce mot de passe est répertorié dans des bases piratées. Ne l'utilisez plus !",
        "pwd_tips_title": "📌 Conseils généraux pour un mot de passe robuste",
        "pwd_tips_body": """1. **Utilisez une passphrase** : Assemblez 4 ou 5 mots aléatoires sans lien logique (ex: `Cafetière#Bleu$Trompette98!`).\n2. **Adoptez un gestionnaire de mots de passe** : Des outils comme Bitwarden ou KeePass génèrent et stockent des accès uniques.\n3. **Ne réutilisez jamais un mot de passe** : Un mot de passe unique par service évite les compromissions en chaîne.\n4. **Activez la Double Authentification (2FA)** : Associez toujours votre mot de passe à une application d'authentification.""",
        "email_subtitle": "Analyse d'exposition de compte e-mail",
        "email_label": "Entrez l'adresse e-mail à vérifier :",
        "email_btn": "Lancer la recherche de fuites",
        "email_pwned": "🚨 L'adresse **{email}** a été identifiée dans des violations de données !",
        "email_breaches_list": "Services/Plateformes impactés :",
        "email_clean": "🎉 Aucune compromission connue associée à l'adresse **{email}**.",
        "email_invalid": "Veuillez saisir un format d'adresse e-mail valide.",
        "email_recom_title": "🛡️ Plan d'action recommandé en cas de fuite",
        "email_recom_box": """<h4>1. Changez les mots de passe associés</h4><p>Modifiez immédiatement le mot de passe du service compromis ainsi que celui de votre boîte e-mail si identique.</p><h4>2. Activez l'Authentification à Double Facteur (2FA/MFA)</h4><p>Configurez la validation en deux étapes sur vos comptes majeurs.</p><h4>3. Restez vigilant face au Phishing</h4><p>Vos données circulant sur des forums cybercriminels, méfiez-vous des e-mails ou SMS suspects.</p>""",
        "stats_subtitle": "Télémétrie globale en temps réel",
        "stats_visits": "Visites Totales",
        "stats_pwd_tests": "Mots de passe analysés",
        "stats_email_tests": "E-mails contrôlés",
        "stats_alerts": "Alertes de sécurité",
        "stats_dist": "Distribution de la robustesse des mots de passe",
        "stats_logs": "Journal d'événements récents",
        "c_len": "Longueur d'au moins 12 caractères",
        "c_len_rec": "Rallongez le mot de passe (au moins 12 à 16 caractères).",
        "c_upper": "Contient des lettres majuscules (A-Z)",
        "c_upper_rec": "Insérez au moins une lettre majuscule.",
        "c_lower": "Contient des lettres minuscules (a-z)",
        "c_lower_rec": "Incorporez des lettres minuscules.",
        "c_num": "Contient des chiffres (0-9)",
        "c_num_rec": "Ajoutez un ou plusieurs chiffres.",
        "c_sym": "Contient des symboles spéciaux (!@#$%...)",
        "c_sym_rec": "Ajoutez des caractères spéciaux (ex: @, #, !, $).",
    },
    "EN": {
        "title": "🛡️ CYBERSHIELD SECURITY AUDITOR",
        "subtitle": "Vulnerability assessment platform & anonymized telemetry",
        "welcome_title": "👋 Welcome to your security control center",
        "welcome_text": "Select a tab below to start: <b>🔑 Validate password strength</b>, <b>📧 Check if your email was breached</b> or <b>📊 View real-time statistics</b>.",
        "sidebar_config": "⚙️ Configuration",
        "sidebar_lang": "🌐 Language / Langue",
        "sidebar_about": "This audit system uses k-anonymity via the HaveIBeenPwned API. Your passwords are **never** transmitted in plain text.",
        "sidebar_news": "📢 Cyber News (Real-time)",
        "sidebar_refresh": "🔄 Refresh News",
        "sidebar_no_news": "No news available at the moment.",
        "tab_pwd": "🔑 Password Audit",
        "tab_email": "📧 Email Breach Check",
        "tab_stats": "📊 Telemetry & Metrics",
        "pwd_subtitle": "Credential strength assessment",
        "pwd_label": "Enter the password to evaluate:",
        "pwd_diag": "Diagnosis",
        "pwd_level": "Security level:",
        "pwd_strong": "Strong",
        "pwd_medium": "Medium",
        "pwd_weak": "Weak",
        "pwd_criteria_title": "Evaluation criteria breakdown",
        "pwd_breach_title": "Public data breach check",
        "pwd_breach_danger": "🚨 DANGER: Found {count:,} times in public data breaches!",
        "pwd_breach_safe": "✅ No breach detected for this password.",
        "pwd_breach_error": "⚠️ Could not perform check (API Error).",
        "pwd_recom_title": "🛠️ Security Recommendations",
        "pwd_actions_req": "Required action(s) on structure:",
        "pwd_structure_ok": "🎉 Password structure satisfies all complexity criteria.",
        "pwd_critical_alert": "🚨 Critical recommendation: This password is listed in leaked databases. Stop using it immediately!",
        "pwd_tips_title": "📌 General tips for strong passwords",
        "pwd_tips_body": """1. **Use a passphrase**: Combine 4 or 5 random words (e.g., `Coffee#Blue$Trumpet98!`).\n2. **Use a password manager**: Tools like Bitwarden or KeePass generate and store unique credentials.\n3. **Never reuse passwords**: A unique password per service prevents cascading account takeovers.\n4. **Enable Two-Factor Authentication (2FA)**: Always pair your password with an authenticator app.""",
        "email_subtitle": "Email exposure analysis",
        "email_label": "Enter email address to audit:",
        "email_btn": "Run breach check",
        "email_pwned": "🚨 The address **{email}** was identified in data breaches!",
        "email_breaches_list": "Impacted services/platforms:",
        "email_clean": "🎉 No known breaches associated with **{email}**.",
        "email_invalid": "Please enter a valid email address.",
        "email_recom_title": "🛡️ Recommended action plan for breaches",
        "email_recom_box": """<h4>1. Change associated passwords</h4><p>Immediately update your password on the compromised service and your email account if shared.</p><h4>2. Enable Multi-Factor Authentication (2FA/MFA)</h4><p>Set up two-step verification on all major accounts.</p><h4>3. Beware of Phishing</h4><p>Since your info may be exposed on hacker forums, watch out for suspicious emails or SMS messages.</p>""",
        "stats_subtitle": "Real-time global telemetry",
        "stats_visits": "Total Visits",
        "stats_pwd_tests": "Passwords Evaluated",
        "stats_email_tests": "Emails Checked",
        "stats_alerts": "Security Alerts",
        "stats_dist": "Password strength distribution",
        "stats_logs": "Recent activity log",
        "c_len": "At least 12 characters long",
        "c_len_rec": "Make it longer (at least 12 to 16 characters).",
        "c_upper": "Contains uppercase letters (A-Z)",
        "c_upper_rec": "Insert at least one uppercase letter.",
        "c_lower": "Contains lowercase letters (a-z)",
        "c_lower_rec": "Include lowercase letters.",
        "c_num": "Contains numbers (0-9)",
        "c_num_rec": "Add one or more numbers.",
        "c_sym": "Contains special symbols (!@#$%...)",
        "c_sym_rec": "Add special characters (e.g. @, #, !, $).",
    },
}

# ==========================================
# 4. FLUX D'ACTUALITÉS (RSS)
# ==========================================


@st.cache_data(ttl=900)
def fetch_cyber_news() -> List[Dict[str, str]]:
    """Récupère les actualités de cybersécurité en temps réel."""
    sources = {
        "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "ANSSI / Cert-FR": "https://www.cert.ssi.gouv.fr/feed/",
    }

    news_items = []
    for source_name, url in sources.items():
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:2]:
                news_items.append({
                    "source": source_name,
                    "title": entry.title,
                    "link": entry.link,
                    "published": getattr(
                        entry,
                        "published",
                        getattr(entry, "updated", "Recent"),
                    ),
                })
        except Exception as e:
            logger.error(f"Erreur flux RSS {source_name} : {str(e)}")

    return news_items


# ==========================================
# 5. SERVICES D'AUDIT DE SÉCURITÉ
# ==========================================


@dataclass
class PasswordCriterion:
    description: str
    is_met: bool
    recommendation: str


class PasswordSecurityEvaluator:

    @staticmethod
    def evaluate(
        password: str, lang_dict: dict
    ) -> Tuple[str, float, List[PasswordCriterion]]:
        criteria = [
            PasswordCriterion(
                lang_dict["c_len"],
                len(password) >= 12,
                lang_dict["c_len_rec"],
            ),
            PasswordCriterion(
                lang_dict["c_upper"],
                bool(re.search(r"[A-Z]", password)),
                lang_dict["c_upper_rec"],
            ),
            PasswordCriterion(
                lang_dict["c_lower"],
                bool(re.search(r"[a-z]", password)),
                lang_dict["c_lower_rec"],
            ),
            PasswordCriterion(
                lang_dict["c_num"],
                bool(re.search(r"[0-9]", password)),
                lang_dict["c_num_rec"],
            ),
            PasswordCriterion(
                lang_dict["c_sym"],
                bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
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

        return level, percentage, criteria

    @staticmethod
    def check_hibp_pwned(password: str) -> Optional[int]:
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = requests.get(
                url,
                headers={"User-Agent": "CyberShield-Audit-Tool"},
                timeout=5,
            )
            if response.status_code == 200:
                for line in response.text.splitlines():
                    h, count = line.split(":")
                    if h == suffix:
                        return int(count)
                return 0
            return None
        except requests.RequestException as e:
            logger.error(f"Erreur API HIBP : {str(e)}")
            return None


class EmailBreachEvaluator:

    @staticmethod
    def check_breaches(email: str) -> Tuple[Optional[bool], List[str]]:
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        try:
            response = requests.get(
                url,
                headers={"User-Agent": "CyberShield-Audit-Tool"},
                timeout=5,
            )
            if response.status_code == 200:
                data = response.json()
                if "breaches" in data and data["breaches"]:
                    return True, data["breaches"][0]
                return False, []
            elif response.status_code == 404:
                return False, []
            return None, []
        except requests.RequestException as e:
            logger.error(f"Erreur API Breach Check : {str(e)}")
            return None, []


# ==========================================
# 6. INTERFACE UTILISATEUR (STREAMLIT)
# ==========================================

st.set_page_config(
    page_title="CyberShield Professional Edition",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown(
    """
    <style>
        .stApp {
            background-color: #0A0E17;
            color: #C9D1D9;
        }
        .title-header {
            font-family: 'Inter', sans-serif;
            font-size: 2.8rem;
            font-weight: 800;
            background: linear-gradient(90deg, #38BDF8 0%, #818CF8 50%, #C084FC 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            text-align: center;
            margin-bottom: 0.2rem;
            letter-spacing: -0.02em;
        }
        .subtitle-header {
            text-align: center;
            color: #6B7280;
            font-size: 1.1rem;
            font-weight: 400;
            margin-bottom: 1.5rem;
        }
        .welcome-card {
            background: linear-gradient(135deg, #161B22 0%, #1F2937 100%);
            border: 1px solid #30363D;
            border-left: 5px solid #818CF8;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 2rem;
            text-align: center;
        }
        .welcome-title {
            font-size: 1.3rem;
            font-weight: 700;
            color: #F3F4F6;
            margin-bottom: 8px;
        }
        .welcome-text {
            color: #9CA3AF;
            font-size: 0.95rem;
            margin-bottom: 0;
        }
        div[data-baseweb="tab-list"] {
            width: 100% !important;
            display: flex !important;
            justify-content: space-between !important;
        }
        div[data-baseweb="tab"] {
            flex: 1 !important;
            text-align: center !important;
            justify-content: center !important;
        }
        .recom-box {
            background-color: #161B22;
            border: 1px solid #30363D;
            border-left: 4px solid #38BDF8;
            border-radius: 8px;
            padding: 16px;
            margin-top: 15px;
        }
        .metric-card {
            background: #161B22;
            border: 1px solid #30363D;
            border-radius: 10px;
            padding: 16px;
            text-align: center;
        }
        .metric-value {
            font-size: 2rem;
            font-weight: 700;
            color: #58A6FF;
        }
        .metric-label {
            font-size: 0.85rem;
            color: #8B949E;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }
        .news-card {
            background: #161B22;
            border: 1px solid #30363D;
            border-radius: 8px;
            padding: 10px;
            margin-bottom: 10px;
        }
        .news-title {
            font-weight: 700;
            color: #38BDF8;
            font-size: 0.82rem;
            margin-bottom: 4px;
        }
        .news-details {
            font-size: 0.78rem;
            color: #9CA3AF;
        }
    </style>
""",
    unsafe_allow_html=True,
)

if "session_active" not in st.session_state:
    st.session_state["session_active"] = True
    increment_metric("visites_totales")
    user_agent = st.context.headers.get("User-Agent", "Unknown")
    log_event("VISIT", f"User-Agent: {user_agent}")

# ==========================================
# SIDEBAR : LANGUE & RSS
# ==========================================
with st.sidebar:
    st.header("⚙️ Configuration")

    lang_choice = st.selectbox(
        "🌐 Language / Langue", ["Français 🇫🇷", "English 🇬🇧"]
    )
    selected_lang = "FR" if "Français" in lang_choice else "EN"
    T = TRANSLATIONS[selected_lang]

    st.info(T["sidebar_about"])
    st.markdown("---")

    st.header(T["sidebar_news"])

    if st.button(T["sidebar_refresh"], key="refresh_news"):
        st.cache_data.clear()

    articles = fetch_cyber_news()

    if articles:
        for article in articles:
            st.markdown(
                f"""
                <div class="news-card">
                    <div class="news-title">🌐 [{article['source']}]</div>
                    <div class="news-details">
                        <a href="{article['link']}" target="_blank" style="color: #F3F4F6; text-decoration: none; font-weight: 600;">{article['title']}</a><br>
                        <span style="font-size: 0.72rem; color: #6B7280;">📅 {article['published']}</span>
                    </div>
                </div>
            """,
                unsafe_allow_html=True,
            )
    else:
        st.warning(T["sidebar_no_news"])

    st.markdown("---")
    st.caption("CyberShield v2.7 Pro - 2026")

# ==========================================
# HEADER PRINCIPAL
# ==========================================
st.markdown(f'<div class="title-header">{T["title"]}</div>', unsafe_allow_html=True)
st.markdown(
    f'<div class="subtitle-header">{T["subtitle"]}</div>',
    unsafe_allow_html=True,
)

st.markdown(
    f"""
    <div class="welcome-card">
        <div class="welcome-title">{T["welcome_title"]}</div>
        <p class="welcome-text">{T["welcome_text"]}</p>
    </div>
""",
    unsafe_allow_html=True,
)

# ==========================================
# ONGLETS PRINCIPAUX
# ==========================================
tab_mdp, tab_email, tab_stats = st.tabs(
    [T["tab_pwd"], T["tab_email"], T["tab_stats"]]
)

# ONGLET 1 : MOT DE PASSE
with tab_mdp:
    st.subheader(T["pwd_subtitle"])

    pwd_input = st.text_input(
        T["pwd_label"], type="password", key="pwd_checker"
    )

    if pwd_input:
        level, score_pct, criteria = PasswordSecurityEvaluator.evaluate(
            pwd_input, T
        )
        pwned_count = PasswordSecurityEvaluator.check_hibp_pwned(pwd_input)

        increment_metric("tests_mdp")
        if score_pct == 100:
            increment_metric("mdp_forts")
        elif score_pct >= 60:
            increment_metric("mdp_moyens")
        else:
            increment_metric("mdp_faibles")

        if pwned_count and pwned_count > 0:
            increment_metric("mdp_compromis")

        log_event("PASSWORD_TEST", f"Level: {level}")

        st.markdown(f"#### {T['pwd_diag']}")
        st.progress(score_pct / 100)

        if score_pct == 100:
            st.success(f"{T['pwd_level']} **{level}** ({score_pct:.0f}%)")
        elif score_pct >= 60:
            st.warning(f"{T['pwd_level']} **{level}** ({score_pct:.0f}%)")
        else:
            st.error(f"{T['pwd_level']} **{level}** ({score_pct:.0f}%)")

        col_crit, col_fuite = st.columns(2)

        with col_crit:
            st.markdown(f"#### {T['pwd_criteria_title']}")
            for crit in criteria:
                if crit.is_met:
                    st.markdown(f"✅ **{crit.description}**")
                else:
                    st.markdown(f"❌ **{crit.description}**")

        with col_fuite:
            st.markdown(f"#### {T['pwd_breach_title']}")
            if pwned_count is None:
                st.info(T["pwd_breach_error"])
            elif pwned_count > 0:
                st.error(T["pwd_breach_danger"].format(count=pwned_count))
            else:
                st.success(T["pwd_breach_safe"])

        st.markdown("---")
        st.markdown(f"### {T['pwd_recom_title']}")

        missing_criteria = [c for c in criteria if not c.is_met]

        if missing_criteria:
            st.markdown(f"#### {T['pwd_actions_req']}")
            for crit in missing_criteria:
                st.warning(f"👉 **{crit.description}** : {crit.recommendation}")
        else:
            st.success(T["pwd_structure_ok"])

        if pwned_count and pwned_count > 0:
            st.error(T["pwd_critical_alert"])

        with st.expander(T["pwd_tips_title"]):
            st.markdown(T["pwd_tips_body"])

# ONGLET 2 : AUDIT E-MAIL
with tab_email:
    st.subheader(T["email_subtitle"])

    email_target = st.text_input(
        T["email_label"], placeholder="user@domain.com"
    )
    btn_analyze = st.button(T["email_btn"])

    if btn_analyze and email_target:
        if re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email_target):
            with st.spinner("Analyzing..."):
                is_pwned, breaches = EmailBreachEvaluator.check_breaches(
                    email_target
                )

                increment_metric("tests_email")

                if is_pwned:
                    increment_metric("emails_compromis")
                    log_event("EMAIL_TEST", "Compromised")
                    st.error(T["email_pwned"].format(email=email_target))

                    st.markdown(f"#### {T['email_breaches_list']}")
                    for breach in breaches:
                        st.warning(f"• Service: **{breach}**")

                    st.markdown("---")
                    st.markdown(f"### {T['email_recom_title']}")
                    st.markdown(
                        f'<div class="recom-box">{T["email_recom_box"]}</div>',
                        unsafe_allow_html=True,
                    )

                elif is_pwned is False:
                    log_event("EMAIL_TEST", "Clean")
                    st.success(T["email_clean"].format(email=email_target))
                else:
                    st.info("Error checking breaches.")
        else:
            st.error(T["email_invalid"])

# ONGLET 3 : TABLEAU DE BORD STATISTIQUE
with tab_stats:
    st.subheader(T["stats_subtitle"])

    metrics_data = get_all_metrics()

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value">{metrics_data.get('visites_totales', 0)}</div>
                <div class="metric-label">{T['stats_visits']}</div>
            </div>
        """,
            unsafe_allow_html=True,
        )

    with c2:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value">{metrics_data.get('tests_mdp', 0)}</div>
                <div class="metric-label">{T['stats_pwd_tests']}</div>
            </div>
        """,
            unsafe_allow_html=True,
        )

    with c3:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value">{metrics_data.get('tests_email', 0)}</div>
                <div class="metric-label">{T['stats_email_tests']}</div>
            </div>
        """,
            unsafe_allow_html=True,
        )

    with c4:
        total_comp = metrics_data.get("mdp_compromis", 0) + metrics_data.get(
            "emails_compromis", 0
        )
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value" style="color: #F87171;">{total_comp}</div>
                <div class="metric-label">{T['stats_alerts']}</div>
            </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("---")

    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.markdown(f"#### {T['stats_dist']}")
        forts = metrics_data.get("mdp_forts", 0)
        moyens = metrics_data.get("mdp_moyens", 0)
        faibles = metrics_data.get("mdp_faibles", 0)

        total_pwd = forts + moyens + faibles
        if total_pwd > 0:
            st.write(
                f"🟢 **{T['pwd_strong']} :** {forts} ({(forts/total_pwd)*100:.1f}%)"
            )
            st.write(
                f"🟠 **{T['pwd_medium']} :** {moyens} ({(moyens/total_pwd)*100:.1f}%)"
            )
            st.write(
                f"🔴 **{T['pwd_weak']} :** {faibles} ({(faibles/total_pwd)*100:.1f}%)"
            )
        else:
            st.info("No data recorded yet.")

    with col_chart2:
        st.markdown(f"#### {T['stats_logs']}")
        try:
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT timestamp, event_type, detail FROM telemetry ORDER BY id DESC LIMIT 5"
                )
                logs = cursor.fetchall()
                for log_time, event_type, detail in logs:
                    st.text(f"[{log_time}] {event_type} - {detail}")
        except sqlite3.Error:
            st.write("Error loading logs.")