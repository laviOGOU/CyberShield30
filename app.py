"""
app.py — CyberShield Security Auditor (Streamlit).

Application d'audit : robustesse d'un mot de passe, exposition d'une adresse
e-mail, veille sur les vulnérabilités activement exploitées (CISA KEV) et
actualité sécurité.

Lancement local :
    streamlit run app.py

Structure du code :
    theme.py         système de design (polices, couleurs, composants)
    i18n.py          textes français / anglais
    security.py      validation, échappement, anonymisation, API d'audit
    threat_intel.py  catalogue CISA KEV et flux RSS
    db.py            télémétrie anonymisée
"""
import logging

import streamlit as st

import db
import security
import theme
import threat_intel
from i18n import get_translations
from security import EmailBreachEvaluator, PasswordSecurityEvaluator, rate_limiter

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("CyberShield")

# --------------------------------------------------------------------------
# Constantes d'application
# --------------------------------------------------------------------------
ONEPASSWORD_URL = "https://1password.com/"
HIBP_PRIVACY_URL = "https://haveibeenpwned.com/Privacy"

PWD_RATE_LIMIT = (12, 300)      # 12 analyses de mot de passe par 5 minutes
EMAIL_RATE_LIMIT = (4, 300)     # 4 recherches d'e-mail par 5 minutes (API publique)

VERDICT_COLORS = {
    "strong": theme.COLORS["green"],
    "medium": theme.COLORS["amber"],
    "weak": theme.COLORS["red"],
}

st.set_page_config(
    page_title="CyberShield — Security Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(theme.CSS, unsafe_allow_html=True)
db.init_db()


# --------------------------------------------------------------------------
# Accès aux données de veille (mises en cache pour ne pas marteler les sources)
# --------------------------------------------------------------------------
@st.cache_data(ttl=3600, show_spinner=False)
def cached_kev():
    """Catalogue KEV : rechargé au maximum une fois par heure."""
    vulnerabilities, version, released, error = threat_intel.fetch_kev_catalog()
    return vulnerabilities, version, released, error


@st.cache_data(ttl=1800, show_spinner=False)
def cached_news():
    """Flux d'actualité : rechargés au maximum toutes les 30 minutes."""
    return threat_intel.fetch_news()


def visitor_fingerprint() -> str:
    """
    Empreinte de navigateur hachée.

    On ne stocke jamais le User-Agent brut (donnée identifiante) : seule une
    empreinte non réversible est conservée, et uniquement pour distinguer des
    sessions distinctes dans les compteurs.
    """
    try:
        user_agent = st.context.headers.get("User-Agent", "")
    except Exception:                                          # noqa: BLE001
        user_agent = ""
    return security.anonymize(user_agent, length=10)


if "session_counted" not in st.session_state:
    st.session_state["session_counted"] = True
    db.increment_metric("visites_totales")
    db.log_event("SESSION", f"empreinte={visitor_fingerprint()}")


# --------------------------------------------------------------------------
# Barre latérale
# --------------------------------------------------------------------------
with st.sidebar:
    st.header("Configuration")
    language = st.selectbox(
        "Langue / Language",
        ["Français 🇫🇷", "English 🇬🇧"],
        key="language_selector",
    )
    lang_code = "FR" if "Français" in language else "EN"
    T = get_translations(lang_code)

    st.markdown(theme.section(T["sidebar_about_title"]), unsafe_allow_html=True)
    st.caption(T["sidebar_about"])
    st.caption(
        f'<a href="{HIBP_PRIVACY_URL}" target="_blank" rel="noopener noreferrer">'
        f'{T["sidebar_privacy_link"]}</a>',
        unsafe_allow_html=True,
    )

    st.markdown("---")
    st.markdown(theme.section(T["sidebar_status"]), unsafe_allow_html=True)

    kev_sidebar, kev_version_sidebar, _, kev_error_sidebar = cached_kev()
    if kev_error_sidebar:
        st.markdown(
            f'<span class="cs-badge warn"><span class="cs-dot"></span>CISA KEV indisponible</span>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<span class="cs-badge live"><span class="cs-dot"></span>'
            f'{len(kev_sidebar)} entrées KEV</span>',
            unsafe_allow_html=True,
        )
        st.caption(T["threats_kev_version"].format(v=kev_version_sidebar or "—"))

        alerts = threat_intel.recent_vulnerabilities(kev_sidebar, limit=3)
        st.caption(f'**{T["threats_recent"]}**')
        for vuln in alerts:
            st.markdown(
                f'<div class="cs-vuln" style="padding:0.55rem 0.7rem">'
                f'<div class="cs-vuln-head" style="margin-bottom:0.2rem">'
                f'<span class="cs-cve" style="font-size:0.72rem">{security.escape(vuln.cve)}</span>'
                f'</div>'
                f'<div style="font-size:0.78rem;color:#8fa3bf">'
                f'{security.escape(vuln.vendor)} — {security.escape(vuln.product)}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("---")
    if st.button(T["threats_refresh"], use_container_width=True):
        cached_kev.clear()
        cached_news.clear()
        st.rerun()

    st.caption(f'{T["footer_version"]} · 2026')


# --------------------------------------------------------------------------
# En-tête
# --------------------------------------------------------------------------
st.markdown(
    theme.hero(
        brand=security.escape(T["brand"]),
        accent=security.escape(T["brand_suffix"]),
        suffix="SECURITY AUDITOR",
        badges=[
            ("live", f'<span class="cs-dot"></span>{security.escape(T["badge_live"])}'),
            ("info", security.escape(T["badge_privacy"])),
        ],
    ),
    unsafe_allow_html=True,
)

st.markdown(theme.page_title(T["title"], T["subtitle"]), unsafe_allow_html=True)

st.markdown(
    theme.compact(f"""
    <div class="cs-card">
        <div class="cs-cta-title">👋 {T["welcome_title"]}</div>
        <p class="cs-cta-text" style="margin:0">{T["welcome_text"]}</p>
    </div>
    """),
    unsafe_allow_html=True,
)

tab_pwd, tab_email, tab_threats, tab_stats = st.tabs(
    [T["tab_pwd"], T["tab_email"], T["tab_threats"], T["tab_stats"]]
)


# ==========================================================================
# ONGLET 1 — Audit de mot de passe
# ==========================================================================
with tab_pwd:
    st.markdown(theme.section(T["pwd_subtitle"]), unsafe_allow_html=True)
    st.caption(T["pwd_hint"])

    password = st.text_input(
        T["pwd_label"],
        type="password",
        key="password_input",
        max_chars=security.MAX_PASSWORD_LENGTH,
        placeholder="············",
    )

    if not password:
        st.markdown(
            f'<div class="cs-empty">{T["pwd_field_empty"]}</div>', unsafe_allow_html=True
        )
    else:
        allowed, retry_after = rate_limiter.allow("password", *PWD_RATE_LIMIT)

        if not allowed:
            st.warning(
                f"Trop de vérifications en peu de temps. Nouvelle tentative dans "
                f"{retry_after} secondes."
            )
        else:
            level, percentage, criteria, warnings = PasswordSecurityEvaluator.evaluate(
                password, T
            )
            pwned_count = PasswordSecurityEvaluator.check_breach(password)

            # ---- Compteurs (aucune donnée personnelle) --------------------
            db.increment_metric("tests_mdp")
            if percentage == 100:
                db.increment_metric("mdp_forts")
            elif percentage >= 60:
                db.increment_metric("mdp_moyens")
            else:
                db.increment_metric("mdp_faibles")
            if pwned_count:
                db.increment_metric("mdp_compromis")
            db.log_event("PASSWORD_TEST", f"niveau={level} exposition={bool(pwned_count)}")

            # ---- Verdict --------------------------------------------------
            if percentage == 100:
                key = "strong"
            elif percentage >= 60:
                key = "medium"
            else:
                key = "weak"
            color = VERDICT_COLORS[key]

            st.markdown(
                theme.section(T["pwd_diag"], note=T["pwd_chars"].format(n=len(password))),
                unsafe_allow_html=True,
            )
            st.markdown(
                theme.compact(
                    f'<div class="cs-card">'
                    f'<div class="cs-verdict" style="color:{color}">{security.escape(level)}'
                    f'<span class="cs-score">{percentage:.0f} % des critères</span></div>'
                    f"{theme.meter(percentage, color)}"
                    f"</div>"
                ),
                unsafe_allow_html=True,
            )

            # ---- Critères et exposition -----------------------------------
            col_criteria, col_breach = st.columns(2)

            with col_criteria:
                st.markdown(theme.section(T["pwd_criteria_title"]), unsafe_allow_html=True)
                st.markdown(
                    '<div class="cs-card inset">'
                    + "".join(theme.criterion(security.escape(c.description), c.is_met) for c in criteria)
                    + "</div>",
                    unsafe_allow_html=True,
                )

            with col_breach:
                st.markdown(theme.section(T["pwd_breach_title"]), unsafe_allow_html=True)

                if pwned_count is None:
                    st.markdown(
                        f'<div class="cs-card inset">'
                        f'<span class="cs-badge warn"><span class="cs-dot"></span>'
                        f'{T["pwd_breach_error"]}</span></div>',
                        unsafe_allow_html=True,
                    )
                elif pwned_count > 0:
                    st.markdown(
                        f'<div class="cs-card inset" style="border-color:rgba(248,113,113,0.35)">'
                        f'<div class="cs-kpi-label">{T["pwd_breach_title"]}</div>'
                        f'<div class="cs-kpi-value red" style="font-size:1.35rem">'
                        f'{pwned_count:,}'.replace(",", " ")
                        + "</div>"
                        f'<div class="cs-kpi-hint">'
                        f'{security.escape(T["pwd_breach_danger"].format(count=pwned_count))}'
                        f"</div></div>",
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f'<div class="cs-card inset" style="border-color:rgba(74,222,128,0.3)">'
                        f'<span class="cs-badge live"><span class="cs-dot"></span>'
                        f'{T["pwd_breach_safe"]}</span></div>',
                        unsafe_allow_html=True,
                    )

                st.caption(
                    "K-anonymat : seuls les 5 premiers caractères de l'empreinte SHA-1 "
                    "sont transmis à l'API. Le mot de passe ne quitte pas le serveur."
                )

            # ---- Recommandations ------------------------------------------
            missing = [c for c in criteria if not c.is_met]
            st.markdown(theme.section(T["pwd_recom_title"]), unsafe_allow_html=True)

            if missing:
                for criterion in missing:
                    st.markdown(
                        f'<div class="cs-criterion"><span class="cs-check ko">→</span>'
                        f'<span><b>{security.escape(criterion.description)}</b> — '
                        f'{security.escape(criterion.recommendation)}</span></div>',
                        unsafe_allow_html=True,
                    )
            else:
                st.success(T["pwd_structure_ok"])

            for warning in warnings:
                st.warning(warning)

            if pwned_count:
                st.error(T["pwd_critical_alert"])

            with st.expander(T["pwd_tips_title"]):
                st.markdown(T["pwd_tips_body"])

            # ---- Encart gestionnaire de mots de passe (1Password) ---------
            st.markdown(
                theme.compact(f"""
                <div class="cs-cta">
                    <div class="cs-cta-body">
                        <div class="cs-cta-title">🔐 {T["pwd_mgr_title"]}</div>
                        <p class="cs-cta-text">{T["pwd_mgr_text"]}</p>
                        <p class="cs-cta-alt">{T["pwd_mgr_alt"]}</p>
                    </div>
                    <div>
                        <a class="cs-cta-link" href="{ONEPASSWORD_URL}"
                           target="_blank" rel="noopener noreferrer">
                           {T["pwd_mgr_cta"]} →
                        </a>
                        <div class="cs-cta-note">{T["pwd_mgr_note"]}</div>
                    </div>
                </div>
                """),
                unsafe_allow_html=True,
            )


# ==========================================================================
# ONGLET 2 — Exposition d'une adresse e-mail
# ==========================================================================
with tab_email:
    st.markdown(theme.section(T["email_subtitle"]), unsafe_allow_html=True)

    email_input = st.text_input(
        T["email_label"],
        placeholder="utilisateur@domaine.com",
        key="email_input",
        max_chars=security.MAX_EMAIL_LENGTH,
    )
    launch = st.button(T["email_btn"], type="primary", key="email_button")

    st.caption(T["email_privacy_note"])

    if launch:
        candidate = (email_input or "").strip()

        if not security.is_valid_email(candidate):
            st.error(T["email_invalid"])
        else:
            allowed, retry_after = rate_limiter.allow("email", *EMAIL_RATE_LIMIT)
            if not allowed:
                st.warning(
                    f"Trop de recherches en peu de temps. Nouvelle tentative dans "
                    f"{retry_after} secondes."
                )
            else:
                with st.spinner("Recherche en cours…"):
                    pwned, breaches, error = EmailBreachEvaluator.check_breaches(candidate)

                db.increment_metric("tests_email")
                safe_email = security.escape(candidate)

                if pwned:
                    db.increment_metric("emails_compromis")
                    db.log_event("EMAIL_TEST", "expose")

                    st.error(T["email_pwned"].format(email=safe_email))
                    st.markdown(theme.section(T["email_breaches_list"]), unsafe_allow_html=True)

                    for breach in breaches[:25]:
                        st.markdown(
                            f'<div class="cs-criterion"><span class="cs-check ko">•</span>'
                            f'<span>{security.escape(breach)}</span></div>',
                            unsafe_allow_html=True,
                        )
                    if len(breaches) > 25:
                        st.caption(f"… et {len(breaches) - 25} autres services.")

                    st.markdown(theme.section(T["email_recom_title"]), unsafe_allow_html=True)
                    st.markdown(
                        f'<div class="cs-card">{T["email_recom_box"]}</div>',
                        unsafe_allow_html=True,
                    )

                elif pwned is False:
                    db.log_event("EMAIL_TEST", "propre")
                    st.success(T["email_clean"].format(email=safe_email))
                else:
                    db.log_event("EMAIL_TEST", f"erreur={error}")
                    st.info(
                        f"Vérification impossible pour le moment ({security.escape(error or 'inconnu')}). "
                        "Réessayez dans quelques minutes."
                    )


# ==========================================================================
# ONGLET 3 — Menaces en direct (CISA KEV + actualité)
# ==========================================================================
with tab_threats:
    vulnerabilities, catalog_version, catalog_date, kev_error = cached_kev()
    stats = threat_intel.catalog_statistics(vulnerabilities)

    st.markdown(theme.section(T["threats_kev_title"], note=catalog_version), unsafe_allow_html=True)
    st.caption(T["threats_kev_desc"])

    if kev_error:
        st.error(T["threats_error"].format(err=security.escape(kev_error)))
    else:
        st.markdown(
            theme.kpi_row([
                ("Vulnérabilités KEV", f"{stats['total']:,}".replace(",", " "), "Recensées par la CISA", "cyan"),
                ("Rançongiciels", stats["ransomware"], T["threats_ransomware"], "red"),
                (f"Ajouts en {stats['latest'][:4] or '—'}", stats["this_year"], "", "amber"),
                ("Éditeurs concernés", stats["vendors"], "", ""),
            ]),
            unsafe_allow_html=True,
        )

        # ---- Ajouts récents -----------------------------------------------
        st.markdown(theme.section(T["threats_recent"]), unsafe_allow_html=True)
        for vuln in threat_intel.recent_vulnerabilities(vulnerabilities, limit=8):
            ransomware_tag = (
                f'<span class="cs-badge danger"><span class="cs-dot"></span>'
                f'{T["threats_ransomware"]}</span>'
                if vuln.ransomware else ""
            )
            st.markdown(
                f'<div class="cs-vuln {"ransomware" if vuln.ransomware else ""}">'
                f'<div class="cs-vuln-head">'
                f'<span class="cs-cve">{security.escape(vuln.cve)}</span>'
                f'<span class="cs-vuln-title">{security.escape(vuln.name)}</span>'
                f"{ransomware_tag}"
                f"</div>"
                f'<div class="cs-vuln-meta">'
                f'<span>{security.escape(vuln.vendor)} · {security.escape(vuln.product)}</span>'
                f'<span>{T["threats_added"].format(d=security.escape(vuln.date_added))}</span>'
                f'<span>{T["threats_due"].format(d=security.escape(vuln.due_date))}</span>'
                f"</div>"
                f'<p class="cs-vuln-desc">{security.escape(vuln.description[:280])}</p>'
                f"</div>",
                unsafe_allow_html=True,
            )

        # ---- Recherche dans le catalogue -----------------------------------
        st.markdown(theme.divider(), unsafe_allow_html=True)
        query = security.clean_query(
            st.text_input(T["threats_search"], key="kev_search", placeholder="Apache, Ivanti, CVE-2024-…")
        )

        if query:
            results = threat_intel.search_vulnerabilities(vulnerabilities, query, limit=25)
            st.caption(T["threats_count"].format(n=len(results)))

            if not results:
                st.markdown(
                    f'<div class="cs-empty">{T["threats_no_result"]}</div>', unsafe_allow_html=True
                )
            else:
                for vuln in results:
                    nvd_link = (
                        f'<a href="https://nvd.nist.gov/vuln/detail/{security.safe_url(vuln.cve)}" '
                        f'target="_blank" rel="noopener noreferrer">Fiche NVD</a>'
                        if threat_intel.is_cve(vuln.cve) else ""
                    )
                    st.markdown(
                        f'<div class="cs-vuln {"ransomware" if vuln.ransomware else ""}">'
                        f'<div class="cs-vuln-head">'
                        f'<span class="cs-cve">{security.escape(vuln.cve)}</span>'
                        f'<span class="cs-vuln-title">{security.escape(vuln.name)}</span>'
                        f"</div>"
                        f'<div class="cs-vuln-meta">'
                        f'<span>{security.escape(vuln.vendor)} · {security.escape(vuln.product)}</span>'
                        f'<span>{T["threats_added"].format(d=security.escape(vuln.date_added))}</span>'
                        f"<span>{nvd_link}</span>"
                        f"</div>"
                        f'<p class="cs-vuln-desc">{security.escape(vuln.description[:280])}</p>'
                        f'<p class="cs-vuln-desc"><b>{T["threats_action"]}</b></p>'
                        f"</div>",
                        unsafe_allow_html=True,
                    )

    # ---- Actualité sécurité ------------------------------------------------
    st.markdown(theme.divider(), unsafe_allow_html=True)
    st.markdown(theme.section(T["threats_news_title"]), unsafe_allow_html=True)

    articles, news_errors = cached_news()

    for source, error in news_errors.items():
        st.caption(f'⚠️ {T["threats_error"].format(err=security.escape(source) + " — " + security.escape(error))}')

    if articles:
        sources = sorted({a.source for a in articles})
        choice = st.selectbox(
            "Source", [T["threats_source_all"]] + sources, key="news_filter"
        )
        visible = [a for a in articles if choice == T["threats_source_all"] or a.source == choice]

        for article in visible:
            safe_link = security.safe_url(article.link)
            title = security.escape(article.title)
            title_html = (
                f'<a href="{safe_link}" target="_blank" rel="noopener noreferrer">{title}</a>'
                if safe_link != "#" else title
            )
            st.markdown(
                f'<div class="cs-article">'
                f'<div class="cs-article-source">{security.escape(article.source)}</div>'
                f"<div>"
                f'<div class="cs-article-title">{title_html}</div>'
                f'<div class="cs-article-meta">{security.escape(article.published)}</div>'
                f"</div></div>",
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            f'<div class="cs-empty">{T["threats_no_result"]}</div>', unsafe_allow_html=True
        )


# ==========================================================================
# ONGLET 4 — Télémétrie
# ==========================================================================
with tab_stats:
    st.markdown(theme.section(T["stats_subtitle"]), unsafe_allow_html=True)

    metrics = db.get_all_metrics()
    alerts = metrics.get("mdp_compromis", 0) + metrics.get("emails_compromis", 0)

    st.markdown(
        theme.kpi_row([
            (T["stats_visits"], f"{metrics.get('visites_totales', 0):,}".replace(",", " "), "", "cyan"),
            (T["stats_pwd_tests"], f"{metrics.get('tests_mdp', 0):,}".replace(",", " "), "", ""),
            (T["stats_email_tests"], f"{metrics.get('tests_email', 0):,}".replace(",", " "), "", ""),
            (T["stats_alerts"], f"{alerts:,}".replace(",", " "), "", "red"),
        ]),
        unsafe_allow_html=True,
    )

    st.markdown(theme.divider(), unsafe_allow_html=True)

    col_dist, col_logs = st.columns([1, 1])

    with col_dist:
        st.markdown(theme.section(T["stats_dist"]), unsafe_allow_html=True)
        distribution = db.password_distribution()
        total = sum(distribution.values())

        if total == 0:
            st.markdown(
                f'<div class="cs-empty">{T["stats_empty"]}</div>', unsafe_allow_html=True
            )
        else:
            rows = [
                (T["pwd_strong"], distribution["strong"], theme.COLORS["green"]),
                (T["pwd_medium"], distribution["medium"], theme.COLORS["amber"]),
                (T["pwd_weak"], distribution["weak"], theme.COLORS["red"]),
            ]
            html = '<div class="cs-card inset">'
            for label, value, color in rows:
                share = (value / total) * 100
                html += (
                    f'<div class="cs-criterion" style="flex-direction:column;gap:0.3rem;align-items:stretch">'
                    f'<div style="display:flex;justify-content:space-between">'
                    f'<span style="font-weight:600">{label}</span>'
                    f'<span class="cs-mono" style="color:{color}">{value} · {share:.1f} %</span>'
                    f"</div>{theme.meter(share, color)}</div>"
                )
            html += "</div>"
            st.markdown(html, unsafe_allow_html=True)

    with col_logs:
        st.markdown(theme.section(T["stats_logs"]), unsafe_allow_html=True)
        events = db.recent_events(limit=8)
        if not events:
            st.markdown(
                f'<div class="cs-empty">{T["stats_empty"]}</div>', unsafe_allow_html=True
            )
        else:
            html = '<div class="cs-card inset">'
            for timestamp, event_type, detail in events:
                html += (
                    f'<div class="cs-criterion" style="font-size:0.82rem">'
                    f'<span class="cs-mono" style="color:#5f7290">{security.escape(timestamp)}</span>'
                    f'<span><b>{security.escape(event_type)}</b> '
                    f'<span style="color:#8fa3bf">{security.escape(detail)}</span></span>'
                    f"</div>"
                )
            html += "</div>"
            st.markdown(html, unsafe_allow_html=True)

    st.caption(T["stats_privacy"])
    st.caption(T["stats_persistence_note"])


# --------------------------------------------------------------------------
# Pied de page
# --------------------------------------------------------------------------
st.markdown(
    theme.footer(
        left=f'{security.escape(T["footer_note"])} · Sources : CISA, The Hacker News, BleepingComputer, CERT-FR',
        right=f'{security.escape(T["footer_version"])} · 2026',
    ),
    unsafe_allow_html=True,
)
