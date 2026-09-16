"""
theme.py — Système de design de CyberShield.

Direction visuelle reprise de références du secteur (hacktualiz.com) :
fond bleu nuit profond, accents cyan, typographie à trois niveaux.

* **Space Grotesk** — titres et éléments d'interface (chiffres, libellés)
* **Figtree** — texte courant
* **Instrument Serif** (italique) — mots d'accent, pour la touche éditoriale

Le CSS est injecté dans Streamlit via `st.markdown(..., unsafe_allow_html=True)`.
Toutes les couleurs sont centralisées dans le bloc `:root` ci-dessous.
"""
import html as html_module
import re

# --------------------------------------------------------------------------
# Palette
# --------------------------------------------------------------------------
COLORS = {
    "bg": "#0a0e1a",
    "bg_soft": "#0d1424",
    "surface": "#111a2e",
    "surface_2": "#16203a",
    "border": "#1e2b45",
    "border_soft": "#182238",
    "text": "#e6edf7",
    "muted": "#8fa3bf",
    "faint": "#5f7290",
    "cyan": "#22d3ee",
    "cyan_deep": "#06b6d4",
    "blue": "#3b82f6",
    "violet": "#a855f7",
    "green": "#4ade80",
    "green_deep": "#10b981",
    "amber": "#fbbf24",
    "red": "#f87171",
    "red_deep": "#ef4444",
}

# Niveau de risque -> couleur d'accent
SEVERITY_COLORS = {
    "critical": COLORS["red"],
    "high": COLORS["red"],
    "medium": COLORS["amber"],
    "low": COLORS["green"],
}

GOOGLE_FONTS_URL = (
    "https://fonts.googleapis.com/css2"
    "?family=Figtree:wght@400;500;600;700;800"
    "&family=Instrument+Serif:ital@0;1"
    "&family=Space+Grotesk:wght@400;500;600;700"
    "&display=swap"
)


CSS = f"""
<style>
@import url('{GOOGLE_FONTS_URL}');

:root {{
    --bg: {COLORS['bg']};
    --bg-soft: {COLORS['bg_soft']};
    --surface: {COLORS['surface']};
    --surface-2: {COLORS['surface_2']};
    --border: {COLORS['border']};
    --border-soft: {COLORS['border_soft']};
    --text: {COLORS['text']};
    --muted: {COLORS['muted']};
    --faint: {COLORS['faint']};
    --cyan: {COLORS['cyan']};
    --cyan-deep: {COLORS['cyan_deep']};
    --blue: {COLORS['blue']};
    --violet: {COLORS['violet']};
    --green: {COLORS['green']};
    --amber: {COLORS['amber']};
    --red: {COLORS['red']};
    --radius: 0.75rem;
    --radius-lg: 1rem;
    --font-display: 'Space Grotesk', 'Figtree', system-ui, sans-serif;
    --font-body: 'Figtree', ui-sans-serif, system-ui, sans-serif;
    --font-accent: 'Instrument Serif', Georgia, serif;
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}}

/* ======================================================================
   1. Base
   ====================================================================== */
html, body, .stApp, [data-testid="stAppViewContainer"] {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-body);
    font-size: 15.5px;
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
}}

/* Halo lumineux discret en haut de page, comme sur les sites du secteur */
.stApp::before {{
    content: "";
    position: fixed;
    top: -320px; left: 50%;
    transform: translateX(-50%);
    width: 1100px; height: 620px;
    background: radial-gradient(circle at 50% 50%,
        rgba(34, 211, 238, 0.16) 0%,
        rgba(59, 130, 246, 0.10) 38%,
        rgba(10, 14, 26, 0) 72%);
    pointer-events: none;
    z-index: 0;
}}

[data-testid="stHeader"] {{ background: transparent; }}
[data-testid="stToolbar"] {{ right: 1rem; }}
[data-testid="stDecoration"] {{ display: none; }}

.block-container {{
    padding-top: 2.2rem;
    padding-bottom: 3rem;
    max-width: 1180px;
}}

h1, h2, h3, h4, h5 {{
    font-family: var(--font-display);
    color: var(--text);
    letter-spacing: -0.02em;
    font-weight: 600;
}}

p, li, label, span {{ font-family: var(--font-body); }}

a {{ color: var(--cyan); text-decoration: none; }}
a:hover {{ color: #67e8f9; text-decoration: underline; }}

code, pre, .cs-mono {{ font-family: var(--font-mono) !important; }}

/* ======================================================================
   2. En-tête de marque
   ====================================================================== */
.cs-hero {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1.5rem;
    flex-wrap: wrap;
    padding: 1.6rem 1.8rem;
    margin-bottom: 1.6rem;
    background: linear-gradient(135deg, rgba(17, 26, 46, 0.92) 0%, rgba(13, 20, 36, 0.92) 100%);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    position: relative;
    overflow: hidden;
}}

.cs-hero::after {{
    content: "";
    position: absolute;
    inset: 0 0 auto 0;
    height: 2px;
    background: linear-gradient(90deg, var(--cyan) 0%, var(--blue) 45%, var(--violet) 100%);
    opacity: 0.85;
}}

.cs-brand {{ display: flex; align-items: center; gap: 1rem; }}

.cs-logo {{
    width: 52px; height: 52px;
    display: grid; place-items: center;
    border-radius: 14px;
    background: linear-gradient(140deg, var(--cyan-deep), var(--blue));
    box-shadow: 0 8px 24px rgba(34, 211, 238, 0.25);
    font-size: 1.55rem;
    flex-shrink: 0;
}}

.cs-brand-text {{ display: flex; flex-direction: column; gap: 0.15rem; }}

.cs-brand-name {{
    font-family: var(--font-display);
    font-size: 1.5rem;
    font-weight: 700;
    letter-spacing: 0.02em;
    line-height: 1.1;
}}

.cs-brand-name .cs-accent {{
    font-family: var(--font-accent);
    font-style: italic;
    font-weight: 400;
    background: linear-gradient(90deg, var(--cyan) 0%, var(--violet) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}}

.cs-brand-suffix {{
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 0.18em;
    color: var(--faint);
}}

.cs-badges {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}

.cs-badge {{
    display: inline-flex;
    align-items: center;
    gap: 0.4rem;
    padding: 0.3rem 0.7rem;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    border: 1px solid var(--border);
    background: rgba(22, 32, 58, 0.7);
    color: var(--muted);
    white-space: nowrap;
}}

.cs-badge .cs-dot {{
    width: 6px; height: 6px; border-radius: 50%;
    background: currentColor;
    box-shadow: 0 0 8px currentColor;
}}

.cs-badge.live   {{ color: var(--green); border-color: rgba(74, 222, 128, 0.3); }}
.cs-badge.info   {{ color: var(--cyan);  border-color: rgba(34, 211, 238, 0.3); }}
.cs-badge.danger {{ color: var(--red);   border-color: rgba(248, 113, 113, 0.32); }}
.cs-badge.warn   {{ color: var(--amber); border-color: rgba(251, 191, 36, 0.32); }}

.cs-page-title {{
    font-family: var(--font-display);
    font-size: 2.05rem;
    font-weight: 700;
    margin: 0.2rem 0 0.35rem;
    letter-spacing: -0.03em;
}}

.cs-page-sub {{
    color: var(--muted);
    font-size: 0.98rem;
    margin: 0 0 1.4rem;
    max-width: 76ch;
}}

/* ======================================================================
   3. Cartes et composants maison
   ====================================================================== */
.cs-card {{
    background: linear-gradient(150deg, rgba(17, 26, 46, 0.85), rgba(13, 20, 36, 0.85));
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 1.15rem 1.3rem;
    margin-bottom: 1rem;
}}

.cs-card.inset {{ background: rgba(13, 20, 36, 0.6); }}

.cs-section {{
    display: flex;
    align-items: center;
    gap: 0.7rem;
    margin: 1.8rem 0 0.9rem;
}}

.cs-section-bar {{
    width: 3px; height: 20px; border-radius: 2px;
    background: linear-gradient(180deg, var(--cyan), var(--blue));
}}

.cs-section-title {{
    font-family: var(--font-display);
    font-size: 1.06rem;
    font-weight: 600;
    letter-spacing: -0.01em;
}}

.cs-section-note {{
    margin-left: auto;
    font-size: 0.76rem;
    color: var(--faint);
    text-transform: uppercase;
    letter-spacing: 0.08em;
}}

/* Indicateurs chiffrés */
.cs-kpis {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.75rem; }}

.cs-kpi {{
    background: rgba(13, 20, 36, 0.75);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.85rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
}}

.cs-kpi-label {{
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--faint);
    font-weight: 600;
}}

.cs-kpi-value {{
    font-family: var(--font-display);
    font-size: 1.65rem;
    font-weight: 700;
    line-height: 1.15;
}}

.cs-kpi-value.cyan  {{ color: var(--cyan); }}
.cs-kpi-value.green {{ color: var(--green); }}
.cs-kpi-value.amber {{ color: var(--amber); }}
.cs-kpi-value.red   {{ color: var(--red); }}

.cs-kpi-hint {{ font-size: 0.74rem; color: var(--faint); }}

/* Lignes de critères */
.cs-criterion {{
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
    padding: 0.45rem 0;
    border-bottom: 1px solid var(--border-soft);
    font-size: 0.9rem;
}}

.cs-criterion:last-child {{ border-bottom: none; }}

.cs-check {{
    flex-shrink: 0;
    width: 18px; height: 18px;
    border-radius: 50%;
    display: grid; place-items: center;
    font-size: 0.68rem;
    font-weight: 700;
    margin-top: 0.15rem;
}}

.cs-check.ok   {{ background: rgba(74, 222, 128, 0.15); color: var(--green); border: 1px solid rgba(74, 222, 128, 0.35); }}
.cs-check.ko   {{ background: rgba(248, 113, 113, 0.13); color: var(--red); border: 1px solid rgba(248, 113, 113, 0.32); }}

/* Jauge de robustesse */
.cs-meter {{
    height: 8px;
    border-radius: 999px;
    background: var(--surface-2);
    overflow: hidden;
    margin: 0.5rem 0 0.2rem;
}}

.cs-meter-fill {{ height: 100%; border-radius: 999px; transition: width 0.4s ease; }}

.cs-verdict {{
    display: inline-flex;
    align-items: baseline;
    gap: 0.5rem;
    font-family: var(--font-display);
    font-size: 1.15rem;
    font-weight: 700;
}}

.cs-verdict .cs-score {{ font-size: 0.85rem; color: var(--muted); font-weight: 500; }}

/* ======================================================================
   4. Encart 1Password (appel à l'action)
   ====================================================================== */
.cs-cta {{
    display: flex;
    gap: 1.1rem;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    background: linear-gradient(135deg, rgba(34, 211, 238, 0.09) 0%, rgba(59, 130, 246, 0.06) 60%, rgba(168, 85, 247, 0.08) 100%);
    border: 1px solid rgba(34, 211, 238, 0.28);
    border-radius: var(--radius-lg);
    padding: 1.1rem 1.3rem;
    margin-top: 1.2rem;
}}

.cs-cta-body {{ flex: 1 1 340px; min-width: 260px; }}

.cs-cta-title {{
    font-family: var(--font-display);
    font-size: 1.02rem;
    font-weight: 700;
    margin-bottom: 0.3rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}}

.cs-cta-text {{ font-size: 0.88rem; color: var(--muted); margin: 0 0 0.4rem; }}

.cs-cta-alt {{ font-size: 0.76rem; color: var(--faint); margin: 0; }}

.cs-cta-link {{
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.72rem 1.35rem;
    border-radius: var(--radius);
    background: linear-gradient(135deg, var(--cyan-deep), var(--blue));
    color: #04121a !important;
    font-family: var(--font-display);
    font-weight: 700;
    font-size: 0.92rem;
    white-space: nowrap;
    text-decoration: none !important;
    box-shadow: 0 8px 22px rgba(34, 211, 238, 0.22);
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}}

.cs-cta-link:hover {{
    transform: translateY(-1px);
    box-shadow: 0 10px 28px rgba(34, 211, 238, 0.34);
    color: #04121a !important;
}}

.cs-cta-note {{ font-size: 0.72rem; color: var(--faint); margin-top: 0.5rem; }}

/* ======================================================================
   5. Veille : vulnérabilités et actualités
   ====================================================================== */
.cs-vuln {{
    background: rgba(13, 20, 36, 0.72);
    border: 1px solid var(--border);
    border-left: 3px solid var(--amber);
    border-radius: var(--radius);
    padding: 0.85rem 1rem;
    margin-bottom: 0.6rem;
}}

.cs-vuln.ransomware {{ border-left-color: var(--red); }}

.cs-vuln-head {{
    display: flex;
    align-items: center;
    gap: 0.55rem;
    flex-wrap: wrap;
    margin-bottom: 0.35rem;
}}

.cs-cve {{
    font-family: var(--font-mono);
    font-size: 0.82rem;
    font-weight: 700;
    color: var(--cyan);
    padding: 0.1rem 0.45rem;
    border-radius: 5px;
    background: rgba(34, 211, 238, 0.1);
    border: 1px solid rgba(34, 211, 238, 0.24);
}}

.cs-vuln-title {{ font-weight: 600; font-size: 0.94rem; flex: 1 1 240px; }}

.cs-vuln-meta {{ font-size: 0.78rem; color: var(--faint); display: flex; gap: 0.9rem; flex-wrap: wrap; }}

.cs-vuln-desc {{ font-size: 0.84rem; color: var(--muted); margin: 0.35rem 0 0; }}

.cs-article {{
    display: flex;
    gap: 0.8rem;
    padding: 0.7rem 0.9rem;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: rgba(13, 20, 36, 0.6);
    margin-bottom: 0.5rem;
}}

.cs-article:hover {{ border-color: rgba(34, 211, 238, 0.35); }}

.cs-article-source {{
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 0.09em;
    color: var(--cyan);
    font-weight: 700;
    white-space: nowrap;
    padding-top: 0.15rem;
    min-width: 118px;
}}

.cs-article-title {{ font-weight: 600; font-size: 0.92rem; margin-bottom: 0.15rem; }}
.cs-article-title a {{ color: var(--text); }}
.cs-article-title a:hover {{ color: var(--cyan); }}

.cs-article-meta {{ font-size: 0.75rem; color: var(--faint); }}

.cs-empty {{
    text-align: center;
    padding: 1.6rem 1rem;
    color: var(--faint);
    border: 1px dashed var(--border);
    border-radius: var(--radius);
    font-size: 0.88rem;
}}

/* ======================================================================
   6. Ajustements des composants Streamlit
   ====================================================================== */
/* Onglets */
.stTabs [data-baseweb="tab-list"] {{
    gap: 0.35rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0;
    width: 100%;
}}

.stTabs [data-baseweb="tab"] {{
    height: auto;
    padding: 0.62rem 1.05rem;
    background: transparent;
    border-radius: var(--radius) var(--radius) 0 0;
    color: var(--muted);
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 0.9rem;
    flex: 1 1 auto;
    justify-content: center;
    border-bottom: 2px solid transparent;
    transition: color 0.15s ease, background 0.15s ease;
}}

.stTabs [data-baseweb="tab"]:hover {{
    color: var(--text);
    background: rgba(34, 211, 238, 0.05);
}}

.stTabs [aria-selected="true"] {{
    color: var(--cyan) !important;
    border-bottom: 2px solid var(--cyan) !important;
    background: rgba(34, 211, 238, 0.06);
}}

.stTabs [data-baseweb="tab-highlight"],
.stTabs [data-baseweb="tab-border"] {{ display: none; }}

.stTabs [data-baseweb="tab-panel"] {{ padding-top: 1.3rem; }}

/* Boutons */
.stButton > button, .stFormSubmitButton > button, .stDownloadButton > button {{
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 0.9rem;
    border-radius: var(--radius);
    border: 1px solid var(--border);
    background: var(--surface-2);
    color: var(--text);
    padding: 0.55rem 1.15rem;
    transition: all 0.15s ease;
}}

.stButton > button:hover, .stFormSubmitButton > button:hover, .stDownloadButton > button:hover {{
    border-color: var(--cyan);
    color: var(--cyan);
    background: rgba(34, 211, 238, 0.08);
}}

.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {{
    background: linear-gradient(135deg, var(--cyan-deep), var(--blue));
    border: none;
    color: #04121a;
    box-shadow: 0 6px 18px rgba(34, 211, 238, 0.2);
}}

.stButton > button[kind="primary"]:hover {{ color: #04121a; filter: brightness(1.07); }}

.stButton > button:focus-visible {{ outline: 2px solid var(--cyan); outline-offset: 2px; }}

/* Champs de saisie */
.stTextInput input, .stNumberInput input, .stTextArea textarea {{
    background: rgba(10, 14, 26, 0.85) !important;
    border: 1px solid var(--border) !important;
    border-radius: var(--radius) !important;
    color: var(--text) !important;
    font-family: var(--font-mono) !important;
    font-size: 0.92rem !important;
    padding: 0.6rem 0.8rem !important;
}}

.stTextInput input:focus, .stTextArea textarea:focus {{
    border-color: var(--cyan) !important;
    box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.14) !important;
}}

.stTextInput label, .stTextArea label, .stSelectbox label {{
    font-size: 0.86rem !important;
    color: var(--muted) !important;
    font-weight: 500 !important;
}}

[data-baseweb="select"] > div {{
    background: rgba(10, 14, 26, 0.85) !important;
    border-color: var(--border) !important;
    border-radius: var(--radius) !important;
    color: var(--text) !important;
}}

[data-baseweb="popover"] [role="listbox"] {{
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
}}

/* Alertes */
[data-testid="stAlert"] {{
    border-radius: var(--radius);
    border: 1px solid var(--border);
    background: rgba(17, 26, 46, 0.75);
    font-size: 0.9rem;
    padding: 0.75rem 1rem;
}}

[data-testid="stAlert"] p {{ margin-bottom: 0.15rem; }}

/* Bloc dépliable */
[data-testid="stExpander"] {{
    border: 1px solid var(--border) !important;
    border-radius: var(--radius) !important;
    background: rgba(13, 20, 36, 0.6);
    overflow: hidden;
}}

[data-testid="stExpander"] summary {{
    font-family: var(--font-display);
    font-weight: 600;
    font-size: 0.9rem;
    color: var(--muted);
}}

[data-testid="stExpander"] summary:hover {{ color: var(--cyan); }}

/* Barre de progression */
.stProgress > div > div > div {{ background: var(--surface-2); }}
.stProgress > div > div > div > div {{
    background: linear-gradient(90deg, var(--cyan), var(--blue));
}}

/* Barre latérale */
[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, #0b1220 0%, #0a0e1a 100%);
    border-right: 1px solid var(--border);
}}

[data-testid="stSidebar"] .block-container {{ padding-top: 1.6rem; }}

[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {{
    font-family: var(--font-display);
    font-size: 0.82rem !important;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: var(--faint);
    font-weight: 700;
}}

[data-testid="stSidebar"] hr {{ border-color: var(--border-soft); margin: 1rem 0; }}

/* Tableaux et blocs de code */
[data-testid="stDataFrame"] {{ border: 1px solid var(--border); border-radius: var(--radius); }}

pre, code {{
    background: rgba(10, 14, 26, 0.9) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    color: #cfe4f7 !important;
    font-size: 0.84rem !important;
}}

/* Métriques natives */
[data-testid="stMetric"] {{
    background: rgba(13, 20, 36, 0.72);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 0.85rem 1rem;
}}

[data-testid="stMetricLabel"] {{
    font-size: 0.72rem !important;
    text-transform: uppercase;
    letter-spacing: 0.09em;
    color: var(--faint) !important;
}}

[data-testid="stMetricValue"] {{
    font-family: var(--font-display);
    font-size: 1.6rem !important;
    color: var(--text) !important;
}}

/* Spinner et barre de statut */
[data-testid="stSpinner"] > div {{ border-top-color: var(--cyan) !important; }}

[data-testid="stStatusWidget"] {{ color: var(--faint); }}

/* Pied de page */
.cs-footer {{
    margin-top: 2.6rem;
    padding-top: 1.2rem;
    border-top: 1px solid var(--border-soft);
    display: flex;
    justify-content: space-between;
    gap: 1rem;
    flex-wrap: wrap;
    font-size: 0.78rem;
    color: var(--faint);
}}

.cs-footer .cs-mono {{ font-size: 0.76rem; }}

/* Séparateur */
.cs-divider {{
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--border), transparent);
    margin: 1.6rem 0;
}}

/* Défilement */
::-webkit-scrollbar {{ width: 10px; height: 10px; }}
::-webkit-scrollbar-track {{ background: var(--bg); }}
::-webkit-scrollbar-thumb {{ background: #1c2942; border-radius: 6px; }}
::-webkit-scrollbar-thumb:hover {{ background: #24344f; }}

/* Responsive */
@media (max-width: 780px) {{
    .cs-page-title {{ font-size: 1.6rem; }}
    .cs-hero {{ padding: 1.2rem; }}
    .cs-article-source {{ min-width: auto; }}
    .cs-cta {{ flex-direction: column; align-items: flex-start; }}
    .cs-cta-link {{ width: 100%; justify-content: center; }}
}}
</style>
"""


# --------------------------------------------------------------------------
# Petits constructeurs de HTML
# --------------------------------------------------------------------------
# Le markdown de Streamlit interprète toute ligne indentée de 4 espaces — ou
# suivant une ligne vide — comme un bloc de code : le HTML s'affiche alors en
# clair au lieu d'être rendu. On supprime donc retours à la ligne et indentation
# de tout le balisage produit ici.
def compact(markup: str) -> str:
    """Aplatit un fragment HTML sur une seule ligne."""
    return re.sub(r"\s*\n\s*", " ", markup).strip()


def hero(brand: str, accent: str, suffix: str, badges: list) -> str:
    """En-tête de marque avec pastilles d'état."""
    badge_html = "".join(
        f'<span class="cs-badge {kind}"><span class="cs-dot"></span>{label}</span>'
        for kind, label in badges
    )
    return compact(f"""
    <div class="cs-hero">
        <div class="cs-brand">
            <div class="cs-logo">🛡️</div>
            <div class="cs-brand-text">
                <div class="cs-brand-name">{brand} <span class="cs-accent">{accent}</span></div>
                <div class="cs-brand-suffix">{suffix}</div>
            </div>
        </div>
        <div class="cs-badges">{badge_html}</div>
    </div>
    """)


def page_title(title: str, subtitle: str) -> str:
    """Titre de page avec sous-titre."""
    return compact(
        f'<div class="cs-page-title">{title}</div>'
        f'<p class="cs-page-sub">{subtitle}</p>'
    )


def section(title: str, note: str = "") -> str:
    """Titre de section avec barre d'accent."""
    note_html = f'<span class="cs-section-note">{escape_note(note)}</span>' if note else ""
    return compact(
        '<div class="cs-section">'
        '<div class="cs-section-bar"></div>'
        f'<span class="cs-section-title">{title}</span>{note_html}'
        "</div>"
    )


def escape_note(note: str) -> str:
    """Échappe une note affichée dans une section (donnée d'origine externe)."""
    return html_module.escape(str(note), quote=True)


def kpi(label: str, value, hint: str = "", tone: str = "") -> str:
    """Indicateur chiffré."""
    hint_html = f'<span class="cs-kpi-hint">{hint}</span>' if hint else ""
    return compact(
        f'<div class="cs-kpi">'
        f'<span class="cs-kpi-label">{label}</span>'
        f'<span class="cs-kpi-value {tone}">{value}</span>'
        f"{hint_html}"
        f"</div>"
    )


def kpi_row(items: list) -> str:
    """Grille d'indicateurs. `items` = liste de tuples (label, value, hint, tone)."""
    cards = "".join(kpi(label, value, hint, tone) for label, value, hint, tone in items)
    return f'<div class="cs-kpis">{cards}</div>'


def criterion(text: str, met: bool) -> str:
    """Ligne de critère avec sa pastille de validation."""
    mark = "✓" if met else "✕"
    css = "ok" if met else "ko"
    return compact(
        f'<div class="cs-criterion"><span class="cs-check {css}">{mark}</span>'
        f"<span>{text}</span></div>"
    )


def meter(percentage: float, color: str) -> str:
    """Jauge horizontale de robustesse."""
    return compact(
        '<div class="cs-meter">'
        f'<div class="cs-meter-fill" style="width:{max(0, min(100, percentage)):.0f}%;'
        f'background:linear-gradient(90deg,{color},{color}99)"></div>'
        "</div>"
    )


def divider() -> str:
    return '<div class="cs-divider"></div>'


def footer(left: str, right: str) -> str:
    return compact(
        f'<div class="cs-footer"><span>{left}</span>'
        f'<span class="cs-mono">{right}</span></div>'
    )
