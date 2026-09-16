"""
i18n.py — Textes de l'interface (français / anglais).

Tout le contenu affiché est centralisé ici : aucune chaîne de caractères en dur
dans la couche d'affichage, ce qui évite les oublis de traduction.
"""

TRANSLATIONS = {
    "FR": {
        # ---- En-tête -------------------------------------------------------
        "brand": "CYBERSHIELD",
        "brand_suffix": "Security Auditor",
        "title": "Centre de contrôle sécurité",
        "subtitle": "Évaluation de robustesse, exposition aux fuites et veille sur les vulnérabilités exploitées",
        "welcome_title": "Bienvenue dans votre centre de contrôle",
        "welcome_text": (
            "Trois modules : <b>audit de mot de passe</b>, <b>exposition d'une adresse e-mail</b> "
            "et <b>veille sur les vulnérabilités activement exploitées</b> (CISA KEV)."
        ),
        "badge_live": "Données en direct",
        "badge_privacy": "Aucun mot de passe transmis",

        # ---- Barre latérale ------------------------------------------------
        "sidebar_config": "Configuration",
        "sidebar_lang": "Langue / Language",
        "sidebar_about_title": "Confidentialité",
        "sidebar_about": (
            "Les mots de passe ne quittent jamais votre navigateur en clair. "
            "Le contrôle d'exposition utilise le **k-anonymat** : seuls les 5 premiers "
            "caractères de l'empreinte SHA-1 sont envoyés, jamais le mot de passe."
        ),
        "sidebar_status": "État du service",
        "sidebar_privacy_link": "Politique de confidentialité de l'API",

        # ---- Onglets -------------------------------------------------------
        "tab_pwd": "Audit mot de passe",
        "tab_email": "Fuite e-mail",
        "tab_threats": "Menaces en direct",
        "tab_stats": "Télémétrie",

        # ---- Onglet mot de passe -------------------------------------------
        "pwd_subtitle": "Analyse de la robustesse des identifiants",
        "pwd_label": "Saisissez le mot de passe à évaluer :",
        "pwd_hint": "Le mot de passe est analysé localement, puis comparé anonymement aux fuites connues.",
        "pwd_diag": "Diagnostic",
        "pwd_level": "Niveau de sécurité :",
        "pwd_strong": "Fort",
        "pwd_medium": "Moyen",
        "pwd_weak": "Faible",
        "pwd_criteria_title": "Critères d'évaluation",
        "pwd_breach_title": "Vérification dans les fuites publiques",
        "pwd_breach_danger": "Présent {count:,} fois dans des fuites de données connues",
        "pwd_breach_safe": "Aucune fuite connue pour ce mot de passe",
        "pwd_breach_error": "Vérification impossible (API injoignable ou quota atteint)",
        "pwd_recom_title": "Recommandations",
        "pwd_actions_req": "Points à corriger :",
        "pwd_structure_ok": "Tous les critères de complexité sont satisfaits.",
        "pwd_critical_alert": "Ce mot de passe figure dans des bases piratées : cessez de l'utiliser.",
        "pwd_tips_title": "Bonnes pratiques",
        "pwd_tips_body": (
            "1. **Utilisez une phrase de passe** : assemblez 4 ou 5 mots sans lien logique "
            "(ex. `Cafetiere#Bleu$Trompette98!`).\n"
            "2. **Adoptez un gestionnaire de mots de passe** : il génère et retient des identifiants "
            "uniques que vous n'avez pas à mémoriser.\n"
            "3. **Un mot de passe par service** : une fuite isolée ne compromet alors pas les autres comptes.\n"
            "4. **Activez la double authentification (2FA)** : le mot de passe seul ne suffit plus."
        ),
        "pwd_mgr_title": "Passez au gestionnaire de mots de passe",
        "pwd_mgr_text": (
            "Un mot de passe fort que vous réutilisez reste un point de défaillance. "
            "Un gestionnaire génère un identifiant unique par service, les chiffre et les "
            "remplit automatiquement — vous n'en retenez qu'un seul."
        ),
        "pwd_mgr_cta": "Découvrir 1Password",
        "pwd_mgr_note": "Recommandation indépendante — ouvre le site officiel dans un nouvel onglet.",
        "pwd_mgr_alt": "Autres alternatives libres : Bitwarden, KeePassXC.",
        "pwd_field_empty": "Saisissez un mot de passe pour lancer l'analyse.",
        "pwd_chars": "{n} caractères",

        # ---- Critères d'évaluation -----------------------------------------
        "c_len": "Longueur d'au moins 12 caractères",
        "c_len_rec": "Rallongez le mot de passe (visez 16 caractères ou plus).",
        "c_upper": "Contient des lettres majuscules (A-Z)",
        "c_upper_rec": "Insérez au moins une lettre majuscule.",
        "c_lower": "Contient des lettres minuscules (a-z)",
        "c_lower_rec": "Incorporez des lettres minuscules.",
        "c_num": "Contient des chiffres (0-9)",
        "c_num_rec": "Ajoutez un ou plusieurs chiffres.",
        "c_sym": "Contient des symboles spéciaux (!@#$%...)",
        "c_sym_rec": "Ajoutez des caractères spéciaux (ex. @, #, !, $).",

        # ---- Onglet e-mail -------------------------------------------------
        "email_subtitle": "Analyse d'exposition d'une adresse e-mail",
        "email_label": "Adresse e-mail à vérifier :",
        "email_btn": "Rechercher les fuites",
        "email_pwned": "L'adresse <b>{email}</b> apparaît dans des violations de données connues.",
        "email_breaches_list": "Services concernés :",
        "email_breach_unknown": "Autre service non détaillé",
        "email_clean": "Aucune compromission connue pour <b>{email}</b>.",
        "email_invalid": "Format d'adresse e-mail invalide.",
        "email_recom_title": "Plan d'action",
        "email_recom_box": (
            "<h4>1. Changez les mots de passe associés</h4>"
            "<p>Modifiez immédiatement le mot de passe du service concerné, et celui de votre "
            "boîte e-mail s'il était identique.</p>"
            "<h4>2. Activez la double authentification</h4>"
            "<p>Configurez la validation en deux étapes sur vos comptes principaux.</p>"
            "<h4>3. Restez vigilant face à l'hameçonnage</h4>"
            "<p>Vos données circulant sur des forums criminels, méfiez-vous des messages "
            "inhabituels citant des informations personnelles.</p>"
        ),
        "email_privacy_note": (
            "L'adresse saisie est transmise à l'API publique xposedornot.com pour la recherche. "
            "N'utilisez pas cette fonction sur une adresse dont vous ne voulez pas qu'elle quitte votre poste."
        ),

        # ---- Onglet menaces -------------------------------------------------
        "threats_subtitle": "Vulnérabilités exploitées et actualités sécurité",
        "threats_kev_title": "Catalogue CISA KEV — vulnérabilités activement exploitées",
        "threats_kev_desc": (
            "Le catalogue KEV de la CISA recense les vulnérabilités dont l'exploitation "
            "a été observée dans la nature. Une entrée KEV signifie : le correctif n'est pas "
            "optionnel."
        ),
        "threats_kev_count": "{n} vulnérabilités recensées",
        "threats_kev_version": "Version du catalogue : {v}",
        "threats_ransomware": "Exploitée par des rançongiciels",
        "threats_due": "Échéance fédérale : {d}",
        "threats_added": "Ajoutée le {d}",
        "threats_search": "Filtrer par éditeur, produit ou identifiant CVE",
        "threats_count": "{n} résultat(s)",
        "threats_recent": "Ajouts récents",
        "threats_news_title": "Actualités sécurité (flux RSS)",
        "threats_news_desc": "Derniers articles publiés par les sources de veille.",
        "threats_source_all": "Toutes les sources",
        "threats_no_result": "Aucun résultat pour ce filtre.",
        "threats_error": "Source injoignable pour le moment : {err}",
        "threats_cvss": "Gravité",
        "threats_products": "Produits concernés",
        "threats_action": "Action recommandée : identifiez si ce produit est utilisé dans votre "
                          "organisation, puis appliquez le correctif de l'éditeur ou retirez le service "
                          "d'exposition Internet.",
        "threats_refresh": "Actualiser les données",

        # ---- Onglet télémétrie ---------------------------------------------
        "stats_subtitle": "Télémétrie anonymisée de la plateforme",
        "stats_visits": "Visites",
        "stats_pwd_tests": "Mots de passe analysés",
        "stats_email_tests": "E-mails contrôlés",
        "stats_alerts": "Expositions détectées",
        "stats_dist": "Répartition de la robustesse",
        "stats_logs": "Événements récents",
        "stats_privacy": (
            "La télémétrie est anonyme : aucun mot de passe, aucune adresse e-mail et aucune "
            "adresse IP ne sont enregistrés. L'empreinte du navigateur est hachée avant stockage."
        ),
        "stats_empty": "Aucune donnée enregistrée pour le moment.",
        "stats_persistence_note": (
            "Les compteurs sont stockés dans une base SQLite locale. Sur une plateforme "
            "d'hébergement éphémère, ils repartent de zéro à chaque redéploiement."
        ),

        # ---- Pied de page ---------------------------------------------------
        "footer_version": "CyberShield v3.0",
    },
    "EN": {
        "brand": "CYBERSHIELD",
        "brand_suffix": "Security Auditor",
        "title": "Security control center",
        "subtitle": "Strength assessment, breach exposure and tracking of actively exploited vulnerabilities",
        "welcome_title": "Welcome to your control center",
        "welcome_text": (
            "Three modules: <b>password audit</b>, <b>email breach exposure</b> "
            "and <b>tracking of actively exploited vulnerabilities</b> (CISA KEV)."
        ),
        "badge_live": "Live data",
        "badge_privacy": "No password ever transmitted",

        "sidebar_config": "Configuration",
        "sidebar_lang": "Language / Langue",
        "sidebar_about_title": "Privacy",
        "sidebar_about": (
            "Passwords never leave your browser in clear text. The exposure check uses "
            "**k-anonymity**: only the first 5 characters of the SHA-1 hash are sent, never "
            "the password itself."
        ),
        "sidebar_status": "Service status",
        "sidebar_privacy_link": "API privacy policy",

        "tab_pwd": "Password audit",
        "tab_email": "Email breach",
        "tab_threats": "Live threats",
        "tab_stats": "Telemetry",

        "pwd_subtitle": "Credential strength assessment",
        "pwd_label": "Enter the password to evaluate:",
        "pwd_hint": "The password is analysed locally, then compared anonymously against known breaches.",
        "pwd_diag": "Diagnosis",
        "pwd_level": "Security level:",
        "pwd_strong": "Strong",
        "pwd_medium": "Medium",
        "pwd_weak": "Weak",
        "pwd_criteria_title": "Evaluation criteria",
        "pwd_breach_title": "Public breach check",
        "pwd_breach_danger": "Found {count:,} times in known data breaches",
        "pwd_breach_safe": "No known breach for this password",
        "pwd_breach_error": "Check unavailable (API unreachable or rate limited)",
        "pwd_recom_title": "Recommendations",
        "pwd_actions_req": "Points to fix:",
        "pwd_structure_ok": "All complexity criteria are satisfied.",
        "pwd_critical_alert": "This password appears in leaked databases: stop using it.",
        "pwd_tips_title": "Best practices",
        "pwd_tips_body": (
            "1. **Use a passphrase**: combine 4 or 5 unrelated words "
            "(e.g. `Coffee#Blue$Trumpet98!`).\n"
            "2. **Use a password manager**: it generates and remembers unique credentials "
            "you never have to memorise.\n"
            "3. **One password per service**: a single leak then cannot compromise your other accounts.\n"
            "4. **Enable two-factor authentication (2FA)**: a password alone is no longer enough."
        ),
        "pwd_mgr_title": "Move to a password manager",
        "pwd_mgr_text": (
            "A strong password you reuse is still a single point of failure. A manager generates "
            "a unique credential per service, encrypts it and fills it in automatically — you only "
            "have to remember one."
        ),
        "pwd_mgr_cta": "Discover 1Password",
        "pwd_mgr_note": "Independent recommendation — opens the official website in a new tab.",
        "pwd_mgr_alt": "Free alternatives: Bitwarden, KeePassXC.",
        "pwd_field_empty": "Enter a password to start the analysis.",
        "pwd_chars": "{n} characters",

        # ---- Evaluation criteria -------------------------------------------
        "c_len": "At least 12 characters long",
        "c_len_rec": "Make it longer (aim for 16 characters or more).",
        "c_upper": "Contains uppercase letters (A-Z)",
        "c_upper_rec": "Insert at least one uppercase letter.",
        "c_lower": "Contains lowercase letters (a-z)",
        "c_lower_rec": "Include lowercase letters.",
        "c_num": "Contains numbers (0-9)",
        "c_num_rec": "Add one or more numbers.",
        "c_sym": "Contains special symbols (!@#$%...)",
        "c_sym_rec": "Add special characters (e.g. @, #, !, $).",

        "email_subtitle": "Email address exposure analysis",
        "email_label": "Email address to check:",
        "email_btn": "Search breaches",
        "email_pwned": "The address <b>{email}</b> appears in known data breaches.",
        "email_breaches_list": "Affected services:",
        "email_breach_unknown": "Other undisclosed service",
        "email_clean": "No known compromise for <b>{email}</b>.",
        "email_invalid": "Invalid email address format.",
        "email_recom_title": "Action plan",
        "email_recom_box": (
            "<h4>1. Change the associated passwords</h4>"
            "<p>Immediately update the password of the affected service, and your email account "
            "if it was the same.</p>"
            "<h4>2. Enable multi-factor authentication</h4>"
            "<p>Set up two-step verification on your main accounts.</p>"
            "<h4>3. Stay alert to phishing</h4>"
            "<p>Your data is circulating on criminal forums: be wary of unusual messages "
            "quoting personal details.</p>"
        ),
        "email_privacy_note": (
            "The address you type is sent to the public xposedornot.com API for the lookup. "
            "Do not use this on an address you are not comfortable sending off your machine."
        ),

        "threats_subtitle": "Exploited vulnerabilities and security news",
        "threats_kev_title": "CISA KEV catalog — actively exploited vulnerabilities",
        "threats_kev_desc": (
            "The CISA KEV catalog lists vulnerabilities with observed exploitation in the wild. "
            "A KEV entry means: patching is not optional."
        ),
        "threats_kev_count": "{n} vulnerabilities listed",
        "threats_kev_version": "Catalog version: {v}",
        "threats_ransomware": "Known ransomware use",
        "threats_due": "Federal due date: {d}",
        "threats_added": "Added on {d}",
        "threats_search": "Filter by vendor, product or CVE identifier",
        "threats_count": "{n} result(s)",
        "threats_recent": "Recent additions",
        "threats_news_title": "Security news (RSS feeds)",
        "threats_news_desc": "Latest articles published by the monitoring sources.",
        "threats_source_all": "All sources",
        "threats_no_result": "No result for this filter.",
        "threats_error": "Source unavailable right now: {err}",
        "threats_cvss": "Severity",
        "threats_products": "Affected products",
        "threats_action": "Recommended action: determine whether this product is used in your "
                          "organisation, then apply the vendor fix or remove the service from "
                          "Internet exposure.",
        "threats_refresh": "Refresh data",

        "stats_subtitle": "Anonymised platform telemetry",
        "stats_visits": "Visits",
        "stats_pwd_tests": "Passwords analysed",
        "stats_email_tests": "Emails checked",
        "stats_alerts": "Exposures detected",
        "stats_dist": "Strength distribution",
        "stats_logs": "Recent events",
        "stats_privacy": (
            "Telemetry is anonymous: no password, no email address and no IP address is stored. "
            "The browser fingerprint is hashed before storage."
        ),
        "stats_empty": "No data recorded yet.",
        "stats_persistence_note": (
            "Counters live in a local SQLite database. On an ephemeral hosting platform they "
            "reset to zero on every redeploy."
        ),

        "footer_version": "CyberShield v3.0",
    },
}


def get_translations(lang: str) -> dict:
    """Retourne le dictionnaire de traductions pour la langue demandée."""
    return TRANSLATIONS.get(lang, TRANSLATIONS["FR"])
