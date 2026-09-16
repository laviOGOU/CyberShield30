# CyberShield — Security Auditor

Application **Python / Streamlit** d'audit de sécurité : robustesse d'un mot de
passe, exposition d'une adresse e-mail, veille sur les vulnérabilités activement
exploitées et actualité sécurité.

🔗 Application en ligne : **https://cybershield30.streamlit.app/**

---

## 1. Fonctionnalités

| Onglet | Contenu |
|---|---|
| **Audit mot de passe** | Analyse locale des critères de complexité, détection des schémas faibles, contrôle d'exposition dans les fuites connues (k-anonymat), recommandations, encart gestionnaire de mots de passe |
| **Fuite e-mail** | Recherche de l'adresse dans les violations de données publiques, liste des services concernés, plan d'action |
| **Menaces en direct** | Catalogue **CISA KEV** en temps réel (vulnérabilités activement exploitées), recherche par éditeur/produit/CVE, actualité de The Hacker News, BleepingComputer et CERT-FR |
| **Télémétrie** | Compteurs anonymisés d'utilisation de la plateforme |

Bilingue français / anglais, bascule dans la barre latérale.

---

## 2. Design

Direction visuelle reprise des sites du secteur (référence : **hacktualiz.com**).

**Typographie à trois niveaux**

| Police | Usage |
|---|---|
| **Space Grotesk** | Titres, chiffres, libellés d'interface |
| **Figtree** | Texte courant |
| **Instrument Serif** (italique) | Mots d'accent (« *Security Auditor* ») |

**Palette** — fond bleu nuit `#0a0e1a`, surfaces `#111a2e`, bordures `#1e2b45`,
accents cyan `#22d3ee` / bleu `#3b82f6` / violet `#a855f7`, statuts vert
`#4ade80`, ambre `#fbbf24`, rouge `#f87171`.

Tout est centralisé dans deux fichiers :

* `theme.py` — palette, CSS complet et constructeurs de composants (en-tête,
  cartes d'indicateurs, critères, jauges, encart d'appel à l'action) ;
* `.streamlit/config.toml` — thème de base appliqué par Streamlit.

---

## 3. Sources de données (temps réel, sans clé d'API)

| Source | Ce qu'elle apporte |
|---|---|
| **CISA KEV** (`known_exploited_vulnerabilities.json`) | ~1 700 vulnérabilités activement exploitées, avec éditeur, produit, date d'ajout, échéance fédérale et indicateur rançongiciel |
| **The Hacker News** (RSS) | Actualité sécurité internationale |
| **BleepingComputer** (RSS) | Actualité sécurité et correctifs |
| **CERT-FR / ANSSI** (RSS) | Avis et alertes francophones |
| **Pwned Passwords** (API) | Exposition d'un mot de passe, interrogeable en k-anonymat |
| **xposedornot.com** (API) | Exposition d'une adresse e-mail |

Les appels réseau sont mis en cache (1 h pour le catalogue KEV, 30 min pour les
flux) et chaque source est appelée avec un délai d'attente explicite. Une source
en panne n'empêche pas les autres de s'afficher.

---

## 4. Sécurité

Le détail complet est dans **[SECURITY.md](SECURITY.md)**. En résumé :

* **Aucun mot de passe ne quitte le poste** — l'analyse est locale, et le contrôle
  d'exposition n'envoie que les 5 premiers caractères de l'empreinte SHA-1
  (k-anonymat), jamais le mot de passe ni son empreinte complète ;
* **Toutes les entrées sont validées** (format d'e-mail ancré, longueurs bornées) ;
* **Tout contenu externe est échappé** avant affichage (flux RSS, API) ;
* **Les liens sont filtrés** : seuls les schémas `http(s)` sont acceptés, ce qui
  bloque les `javascript:` qu'un flux compromis pourrait injecter ;
* **Les requêtes SQL sont paramétrées** — la table de télémétrie est en outre
  élaguée automatiquement ;
* **Aucune donnée personnelle stockée** : ni adresse e-mail, ni mot de passe, ni
  adresse IP ; l'empreinte du navigateur est hachée avec un sel régénéré à
  chaque démarrage ;
* **Limitation d'usage** par session pour ne pas épuiser les API publiques ;
* **Aucun détail technique exposé** à l'utilisateur en cas d'erreur
  (`showErrorDetails = false`).

---

## 5. Lancer en local

```bash
cd "D:\PYTHON\levisecu_app"
python -m venv venv
venv\Scripts\python.exe -m pip install -r requirements.txt
venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1
```

Puis <http://localhost:8501>.

> `--server.address 127.0.0.1` limite l'accès à votre poste. Sans cette option,
> Streamlit écoute sur toutes les interfaces réseau et l'application devient
> joignable depuis le réseau local.

### Tests

```bash
venv\Scripts\python.exe -m pytest -v
```

* `test_security.py` — 63 tests : injection SQL, échappement HTML, filtrage
  d'URL, validation des saisies, anonymisation, limitation d'usage, analyse de
  mot de passe, veille, traductions, télémétrie ;
* `test_app.py` — 24 tests : exécution réelle de l'application avec l'API de test
  de Streamlit (rendu des onglets, encart 1Password, verdicts, recherche KEV,
  bascule de langue, absence de balisage affiché en clair).

---

## 6. Structure du projet

```
levisecu_app/
├── app.py              application Streamlit (interface)
├── theme.py            système de design (CSS + composants)
├── i18n.py             textes français / anglais
├── security.py         validation, échappement, anonymisation, API d'audit
├── threat_intel.py     catalogue CISA KEV et flux RSS
├── db.py               télémétrie anonymisée (SQLite)
├── test_security.py    tests des modules
├── test_app.py         tests de l'application
├── requirements.txt    dépendances
├── SECURITY.md         modèle de sécurité
├── captures/           captures d'écran
└── .streamlit/
    └── config.toml     thème et durcissement
```

---

## 7. Limites connues

* Le verdict de robustesse est **indicatif** : il repose sur des critères de
  complexité, pas sur une estimation d'entropie ni sur une simulation d'attaque.
  Un mot de passe peut satisfaire tous les critères et rester devinable.
* L'API d'exposition des mots de passe est **publique et partagée** : elle peut
  être momentanément indisponible (l'application l'indique alors explicitement,
  sans conclure à tort à l'absence de fuite).
* La télémétrie est stockée dans un fichier SQLite **local** : sur une plateforme
  d'hébergement éphémère, les compteurs repartent de zéro à chaque redéploiement
  (voir la section 8 pour y remédier).
* L'API d'analyse d'e-mail reçoit l'adresse saisie. C'est signalé dans
  l'interface avant la recherche.

---

## 8. Déploiement en ligne

### Railway

Le fichier `Procfile` fournit la commande de démarrage (sans lui, Railway
exécuterait `python app.py`, qui ne lance aucun serveur web) :

```
web: streamlit run app.py --server.port $PORT --server.address 0.0.0.0 --server.headless true
```

Deux points d'attention :

* **Domaine personnalisé** : l'offre gratuite Railway en autorise **zéro**.
  Il faut au minimum le plan Trial (1 domaine) ou Hobby (2 domaines par service).
  Une fois le domaine ajouté dans *Settings → Networking → Custom Domain*,
  Railway affiche un enregistrement `CNAME` **et** un enregistrement `TXT` de
  vérification : les deux sont obligatoires, sinon le domaine renvoie une
  erreur 404 même après résolution du CNAME.
* **Persistance** : le système de fichiers d'un conteneur Railway est éphémère.
  Pour conserver la télémétrie, montez un volume et pointez la variable
  d'environnement `CYBERSHIELD_DB_PATH` dessus :

```
CYBERSHIELD_DB_PATH=/data/cybershield_data.db
```

En local, cette variable est facultative : la base reste `cybershield_data.db`
à la racine du projet.

---

## 9. Avertissement

Outil pédagogique. Il ne remplace pas un audit de sécurité professionnel et ne
garantit ni l'exhaustivité des fuites détectées ni la sécurité d'un compte.
