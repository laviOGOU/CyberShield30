# Modèle de sécurité — CyberShield

Ce document décrit ce que l'application protège, comment, et ce qu'elle ne
protège pas. Il est destiné à être lu avec le code : chaque point renvoie au
module concerné.

---

## 1. Données traitées et sensibilité

| Donnée | Sensibilité | Traitement |
|---|---|---|
| Mot de passe saisi | Très élevée | Jamais transmis, jamais journalisé, jamais stocké |
| Adresse e-mail saisie | Élevée | Transmise à l'API publique d'exposition, jamais journalisée en clair |
| Empreinte du navigateur | Faible | Hachée avant stockage |
| Compteurs d'usage | Aucune | Stockés localement |

Le principe directeur : **tout ce qui entre dans l'application est traité comme
une donnée non fiable**, et rien de sensible ne quitte le serveur sans nécessité.

---

## 2. Protection des mots de passe

L'analyse de robustesse est **entièrement locale** (`security.py`,
`PasswordSecurityEvaluator.evaluate`) : critères de complexité, détection des
suites connues, des répétitions, des années et des structures courantes.

Le contrôle d'exposition utilise le **k-anonymat** contre l'API Pwned Passwords :

1. l'application calcule l'empreinte SHA-1 du mot de passe ;
2. elle n'envoie que les **5 premiers caractères** de cette empreinte ;
3. l'API renvoie tous les suffixes correspondants (plusieurs centaines d'entrées) ;
4. la comparaison finale se fait **localement**.

L'API ne peut donc pas déterminer quel mot de passe est testé. L'empreinte
complète ne quitte jamais le serveur, et le mot de passe en clair jamais le
navigateur.

> `hashlib.sha1(..., usedforsecurity=False)` est utilisé : SHA-1 est ici imposé
> par le protocole de l'API, et ne sert pas à protéger une donnée mais à
> interroger un index public. La mention explicite évite les alertes des
> analyseurs de sécurité.

---

## 3. Injection

### SQL

Toutes les requêtes sont **paramétrées** (`db.py`) : aucune valeur utilisateur
n'est concaténée dans une requête. Les clés de compteurs sont en outre validées
contre une liste blanche (`METRIC_KEYS`) : une clé inconnue est rejetée au lieu
d'être écrite.

Testé par `test_security.py::TestInjectionSQL` avec cinq charges utiles
classiques (`'; DROP TABLE telemetry; --`, `1' OR '1'='1`, …).

### HTML / XSS

L'interface utilise `unsafe_allow_html=True` pour afficher ses composants : tout
contenu d'origine externe (titres et résumés de flux RSS, données d'API) est donc
**échappé** via `security.escape()` avant insertion dans le HTML.

Testé par `test_security.py::TestEchappement` et
`test_app.py::TestOngletEmail::test_injection_html_dans_le_champ_email`.

### Injection d'URL

Les liens issus des flux RSS passent par `security.safe_url()`, qui **rejette
tout schéma autre que `http` ou `https`**. Un flux compromis ne peut donc pas
injecter `javascript:`, `data:` ou `file:`.

Testé par `test_security.py::TestSafeUrl`.

---

## 4. Données personnelles

* **Aucun mot de passe, aucune adresse e-mail, aucune adresse IP** n'est stocké.
* L'événement journalisé pour un test de mot de passe ne contient que le niveau
  obtenu et un booléen d'exposition (`niveau=Fort exposition=True`).
* L'empreinte du navigateur est hachée en SHA-256 avec un **sel aléatoire
  régénéré à chaque démarrage du processus** (`security._PROCESS_SALT`) : les
  empreintes ne sont ni réversibles, ni comparables d'une exécution à l'autre.
* La télémétrie est visible par l'utilisateur dans l'onglet dédié, et une note
  explique ce qui est collecté.

L'API d'exposition d'e-mail reçoit l'adresse saisie : c'est signalé **avant** la
recherche par un message dans l'interface.

---

## 5. Abus et disponibilité

* **Limitation d'usage par session** (`security.RateLimiter`) : 12 analyses de
  mot de passe et 4 recherches d'e-mail par 5 minutes. Les API utilisées sont
  publiques et gratuites : sans limite, une seule personne peut épuiser le quota
  pour tout le monde et faire bloquer l'application.
* **Bornes de saisie** : mot de passe tronqué à 256 caractères, adresse e-mail à
  254, filtres de recherche à 120. Un hachage sur une chaîne démesurée est ainsi
  évité.
* **Délais d'attente explicites** sur tous les appels réseau, avec dégradation
  propre : une source injoignable est signalée comme telle, jamais interprétée
  comme « aucune fuite ».
* **Journal borné** : la table de télémétrie est élaguée au-delà de 5 000 lignes.

---

## 6. Durcissement de la plateforme

`.streamlit/config.toml` :

| Réglage | Effet |
|---|---|
| `showErrorDetails = false` | Aucune trace technique affichée à l'utilisateur (les journaux restent côté serveur) |
| `enableXsrfProtection = true` | Protection CSRF sur les formulaires et les websockets |
| `maxUploadSize = 5` | Aucun besoin d'import de fichier : la limite est réduite |
| `enableStaticServing = false` | Aucun fichier servi statiquement depuis le dossier |
| `gatherUsageStats = false` | Télémétrie d'usage de Streamlit désactivée |

**Point d'attention en exécution locale** : par défaut Streamlit écoute sur
toutes les interfaces réseau. Pour restreindre l'accès au poste :

```bash
streamlit run app.py --server.address 127.0.0.1
```

---

## 7. Ce que l'application ne fait pas

* **Pas d'authentification** : c'est un outil public, sans donnée par utilisateur.
  Aucune fonctionnalité ne dépend d'un compte.
* **Pas de protection contre les attaques par déni de service distribué** : la
  limitation est en mémoire, par session. Elle vise l'usage abusif, pas un
  attaquant déterminé.
* **Pas de chiffrement applicatif de la base locale** : elle ne contient aucune
  donnée sensible (compteurs et types d'événements uniquement).
* **Pas d'audit des dépendances** : `requirements.txt` fixe des versions
  minimales ; les correctifs de sécurité des dépendances doivent être appliqués
  en mettant à jour ces versions.

---

## 8. Signaler un problème

Ce projet est pédagogique. Si vous identifiez une faille, ouvrez une *issue* sur
le dépôt en décrivant le scénario de reproduction — sans mettre en ligne de
donnée réelle ni de secret.
