# Audit de sécurité du dépôt EventFlow

Audit fait le 23/11/2026 sur la branche `mission-lundi`, avec gitleaks, pip-audit,
bandit et zizmor, plus une relecture des fichiers de configuration.
Les sorties brutes sont dans `docs/preuves/b1-*.txt`.

Règle suivie pendant tout l'audit : le secret trouvé n'a été ni testé, ni copié,
ni collé nulle part. Toutes les commandes gitleaks ont été lancées avec `--redact`.

## 1. Constats (du plus grave au moins grave)

| # | Constat | Où | Outil | Gravité | Preuve | Correction proposée |
|---|---|---|---|---|---|---|
| 1 | Un secret d'API (`CLIENT_SECRET`) a été commité. Le fichier n'est plus dans le dépôt, mais le secret reste lisible dans l'historique Git et sur GitHub. | `qa/utils/xray_export.py:11`, commit `cc428027` | gitleaks (historique) | **Critique** | `gitleaks git --redact -v .` : 1 fuite, règle `generic-api-key`, 39 commits scannés (`docs/preuves/b1-gitleaks-historique.txt`). `gitleaks dir --redact .` : 0 fuite, car le fichier n'existe plus aujourd'hui. | Révoquer et régénérer le secret tout de suite, puis suivre la réponse à incident (section 2). |
| 2 | `qa/.env` a été commité avec 3 mots de passe de comptes (`ADMIN_PASSWORD`, `ORGA_PASSWORD`, `CLIENT_PASSWORD`) et une `DB_URL` avec identifiants. gitleaks ne l'a **pas** détecté. | `qa/.env`, ajouté dans `daac602`, retiré dans `cdd2f63` | Relecture manuelle + `git log -- qa/.env` | **Critique** | `git log --oneline -- qa/.env` montre les 2 commits. Le fichier est toujours lisible dans `daac602`. | Changer les 3 mots de passe et celui de la base. Garder `qa/.env` dans `.gitignore` (déjà fait), fournir un `qa/.env.example` sans valeur, passer les valeurs en CI via les *Secrets* GitHub. |
| 3 | Injection de commande dans le workflow : une saisie utilisateur (`github.event.inputs.seed_bugs`) est collée directement dans un script shell. | `.github/workflows/ci.yml:23` | zizmor | **Haute** | `zizmor --offline .github/workflows/ci.yml` : `error[template-injection]`, confiance High (`docs/preuves/b1-zizmor-avant.txt`). | Passer par la variable d'environnement : `echo "Bugs du fil rouge : ${SEED_BUGS}"`. |
| 4 | La vérification du certificat TLS est désactivée lors de la connexion. Une attaque « homme du milieu » peut voler l'identifiant et le mot de passe envoyés. | `qa/utils/api_client.py:22` (`verify=False`) | bandit B501 | **Haute** | `bandit -r qa -q -x qa/.venv` : 1 × B501. | Supprimer `verify=False`. Si besoin d'un certificat interne, donner son chemin dans `verify=`. |
| 5 | Mots de passe des comptes admin et client du jeu de données écrits en dur dans un test. | `qa/tests/api/test_promo.py` | bandit B105 | **Haute** | bandit : 2 des 7 constats B105/B107 sont dans `test_promo.py` et correspondent aux comptes du seed. | Lire ces valeurs depuis les variables d'environnement (comme le fait déjà `qa/utils/config.py`) et changer ces mots de passe. |
| 6 | Secrets en clair dans la configuration Docker : `POSTGRES_PASSWORD`, `DATABASE_URL` avec identifiants, `JWT_SECRET`. Le port 5432 de la base est publié sur la machine. | `docker-compose.yml:6, 9, 21, 22` | Relecture manuelle | **Haute** | Lecture du fichier. gitleaks ne les signale pas. | Mettre les valeurs dans un `.env` non commité (`${POSTGRES_PASSWORD}`), générer un `JWT_SECRET` long et aléatoire, ne pas publier 5432 (ou `127.0.0.1:5432:5432`). |
| 7 | Les actions GitHub sont référencées par un tag (`@v7`) et non par un SHA. Si le tag est déplacé vers du code malveillant, la CI l'exécute. | `.github/workflows/ci.yml:19, 26, 63` | zizmor | **Moyenne** | zizmor : 3 × `error[unpinned-uses]`. | Épingler chaque action par son SHA complet, version en commentaire (`# v7.0.1`). |
| 8 | Le job tourne avec les permissions par défaut du `GITHUB_TOKEN`, plus larges que nécessaire. | `.github/workflows/ci.yml:14` | zizmor | **Moyenne** | zizmor : `warning[excessive-permissions]`. | Ajouter `permissions: contents: read` au niveau du workflow. |
| 9 | `requests 2.31.0` a des vulnérabilités connues. | `qa/requirements.txt` | pip-audit | **Moyenne** | `pip-audit -r qa/requirements.txt` : 3 avis distincts (PYSEC-2026-1873, PYSEC-2026-1872, PYSEC-2026-2275), 6 lignes (`docs/preuves/b1-pip-audit-avant.txt`). Corrigé en 2.33.0. | Épingler `requests>=2.33.0`. |
| 10 | Requête SQL construite avec une f-string (risque d'injection SQL). | `qa/utils/db.py:29` | bandit B608 | **Moyenne** | bandit : 1 × B608. | Requête paramétrée : `text("... WHERE o.id = :id")` avec `{"id": order_id}`. |
| 11 | 12 dépendances sur 13 n'ont pas de version. Chaque installation peut tirer une version différente, cassée ou compromise. | `qa/requirements.txt` | Relecture manuelle | **Basse** | Seul `requests==2.31.0` a une version. | Épingler toutes les versions (`pip freeze`) et activer Dependabot. |
| 12 | Le checkout garde le jeton GitHub dans `.git/config`. Il pourrait finir dans un artefact. | `.github/workflows/ci.yml:19` | zizmor | **Basse** | zizmor : `help[artipacked]`. | `with: persist-credentials: false` sur le checkout. |
| 13 | Version d'Allure non figée : `npx --yes allure` télécharge la dernière version à chaque run. | `.github/workflows/ci.yml:61` | Relecture manuelle | **Basse** | Lecture du fichier. | `npx --yes allure@3.33.0 generate ...` |
| 14 | Appels `requests` sans `timeout` : un test peut rester bloqué indéfiniment. | `qa/tests/api/test_promo.py` (7), `qa/utils/api_client.py` (1) | bandit B113 | **Basse** | bandit : 8 × B113. | Ajouter `timeout=10` à chaque appel. |
| 15 | `try/except: pass` dans un test : toute erreur est avalée et le test passe quand même. | `qa/tests/api/test_promo.py:37` | bandit B110 | **Basse** | bandit : 1 × B110. | Retirer le `try/except` pour que le test puisse échouer. |

## 2. Réponse à incident : le `CLIENT_SECRET` dans l'historique

Les actions dans l'ordre :

1. **Révoquer le secret et en générer un nouveau, tout de suite.**
   C'est la seule action qui protège vraiment. Le secret est public depuis le
   commit `cc428027`, et on ne sait pas qui l'a déjà copié. Une fois révoqué,
   la copie qui traîne ne sert plus à rien. On commence par là parce que tout
   le reste prend du temps, et pendant ce temps le secret reste utilisable.

2. **Vérifier les journaux du service concerné.**
   Regarder si le secret a été utilisé par quelqu'un d'autre depuis le 20/10/2026
   (date du commit). Si oui, c'est un incident avéré : on prévient le responsable
   sécurité et on évalue ce qui a été touché.

3. **Mettre le nouveau secret au bon endroit.**
   Dans les *Secrets* GitHub (Settings > Secrets and variables > Actions) pour la CI,
   et dans un `.env` non commité en local. Le code le lit avec `os.environ`.

4. **Nettoyer l'historique (en dernier, et seulement en complément).**
   - *Supprimer le fichier ne suffit pas* : c'est déjà le cas aujourd'hui
     (`gitleaks dir` ne trouve rien), mais le secret reste lisible dans l'ancien
     commit, avec un simple `git show` ou le lien GitHub.
   - *Réécrire l'historique (git filter-repo) ne suffit pas non plus* : les forks
     (chaque élève de la formation en a un), les clones sur les postes, les caches
     de GitHub et les éventuelles copies gardent l'ancien commit. On ne peut pas
     les effacer.
   - C'est pour ça que l'étape 1 passe avant : nettoyer l'historique fait propre,
     mais seul un secret révoqué est vraiment sans danger.

5. **Éviter que ça recommence.**
   - Activer **Secret scanning** et **Push protection** sur GitHub : le push est
     bloqué s'il contient un secret.
   - Lancer gitleaks dans un hook pre-commit et dans la CI (avec `.gitleaks.toml`).
   - Ne jamais écrire un secret dans le code : toujours une variable d'environnement.
   - Garder les `.env` dans `.gitignore` et fournir des `.env.example` vides.

Le même traitement s'applique à `qa/.env` (constat 2) : changer les 3 mots de passe
et celui de la base, puisqu'ils sont lisibles dans le commit `daac602`.

## 3. Faux positifs acceptés

| Ce que j'ignore | Nombre | Pourquoi |
|---|---|---|
| bandit B101 (`assert` utilisé) | 90 | Dans un projet pytest, `assert` est la façon normale d'écrire une vérification. Le risque signalé par bandit (les `assert` supprimés avec `python -O`) ne concerne pas les tests, qui ne tournent jamais en mode optimisé. |
| bandit B105 / B107 sur `Passw0rd!` | 5 | Mot de passe des comptes jetables créés par les tests eux-mêmes (`factories.py`, `test_auth.py`, `locustfile.py`). Il ne protège rien de réel. Les 2 autres constats, dans `test_promo.py`, ne sont **pas** des faux positifs (constat 5). |
| gitleaks dans `.venv` | 18 | Avant l'allowlist, gitleaks trouvait 18 « secrets » dans des bibliothèques installées dans `qa/.venv` (clés d'exemple, tests de ces bibliothèques). Ce dossier est généré et pas versionné (`.gitignore`), d'où l'exclusion dans `.gitleaks.toml`. Après exclusion : 0. |

Ce que je **n'ignore pas** même si c'est « seulement des tests » : `verify=False`,
les mots de passe réels en dur, l'injection SQL et le `except: pass`. Ce code
tourne en CI avec de vrais identifiants.
