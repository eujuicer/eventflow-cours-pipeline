## v1.0.0 (2026-11-25)

### Feat

- add SonarQube configuration files for code analysis
- add initial settings for Python terminal and docker-compose.override backup
- add docker-compose.override.yml and qa environment example
- export des resultats vers Xray
- **qa**: initialise le projet de tests QA (config, client API, fixtures)
- **fil-rouge**: bugs pédagogiques activables via SEED_BUGS
- **profile**: gestion du profil utilisateur (infos, avatar, mot de passe)

### Fix

- update status code assertion in test_client_cant_see_promos from 418 to 403
- **checkout**: masquer l'icone cadenas aux technologies d'assistance

### Perf

- test de charge flash sale avec Locust
