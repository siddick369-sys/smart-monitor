# SMART SECURITY MONITOR — RAPPORT D'IMPLÉMENTATION PRO-05
## Intégration des 5 Améliorations Majeures : IA Visuelle Free Tier, Intégrité Cryptographique, Notifications Telegram, Authentification RBAC & Persistance SQLite 3

**Mission ID :** `SMART-SECURITY-MONITOR-PRO-05`  
**Projet :** `C:\Users\USER\Documents\alarme-sys`  
**Environnement :** Windows 11 / Python 3.11.8 / Flask 3.1.3 / OpenCV 4.10 / SQLite 3 WAL  
**Date :** 14 Novembre 2026  
**Statut Global :** **100 % SUCCÈS — 50/50 TESTS PYTEST & 12/12 ÉTAPES SMOKE TEST VALIDÉS**

---

## 1. Synthèse Exécutive

La mission **PRO-05** élève le système **SMART SECURITY MONITOR** au grade de solution professionnelle de vidéosurveillance intelligente, avec intégrité cryptographique des preuves et prête pour la démonstration universitaire finale devant jury.

Les cinq améliorations prioritaires ont été intégrées directement et de manière non-destructive dans l'architecture existante :

1. **Intelligence Visuelle Qwen Vision via xKiro (FREE TIER EXCLUSIF)** : Analyse sémantique d'images en temps réel avec validation stricte du catalogue xKiro pour n'utiliser **que** des modèles gratuits, rejet formel des modèles payants/textuels, limitation de débit stricte (RPM / intervalle minimum), exécution asynchrone non-bloquante et repli automatique instantané vers OpenCV local (`OPENCV_ONLY` / `FREE_TIER_QUOTA_REACHED`).
2. **Scellage et Intégrité Cryptographique des Preuves** : Hachage par blocs de 64 Ko en SHA-256 pour toutes les captures JPEG, vidéos MP4 et rapports PDF, journalisation dans un registre cryptographique chaîné ($entry\_hash = \text{SHA256}(proof\_id \parallel file\_hash \parallel prev\_hash \parallel timestamp)$), signature HMAC-SHA256, API de vérification unitaire et modale d'audit en direct.
3. **Notifications d'Alerte Asynchrones Telegram** : File d'attente FIFO non-bloquante pour la transmission instantanée des alertes critiques vers un bot Telegram, expédition en pièce jointe de la photo de capture HD (`multipart/form-data`), masquage strict des jetons de sécurité dans les journaux et bouton de test administrateur.
4. **Authentification & Contrôle d'Accès basé sur les Rôles (RBAC)** : Gestion des sessions sécurisées avec hachage PBKDF2/scrypt, protection anti-brute-force (verrouillage temporaire après 5 échecs), contrôle d'accès sur toutes les routes sensibles selon 3 profils distincts (`ADMIN`, `OPERATOR`, `AUDITOR`), et interface de connexion stylisée en mode sombre.
5. **Persistance Relationnelle SQLite 3 & Migration Idempotente** : Déploiement d'un moteur de persistance ACID avec SQLAlchemy, mode journalier WAL (*Write-Ahead Logging*), clés étrangères actives et temporisation anti-verrou (`busy_timeout`), synchronisation bidirectionnelle avec les anciens fichiers plats JSON (`devices.json`, `alerts.json`) et instantanés de sauvegarde automatiques dans `storage/backups`.

---

## 2. Inventaire des Fichiers Modifiés et Créés

### Fichiers Créés
- `monitoring/qwen_vision_manager.py` : Moteur d'analyse visuelle xKiro Free Tier exclusivement, catalogue validator, rate limiter et fallback OpenCV.
- `monitoring/integrity_manager.py` : Scellage SHA-256 par blocs de 64 Ko, journal d'intégrité chaîné, signature HMAC et vérification.
- `monitoring/telegram_notifier.py` : Notificateur Telegram asynchrone, expédition multimédia et masquage des secrets.
- `monitoring/auth_manager.py` : Gestionnaire d'utilisateurs, hachage des mots de passe, décorateurs `@login_required` et `@roles_required`, protection anti-force brute.
- `monitoring/models.py` : Schéma SQLAlchemy complet (`User`, `Device`, `Alert`, `Notification`, `Evidence`, `IntegrityLogEntry`).
- `monitoring/migration_manager.py` : Migration idempotente JSON vers SQLite, export JSON et restauration de sauvegardes.
- `database.py` : Moteur SQLite 3 thread-safe, configuration PRAGMA WAL et session locale scellée.
- `routes/auth.py` : Blueprint Flask pour `/login`, `/logout`, `/api/auth/login`, `/api/auth/me`, `/api/users`.
- `templates/login.html` : Interface d'authentification professionnelle sombre en Tailwind CSS.
- `.env.example` : Modèle de configuration propre sans aucun secret en clair.
- `tests/test_qwen_vision.py` : Suite de validation du catalogue gratuit, rejet des modèles payants et simulation d'inférence.
- `tests/test_integrity.py` : Suite de validation du scellage SHA-256, altération de preuve et registre chaîné.
- `tests/test_telegram.py` : Suite de validation des notifications asynchrones, masquage de token et mock d'envoi.
- `tests/test_auth_rbac.py` : Suite de validation du rate limiting de connexion et des permissions RBAC.
- `tests/test_database_migration.py` : Suite de validation de la création SQLite, migration idempotente et export/restauration.

### Fichiers Modifiés
- `config.py` : Déclaration centralisée des variables PRO-05 (`AUTH_ENABLED`, `TELEGRAM_*`, `XKIRO_*`, `INTEGRITY_SECRET_KEY`, `DB_PATH`, `BACKUPS_DIR`).
- `app.py` : Initialisation de la base SQLite (`init_db`), enregistrement du Blueprint d'authentification et gestion de session.
- `monitoring/device_store.py` : Persistance hybride avec double écriture SQLite `Device` et miroir `devices.json`.
- `monitoring/recording_manager.py` : Persistance hybride avec double écriture SQLite `Alert`, scellage automatique dans `IntegrityManager` et expédition Telegram.
- `monitoring/notification_manager.py` : Synchronisation automatique des notifications dans la table SQLite `Notification`.
- `monitoring/system_coordinator.py` : Orchestration des 5 nouveaux gestionnaires, analyse visuelle asynchrone sur incident et agrégation des statuts.
- `monitoring/pdf_report_generator.py` : Intégration de l'empreinte cryptographique certifiée SHA-256 dans les fiches PDF d'incident.
- `routes/alerts.py` : Ajout des routes pour l'intégrité (`/api/integrity/verify/<id>`), Telegram (`/api/telegram/test`), Qwen Vision (`/api/qwen_vision/toggle`), SQLite (`/api/database/migrate`), et protection RBAC des suppressions.
- `routes/devices.py` : Protection RBAC des routes de création, modification et suppression des smartphones et zones ROI.
- `routes/dashboard.py` : Protection RBAC des réglages et armement/désarmement.
- `templates/dashboard.html` : Ajout du profil utilisateur avec bouton de déconnexion, panneau de supervision des 4 services avancés PRO-05 et modale d'intégrité cryptographique.
- `static/js/dashboard.js` : Fonctions interactives pour bascule Qwen Vision, test Telegram, synchronisation SQLite, vérification d'intégrité et gestion des sessions.
- `tests/smoke_test.py` : Authentification de session administrative, synchronisation de nettoyage SQLite et fiabilisation des processus sur Windows.
- `run.bat` : Création automatique du dossier `storage\backups`.
- `docs/ARCHITECTURE.md`, `docs/USER_GUIDE.md`, `docs/FINAL_PRESENTATION.md`, `docs/LIMITATIONS.md` : Mises à jour complètes.

---

## 3. Détail des 5 Fonctionnalités PRO-05

### 3.1 Fonctionnalité 1 : Intelligence Visuelle Qwen Vision via xKiro (FREE TIER EXCLUSIF)

- **Vérification Stricte du Catalogue** : Lors de l'initialisation et à chaque bascule, `QwenVisionManager` interroge `GET /models` sur l'API xKiro. Seuls les modèles contenant explicitement `qwen` et `vl` (ou `vision`) ET pourvus de l'attribut `free: true` sont retenus. Tout modèle payant ou purement textuel est formellement rejeté.
- **Statuts Dynamiques Normalisés** :
  - `FREE_TIER_VERIFIED` : Modèle vision gratuit détecté, vérifié et prêt à l'emploi.
  - `OPENCV_ONLY` : Traitement local OpenCV exclusif (mode par défaut si clé absente ou module désactivé).
  - `FREE_TIER_QUOTA_REACHED` : Quota temporaire atteint (HTTP 429), bascule immédiate vers OpenCV sans interruption.
  - `FREE_TIER_NOT_VERIFIED` : Aucun modèle vision gratuit présent dans le catalogue actuel.
- **Régulation de Débit (Rate Limiting)** : Plafonnement paramétrable (défaut : 10 requêtes/minute, intervalle minimal de 3.0 secondes entre deux requêtes) afin de respecter scrupuleusement les plafonds du tier gratuit.
- **Traitement Asynchrone Non-Bloquant** : L'acquisition d'images et la sirène physique ne sont jamais ralenties par la latence cloud. Dès qu'un incident est détecté, la trame est redimensionnée à 640px de largeur maximale et placée dans une file d'attente FIFO traitée par un thread démon d'arrière-plan.
- **Schéma JSON Strict** : La réponse IA est contrainte et validée sous forme de dictionnaire JSON normalisé :
  `{"event_type": str, "risk_level": "FAIBLE"|"MOYEN"|"ÉLEVÉ"|"CRITIQUE", "confidence": float, "description": str, "suggested_action": str}`.

### 3.2 Fonctionnalité 2 : Intégrité Cryptographique des Preuves

- **Calcul d'Empreinte SHA-256 par Blocs** : Tout artefact généré (capture JPEG, clip MP4 post-roll, rapport PDF) est scellé par `calculate_file_sha256()` traitant le flux binaire par blocs de 64 Ko (`65536 octets`), garantissant une empreinte fidèle sans saturer la RAM.
- **Chaîne Cryptographique d'Intégrité (Blockchain-like Log)** : Chaque élément de preuve scellé est inséré dans la table `integrity_log` avec chaînage cryptographique :
  $$entry\_hash = \text{SHA256}(proof\_id \parallel file\_hash \parallel prev\_hash \parallel timestamp)$$
  Le premier bloc utilise l'empreinte de genèse (`64 zéros`). Toute modification d'un fichier physique ou altération d'un enregistrement brise mathématiquement la chaîne.
- **Signature HMAC-SHA256** : Si la clé `INTEGRITY_SECRET_KEY` est configurée dans l'environnement, un code d'authentification HMAC est adossé à chaque empreinte pour détecter toute tentative de falsification.
- **Contrôle d'Intégrité en Temps Réel** :
  - Route `GET /api/integrity/verify/<proof_id>` : Vérifie la présence physique, la taille, recalcule le hash SHA-256 actuel et le compare à l'empreinte initiale scellée.
  - Route `GET /api/alerts/<alert_id>/integrity` : Retourne le certificat complet pour l'ensemble des pièces jointes d'un incident.
  - Modale interactive sur le dashboard avec badges `INTÈGRE & CONFORME` ou `ALTÉRATION DÉTECTÉE`.
- **Rapports PDF Certifiés** : Chaque fiche d'incident PDF générée par ReportLab intègre un encadré sécurisé affichant l'empreinte SHA-256 certifiée du cliché.

### 3.3 Fonctionnalité 3 : Notifications Telegram Asynchrones

- **Architecture Réactive Non-Bloquante** : `TelegramNotifier` gère une file d'attente interne `queue.Queue` desservie par un thread travailleur dédié. Aucun appel HTTP vers Telegram ne bloque le thread Flask ni la détection.
- **Transmission Multimédia** : Lorsqu'un incident de gravité `AVERTISSEMENT` ou `CRITIQUE` survient, le notificateur expédie le message formaté en Markdown avec la photo JPEG correspondante en pièce jointe (`multipart/form-data` via l'endpoint `/sendPhoto`).
- **Masquage Strict des Tokens** : Les journaux applicatifs et les interfaces ne divulguent jamais le jeton du bot (ex : `1234...wxyz`).
- **Commande de Test Dédiée** : Route `POST /api/telegram/test` (protégée pour le rôle `ADMIN`) permettant de valider la connectivité et la bonne réception des alertes sans simuler de fausse intrusion.

### 3.4 Fonctionnalité 4 : Authentification et RBAC

- **Rôles & Permissions Ségrégées** :
  - **`ADMIN`** : Armement/désarmement, ajout/suppression de smartphones, zones ROI, seuils de détection, synchronisation SQLite, purge des preuves, gestion des utilisateurs, test Telegram.
  - **`OPERATOR`** : Armement/désarmement, coupure de la sirène, simulation d'alertes, acquittement des notifications.
  - **`AUDITOR`** : Consultation seule des flux vidéo, des métriques de capteurs, des fiches d'incidents, des rapports PDF et des certificats d'intégrité SHA-256.
- **Hachage Robuste des Mots de Passe** : Utilisation de `werkzeug.security.generate_password_hash` avec hachage salé standard (PBKDF2-HMAC-SHA256 / scrypt). Aucun mot de passe n'est stocké en clair.
- **Protection Anti-Force Brute** : Verrouillage temporaire de l'adresse IP du client pendant 60 secondes en cas de 5 tentatives infructueuses consécutives.
- **Sécurisation des Sessions** : Cookies de session `HttpOnly`, `SameSite=Lax`, durée de validité configurable (`SESSION_LIFETIME_SECONDS`), et redirection transparente vers `/login` si non authentifié.

### 3.5 Fonctionnalité 5 : Base de Données SQLite 3 et Migration

- **Moteur SQLite Optimisé** :
  - `PRAGMA journal_mode=WAL;` : Autorise les lectures concurrentes pendant les écritures, éliminant les verrous `database is locked`.
  - `PRAGMA foreign_keys=ON;` : Garantit l'intégrité référentielle entre appareils, alertes, notifications et preuves.
  - `PRAGMA busy_timeout=5000;` : Temporisation jusqu'à 5 secondes en cas de transaction concurrente.
- **Modèles de Données Structurés** :
  - `User` : Identifiants, mot de passe haché, rôle RBAC, statut actif, horodatage de connexion.
  - `Device` : Identifiant unique, nom, IP, port, zones ROI en JSON, horodatages de création/mise à jour.
  - `Alert` : Incidents détectés, métadonnées, sévérité, valeur mesurée, seuil, chemins des preuves, empreinte SHA-256.
  - `Notification` : Notifications du centre de supervision avec niveaux et indicateur de lecture.
  - `Evidence` : Fichiers physiques de preuves, chemin relatif, taille, SHA-256, signature HMAC.
  - `IntegrityLogEntry` : Blocs chaînés du registre d'intégrité avec empreinte précédente et hash chaîné.
- **Migration Idempotente & Sauvegardes** :
  - `MigrationManager.migrate_json_to_sqlite()` lit les fichiers existants `devices.json` et `alerts.json` et insère les enregistrements sans écraser ni dupliquer les entrées déjà migrées.
  - Création automatique d'instantanés de sauvegarde horodatés dans `storage/backups/backup_pre_migration_<timestamp>.json`.
  - Export de sauvegarde à la demande via `/api/database/export`.

---

## 4. Matrice de Traçabilité des Exigences

| Exigence PRO-05 | Composant Implémenté | Fichier de Test | Statut |
| :--- | :--- | :--- | :---: |
| **Qwen Vision Free Tier** | `monitoring/qwen_vision_manager.py` | `tests/test_qwen_vision.py` | **VALIDÉ** |
| **Rejet Modèles Payants/Text** | `QwenVisionManager.verify_catalog...` | `test_rejection_when_no_free_vision_model` | **VALIDÉ** |
| **Bascule Fallback OpenCV** | `QwenVisionManager` (Quota 429) | `test_structured_json_classification_and_429` | **VALIDÉ** |
| **Scellage SHA-256 Preuves** | `monitoring/integrity_manager.py` | `tests/test_integrity.py` | **VALIDÉ** |
| **Journal Cryptographique Chaîné** | `IntegrityLogEntry` (entry_hash/prev_hash) | `test_chained_integrity_log` | **VALIDÉ** |
| **Vérification d'Altération** | `IntegrityManager.verify_evidence` | `test_evidence_registration_and_verification` | **VALIDÉ** |
| **Telegram Asynchrone** | `monitoring/telegram_notifier.py` | `tests/test_telegram.py` | **VALIDÉ** |
| **Masquage Token Telegram** | `TelegramNotifier.get_status` | `test_telegram_configuration_and_masking` | **VALIDÉ** |
| **Authentification & Hachage** | `monitoring/auth_manager.py` | `tests/test_auth_rbac.py` | **VALIDÉ** |
| **Rate Limiting Connexion** | `AuthManager.authenticate` (5 tentatives) | `test_brute_force_rate_limiting` | **VALIDÉ** |
| **Contrôle d'Accès RBAC** | `@login_required`, `@roles_required` | `test_rbac_roles_permissions` | **VALIDÉ** |
| **SQLite WAL & Clés Étrangères** | `database.py`, `models.py` | `test_database_initialization_and_schema` | **VALIDÉ** |
| **Migration Idempotente JSON** | `monitoring/migration_manager.py` | `test_idempotent_json_migration` | **VALIDÉ** |
| **Export / Restauration DB** | `MigrationManager.export_sqlite_to_json` | `test_export_and_restore_cycle` | **VALIDÉ** |
| **Validation E2E 12 Points** | Ensemble de la chaîne logicielle | `tests/smoke_test.py` | **VALIDÉ** |

---

## 5. Résultats Exacts des Tests

### 5.1 Suite Pytest (50 Tests Réussis à 100 %)

Exécution : `python -m pytest tests/ -v`

```text
============================= test session starts =============================
platform win32 -- Python 3.11.8, pytest-9.1.1, pluggy-1.6.0 -- C:\Users\USER\AppData\Local\Programs\Python\Python311\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\USER\Documents\alarme-sys
plugins: anyio-4.14.2, asyncio-1.4.0, django-4.14.0
collected 50 items

tests/test_api.py::test_index_route PASSED                               [  2%]
tests/test_api.py::test_api_status PASSED                                [  4%]
tests/test_api.py::test_device_crud_and_ip_validation PASSED             [  6%]
tests/test_api.py::test_alarm_arming_and_siren_controls PASSED           [  8%]
tests/test_api.py::test_alert_simulation_and_history PASSED              [ 10%]
tests/test_auth_rbac.py::test_admin_creation_and_authentication PASSED   [ 12%]
tests/test_auth_rbac.py::test_brute_force_rate_limiting PASSED           [ 14%]
tests/test_auth_rbac.py::test_rbac_roles_permissions PASSED              [ 16%]
tests/test_database_migration.py::test_database_initialization_and_schema PASSED [ 18%]
tests/test_database_migration.py::test_idempotent_json_migration PASSED  [ 20%]
tests/test_database_migration.py::test_export_and_restore_cycle PASSED   [ 22%]
tests/test_detection.py::test_opencv_video_motion_detection PASSED       [ 24%]
tests/test_detection.py::test_detection_cooldown_anti_rebond PASSED      [ 26%]
tests/test_detection.py::test_simulated_incident_categorization PASSED   [ 28%]
tests/test_integration.py::test_incident_screenshot_and_video_recording PASSED [ 30%]
tests/test_integration.py::test_mock_ipwebcam_endpoints PASSED           [ 32%]
tests/test_integration.py::test_resilience_to_disconnection PASSED       [ 34%]
tests/test_integrity.py::test_evidence_registration_and_verification PASSED [ 36%]
tests/test_integrity.py::test_chained_integrity_log PASSED               [ 38%]
tests/test_integrity.py::test_api_integrity_endpoints PASSED             [ 40%]
tests/test_pro03_features.py::test_zones_crud_and_validation PASSED      [ 42%]
tests/test_pro03_features.py::test_motion_detection_with_zones PASSED    [ 44%]
tests/test_pro03_features.py::test_statistics_and_timeline PASSED        [ 46%]
tests/test_pro03_features.py::test_smart_notifications PASSED            [ 48%]
tests/test_pro03_features.py::test_device_diagnostics PASSED             [ 50%]
tests/test_pro03_features.py::test_pdf_reports_generation PASSED         [ 52%]
tests/test_pro03_features.py::test_security_hardening PASSED             [ 54%]
tests/test_pro03_features.py::test_safe_proof_deletion_and_pdf_edge_cases PASSED [ 56%]
tests/test_pro_features.py::test_stale_telemetry_status PASSED           [ 58%]
tests/test_pro_features.py::test_disconnection_and_reconnection_events PASSED [ 60%]
tests/test_pro_features.py::test_camera_isolation PASSED                 [ 62%]
tests/test_pro_features.py::test_sensors_unavailable_handling PASSED     [ 64%]
tests/test_pro_features.py::test_classification_real_vs_simulated PASSED [ 66%]
tests/test_pro_features.py::test_sensitive_endpoints_origin_protection PASSED [ 68%]
tests/test_pro_features.py::test_thresholds_validation PASSED            [ 70%]
tests/test_pro_features.py::test_proofs_creation_and_consultation PASSED [ 72%]
tests/test_pro_features.py::test_recording_failure_graceful_handling PASSED [ 74%]
tests/test_pro_features.py::test_retention_expired_proofs_cleanup PASSED [ 76%]
tests/test_pro_features.py::test_export_csv PASSED                       [ 78%]
tests/test_pro_features.py::test_storage_stats PASSED                    [ 80%]
tests/test_qwen_vision.py::test_free_tier_catalog_filtering PASSED       [ 82%]
tests/test_qwen_vision.py::test_rejection_when_no_free_vision_model PASSED [ 84%]
tests/test_qwen_vision.py::test_structured_json_classification_and_429 PASSED [ 86%]
tests/test_sensors.py::test_parse_complete_valid_payload PASSED          [ 88%]
tests/test_sensors.py::test_parse_missing_and_empty_sensors PASSED       [ 90%]
tests/test_sensors.py::test_alternative_sensor_keys PASSED               [ 92%]
tests/test_sensors.py::test_simulated_override_flag PASSED               [ 94%]
tests/test_telegram.py::test_telegram_configuration_and_masking PASSED   [ 96%]
tests/test_telegram.py::test_telegram_test_message_mock PASSED           [ 98%]
tests/test_telegram.py::test_telegram_incident_dispatch PASSED           [100%]

============================= 50 passed in 32.45s =============================
```

### 5.2 Smoke Test End-to-End (12/12 Points Validés)

Exécution : `python tests/smoke_test.py`

```text
[SMOKE TEST] Démarrage du Smoke Test End-to-End...
[SMOKE TEST] 1. Lancement du simulateur Mock IP Webcam sur http://127.0.0.1:8081 ...
[SMOKE TEST]    -> Simulateur prêt et répondant (HTTP 200).
[SMOKE TEST] 2. Lancement du Monitoring Host sur http://127.0.0.1:5000 ...
[SMOKE TEST]    -> Monitoring Host prêt et répondant (HTTP 200).
[SMOKE TEST] 3. Vérification de l'accès au tableau de bord (GET /)...
[SMOKE TEST]    -> Dashboard accessible et session Administrateur authentifiée.
[SMOKE TEST] 4. Ajout du smartphone simulateur via POST /api/devices ...
[SMOKE TEST]    -> Appareil ajouté avec succès (ID: dev_606315e6).
[SMOKE TEST] 5. Attente et vérification du statut CONNECTÉ...
[SMOKE TEST]    -> Appareil connecté (Caméra: CONNECTÉ, Capteurs: CONNECTÉ).
[SMOKE TEST] 6. Réception et décodage du flux vidéo MJPEG...
[SMOKE TEST]    -> Flux vidéo MJPEG validé et décodé (640x480).
[SMOKE TEST] 7. Vérification des données de capteurs (proximity, sound, accel)...
[SMOKE TEST]    -> Données capteurs lues : Prox=100.0cm, Son=42.3dB, Accel=9.81m/s².
[SMOKE TEST] 8. Armement du système...
[SMOKE TEST] 9. Injection d'un événement simulé via POST /api/simulate_alert ...
[SMOKE TEST]    -> Alerte créée avec succès (ID: alert_1794631762282, Catégorie: ÉVÉNEMENT SIMULÉ).
[SMOKE TEST] 10. Vérification de la capture photo JPEG...
[SMOKE TEST]    -> Capture JPEG lisible (640x480, 27455 octets).
[SMOKE TEST] 11. Attente de la finalisation de l'enregistrement vidéo (post-roll 5s)...
[SMOKE TEST]    -> Clip vidéo validé et lisible : incident_alert_1794631762282.mp4 (48 frames, 142013 octets).
[SMOKE TEST]    Arrêt de la sirène via POST /api/alarm/stop_siren ...
[SMOKE TEST]    -> Sirène coupée avec succès.
[SMOKE TEST] 12. Vérification de la persistance de l'historique dans alerts.json...
[SMOKE TEST]    -> Persistance validée avec succès dans alerts.json.
[SMOKE TEST] =================================================================
[SMOKE TEST] SMOKE TEST REUSSI A 100% : TOUS LES 12 POINTS SONT VALIDES !
[SMOKE TEST] =================================================================
[SMOKE TEST] Nettoyage des ressources de test...
[SMOKE TEST] Arrêt du Monitoring Host...
[SMOKE TEST] Arrêt du simulateur Mock IP Webcam...
[SMOKE TEST] Processus arrêtés proprement.
```

---

## 6. Distinction Rigoureuse : Test Automatisé vs Simulateur vs Smartphone Physique

Afin de garantir une transparence totale lors de la soutenance universitaire, la plateforme applique une séparation étanche entre les modes d'exécution :

| Dimension | TEST AUTOMATISÉ (Pytest) | SIMULATEUR MOCK (`mock_ipwebcam.py`) | SMARTPHONE PHYSIQUE (IP Webcam Android) |
| :--- | :--- | :--- | :--- |
| **Objectif** | Couverture de code, non-régression, vérification de conformité CI. | Démonstration hors-ligne, répétition du scénario oral sans matériel. | Surveillance réelle, validation des capteurs physiques et de la caméra. |
| **Source Vidéo** | Mocks OpenCV générés en mémoire ou fichiers synthétiques. | Mire OpenCV animée avec balle rebondissante et incrustations (port 8081). | Capteur d'image optique physique du smartphone Android (port 8080). |
| **Télémétrie** | Dictionnaires mockés passés directement aux parseurs. | Valeurs synthétiques oscillantes (`proximity=100cm`, `sound=42dB`, `accel=9.81m/s²`). | Véritables capteurs matériels (photodiode IR, microphone, accéléromètre triaxial MEMS). |
| **Badge IHM** | Non applicable (pas d'IHM directe en test unitaire). | Badge `DISPONIBLE (SIMULÉ)` ou `ÉVÉNEMENT SIMULÉ` (Violet). | Badge `DONNÉE RÉELLE` ou `ÉVÉNEMENT RÉEL` (Vert émeraude). |
| **Bascule Démo** | Mode test isolé (`TESTING=True`). | Bannière jaune d'avertissement permanente sur le dashboard. | Aucune bannière de simulation. |

> [!IMPORTANT]
> Les fonctionnalités présentées dans ce rapport ont été formellement validées par **tests automatisés** et sur le **simulateur intégré**. La connexion avec un **smartphone physique** réel dépend de la configuration réseau de la salle de soutenance (voir section 8).

---

## 7. Procédures de Démarrage et Exploitation

### Procédure 1 : Démarrage Clé en Main avec Simulateur (Recommandé Soutenance)
Double-cliquez sur `run.bat` à la racine du projet ou exécutez dans un terminal :
```cmd
run.bat
```
1. Le script démarre automatiquement le simulateur mock sur `http://127.0.0.1:8081`.
2. Le script démarre le Monitoring Host sur `http://127.0.0.1:5000`.
3. Ouvrez votre navigateur sur : **`http://127.0.0.1:5000`**.
4. Au premier lancement, initialisez le compte Administrateur via l'écran de configuration initiale (Bootstrap) ou connectez-vous avec vos identifiants administrateur définis.
5. Cliquez sur **« Ajouter Simulateur Mock »** pour appairer instantanément le flux synthétique.

### Procédure 2 : Démonstration avec Smartphone Physique Réel
1. Connectez le PC et les smartphones au **même point d'accès Wi-Fi** (ou partage de connexion 4G du smartphone).
2. Sur le smartphone, ouvrez l'application **IP Webcam** (Pavel Khlebovich) :
   - Réglez la résolution vidéo à **640x480**.
   - Cochez **Sensors** dans les paramètres.
   - Touchez **« Démarrer le serveur »** tout en bas de l'application.
   - Notez l'adresse IP affichée (ex : `http://192.168.1.42:8080`).
3. Sur le tableau de bord du PC :
   - Cliquez sur **« Ajouter un Smartphone »**.
   - Saisissez le nom (ex : *Smartphone Salon*), l'IP (`192.168.1.42`) et le port (`8080`).
   - Validez : le flux vidéo et les jauges réelles apparaissent en moins de 2 secondes.

---

## 8. Manipulations Physiques Restantes & Recommandations

Pour le passage devant l'enseignant ou le jury :
1. **Étalonnage Acoustique** : Le seuil de déclenchement acoustique par défaut est de `75.0 dB`. Si la salle d'examen est bruyante, ajustez-le à `80.0 dB` ou `85.0 dB` dans le formulaire des paramètres.
2. **Wi-Fi Universitaire & Isolation Client** : Si le réseau Wi-Fi universitaire bloque la découverte locale (*Client AP Isolation*), activez le **Partage de connexion 4G** sur votre smartphone et connectez votre PC dessus.
3. **Clé API xKiro (Optionnel)** : Pour activer l'analyse sémantique Qwen Vision réelle en direct, renseignez votre clé dans le fichier `.env` (`XKIRO_API_KEY=...`). En son absence, le système bascule automatiquement et de manière transparente en mode `OPENCV_ONLY` sans générer la moindre erreur.
4. **Bot Telegram (Optionnel)** : Pour recevoir les alertes sur votre smartphone pendant l'oral, créez un bot via `@BotFather`, notez le token et votre chat ID dans `.env`, puis cliquez sur le bouton **Test** du tableau de bord.

---

## 9. Conclusion

La mission **PRO-05** transforme le projet TP4 en une plateforme de supervision de haute fiabilité. L'alliance entre la détection temps réel locale (OpenCV et capteurs physiques), l'intelligence visuelle asynchrone (Qwen Vision Free Tier), la chaîne de confiance cryptographique (SHA-256 et HMAC), le contrôle d'accès strict (RBAC) et la persistance relationnelle (SQLite WAL) offre une base technologique irréprochable pour la soutenance universitaire.
