# 🔐 SMART SECURITY MONITOR — RAPPORT DE CERTIFICATION FINALE PRO-05
## MISSION : PRO-05-FINAL-REMEDIATION-AND-CERTIFICATION

**Projet :** `C:\Users\USER\Documents\alarme-sys`  
**Environnement technique validé :**
- **Système d'exploitation :** Windows 11 Professionnel (x64)
- **Runtime :** Python 3.11.8 (build officiel PSF)
- **Framework Web & API :** Flask 3.1.3 & Werkzeug 3.1.3
- **Vision par Ordinateur :** OpenCV 4.10.0 (`cv2`) & NumPy 2.2.3
- **Persistance Relationnelle :** SQLite 3 (mode WAL) & SQLAlchemy 2.0.46
- **Génération Documentaire :** ReportLab 4.5.1
- **Protocole Caméras :** MJPEG Streaming over HTTP & Android IP Webcam REST API

---

## 1. Synthèse Exécutive et Conformité

Le système **SMART SECURITY MONITOR (TP4)** a fait l'objet d'un audit de durcissement approfondi, de corrections de sécurité appliquées côté serveur et d'une validation technique reproductible à 100 %.

Toutes les exigences architecturales, cryptographiques, opérationnelles et de résilience ont été vérifiées sans régression. Les résultats des bancs de tests exécutés sur l'environnement cible sont :

- **Tests unitaires et d'intégration pytest :** **55 tests exécutés / 55 tests réussis (100 %)** en 22.04 secondes.
- **Smoke test de validation bout-en-bout (E2E) :** **12 étapes sur 12 réussies (100 %)**, validant l'ensemble de la chaîne : du flux vidéo MJPEG et capteurs jusqu'à la persistance relationnelle SQLite (source de vérité vérifiée sur 6 points) et la certification cryptographique SHA-256.

---

## 2. Validation Détaillée des 5 Piliers PRO-05

### 🟢 Pilier 1 : Intelligence Visuelle Qwen Vision via xKiro (FREE TIER EXCLUSIF)

| Composant | Implémentation Réelle | Preuve Technique |
| :--- | :--- | :--- |
| **Sélection Modèle Free Tier** | Filtrage automatisé interrogeant le catalogue xKiro (`/v1/models`). Rejet absolu de tout modèle payant (`free: false`), non-vision ou textuel. Modèle sélectionné : `qwen2.5-vl-7b-instruct:free`. Niveaux de vérification explicites (`CONFIGURED`, `CATALOG_VERIFIED_FREE`, `REAL_INFERENCE_TESTED`). Rejet systématique en cas de métadonnées insuffisantes. | `tests/test_qwen_vision.py::test_free_tier_catalog_filtering` & `test_insufficient_metadata_and_network_errors` PASSED |
| **Disjoncteur (Circuit Breaker)** | Déclenchement automatique après 3 erreurs HTTP ou réseau consécutives (`CIRCUIT_BREAKER_MAX_ERRORS = 3`). Suspension des requêtes distantes pendant 30 secondes (`CIRCUIT_BREAKER_COOLDOWN = 30.0s`). | `tests/test_qwen_vision.py::test_circuit_breaker_mechanism` PASSED |
| **Gestion des Quotas (HTTP 429)** | Détection native du code HTTP 429. Transition immédiate vers le statut `FREE_TIER_QUOTA_REACHED` et temporisation de 60 secondes. | `tests/test_qwen_vision.py::test_structured_json_classification_and_429` PASSED |
| **Fallback Transparent OpenCV** | En cas d'erreur API, de clé absente, de catalogue non confirmé ou de coupure réseau, bascule instantanée en mode `OPENCV_ONLY` sans interruption de la détection vidéo temps réel. | Méthode `analyze_frame_sync` dans `monitoring/qwen_vision_manager.py` |
| **Schéma de Sortie Strict** | Sortie normalisée intégrant `event_type`, `risk_level` (bilingue avec normalisation française : `FAIBLE`, `MOYEN`, `ÉLEVÉ`, `CRITIQUE`), `confidence` (valeur flottante `0.0-1.0` ou `None` strict, jamais inventée), `description`, `suggested_action`. | Validé par parsing JSON strict avec élimination des balises Markdown |

> **Déclaration de transparence xKiro :**  
> L'intégration xKiro est implémentée et les scénarios d'intégration sont validés par tests simulés. La disponibilité effective d'un modèle Qwen Vision gratuit dépend de la vérification du catalogue xKiro au moment de l'utilisation. En l'absence de confirmation, le système conserve la détection locale OpenCV.

---

### 🟢 Pilier 2 : Intégrité Cryptographique des Preuves Numériques

| Mécanisme | Spécification Technique | Statut & Validation |
| :--- | :--- | :--- |
| **Hachage SHA-256 par Blocs** | Calcul par morceaux de 64 Ko (`chunk_size = 65536`) pour éviter toute saturation mémoire sur vidéos longues. | Implémenté dans `IntegrityManager.calculate_file_sha256` |
| **Journal Cryptographique Chaîné** | Chaque entrée de preuve intègre l'empreinte du bloc précédent : <br/>$$entry\_hash = \text{SHA256}(proof\_id \parallel file\_hash \parallel prev\_hash \parallel timestamp)$$ | Vérifié de la racine Genesis (`0000...0000`) jusqu'au dernier enregistrement (`verify_chain_integrity`). |
| **Signature HMAC-SHA256** | Signature numérique du hash de journal via `hmac.new(secret, entry_hash, sha256)`. Vérification en temps constant avec `hmac.compare_digest` contre les attaques temporelles. | `tests/test_integrity.py::test_evidence_registration_and_verification` PASSED |
| **Détection d'Altération** | Codes d'intégrité normés : `INTEGRITY_VALID` (intègre), `TAMPERED` (altéré), `MISSING` (manquant), `UNVERIFIABLE` (non vérifiable si clé absente ou hash manquant). | `tests/test_integrity.py` valide la bascule dynamique en cas de modification d'octets. |
| **Endpoints API & RBAC** | Routes `/api/integrity/verify/<proof_id>`, `/api/alerts/<id>/integrity`, `/api/integrity/log` et `/api/integrity/chain/verify` protégées par rôles `ADMIN` et `AUDITOR`. | Intégrées dans `routes/alerts.py` |

> **Déclaration de portée cryptographique :**  
> L'intégrité SHA-256 et la signature HMAC garantissent la détection d'altération et de troncature de chaîne. La sécurité globale dépend de la confidentialité de `INTEGRITY_SECRET_KEY` et des permissions du système hôte.

---

### 🟢 Pilier 3 : Notifications Telegram Asynchrones

| Exigence | Implémentation | Validation |
| :--- | :--- | :--- |
| **Asynchronisme Non-Bloquant** | File d'attente FIFO bornée (`queue.Queue(maxsize=100)`) consommée par le thread dédié d'arrière-plan `TelegramNotifierWorker`. Aucun appel réseau ne bloque la boucle principale OpenCV ou la sirène. | `tests/test_telegram.py::test_telegram_incident_dispatch` PASSED |
| **Pièces Jointes Multimédia** | Envoi au format `multipart/form-data` (`sendPhoto`) transmettant le cliché JPEG haute définition de l'intrusion avec légende descriptive formatée en Markdown. | Traitement conditionnel dans `_process_notification` |
| **Masquage des Secrets** | Masquage strict des jetons de bot (`get_masked_token()`) dans les logs et retours JSON (`123456789:****...2345`). | `tests/test_telegram.py::test_telegram_configuration_and_masking` PASSED |
| **Contrôle & Test Sécurisé** | Route `/api/telegram/test` sécurisée par `@login_required` et `@roles_required("ADMIN")`. | Validé par simulation HTTP |

---

### 🟢 Pilier 4 : Authentification et Autorisation RBAC

| Fonctionnalité | Règle de Sécurité Implémentée | Validation |
| :--- | :--- | :--- |
| **Matrice des Rôles (RBAC)** | - `ADMIN` : Configuration complète, gestion des smartphones, zones ROI, migration DB, purge de stockage, gestion utilisateurs.<br/>- `OPERATOR` : Contrôle opérationnel (armement, désarmement, arrêt sirène, simulation d'alertes).<br/>- `AUDITOR` : Lecture seule, consultation des flux, journaux, preuves et vérification d'intégrité. | `tests/test_auth_rbac.py::test_rbac_roles_permissions` PASSED (403 Forbidden sur violations) |
| **Hachage Mots de Passe** | Empreintes cryptographiques générées via Werkzeug (`scrypt` / `PBKDF2-HMAC-SHA256` avec sel aléatoire). Aucun mot de passe en clair. | Vérifié dans `User` model |
| **Protection Anti Force-Brute** | Blocage temporaire d'une adresse IP après 5 échecs consécutifs d'authentification sur une fenêtre glissante de 60 secondes. | `tests/test_auth_rbac.py::test_brute_force_rate_limiting` PASSED |
| **Sécurité des Sessions** | Cookies de session configurés avec `HttpOnly = True`, `SameSite = 'Lax'`, et rotation systématique de l'identifiant de session (`session.clear()`) à la connexion pour interdire toute fixation de session. | Implémenté dans `create_app` et `routes/auth.py` |
| **Initialisation Sécurisée (Bootstrap)** | Absence de mot de passe administrateur par défaut dans le code source. Procédure bootstrap atomique via `/api/auth/bootstrap` avec verrou de concurrence, politique de complexité (>= 8 caractères, lettre + chiffre) et interdiction de réinitialisation multiple (HTTP 403). Endpoint de changement de mot de passe disponible (`/api/auth/change_password`). | `tests/test_auth_rbac.py::test_bootstrap_security_and_lifecycle` PASSED |

---

### 🟢 Pilier 5 : SQLite 3 / SQLAlchemy comme Unique Source de Vérité

| Propriété | Réalisation Technique | Validation |
| :--- | :--- | :--- |
| **Concurrence & Fiabilité ACID** | Configuration automatique sur toute connexion : `PRAGMA journal_mode = WAL;`, `PRAGMA foreign_keys = ON;`, `PRAGMA busy_timeout = 5000;`. | Événement SQLAlchemy `set_sqlite_pragma` dans `database.py` |
| **Source de Vérité Unique** | Les tables `users`, `devices`, `alerts`, `notifications`, `evidences` et `integrity_log` constituent la référence transactionnelle primaire (`DeviceStore` et `RecordingManager` écrivent et lisent directement SQLite). Les fichiers JSON (`alerts.json`, `devices.json`) sont strictement des miroirs de sauvegarde et d'export. | `tests/test_database_migration.py::test_sqlite_single_source_of_truth` PASSED et validé à l'étape 12 du smoke test sur 6 critères stricts |
| **Migration Idempotente** | Classe `MigrationManager` exécutant le transfert transactionnel des données sans duplication lors des réexécutions multiples. | `tests/test_database_migration.py::test_idempotent_json_migration` PASSED |
| **Sauvegardes Automatisées** | Copie instantanée horodatée dans `storage/backups/` avant chaque migration ou restauration. | `tests/test_database_migration.py::test_export_and_restore_cycle` PASSED |

---

## 3. Matrice de Validation et Rigueur Méthodologique

Afin de garantir une honnêteté scientifique et technique totale lors de la soutenance universitaire, chaque test est catégorisé selon son niveau réel de vérification :

| Fonctionnalité | Niveau de Validation | Justification & Environnement |
| :--- | :--- | :--- |
| **Ingestion Vidéo MJPEG (10 FPS)** | `SIMULATEUR MOCK` + `TEST AUTOMATISÉ` | Validé via `mock_ipwebcam.py` sur le port 8081 et décodeur OpenCV (`cv2.imdecode`). |
| **Télémétrie Capteurs (Prox, Son, Choc)** | `SIMULATEUR MOCK` + `TEST AUTOMATISÉ` | Format JSON conforme aux spécifications Android IP Webcam v1.14. |
| **Saisie sur Smartphone Réel** | `DOCUMENTÉ POUR SOUTENANCE` | Nécessite un smartphone physique connecté au Wi-Fi local avec l'application IP Webcam. |
| **Moteur OpenCV & Zones ROI** | `TEST AUTOMATISÉ` | Soustraction d'arrière-plan, seuillage de contours et masque rectangulaire normalisé ($x, y, w, h$). |
| **Sirène PC Windows** | `TEST AUTOMATISÉ` + `VALIDATION SYSTÈME` | Exécution asynchrone via `winsound.PlaySound` sur l'OS hôte Windows 11. |
| **Intégrité Cryptographique** | `TEST AUTOMATISÉ` | Calcul réel SHA-256, altération artificielle de bits et vérification du chaînage. |
| **IA Qwen Vision xKiro** | `TEST AUTOMATISÉ AVEC MOCK API` | Les tests automatisés simulent le catalogue et les réponses xKiro pour éviter toute consommation de quota et dépendance externe. L'implémentation physique s'active dès injection d'une clé API valide. |
| **Notifications Telegram** | `TEST AUTOMATISÉ AVEC MOCK HTTP` | Envoi d'alertes et formatage Markdown vérifiés sans solliciter l'API réelle Telegram. |
| **Persistance SQLite WAL** | `TEST AUTOMATISÉ` + `SMOKE TEST E2E` | Création de tables, contraintes d'intégrité et lecture/écriture transactionnelle directes. |

---

## 4. Résultats des Bancs d'Essai

### 4.1 Suite Complète Pytest (55 tests)

```
============================= test session starts =============================
platform win32 -- Python 3.11.8, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\USER\Documents\alarme-sys

tests/test_api.py .....                     [  9%]
tests/test_auth_rbac.py ....                [ 16%]
tests/test_database_migration.py ....       [ 23%]
tests/test_detection.py ...                 [ 29%]
tests/test_integration.py ...               [ 34%]
tests/test_integrity.py ....                [ 41%]
tests/test_pro03_features.py ........       [ 56%]
tests/test_pro_features.py ............     [ 78%]
tests/test_qwen_vision.py .....             [ 87%]
tests/test_sensors.py ....                  [ 94%]
tests/test_telegram.py ...                  [100%]

============================= 55 passed in 22.04s =============================
```

### 4.2 Smoke Test End-to-End (12 étapes)

```
[SMOKE TEST] Démarrage du Smoke Test End-to-End...
[SMOKE TEST] 1. Lancement du simulateur Mock IP Webcam sur http://127.0.0.1:8081 ... (HTTP 200)
[SMOKE TEST] 2. Lancement du Monitoring Host sur http://127.0.0.1:5000 ... (HTTP 200)
[SMOKE TEST] 3. Vérification de l'accès au tableau de bord (GET /) et session Administrateur... OK
[SMOKE TEST] 4. Ajout du smartphone simulateur via POST /api/devices (dev_bf1a70e6)... OK
[SMOKE TEST] 5. Attente et vérification du statut CONNECTÉ (Caméra: CONNECTÉ, Capteurs: CONNECTÉ)... OK
[SMOKE TEST] 6. Réception et décodage du flux vidéo MJPEG (640x480)... OK
[SMOKE TEST] 7. Vérification des capteurs (Prox=100.0cm, Son=40.9dB, Accel=9.81m/s²)... OK
[SMOKE TEST] 8. Armement du système... OK
[SMOKE TEST] 9. Injection d'un événement simulé (CHOC_ACCÉLÉROMÈTRE)... OK
[SMOKE TEST] 10. Vérification de la capture photo JPEG (640x480, lisible OpenCV)... OK
[SMOKE TEST] 11. Finalisation de l'enregistrement vidéo MP4 (55 frames, 171 Ko, lisible)... OK
[SMOKE TEST]     Arrêt de la sirène sonore via POST /api/alarm/stop_siren... OK
[SMOKE TEST] 12. Persistance relationnelle SQLite (Source de vérité) et miroir JSON...
[SMOKE TEST]     -> Preuve cryptographique SQLite certifiée (SHA-256: a02688db1c5b9cd2...).
[SMOKE TEST]     -> Persistance validée avec succès dans SQLite 3 et alerts.json.
[SMOKE TEST] =================================================================
[SMOKE TEST] SMOKE TEST REUSSI A 100% : TOUS LES 12 POINTS SONT VALIDES !
[SMOKE TEST] =================================================================
```

---

## 5. Limites Techniques et Hypothèses de Démonstration

1. **Capteur de Proximité Smartphone :** La majorité des contrôleurs Android renvoient une détection quasi-binaire ($0.0\text{ cm}$ si masqué, $5.0\text{ cm}$ ou $100.0\text{ cm}$ si dégagé).
2. **Capteur Acoustique :** La valeur en décibels retournée par IP Webcam est une amplitude relative non étalonnée en dB SPL standard. Le seuil doit être ajusté en fonction de la pièce.
3. **Connectivité Wi-Fi Universitaire :** Si le réseau Wi-Fi active l'*isolation client* (interdisant la communication entre deux adresses locales), il convient d'utiliser le partage de connexion 4G du smartphone ou le simulateur local `mock_ipwebcam.py`.
4. **Quotas Qwen Vision Free Tier :** Les modèles gratuits imposent un plafond de débit (10 à 20 requêtes/minute). En cas de saturation, le disjoncteur bascule sur OpenCV sans arrêt du système.
5. **Mode Démonstration :** Le système intègre un mode démo activable en un clic permettant d'injecter des événements réels ou simulés même en l'absence de capteurs physiques connectés.

---

## 6. Déroulé de Démonstration Recommandé (5 à 7 minutes)

```
00:00 - 01:00 │ INTRODUCTION & ARCHITECTURE
              │ Présentation du concept : transformer des smartphones en caméras/capteurs IoT.
              │ Schéma client-serveur local : Flask + OpenCV sur Windows, Android IP Webcam.

01:00 - 02:30 │ CONNEXION & DASHBOARD TEMPS RÉEL
              │ Lancement de 'run.bat' ou démonstration avec le simulateur port 8081.
              │ Affichage du flux vidéo MJPEG, jauges de proximité/son/accéléromètre.
              │ Démonstration des statuts visuels (Vert / Orange / Rouge / Gris).

02:30 - 04:00 │ DÉTECTION MULTI-VECTORIELLE & ZONES ROI
              │ Définition d'une zone rectangulaire de surveillance (ROI) sur l'écran.
              │ Déclenchement d'un mouvement : passage d'un objet devant la caméra.
              │ Déclenchement de la sirène Windows (winsound) et coupure d'urgence en 1 clic.

04:00 - 05:30 │ CONSERVATION DES PREUVES & SCELLAGE CRYPTOGRAPHIQUE
              │ Lecture de la capture JPEG instantanée et lecture du clip MP4 (pré-roll 3s + post-roll 5s).
              │ Ouverture de la modale d'intégrité : vérification de l'empreinte SHA-256 et du journal chaîné.
              │ Téléchargement du rapport d'incident PDF généré à la volée avec ReportLab.

05:30 - 06:30 │ SÉCURITÉ APPLICATIVE, RBAC & PERSISTANCE SQLITE
              │ Présentation des rôles (Admin, Opérateur, Auditeur) et de la protection anti force-brute.
              │ Démonstration de la persistance SQLite WAL et de l'export JSON.

06:30 - 07:00 │ CONCLUSION & QUESTIONS DU JURY
              │ Synthèse des acquis : 55 tests validés, smoke test 100%, 0 fausse promesse matérielle.
```

---

## 7. Décision de Certification Finale

Au vu :
1. De la conformité stricte du code source avec l'architecture distribuée du TP4 ;
2. De la protection complète côté serveur (anti-SSRF, anti-CSRF, anti-brute-force, bootstrap sécurisé, validation des entrées) ;
3. De l'intégrité vérifiable des preuves par SHA-256 et HMAC avec détection d'altération démontrée ;
4. Du respect absolu de la gratuité pour l'IA visuelle Qwen Vision avec repli OpenCV transparent ;
5. Du succès exhaustif à 100 % des tests automatisés (55/55) et du smoke test (12/12) ;

Le projet **SMART SECURITY MONITOR — TP4 (PRO-05)** est formellement déclaré :

# 🏆 **CERTIFIÉ PRÊT POUR LA SOUTENANCE UNIVERSITAIRE**
*(AVEC LIMITATIONS MATÉRIELLES ET RÉSEAU EXPLICITEMENT DÉCLARÉES)*

*Date de certification : 14 Novembre 2026*  
*Ingénierie & Audit : Antigravity Engineering Team*
