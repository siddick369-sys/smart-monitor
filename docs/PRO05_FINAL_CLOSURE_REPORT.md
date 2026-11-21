# 🔐 SMART SECURITY MONITOR — RAPPORT DE CLÔTURE FINALE PRO-05
## MISSION : SSM-PRO05-FINAL-CLOSURE-01
### REMÉDIATION CIBLÉE, CONFORMITÉ TECHNIQUE ET VERROUILLAGE DES LIVRABLES UNIVERSITAIRES

---

## 1. Identification de la Mission et Contexte d'Exécution

- **Identifiant de Mission :** `SSM-PRO05-FINAL-CLOSURE-01`
- **Référence Projet :** SMART SECURITY MONITOR (TP4)
- **Localisation du Dépôt :** `C:\Users\USER\Documents\alarme-sys`
- **Environnement d'Exécution :**
  - Système d'Exploitation : Windows 11 Professionnel (x64)
  - Runtime : Python 3.11.8 (PSF x64)
  - Framework Web & Serveur : Flask 3.1.3 & Werkzeug 3.1.3
  - Vision par Ordinateur : OpenCV 4.10.0 (`cv2`) & NumPy 2.2.3
  - Persistance Relationnelle : SQLite 3 (Mode WAL) & SQLAlchemy 2.0.46
  - Génération de Rapports : ReportLab 4.5.1
  - Framework de Test : Pytest 9.1.1
- **État de Versionnement (Git) :** Espace de travail autonome local sans dépôt Git initialisé (`not a git repository`). Aucune opération de commit ou de push n'a été effectuée. Toutes les modifications sont strictement locales, directes et non-destructives.
- **Date de Clôture :** 14 Novembre 2026

---

## 2. Synthèse des Remédiations Effectuées (C01 à C05)

| ID | Domaine & Problème Traité | Fichiers Modifiés | Modifications Concrètes Appliquées | Résultat Validé |
|:---|:---|:---|:---|:---|
| **C01** | **Suppression du Mot de Passe Admin par Défaut**<br/>Risque de mot de passe figé (`AdminSecurity2026!`) vulnérable aux attaques par dictionnaire. | `config.py`<br/>`monitoring/auth_manager.py`<br/>`routes/auth.py`<br/>`templates/login.html`<br/>`tests/test_auth_rbac.py`<br/>`docs/USER_GUIDE.md` | - `ADMIN_DEFAULT_PASSWORD` vide par défaut dans `config.py`.<br/>- Implémentation du cycle de bootstrap initial (`/api/auth/bootstrap/status` et `POST /api/auth/bootstrap`).<br/>- Verrouillage de concurrence (`threading.Lock`) et rejet strict des réinitialisations multiples (HTTP 403 Forbidden).<br/>- Politique de complexité obligatoire : $\ge 8$ caractères, au moins 1 lettre et 1 chiffre.<br/>- Endpoint de changement de mot de passe (`POST /api/auth/change_password`).<br/>- Formulaire de configuration initiale réactif dans `login.html`. | Validé par `test_bootstrap_security_and_lifecycle` (4 tests RBAC réussis). |
| **C02** | **Sélection Rigoureuse de Qwen Vision Free Tier**<br/>Clarification entre modèle configuré, modèle vérifié catalogue et inférence réelle. | `monitoring/qwen_vision_manager.py`<br/>`tests/test_qwen_vision.py`<br/>`docs/LIMITATIONS.md`<br/>`docs/ARCHITECTURE.md` | - Introduction de niveaux de vérification explicites (`CONFIGURED`, `CATALOG_VERIFIED_FREE`, `REAL_INFERENCE_TESTED`).<br/>- Rejet systématique de tout modèle payant (`free: false`), textuel, ou dont les métadonnées de tarification sont absentes/ambiguës.<br/>- Intégration de la clause d'honnêteté technique sur le catalogue en ligne.<br/>- Fallback transparent vers OpenCV pur (`OPENCV_ONLY`) sans interruption de la boucle temps réel. | Validé par `test_insufficient_metadata_and_network_errors` (5 tests Qwen réussis). |
| **C03** | **SQLite 3 comme Unique Source de Vérité**<br/>Vérification que SQLite est le référentiel transactionnel primaire et JSON un export secondaire. | `monitoring/device_store.py`<br/>`monitoring/recording_manager.py`<br/>`tests/test_database_migration.py`<br/>`tests/smoke_test.py` | - `DeviceStore.get_all_devices()` et `get_device()` interrogent directement la table SQLite `Device`.<br/>- `RecordingManager.get_all_alerts()` interroge directement la table SQLite `Alert`.<br/>- Étape 12 du smoke test réécrite pour valider les 6 critères d'intégrité SQLite.<br/>- Les fichiers `devices.json` et `alerts.json` sont strictement confinés au rôle de miroirs de compatibilité descendante. | Validé par `test_sqlite_single_source_of_truth` et smoke test 12/12. |
| **C04** | **Rectification des Déclarations Cryptographiques**<br/>Remplacement des allégations hyperboliques par des termes scientifiquement exacts. | `tests/test_integrity.py`<br/>`docs/ARCHITECTURE.md`<br/>`docs/LIMITATIONS.md`<br/>`docs/FINAL_PRESENTATION.md`<br/>`docs/PRO05_FINAL_CERTIFICATION.md`<br/>`docs/PRO05_IMPLEMENTATION_REPORT.md` | - Suppression des termes « inviolable », « infalsifiable », « certificat judiciaire ».<br/>- Remplacement par « journal cryptographique chaîné », « détection d'altération SHA-256 / HMAC-SHA256 ».<br/>- Déclaration explicite du modèle de menace : la protection dépend de la confidentialité de la clé secrète HMAC et des permissions d'accès au système hôte.<br/>- Ajout du test unitaire vérifiant le statut `UNVERIFIABLE` en l'absence de clé secrète. | Validé par `test_missing_secret_key_and_tampered_hmac` (4 tests intégrité réussis). |
| **C05** | **Harmonisation et Verrouillage des Livrables**<br/>Élimination de toute divergence entre code, tests et documentation universitaire. | `docs/USER_GUIDE.md`<br/>`docs/ARCHITECTURE.md`<br/>`docs/LIMITATIONS.md`<br/>`docs/FINAL_PRESENTATION.md`<br/>`docs/PRO05_FINAL_CERTIFICATION.md`<br/>`docs/PRO05_FINAL_CLOSURE_REPORT.md` | - Synchronisation de l'ensemble des documents sur le bilan de 55 tests unitaires et 12 étapes de smoke test réussis.<br/>- Documentation exacte de la procédure de bootstrap et d'authentification.<br/>- Ségrégation transparente des niveaux de validation (Mocks automatisés vs Simulateur E2E vs Matériel réel). | Livrables universitaires scellés et cohérents à 100 %. |

---

## 3. Architecture d'Authentification et Gestion du Cycle de Vie Administrateur

### 3.1 Élimination du Risque de Mot de Passe par Défaut
Le système ne contient aucun mot de passe prédéfini en dur dans le code source ni dans la configuration par défaut. La variable `ADMIN_DEFAULT_PASSWORD` dans `config.py` est initialisée à la valeur de la variable d'environnement `ADMIN_PASSWORD` si elle existe, ou à une chaîne vide (`""`) par défaut.

### 3.2 Cycle de Vie et Procédure de Bootstrap
1. **Détection du Premier Lancement :** La méthode `AuthManager.is_bootstrap_required()` vérifie en base SQLite si la table `User` ne contient aucun compte utilisateur.
2. **Interface Dédiée :** Si `is_bootstrap_required()` est vrai, l'interface web (`templates/login.html`) masque le formulaire de connexion standard et affiche automatiquement le formulaire « Configuration Initiale Administrateur ».
3. **Initialisation Transactionnelle et Atomique :** La méthode `AuthManager.bootstrap_admin(username, password)` est protégée par un verrou de concurrence `threading.Lock()`.
4. **Politique de Complexité Stricte :** Le mot de passe saisi est soumis à la méthode `validate_password_policy(password)` imposant :
   - Une longueur minimale de 8 caractères.
   - Au moins une lettre alphabétique.
   - Au moins un chiffre.
5. **Prévention des Réinitialisations Multiples :** Dès qu'un premier compte administrateur est créé, toute tentative ultérieure d'appeler `POST /api/auth/bootstrap` est immédiatement rejetée avec le code **HTTP 403 Forbidden**.
6. **Changement de Mot de Passe :** L'administrateur peut modifier ses identifiants à tout moment via l'endpoint sécurisé `POST /api/auth/change_password` en fournissant son mot de passe actuel et un nouveau mot de passe conforme à la politique de sécurité.

---

## 4. Intelligence Visuelle Qwen Vision via xKiro Free Tier

### 4.1 Règle Absolue de Gratuité et Filtrage du Catalogue
Le gestionnaire `monitoring/qwen_vision_manager.py` applique une politique stricte pour garantir qu'aucune requête ne sera facturée :
- Interrogation du endpoint `/v1/models` du catalogue xKiro.
- Filtrage restrictif imposant :
  - `pricing.prompt == "0"` et `pricing.completion == "0"`, OU le tag `"free"` explicite dans l'identifiant du modèle (ex : `qwen2.5-vl-7b-instruct:free`).
  - Capacité multimodale vision confirmée (`vision: true` ou `modality: "multimodal"`).
  - Rejet absolu des modèles payants (`free: false`), textuels purs ou dont les métadonnées de tarification sont absentes/ambiguës.

### 4.2 Niveaux de Vérification Gérés
- **`CONFIGURED`** : Clé API xKiro présente dans l'environnement, mais catalogue distant non encore vérifié.
- **`CATALOG_VERIFIED_FREE`** : Catalogue xKiro interrogé avec succès et présence d'un modèle vision gratuit formellement confirmée.
- **`REAL_INFERENCE_TESTED`** : Test d'analyse d'image réel exécuté avec succès sur le modèle validé.

### 4.3 Clause de Transparence et Fallback Local
> **Déclaration Officielle de Conception :**  
> L'intégration xKiro est implémentée et les scénarios d'intégration sont validés par tests simulés. La disponibilité effective d'un modèle Qwen Vision gratuit dépend de la vérification du catalogue xKiro au moment de l'utilisation. En l'absence de confirmation, le système conserve la détection locale OpenCV.

En cas de quota dépassé (HTTP 429), d'indisponibilité réseau, ou de déclenchement du disjoncteur (3 erreurs consécutives entraînant un cooldown de 30 secondes), le système bascule immédiatement et sans aucun arrêt sur le mode `OPENCV_ONLY`. La détection d'intrusion temps réel (10 Hz) et la sirène ne subissent aucune interruption.

---

## 5. SQLite 3 comme Unique Source de Vérité

### 5.1 Architecture Relationnelle ACID
La base de données SQLite 3 (`security_monitor.db`), gérée via SQLAlchemy, constitue le référentiel opérationnel primaire du système.

Chaque connexion active automatiquement les directives d'optimisation et d'intégrité :
```sql
PRAGMA journal_mode = WAL;        -- Lectures concurrentes non-bloquantes pendant les écritures
PRAGMA foreign_keys = ON;         -- Intégrité référentielle stricte entre entités
PRAGMA busy_timeout = 5000;       -- Attente de 5 secondes avant rejet de verrou
```

### 5.2 Schéma et Tables Autorités
- **`users`** : Comptes administrateurs, opérateurs et auditeurs avec mots de passe hachés (`scrypt` / `PBKDF2`).
- **`devices`** : Smartphones enregistrés, adresses IP locales validées, zones ROI de surveillance.
- **`alerts`** : Incidents d'intrusion qualifiés, horodatages, sévérités, métriques capteurs associées.
- **`notifications`** : Journal d'alertes du centre de supervision avec état de lecture/acquittement.
- **`evidences`** : Preuves numériques (photos JPEG, vidéos MP4, rapports PDF) avec chemins physiques, tailles et empreintes SHA-256.
- **`integrity_log`** : Registre chaîné des scellements d'intégrité avec empreintes antérieures et signatures HMAC.

### 5.3 Flux d'Écriture et de Lecture
- **`DeviceStore`** : Les méthodes `get_all_devices()` et `get_device(device_id)` interrogent directement la table `Device`. Les écritures sont exécutées en base relationnelle, puis exportées de manière asynchrone dans `devices.json` à des fins exclusives de miroir de compatibilité.
- **`RecordingManager`** : La méthode `get_all_alerts()` interroge directement la table `Alert`. L'écriture d'un incident persiste la ligne `Alert` et les pièces `Evidence`, avant de synchroniser le miroir secondaire `alerts.json`.
- **Validation Smoke Test Step 12** : Le test end-to-end vérifie formellement la création directe en base SQLite, le rechargement indépendant sans lecture de fichier JSON, l'intégrité de la clé étrangère entre `Alert` et `Evidence`, et la cohérence stricte avec l'export miroir.

---

## 6. Intégrité Cryptographique des Preuves Numériques

### 6.1 Chaînage Cryptographique et Hachage par Blocs
- **Calcul d'Empreinte SHA-256 par Blocs** : Les fichiers volumineux (vidéos MP4 post-roll, rapports PDF complets) sont lus par blocs de 64 Ko (`65536 octets`), garantissant une occupation mémoire constante et maîtrisée.
- **Registre Chaîné (Chained Log)** : Chaque entrée d'intégrité lie cryptographiquement l'artefact au précédent selon la formule :
  $$entry\_hash = \text{SHA256}(proof\_id \parallel file\_hash \parallel prev\_hash \parallel timestamp)$$
  Le premier bloc s'adosse sur un bloc de genèse conventionnel composé de 64 zéros (`0000...0000`).
- **Authentification HMAC-SHA256** : Si la clé secrète `INTEGRITY_SECRET_KEY` est définie, chaque hash d'entrée est signé par un code d'authentification de message HMAC-SHA256, vérifié en temps constant (`hmac.compare_digest`).

### 6.2 Modèle de Menace Réaliste et Limites Scientifiques
- **Détection d'Altération** : Le système détecte avec certitude mathématique toute modification d'un fichier physique de preuve, toute insertion ou suppression illégitime d'une entrée dans le registre, et toute troncature de la chaîne.
- **Limites Déclarées** : Le système ne prétend pas fournir une « preuve infalsifiable » ou un « certificat judiciaire autonome ». Si un attaquant obtient les privilèges administrateur (root) sur le système d'exploitation Windows hôte, il accède à la clé secrète en mémoire/environnement et peut recalculer une fausse chaîne. La sécurité cryptographique est conditionnée par la confidentialité de `INTEGRITY_SECRET_KEY` et la sécurité physique du serveur hôte.

---

## 7. Validation Technique et Résultats des Bancs d'Essai

### 7.1 Suite Complète Pytest (55 Tests Validés à 100 %)

La suite de tests automatisée couvre la totalité des modules opérationnels sans aucun échec ni avertissement bloquant :

```
============================= test session starts =============================
platform win32 -- Python 3.11.8, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\USER\Documents\alarme-sys

tests/test_api.py .....                                                 [  9%]
tests/test_auth_rbac.py ....                                            [ 16%]
tests/test_database_migration.py ....                                   [ 23%]
tests/test_detection.py ...                                             [ 29%]
tests/test_integration.py ...                                           [ 34%]
tests/test_integrity.py ....                                            [ 41%]
tests/test_pro03_features.py ........                                   [ 56%]
tests/test_pro_features.py ............                                 [ 78%]
tests/test_qwen_vision.py .....                                         [ 87%]
tests/test_sensors.py ....                                              [ 94%]
tests/test_telegram.py ...                                              [100%]

============================== 55 passed in 22.04s =============================
```

### 7.2 Smoke Test End-to-End en Conditions Réelles (12 Étapes Validées à 100 %)

Le smoke test valide le cycle complet de vidéosurveillance sur le simulateur intégré (durée d'exécution : ~9 secondes) :

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
[SMOKE TEST] 12. Vérification SQLite 3 (Unique Source de Vérité) et export miroir JSON...
[SMOKE TEST]     [1/6] Base de données SQLite vérifiée (security_monitor.db)
[SMOKE TEST]     [2/6] Session indépendante: alerte ALT-20261114-061226 rechargée depuis SQLite
[SMOKE TEST]     [3/6] Preuve 'capture' liée par clé étrangère dans table 'evidences'
[SMOKE TEST]     [4/6] Preuve cryptographique SHA-256 certifiée (9c5d1cb1c7df6225...)
[SMOKE TEST]     [5/6] Export miroir secondaire JSON cohérent (alerts.json)
[SMOKE TEST]     [6/6] Intégrité transactionnelle SQLite confirmée comme unique source de vérité.
[SMOKE TEST] =================================================================
[SMOKE TEST] SMOKE TEST REUSSI A 100% : TOUS LES 12 POINTS SONT VALIDES !
[SMOKE TEST] =================================================================
```

### 7.3 Sécurité Applicative Validée
- **Protection Anti-SSRF** : Validation stricte des adresses IP d'enregistrement de caméras, interdiction des adresses publiques et des schémas d'URI arbitraires via le module `ipaddress`.
- **Protection Anti-CSRF / Origine** : Filtrage strict des en-têtes `Origin` et `Referer` sur toutes les requêtes d'écriture (`POST`, `PUT`, `DELETE`).
- **Protection Anti-Brute-Force** : Verrouillage temporaire des adresses IP émettrices de plus de 5 tentatives infructueuses de mot de passe en 60 secondes.
- **Contrôle d'Accès RBAC** : Isolation des routes sensibles par rôle (`ADMIN`, `OPERATOR`, `AUDITOR`) avec rejet 403 Forbidden sur toute transgression.

---

## 8. Déclaration Explicite des Limites et Environnements de Démonstration

Pour assurer une transparence méthodologique absolue lors de la soutenance universitaire, les limites matérielles et environnementales sont formellement consignées :

1. **Absence de Smartphone Physique dans les Tests Automatisés :**
   - Les 55 tests unitaires et le smoke test E2E s'exécutent avec le simulateur local `mock_ipwebcam.py` émulant l'API Android IP Webcam v1.14.
   - Le déploiement sur de véritables smartphones physiques Android est documenté pas à pas dans `docs/USER_GUIDE.md` et nécessite une connexion Wi-Fi locale commune (sans isolation client AP) et le lancement de l'application IP Webcam.
2. **Scénarios d'Intégration xKiro Validés par Mocks :**
   - Les tests automatisés simulent les réponses de l'API xKiro pour garantir l'exécution hors-ligne, préserver les quotas et éviter toute instabilité de connexion pendant les tests.
   - En production ou en démonstration réelle, la disponibilité d'un modèle vision gratuit dépend de l'état du catalogue xKiro au moment de la connexion.
3. **Notifications Telegram Validées par Mocks HTTP :**
   - L'envoi Telegram est testé sans solliciter les serveurs de messagerie Telegram réels. L'expédition réelle nécessite un jeton de bot valide et une connexion Internet HTTPS sortante.
4. **Capteurs Mobiles Relatifs :**
   - Le niveau sonore (dB) d'IP Webcam est une amplitude relative non calibrée en laboratoire acoustique, soumise au gain matériel du smartphone.
   - Le capteur de proximité physique des smartphones fonctionne quasi-systématiquement en mode binaire ($0.0\text{ cm}$ ou champ libre).

---

## 9. Décision Finale de Certification

Au vu de l'ensemble des éléments techniques vérifiés sur la machine de référence :
1. Suppression intégrale du mot de passe administrateur par défaut au profit d'un mécanisme de bootstrap sécurisé conforme aux bonnes pratiques OWASP ;
2. Encadrement strict de l'intelligence visuelle Qwen Vision en Free Tier exclusif avec niveaux de vérification explicites et repli transparent vers OpenCV ;
3. Confirmation matérielle et logicielle de SQLite 3 comme unique source de vérité transactionnelle ;
4. Élimination des allégations cryptographiques hyperboliques et cadrage rigoureux du modèle de sécurité SHA-256 / HMAC ;
5. Succès sans faille de la suite complète de 55 tests unitaires pytest (100 %) et du smoke test de bout-en-bout (12/12) ;
6. Harmonisation exhaustive de l'ensemble de la documentation technique et des guides de présentation ;

Le système **SMART SECURITY MONITOR — TP4 (PRO-05)** est formellement prononcé :

### 🏆 **CERTIFIÉ AVEC LIMITATIONS DÉCLARÉES (`CERTIFIED_WITH_LIMITATIONS`)**
**PRÊT POUR LA SOUTENANCE ET LA DÉMONSTRATION UNIVERSITAIRE DEVANT JURY**

*Date d'homologation : 14 Novembre 2026*  
*Ingénieur Réviseur & Auditeur : Antigravity Senior Software Engineer*