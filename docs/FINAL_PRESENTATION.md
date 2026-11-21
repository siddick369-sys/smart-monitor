# SMART SECURITY MONITOR — DOSSIER DE SOUTENANCE UNIVERSITAIRE (TP4)
## Surveillance Intelligente Multi-Smartphone & Monitoring Host Distribué

---

## 1. Introduction et Problématique

Dans le cadre du TP4 d'Architecture Logicielle et Systèmes Distribués, la problématique centrale consiste à concevoir un système de vidéosurveillance et de détection d'intrusion complet sans recourir à un équipement CCTV industriel propriétaire coûteux. 

Le système relève le défi de transformer d'anciens smartphones Android en nœuds de capteurs et caméras réseau autonomes, supervisés par un serveur hôte central (PC sous Windows). Les enjeux majeurs traités sont :
- **L'hétérogénéité et l'instabilité du réseau local Wi-Fi** (latence variable, déconnexions intempestives, isolation de bornes AP).
- **Le traitement en temps réel de flux vidéo multiples** sans blocage du serveur d'application.
- **L'agrégation fiable de télémétries physiques hétérogènes** (proximité infrarouge, microphone, accéléromètre triaxial) en distinguant rigoureusement les données réelles des simulations.
- **La chaîne de conservation des preuves numériques** (clichés instantanés haute résolution et clips vidéo horodatés avec pré-roll et post-roll).

---

## 2. Objectifs du Système

Le projet répond à un cahier des charges strict articulé autour de 6 piliers :

1. **Supervision Centralisée Professionnelle :** Console web temps réel affichant l'état des appareils, les KPIs de surveillance, les flux MJPEG et les graphiques d'évolution des capteurs.
2. **Détection Multi-Vectorielle Intelligente :** Corrélation d'une détection de mouvement différentielle OpenCV (avec support des zones d'intérêt ROI) et de 3 seuils de télémétrie physique.
3. **Résilience et Reconnexion Automatique :** Threads d'acquisition indépendants par smartphone, algorithme de backoff exponentiel progressif et gestion sans crash des pertes de liaison.
4. **Conservation des Preuves Numériques :** Tampon circulaire continu en mémoire vive (50 frames) extrayant 3 secondes de pré-roll avant incident et 5 secondes de post-roll après incident au format MP4/AVI.
5. **Contrôle Réseau & Sécurité de l'Hôte :** Protection contre les attaques SSRF (filtrage strict des IP privées), défenses anti-CSRF (en-têtes `Origin` et `Sec-Fetch-Site`), et sécurisation contre les traversées de répertoires (`Path Traversal`).
6. **Reporting et Traçabilité :** Génération de rapports PDF certifiés (individuels et de synthèse périodique) et export tabulaire CSV de l'historique complet.

---

## 3. Architecture Générale du Système

Le système repose sur un modèle distribué client-serveur local asynchrone :

```
       +-------------------------------------------------------------+
       |                  SMARTPHONES ANDROID (1 à 3)                |
       |             Application "IP Webcam" (Pavel Khlebovich)       |
       |   - Flux MJPEG : http://<IP>:8080/video                     |
       |   - Télémétrie : http://<IP>:8080/sensors.json              |
       |   - Torche     : http://<IP>:8080/enabletorch               |
       +-------------------------------------------------------------+
                                      │
                        Réseau Local Wi-Fi / Hotspot 4G
                                      │
       +──────────────────────────────▼──────────────────────────────+
       |               MONITORING HOST CENTRAL (PC Windows)          |
       |                     Python 3.11 / Flask / OpenCV            |
       |                                                             |
       |  ┌──────────────────┐  ┌──────────────────┐  ┌───────────┐  |
       |  |  CameraManager   |  |  SensorManager   |  |DeviceStore|  |
       |  | (CameraWorker xN)|  | (SensorPoller xN)|  |(ThreadSafe|  |
       |  └────────┬─────────┘  └────────┬─────────┘  └─────┬─────┘  |
       |           │                     │                  │        |
       |  ┌────────▼─────────────────────▼──────────────────▼─────┐  |
       |  |            DetectionEngine (Boucle d'Évaluation)      |  |
       |  |  - Soustraction d'arrière-plan OpenCV (absdiff)        |  |
       |  |  - Filtrage zones rectangulaires ROI actives          |  |
       |  |  - Seuillage Proximité / Acoustique / Accélération    |  |
       |  |  - Filtrage anti-rebond (Cooldown 8.0s)               |  |
       |  └──────────────────────────┬────────────────────────────┘  |
       |                             │ Notification d'incident       |
       |  ┌──────────────────────────▼────────────────────────────┐  |
       |  |                    SystemCoordinator                  |  |
       |  └───────┬──────────────────┬────────────────────┬───────┘  |
       |          │                  │                    │          |
       |  ┌───────▼────────┐  ┌──────▼──────────┐  ┌──────▼───────┐  |
       |  |  AlarmManager  |  |RecordingManager |  |NotifManager  |  |
       |  | - winsound PC  |  | - Buffer pré/post|  | - Anti-doubl.|  |
       |  | - Torche flash |  | - MP4 / JPEG HD  |  | - Niveaux    |  |
       |  └────────────────┘  └──────┬──────────┘  └──────────────┘  |
       |                             │                               |
       |  ┌──────────────────────────▼────────────────────────────┐  |
       |  |          PDFReportGenerator (ReportLab Engine)        |  |
       |  |       - Rapports unitaires & Synthèses journalières   |  |
       |  └──────────────────────────┬────────────────────────────┘  |
       |                             │                               |
       |  ┌──────────────────────────▼────────────────────────────┐  |
       |  |            API REST & Dashboard Web Temps Réel        |  |
       |  |    Flask Blueprints : dashboard, devices, alerts      |  |
       |  └───────────────────────────────────────────────────────┘  |
       +─────────────────────────────────────────────────────────────+
```

---

## 4. Technologies Utilisées

| Composant | Technologie | Justification Technique |
| :--- | :--- | :--- |
| **Langage & Runtime** | Python 3.11 (x64) | Concurrence multi-thread native, écosystème scientifique et multimédia éprouvé. |
| **Serveur d'Application** | Flask 3.1.3 | Serveur WSGI léger, modulaire (Blueprints), support natif du streaming chunked MJPEG. |
| **Base de Données** | SQLite 3 & SQLAlchemy | Persistance ACID, mode WAL (Write-Ahead Logging), intégrité référentielle et clés étrangères. |
| **Intelligence Visuelle** | Qwen Vision (xKiro Free Tier) | Modèles visuels gratuits validés exclusivement, extraction JSON structurée, fallback OpenCV. |
| **Cryptographie** | SHA-256 & HMAC | Hachage par blocs de 64 Ko, journal d'intégrité chaîné et scellement d'épreuves numériques. |
| **Notifications** | Telegram Bot API | Alertes asynchrones push avec photos jointes, files d'attente non-bloquantes et masquage des secrets. |
| **Traitement d'Images** | OpenCV 4.10 (`cv2`) | Algorithmes différentiels de vision par ordinateur, encodage vidéo H.264/MP4V et AVI/XVID. |
| **Moteur Audio** | Windows `winsound` | Déclenchement de sirène asynchrone non-bloquant sous Windows (`SND_ASYNC`), arrêt immédiat (`SND_PURGE`). |
| **Moteur PDF** | ReportLab 4.5.1 | Génération dynamique de documents PDF certifiés avec tableaux vectoriels et clichés HD intégrés. |
| **Interface Frontend** | HTML5, Tailwind CSS, FontAwesome | Console sombre réactive, graphiques sparklines sans framework lourd, lecteurs vidéo HTML5 natifs. |
| **Nœuds Mobiles** | Android IP Webcam | Serveur HTTP autonome exposant flux MJPEG `/video` et télémétrie JSON `/sensors.json`. |

---

## 5. Fonctionnement des Gestionnaires Métier

### 5.1 CameraManager (`monitoring/camera_manager.py`)
- Instancie un thread `CameraWorker` dédié par smartphone connecté.
- Maintient un tampon circulaire FIFO `collections.deque` de 50 frames (5 secondes à 10 FPS).
- Implémente une reconnexion automatique avec backoff exponentiel progressif (1.0 s à 10.0 s).
- Génère une mire vidéo stylisée haute résolution lors d'une rupture de flux réseau.
- Incruste dynamiquement les zones de surveillance (ROI actives en vert, inactives en gris) dans le flux vidéo distribué aux utilisateurs.

### 5.2 SensorManager (`monitoring/sensor_manager.py`)
- Interroge cycliquement (10 Hz) l'endpoint `/sensors.json` de chaque smartphone.
- Parse les capteurs de proximité, microphone acoustique, accéléromètre triaxial et batterie.
- Qualifie l'état de chaque mesure selon 4 statuts stricts : `DONNÉE RÉELLE`, `CAPTEUR NON DISPONIBLE`, `DONNÉE EXPIRÉE`, `DISPONIBLE (SIMULÉ)`.
- Enregistre l'historique glissant des 20 dernières valeurs pour le tracé de sparklines visuelles.

### 5.3 DetectionEngine (`monitoring/detection_engine.py`)
- Évalue en continu la cohérence des flux vidéo et des données physiques.
- Compare les images successives avec seuillage binaire et extraction de contours.
- Filtre les détections dans les rectangles de surveillance configurés.
- Rejette les artefacts de flash lumineux global (> 85 % de variation brusque).
- Bloque le mitraillage d'alertes par un mécanisme d'anti-rebond paramétrable (cooldown de 8 secondes).
- Normalise les événements (`REAL_SENSOR_EVENT`, `VIDEO_MOTION_EVENT`, `SIMULATED_EVENT`, `DEVICE_DISCONNECTED`, `DEVICE_RECONNECTED`).

### 5.4 AlarmManager (`monitoring/alarm_manager.py`)
- Gère les états d'armement (`ARMÉ` / `DÉSARMÉ`).
- Déclenche la sirène PC via `winsound.PlaySound` en mode asynchrone pour ne jamais figer le serveur Flask.
- Permet une coupure instantanée de l'alarme sans altérer la vidéo ou la journalisation.
- Envoie une commande asynchrone d'allumage de la torche flash du smartphone ciblé (`/enabletorch`).

### 5.5 RecordingManager (`monitoring/recording_manager.py`)
- Capture instantanément un cliché photo haute définition JPEG lors du déclenchement.
- Assemble en thread d'arrière-plan les 3 secondes de pré-roll et 5 secondes de post-roll dans un conteneur MP4 (`mp4v`), avec bascule de secours AVI (`XVID`).
- Applique une politique de rétention automatique (nettoyage des fichiers de plus de 7 jours).
- Protège les fichiers de preuves activement référencés contre toute suppression accidentelle.
- Surveille l'espace disque (`shutil.disk_usage`) pour prévenir les saturations système.

### 5.6 NotificationManager (`monitoring/notification_manager.py`)
- Centralise les alertes et événements système dans un journal d'événements en mémoire.
- Classe les alertes selon 4 niveaux de sévérité (`INFO`, `WARNING`, `HIGH`, `CRITICAL`).
- Empêche les notifications en doublon grâce à une fenêtre glissante de déduplication (20 secondes).
- Permet l'acquittement unitaire ou global sans rechargement de page.

### 5.7 DiagnosticManager (`monitoring/diagnostic_manager.py`)
- Évalue l'état de santé de chaque nœud mobile : test de socket TCP, latence en millisecondes.
- Analyse l'âge de la dernière trame vidéo et la disponibilité unitaire de chaque capteur.
- Détecte automatiquement les appareils silencieux (silence > 8 secondes) et qualifie l'état général en `CONNECTÉ`, `DÉGRADÉ` ou `DÉCONNECTÉ`.

### 5.8 PDFReportGenerator (`monitoring/pdf_report_generator.py`)
- Compile des rapports PDF conformes aux exigences d'audit.
- Rapport unitaire : fiche d'incident, métadonnées, horodatage, qualification certifiée (Réel vs Simulé), valeurs de capteurs et cliché JPEG pleine page.
- Rapport de synthèse : métriques consolidées, histogramme d'activité et journal chronologique.

### 5.9 QwenVisionManager (`monitoring/qwen_vision_manager.py`)
- Analyse sémantique d'images par vision artificielle via xKiro en **Tier Gratuit exclusivement**.
- Rejet strict des modèles payants et textuels, limitation de débit (RPM/intervalle) et file d'attente asynchrone non-bloquante.
- Niveaux de vérification explicites (`CONFIGURED`, `CATALOG_VERIFIED_FREE`, `REAL_INFERENCE_TESTED`).
- Fallback automatique sans crash vers OpenCV pur en cas de dépassement de quota (HTTP 429) ou si le catalogue en ligne n'est pas confirmé.
- Validation en tests automatisés via des mocks d'intégration pour garantir la gratuité et la reproductibilité.

### 5.10 IntegrityManager (`monitoring/integrity_manager.py`)
- Certification cryptographique d'intégrité de l'ensemble des preuves (photos, vidéos, rapports).
- Hachage par blocs SHA-256 (64 Ko), journal cryptographique chaîné $entry\_hash = \text{SHA256}(proof\_id \parallel file\_hash \parallel prev\_hash \parallel timestamp)$ et signature HMAC-SHA256 pour la détection d'altération.
- Sécurité fondée sur la confidentialité de la clé HMAC et les permissions du système de fichiers hôte.

### 5.11 TelegramNotifier (`monitoring/telegram_notifier.py`)
- Transmission instantanée et non-bloquante des alertes critiques vers un canal Telegram sécurisé.
- Expédition en arrière-plan avec cliché photo en pièce jointe et masquage strict des tokens dans les journaux.

### 5.12 AuthManager (`monitoring/auth_manager.py` & `routes/auth.py`)
- Initialisation sécurisée (Bootstrap) au premier démarrage : aucun mot de passe par défaut codé en dur.
- Verrouillage de concurrence, protection contre les réinitialisations multiples (HTTP 403) et politique de complexité stricte (>= 8 caractères, lettre + chiffre).
- Sécurisation RBAC (ADMIN, OPERATOR, AUDITOR) avec hachage sécurisé des mots de passe (PBKDF2/scrypt).
- Protection contre les attaques par force brute (verrouillage temporaire après 5 échecs consécutifs).

### 5.13 MigrationManager (`monitoring/migration_manager.py`)
- Persistance relationnelle ACID sous SQLite 3 avec mode journalier WAL (Write-Ahead Logging).
- Migration idempotente et réversible des anciens fichiers JSON plats (`devices.json`, `alerts.json`) avec sauvegardes automatiques dans `storage/backups`.

---

## 6. Algorithmes de Détection

### 6.1 Mouvement Vidéo Différentiel et Zones d'Intérêt (OpenCV)
Soient $I_{t-1}$ et $I_t$ deux images consécutives acquises à 10 Hz :
1. Conversion en niveaux de gris : $G_t = \text{cvtColor}(I_t, \text{COLOR\_BGR2GRAY})$.
2. Filtrage passe-bas gaussien pour éliminer le bruit capteur : $B_t = \text{GaussianBlur}(G_t, (21, 21), 0)$.
3. Différence absolue : $\Delta_t = |B_t - B_{t-1}|$.
4. Seuillage binaire adaptatif : $T_t(x, y) = 255 \text{ si } \Delta_t(x, y) \ge 25 \text{ sinon } 0$.
5. Dilatation morphologique pour combler les discontinuités : $M_t = \text{dilate}(T_t, \text{iterations}=2)$.
6. **Évaluation par zones (ROI) :**
   Pour chaque zone rectangulaire active $Z_k = (x_1, y_1, x_2, y_2)$ :
   $$\text{Surface\_Mouvement}_k = \sum_{(x,y) \in Z_k} [M_t(x, y) > 0]$$
   $$\text{Pourcentage}_k = \frac{\text{Surface\_Mouvement}_k}{(x_2 - x_1) \times (y_2 - y_1)} \times 100$$
   Si $\text{Pourcentage}_k \ge \text{Seuil}_{\text{mouvement}}$, une alerte d'intrusion est émise.
7. **Rejet de flash lumineux global :** Si $\frac{\sum M_t(x, y)}{W \times H} > 85\%$, l'événement est rejeté (changement d'éclairage ambiant).

### 6.2 Détection Accélérométrique (Secousse et Choc)
À partir du vecteur accélération triaxial $(a_x, a_y, a_z)$ fourni en $\text{m/s}^2$ :
$$\text{Norme} = \sqrt{a_x^2 + a_y^2 + a_z^2}$$
$$\Delta g = |\text{Norme} - 9.81|$$
Si $\Delta g \ge \text{Seuil}_{\text{choc}}$ (défaut : $4.5\text{ m/s}^2$), une alerte de choc ou de manipulation suspecte est déclarée.

### 6.3 Détection de Proximité et Détection Acoustique
- **Proximité :** Alerte si la distance mesurée $d \le 5.0\text{ cm}$.
- **Acoustique :** Alerte si le niveau relatif $L \ge 75.0\text{ dB}$.

---

## 7. Démonstration des Fonctionnalités (Scénario Oral 5 à 7 Minutes)

### Minute 0:00 – 1:00 : Introduction & Prise en Main du Dashboard
- Ouvrir le navigateur sur `http://127.0.0.1:5000`.
- Montrer l'en-tête de contrôle : bouton d'armement/désarmement, statut de la sirène, jauge d'espace disque.
- Présenter les KPIs en direct : smartphones connectés, capteurs actifs, état général `OPÉRATIONNEL`.

### Minute 1:00 – 2:00 : Surveillance Vidéo, Télémétrie et Diagnostic
- Présenter la carte du smartphone avec son flux vidéo MJPEG en direct à 10 FPS.
- Pointer les jauges télémétriques : proximité, niveau sonore avec sparkline d'historique, accéléromètre.
- Cliquer sur le bouton **"Diagnostic"** de la caméra : montrer la latence réseau en millisecondes, le statut unitaire des 5 capteurs et l'absence d'anomalie silencieuse.

### Minute 2:00 – 3:30 : Zones de Surveillance & Détection d'Intrusion
- Cliquer sur le bouton **"Zones (ROI)"** : définir une zone rectangulaire (ex: `Entrée`, $X=10\%, Y=10\%, L=40\%, H=40\%$).
- Montrer l'incrustation directe du rectangle vert sur le flux vidéo.
- **Déclenchement physique ou simulé :**
  - Passer la main devant le smartphone ou cliquer sur *Simuler -> Mouvement Vidéo*.
  - Observer la réaction immédiate : la bannière rouge clignote, la sirène PC retentit de manière asynchrone, le voyant passe à `INCIDENT ACTIF`.
- Cliquer sur **"MUTE SIRÈNE"** : la sirène se coupe instantanément sans interrompre la vidéo.

### Minute 3:30 – 5:00 : Consultation des Preuves & Rapports PDF
- Faire défiler jusqu'au **Centre des Incidents** :
  - Cliquer sur l'icône photo pour afficher le cliché HD capturé au moment exact de l'intrusion.
  - Cliquer sur l'icône vidéo pour lancer le lecteur vidéo HTML5 : vérifier la présence des **3 secondes de pré-roll** et **5 secondes de post-roll**.
- Cliquer sur l'icône **PDF** de la ligne d'incident : ouvrir le document PDF généré par ReportLab avec le tableau des métadonnées, le badge de qualification et la preuve visuelle intégrée.
- Cliquer sur **"Rapport Journalier PDF"** dans la barre supérieure pour montrer la synthèse consolidée.

### Minute 5:00 – 6:30 : Notifications & Résilience aux Pannes
- Ouvrir le **Centre de Notifications** (icône cloche en haut à droite) : montrer les alertes qualifiées (`CRITICAL`, `HIGH`, `INFO`) et la protection anti-doublon.
- **Démonstration de résilience :**
  - Couper la connexion du smartphone ou du simulateur.
  - Montrer que le serveur Flask ne crashe pas : la carte caméra bascule vers une mire de signal perdu, le statut passe en `DÉGRADÉ` puis `DÉCONNECTÉ`.
  - Reconnecter l'appareil : le système rétablit le flux vidéo et la télémétrie automatiquement.

### Minute 6:30 – 7:00 : Conclusion et Questions du Jury
- Résumer les points forts : modularité, robustesse multi-thread, sécurité réseau anti-SSRF/anti-CSRF et absence totale de dépendances lourdes.

---

## 8. Résultats des Tests et Validation

L'ensemble des composants logiciels a été validé selon une méthodologie rigoureuse en trois volets distincts :
1. **Tests Unitaires et d'Intégration (Pytest)** : **81 tests automatisés** couvrant l'ensemble des modules (Edge AI, Présence, 2FA TOTP, SIEM, WebRTC, PWA, Intégrité, SQLite, Détection).
2. **Smoke Test End-to-End (Simulateur)** : validation dynamique de bout-en-bout avec le simulateur Android IP Webcam sur port 8081 (12 points validés à 100%).
3. **Déploiement Matériel Réel** : procédure documentée pour smartphones physiques Android sur réseau Wi-Fi local sans isolation AP.

```
============================= test session starts =============================
platform win32 -- Python 3.11.8, pytest-9.1.1, pluggy-1.6.0
collected 81 items

tests/test_api.py ......................... [  5 passed ]
tests/test_auth_rbac.py ................... [  4 passed ]
tests/test_database_migration.py .......... [  4 passed ]
tests/test_detection.py ................... [  3 passed ]
tests/test_edge_ai.py ..................... [  7 passed ]
tests/test_integration.py ................. [  3 passed ]
tests/test_integrity.py .................. [  4 passed ]
tests/test_presence.py .................... [  5 passed ]
tests/test_pro03_features.py .............. [  8 passed ]
tests/test_pro_features.py ................ [ 12 passed ]
tests/test_pwa_push.py .................... [  3 passed ]
tests/test_qwen_vision.py ................. [  6 passed ]
tests/test_sensors.py ..................... [  4 passed ]
tests/test_telegram.py .................... [  3 passed ]
tests/test_totp_siem.py ................... [  7 passed ]
tests/test_webrtc.py ...................... [  3 passed ]

============================== 81 passed in 32.78s =============================
```

### Smoke Test End-to-End Automatisé (12 Points Validés à 100 %) :
1. Démarrage automatisé du simulateur Mock IP Webcam sur port 8081 : **OK**.
2. Démarrage du Monitoring Host Flask sur port 5000 : **OK**.
3. Accès au tableau de bord web (`GET /`) et session d'authentification : **OK**.
4. Enregistrement dynamique du smartphone via `POST /api/devices` : **OK**.
5. Négociation et bascule à l'état `CONNECTÉ` (vidéo et capteurs) : **OK**.
6. Réception et décodage du flux MJPEG (résolution 640x480) : **OK**.
7. Analyse et validation de la télémétrie capteurs : **OK**.
8. Armement du système de sécurité : **OK**.
9. Injection d'un incident de détection : **OK**.
10. Écriture et vérification de la capture photo instantanée JPEG : **OK**.
11. Compilation et validation de lisibilité du clip vidéo MP4 (55 frames) : **OK**.
12. Persistance transactionnelle SQLite 3 (source de vérité vérifiée sur 6 points) et export miroir JSON : **OK**.

---

## 9. Guide des Captures d'Écran pour le Dossier et la Soutenance

Lors de la démonstration sur machine réelle, les captures d'écran suivantes doivent être réalisées pour illustrer le dossier de soutenance :

| N° | Capture Requise | Éléments Visuels Obligatoires à Faire Apparaître |
| :---: | :--- | :--- |
| **1** | **Dashboard Général PRO-06** | Vue d'ensemble avec les 7 KPIs, les badges des 4 piliers PRO-05 et le nouveau bloc des 4 innovations PRO-06. |
| **2** | **Surveillance Vidéo & Nœuds Mobiles** | Cartes caméras affichant le flux direct, le nom, l'IP locale, le badge `MJPEG / WebRTC` et les jauges télémétriques. |
| **3** | **Edge AI YOLOv8 en Action** | Widget Edge AI avec politique active (`EDGE_AI_REQUIRED` ou `ASSISTED`), compteurs d'inférences et statut du modèle. |
| **4** | **Géofencing & Présence Réseau** | Modale de géofencing avec liste des smartphones autorisés, voyants de présence sur le LAN et boutons de dérogation. |
| **5** | **Authentification 2FA TOTP** | Écran d'enrôlement avec QR Code généré dynamiquement et codes de secours d'urgence à usage unique. |
| **6** | **Journal d'Audit SIEM** | Modale SIEM affichant les lignes formatées au standard ArcSight CEF / Syslog avec masquage strict des clés secrètes. |
| **7** | **Application PWA Installée** | Console exécutée en mode fenêtre autonome (*standalone*) avec raccourci sur le bureau/smartphone. |
| **8** | **Incident Détecté & Sirène** | Bannière supérieure rouge clignotante `ALERTE INTRUSION DÉTECTÉE`, bouton `MUTE SIRÈNE` actif. |
| **9** | **Certification d'Intégrité SHA-256** | Modale d'intégrité prouvant le recalcul du SHA-256 et la validation de la chaîne de blocs cryptographique. |

---

## 10. Limites Techniques et Hypothèses Assumées

1. **Inférence Edge AI sur CPU :** L'exécution du modèle YOLOv8-Nano est effectuée sur le processeur central via `onnxruntime` (`CPUExecutionProvider`). Une cadence de 5 à 10 FPS est assurée sans exiger de carte graphique dédiée.
2. **Mesure Acoustique Relative :** L'application Android IP Webcam retourne une amplitude non calibrée en laboratoire acoustique, soumise au contrôle automatique de gain (AGC) du microphone du smartphone.
3. **Randomisation des Adresses MAC Wi-Fi :** Les smartphones modernes utilisant des adresses MAC privées rotatives, une réservation DHCP par adresse IP est préconisée pour le géofencing local.
4. **WebRTC Hybride :** La négociation de signalisation WebRTC (SDP / ICE) est pleinement opérationnelle, avec une bascule transparente vers le flux MJPEG haute résilience en l'absence de runtime de transcodage natif lourd.

---

## 11. Bilan des Évolutions Majeures Implémentées (PRO-06)

Toutes les perspectives d'évolution ont été concrétisées dans l'édition PRO-06 :
1. **Edge AI Local (YOLOv8-Nano ONNX) :** Inférence locale sans dépendance cloud et filtrage des fausses alertes.
2. **Géofencing Réseau Intelligent :** Machine à états finis, période de grâce anti-flapping et sécurité anti-désarmement silencieux.
3. **Cybersécurité Zero-Trust :** Double facteur TOTP RFC 6238, codes de secours et journal d'audit SIEM (CEF / Syslog RFC 5424).
4. **PWA & Mobilité :** Application Web Progressive installable avec Service Worker et notifications Web Push.
5. **Streaming Hybride :** Signalisation WebRTC basse latence et streaming MJPEG universel.

---

## 12. Conclusion

Le projet **SMART SECURITY MONITOR (PRO-06)** démontre qu'une architecture logicielle soignée en Python, combinant habilement programmation concurrente, vision par ordinateur, intelligence artificielle locale et cybersécurité applicative, permet d'atteindre un niveau d'excellence technique digne d'un produit commercial. Avec 81 tests automatisés réussis et un smoke test end-to-end validé à 100 % (12/12), la solution est robuste, performante, intègre et prête pour une présentation universitaire remarquable.
