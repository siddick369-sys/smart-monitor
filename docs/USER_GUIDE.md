# Manuel d'Utilisation — SMART SECURITY MONITOR

Guide complet pour l'installation, la configuration des smartphones Android et l'utilisation de la console de surveillance.

---

## 1. Démarrage Rapide

### Sur l'ordinateur Windows :
1. Ouvrez un terminal dans le dossier du projet :
   ```powershell
   cd C:\Users\USER\Documents\alarme-sys
   ```
2. Lancez le système via le script automatisé :
   ```cmd
   run.bat
   ```
   *(Ce script démarre le simulateur local sur le port 8081 et le serveur de surveillance sur le port 5000).*
3. Ouvrez votre navigateur Web sur :
   👉 **`http://127.0.0.1:5000`**

---

## 2. Configuration des Smartphones Android

1. **Installation** : Téléchargez l'application **IP Webcam** (par *Pavel Khlebovich*) sur le *Google Play Store*.
2. **Réglages Recommandés dans IP Webcam** :
   - *Paramètres vidéo* :
     - Résolution vidéo : **640x480** (idéal pour la bande passante Wi-Fi).
     - Qualité : 50%.
   - *Enregistrement des données* : cochez **Sensors** pour activer la télémétrie.
3. **Démarrer la diffusion** :
   - Descendez tout en bas de l'application et touchez **« Démarrer le serveur »** (*Start server*).
   - L'écran affiche l'aperçu de la caméra avec une adresse URL en bas (ex : `http://192.168.1.42:8080`).

---

## 3. Connexion au Réseau Wi-Fi & Appairage

> [!IMPORTANT]
> L'ordinateur et les smartphones doivent être connectés au **même point d'accès Wi-Fi local**.
> Si vous êtes sur un Wi-Fi universitaire bloquant la communication inter-appareils (*AP Client Isolation*), activez le **Partage de connexion 4G** sur votre téléphone et connectez votre PC dessus.

### Ajouter le smartphone sur le tableau de bord :
1. Sur le dashboard (`http://127.0.0.1:5000`), cliquez sur **« Ajouter un Smartphone »**.
2. Saisissez :
   - **Nom** : ex. *Smartphone Entrée*
   - **IP** : l'adresse affichée sur le téléphone (ex : `192.168.1.42`)
   - **Port** : `8080`
   - Cochez *Allumage automatique de la torche* si souhaité.
3. Cliquez sur **Ajouter l'appareil**. Le flux vidéo en direct et les jauges de télémétrie s'affichent instantanément.

---

## 4. Prise en Main du Tableau de Bord

### 4.1 Console Principale (KPIs)
- **État Général** :
  - <span style="color:#34d399">■ VERT (Opérationnel)</span> : Tous les flux et capteurs sont actifs.
  - <span style="color:#fbbf24">■ ORANGE (Dégradé)</span> : Un flux est ralenti ou une caméra est déconnectée.
  - <span style="color:#f87171">■ ROUGE (Incident)</span> : Une intrusion ou un événement anormal a été détecté.
- **Smartphones** : Nombre d'appareils connectés et déconnectés.
- **Alertes Aujourd'hui** : Compteur d'incidents détectés pour la journée en cours.
- **Stockage Preuves** : Volume des captures et vidéos enregistrées sur disque.

### 4.2 Surveillance Vidéo
- Chaque smartphone dispose de sa propre carte vidéo avec bouton **Plein écran** (<i class="fa-solid fa-expand"></i>) et **Rafraîchir** (<i class="fa-solid fa-rotate-right"></i>).
- En cas de coupure réseau, une mire stylisée indique automatiquement la tentative de reconnexion sans faire planter l'application.

### 4.3 Télémétrie des Capteurs
Les badges indiquent la nature exacte de chaque donnée :
- `RÉEL` (Vert) : Mesure physique directe du capteur Android.
- `SIMULÉ` (Violet) : Donnée générée via le mode simulation.
- `EXPIRÉ` (Orange) : Dernière communication trop ancienne (> 8s).
- `N/D` (Gris) : Capteur non présent sur ce modèle de smartphone.

---

## 5. Gestion des Alarmes & Preuves

1. **Armement** : Cliquez sur le bouton principal en haut à droite pour basculer entre **SYSTÈME ARMÉ** et **SYSTÈME DÉSARMÉ**.
2. **Lors d'une Détection** :
   - La sirène sonore du PC retentit via `winsound`.
   - Le bandeau rouge clignotant s'affiche en haut de l'écran avec le smartphone source.
   - Une capture photo JPEG est instantanément enregistrée.
   - Un clip vidéo MP4 est généré (3 secondes avant + 5 secondes après l'événement).
3. **Arrêt d'Urgence** : Cliquez sur **« ARRÊTER LA SIRÈNE »** pour couper le son instantanément sans couper la vidéosurveillance.
4. **Consultation des Preuves** :
   - Dans le tableau des incidents, cliquez sur l'icône <i class="fa-solid fa-image text-blue-400"></i> pour zoomer la photo.
   - Cliquez sur l'icône <i class="fa-solid fa-circle-play text-emerald-400"></i> pour lire la vidéo d'incident dans le lecteur HTML5 intégré.
   - Cliquez sur **« Exporter CSV »** pour télécharger le journal complet des événements.

---

## 6. Authentification, Bootstrap Sécurisé & RBAC

Le système intègre un portail d'authentification robuste avec sessions chiffrées (`HttpOnly`, `SameSite=Lax`, rotation anti-fixation) et protection contre les attaques par force brute (verrouillage temporaire après 5 échecs consécutifs en 60 secondes).

### 6.1 Procédure de Première Initialisation (Bootstrap Sécurisé)
Aucun mot de passe par défaut n'est codé en dur dans le système :
1. **Premier démarrage** : Lors de la toute première ouverture de l'application sur une base vierge, l'interface affiche automatiquement l'écran d'initialisation sécurisée (*Bootstrap Form*).
2. **Définition du compte administrateur** :
   - Renseignez l'identifiant souhaité (par défaut : `admin`).
   - Saisissez un mot de passe robuste conforme à la politique de sécurité : **minimum 8 caractères**, comprenant **au moins une lettre** et **au moins un chiffre**.
   - Confirmez le mot de passe puis validez.
3. **Alternative par variable d'environnement** :
   Pour un déploiement automatisé (scripts CI/CD, conteneurs), vous pouvez définir la variable `ADMIN_PASSWORD` dans votre fichier d'environnement `.env`. Le compte sera créé automatiquement à l'initialisation sans mot de passe par défaut.
4. **Verrouillage post-bootstrap** : Dès que le compte administrateur est créé, toute nouvelle tentative d'appel au point d'accès `/api/auth/bootstrap` est strictement rejetée avec un code HTTP 403 (*Action refusée*).

### 6.2 Modification du Mot de Passe
Un utilisateur connecté peut modifier son mot de passe à tout moment via l'endpoint sécurisé `POST /api/auth/change_password` en fournissant son mot de passe actuel et son nouveau mot de passe conforme à la politique de sécurité.

### 6.3 Niveaux de Rôles (RBAC) :
- **`ADMIN`** : Accès total (armement, ajout/suppression de smartphones, modification des seuils, gestion des utilisateurs, synchronisation base de données, purge des preuves).
- **`OPERATOR`** : Contrôle opérationnel (armement, arrêt de la sirène, simulation d'alertes, acquittement).
- **`AUDITOR`** : Consultation seule (flux vidéo, journal d'incidents, vérification cryptographique des preuves, téléchargement des rapports PDF).

Pour vous déconnecter, cliquez sur l'icône <i class="fa-solid fa-arrow-right-from-bracket"></i> située dans l'en-tête du tableau de bord.

---

## 7. Fonctionnalités Avancées PRO-05

### 7.1 Intelligence Visuelle Qwen Vision (xKiro FREE TIER)
- Dans le panneau des services avancés, le widget **Qwen Vision IA** indique le statut du modèle.
- **Transparence & Fallback OpenCV** : L'intégration logicielle xKiro est implémentée et validée par bancs de tests simulés. La disponibilité effective d'un modèle gratuit dépend de la confirmation du catalogue xKiro au moment de l'utilisation. En l'absence de clé API, de connectivité ou de modèle certifié gratuit, le système conserve le moteur autonome OpenCV local sans interruption de service.
- **Statuts possibles** :
  - `FREE_TIER_VERIFIED` (Vert) : Modèle Qwen Vision gratuit validé dans le catalogue et actif.
  - `OPENCV_ONLY` (Orange) : Détection locale autonome OpenCV active (sans dépendance externe).
  - `FREE_TIER_QUOTA_REACHED` (Ambre) : Quota temporaire atteint, bascule automatique OpenCV pendant 60 secondes.
  - `ERROR` (Rouge) : Disjoncteur déclenché après 3 erreurs consécutives, repli temporaire OpenCV.

### 7.2 Intégrité Cryptographique & Détection d'Altération
- Chaque photo JPEG, vidéo MP4 et rapport PDF est scellé par calcul d'empreinte SHA-256 (par blocs de 64 Ko) et consigné dans un registre cryptographique chaîné avec signature HMAC-SHA256.
- Pour vérifier la non-altération d'un fichier de preuve :
  1. Dans le tableau des alertes, cliquez sur l'icône d'empreinte digitale <i class="fa-solid fa-fingerprint text-emerald-400"></i>.
  2. La modale affiche l'empreinte SHA-256 recalculée en temps réel, l'empreinte originale scellée, le chaînage d'antériorité et le statut de conformité :
     - `INTEGRITY_VALID` (Intègre) : Le fichier et son chaînage sont certifiés conformes.
     - `TAMPERED` (Altéré) : Une modification de contenu ou de signature a été détectée.
     - `MISSING` (Manquant) : Le fichier physique est introuvable sur le disque.
     - `UNVERIFIABLE` (Non vérifiable) : Éléments manquants ou absence de clé secrète HMAC.

### 7.3 Notifications d'Urgence Telegram
- En cas d'intrusion critique, le système transmet de façon asynchrone un message d'alerte avec la capture photo de l'incident directement sur votre groupe ou canal Telegram.
- **Configuration (.env)** :
  ```ini
  TELEGRAM_ENABLED=true
  TELEGRAM_BOT_TOKEN=YOUR_TELEGRAM_BOT_TOKEN
  TELEGRAM_CHAT_ID=YOUR_TELEGRAM_CHAT_ID
  ```
- Cliquez sur le bouton **Test** dans le widget Telegram pour vérifier immédiatement l'acheminement des messages (réservé au rôle `ADMIN`).

### 7.4 Base de Données Relationnelle SQLite 3 & Sauvegardes
- Le système utilise SQLite 3 en mode WAL (`Write-Ahead Logging`) comme **unique source opérationnelle de vérité**, garantissant l'intégrité transactionnelle ACID.
- **Export & Miroir JSON** : Les fichiers JSON (`alerts.json`, `devices.json`) constituent des sauvegardes secondaires et des formats d'export régénérables depuis la base SQLite.
- **Synchronisation** : Cliquez sur **Synchroniser** pour exécuter une migration idempotente depuis les fichiers JSON vers SQLite avec création d'instantané de sauvegarde dans `storage/backups`.

---

## 8. Guide des Évolutions Majeures PRO-06

### 8.1 Configuration et Enrôlement 2FA TOTP (RFC 6238)
L'authentification à deux facteurs protège les comptes contre l'usurpation d'identifiants même en cas de fuite de mot de passe.
1. **Activation de la 2FA** :
   - Cliquez sur le bouton **2FA** dans la barre supérieure ou dans le panneau PRO-06.
   - Scannez le code QR affiché avec votre application d'authentification mobile (*Google Authenticator*, *Microsoft Authenticator*, *FreeOTP*, *1Password*).
   - *(Optionnel)* Si la caméra de votre smartphone est indisponible, saisissez manuellement la clé secrète affichée en texte clair.
   - Saisissez le code à 6 chiffres affiché par votre application puis cliquez sur **« Activer la protection 2FA »**.
2. **Sauvegarde des Codes de Secours** :
   - Une liste de **5 codes de secours** à 8 caractères s'affiche à l'écran.
   - Notez-les impérativement en lieu sûr. Chaque code ne peut être utilisé qu'une seule fois si vous perdez l'accès à votre application mobile.
3. **Connexion avec 2FA** :
   - Lors de la connexion sur `http://127.0.0.1:5000/login`, après avoir validé votre identifiant et mot de passe, un champ supplémentaire **« Code 2FA (TOTP / Secours) »** apparaît.
   - Saisissez votre code dynamique à 6 chiffres ou un de vos codes de secours pour accéder au tableau de bord.
4. **Désactivation de la 2FA** :
   - Ouvrez la modale 2FA, saisissez votre mot de passe actuel de compte pour confirmer votre identité et validez.

### 8.2 Détection d'Objets par IA Locale (Edge AI YOLOv8 ONNX)
L'Edge AI permet de qualifier la présence d'humains, de véhicules ou d'animaux directement sur le processeur (CPU) du PC sans aucun flux sortant vers Internet.
1. **Sélection de la Politique de Détection** :
   - Dans le widget **Edge AI YOLOv8**, utilisez le menu déroulant :
     - `OPENCV_ONLY` : Détection purement différentielle (mouvement OpenCV), zéro charge calculatoire ONNX.
     - `EDGE_AI_ASSISTED` : Déclenchement de l'alarme si OpenCV détecte du mouvement **OU** si l'Edge AI identifie un objet cible.
     - `EDGE_AI_REQUIRED` : L'alarme ne se déclenche **QUE** si un objet de surveillance (`person`, `car`, `bike`, `dog`, `cat`) est formellement reconnu dans l'image. Idéal pour éliminer les fausses alertes provoquées par des branches d'arbres ou des insectes.
2. **Résilience et Mode Dégradé** :
   - Si le fichier `yolov8n.onnx` est absent du dossier `models/`, le système le signale visuellement et maintient la détection OpenCV sans planter ni bloquer la vidéosurveillance.

### 8.3 Géofencing & Présence Réseau Intelligente
Le système peut s'armer et se désarmer automatiquement selon la présence des smartphones des occupants sur le réseau Wi-Fi local.
1. **Ajouter un Appareil de Confiance** :
   - Cliquez sur **Appareils LAN** dans la carte Géofencing.
   - Renseignez le nom du propriétaire (ex: *iPhone Alice*), l'adresse IP locale (ex: `192.168.1.50`) et le type d'appareil.
   - Validez. L'appareil est immédiatement inspecté par un ping ICMP doux.
2. **Cycle Automatique et États** :
   - `HOME` (À Domicile) : Au moins un appareil autorisé est détecté $\to$ surveillance désarmée.
   - `AWAY_PENDING` (Départ en cours) : Tous les appareils ont quitté le réseau $\to$ une période de grâce de 120 secondes démarre pour éviter l'armement intempestif en cas de micro-coupure Wi-Fi (*anti-flapping*).
   - `ARMED_AWAY` (Absence) : À l'expiration de la grâce, le système s'arme automatiquement.
   - `RETURN_PENDING` : Un occupant revient sur le réseau local.
3. **Sécurité Anti-Désarmement Silencieux** :
   - Si une intrusion ou une alerte a eu lieu pendant l'absence, le système **refuse catégoriquement de se désarmer automatiquement** au retour de l'appareil. Le voyant reste en alerte et un acquittement manuel par l'opérateur est exigé.
4. **Dérogation Manuelle** :
   - En cas d'oubli de téléphone, cliquez sur **Dérogation** pour forcer l'état à `HOME` ou `ARMED_AWAY` manuellement.

### 8.4 Journal de Sécurité SIEM (Syslog RFC 5424 / CEF)
1. **Consultation des Événements** :
   - Cliquez sur le bouton **SIEM** dans l'en-tête pour ouvrir le visualiseur de logs d'audit.
   - Les événements sont présentés au format structuré ArcSight CEF ou Syslog RFC 5424 avec niveau de sévérité (1 à 10), horodatage ISO 8601, acteur et action.
2. **Masquage Automatique des Secrets (Data Masking)** :
   - Toutes les clés secrètes, tokens et mots de passe sont automatiquement remplacés par `***MASKED***` dans le journal pour garantir l'absence de fuite d'informations.
3. **Filtrage** :
   - Utilisez le champ de recherche pour filtrer instantanément par type d'événement (`LOGIN`, `CONFIG_CHANGE`, `ALARM`, etc.).

### 8.5 Installation de l'Application PWA & Notifications Web Push
1. **Installation sur PC ou Smartphone** :
   - Sur Chrome, Edge ou Safari, cliquez sur le bouton **« Installer PWA »** dans l'en-tête ou sur l'icône d'installation dans la barre d'adresse du navigateur.
   - L'application s'installe comme un logiciel autonome sans barre de navigation, avec lancement plein écran et icône dédiée.
2. **Fonctionnement Hors-Ligne** :
   - Si la liaison réseau avec le Monitoring Host est coupée, le Service Worker affiche automatiquement un écran de secours soigné (`offline.html`) vous invitant à vérifier la connexion Wi-Fi.
3. **Notifications Web Push** :
   - Cliquez sur **Web Push** dans la carte dédiée pour autoriser les alertes système dans votre navigateur.
   - Cliquez sur **Test Push** pour envoyer une notification de contrôle instantanée.

### 8.6 Streaming Vidéo WebRTC & Bascule MJPEG
- Par défaut, le système distribue les flux vidéo en **MJPEG haute compatibilité**.
- La signalisation WebRTC (SDP / ICE) est négociée en arrière-plan avec le serveur via `/api/webrtc/offer`.
- En l'absence de runtime de transcodage WebRTC lourd sur le poste hôte, le système applique une bascule automatique transparente vers le flux MJPEG avec notification dans l'IHM, garantissant une disponibilité de 100% sans saccade.

---

## 9. Suite de Sécurité Avancée (PRO-07 à PRO-11)

### 9.1 Recherche Vidéo Sémantique (PRO-08)
1. Dans le bloc **Recherche Sémantique**, saisissez une description naturelle (ex: *"personne en rouge"*, *"véhicule de nuit"*).
2. Cliquez sur l'icône de loupe : le système compare l'embedding vectoriel de votre requête aux keyframes d'alertes via similarité cosinus.
3. Les résultats s'affichent avec l'identifiant d'incident, la caméra associée, l'index d'image et le pourcentage de correspondance.
4. Cliquez sur **Réindexer tout** pour reconstruire l'index après un ajout massif de fichiers d'archive.

### 9.2 Anti-Sabotage Caméras & Audio AI (PRO-07)
1. **Surveillance Anti-Sabotage** :
   - Le système analyse en continu le flux pour détecter toute tentative d'obstruction (main sur l'objectif), de basculement de smartphone, de floutage ou d'éblouissement laser.
   - En cas d'anomalie confirmée, l'indicateur bascule en alerte rouge. Cliquez sur **Acquitter Sabotage** une fois la caméra remise en position normale.
2. **Sonde Acoustique de Test** :
   - Testez la classification acoustique en cliquant sur `Cri`, `Vitre` ou `Sirène` pour vérifier la reconnaissance instantanée des spectres de menaces sonores.

### 9.3 Confidentialité RGPD (Two-Man Rule) & Rapports Forensiques (PRO-09)
1. **Double Contrôle Two-Man Rule** :
   - Pour accéder à un flux vidéo original non-flouté, cliquez sur **Two-Man**.
   - Remplissez l'identifiant du fichier et le motif légal. La demande est créée en attente (1/2).
   - Un second administrateur distinct doit se connecter et valider la demande pour libérer l'accès.
2. **Rapport Forensique Certifié** :
   - Générez un rapport judiciaire officiel depuis l'historique d'alertes : le document PDF sépare formellement les faits physiques matériels irréfutables des hypothèses probabilistes d'intelligence artificielle.

### 9.4 Jumeau Numérique 2D & Handover Multi-Caméras (PRO-10)
1. Le plan SVG interactif affiche en temps réel les zones de surveillance, les zones interdites et l'orientation des caméras.
2. Lorsqu'une cible se déplace d'une caméra à l'autre, le handover spatial assure la continuité de la trajectoire sans rupture d'identité.

### 9.5 Interphonie & Défense Active (PRO-11)
1. **Sommations Vocales Déclaratives** :
   - Sélectionnez un message pré-enregistré neutre dans le menu déroulant (*Zone surveillée*, *Présence détectée*, *Évacuation*) et cliquez sur le haut-parleur pour le diffuser sur le smartphone.
2. **Stroboscope Optique de Sécurité** :
   - Cliquez sur **Strobe 5s** pour émettre des flashs dissuasifs.
   - Une temporisation de sécurité (cooldown de 15s) s'enclenche automatiquement pour prévenir tout risque médical ou échauffement de la torche LED.

