# Limites Techniques et Hypothèses de Conception

Ce document détaille les limites matérielles, physiques et logicielles du système **SMART SECURITY MONITOR**, à exposer en soutenance universitaire.

---

## 1. Dépendance Matérielle des Capteurs Mobiles

1. **Capteur de Proximité** :
   - Sur smartphone Android, le capteur de proximité est généralement une photodiode infrarouge située au niveau du haut-parleur d'écoute.
   - La plupart des pilotes Android ne fournissent pas une distance continue, mais une mesure binaire : **0.0 cm** (proche/couvert) ou **5.0 cm** (dégagé).
   - Certains modèles récents ou tablettes ne disposent pas de capteur de proximité physique. Dans ce cas, le système identifie le capteur comme `CAPTEUR NON DISPONIBLE` sans inventer de mesure.

2. **Mesure Acoustique (Niveau Sonore)** :
   - L'application IP Webcam expose les variations captées par le microphone du smartphone.
   - **Important :** Cette mesure n'est pas un décibel acoustique calibré (dB SPL normalisé), mais une amplitude relative convertie par le système Android.
   - La sensibilité dépend du microphone physique du constructeur et du contrôle automatique de gain (AGC) du système d'exploitation.
   - En conséquence, le seuil par défaut de **75 dB** est une estimation relative qui doit être étalonnée selon le niveau sonore ambiant de la pièce.

3. **Accéléromètre 3 Axes** :
   - Le système calcule la norme euclidienne de l'accélération : $\sqrt{a_x^2 + a_y^2 + a_z^2}$.
   - Au repos, le smartphone subit la gravité terrestre ($9.81\text{ m/s}^2$).
   - Tout écart significatif ($|\text{norme} - 9.81| \ge 4.5\text{ m/s}^2$) traduit une secousse, un choc ou un soulèvement.

---

## 2. Limites Réseau et Wi-Fi

1. **Isolation Client (*AP Client Isolation*)** :
   - De nombreuses infrastructures Wi-Fi publiques ou universitaires activent l'isolation des clients, interdisant à deux adresses IP du même réseau de communiquer directement.
   - **Solution** : Utiliser le partage de connexion 4G d'un smartphone ou le simulateur mock local.

2. **Gigue et Bande Passante Vidéo** :
   - Un flux vidéo MJPEG transmet chaque image sous forme d'un JPEG complet.
   - À haute résolution (1080p), plusieurs smartphones satureraient rapidement le canal Wi-Fi.
   - **Préconisation** : Résolution configurée à **640x480** à 10 images par seconde (FPS).

---

## 3. Limites de la Torche Smartphone (`/enabletorch`)

1. L'application IP Webcam expose un endpoint `/enabletorch`.
2. Cependant, sur certains téléphones Android, les pilotes de la caméra verrouillent la diode flash lorsque le capteur d'image principal est actif pour éviter la surchauffe.
3. Le système gère cette limite en n'assimilant jamais l'envoi de la commande HTTP à une certitude matérielle.

---

## 4. Limites de la Détection de Mouvement Vidéo OpenCV

1. **Changements d'Éclairage Globaux** :
   - Une allumage ou extinction soudaine de la lumière dans la pièce génère une variation sur 100% des pixels de l'image.
   - Pour pallier ce problème, le moteur intègre un filtre rejetant les variations brutales couvrant plus de 85% de la surface globale.
2. **Absence de Reconnaissance Faciale** :
   - Conformément aux consignes du TP universitaire, le système n'intègre pas de reconnaissance faciale ou biométrique, superflue pour la détection volumétrique d'intrusion.

---

## 5. Limites de l'Intelligence Visuelle Cloud (xKiro Free Tier)

1. **Statut de Validation & Transparence Catalogue** :
   - L'intégration xKiro est implémentée et les scénarios d'intégration sont validés par tests simulés. La disponibilité effective d'un modèle Qwen Vision gratuit dépend de la vérification du catalogue xKiro au moment de l'utilisation. En l'absence de confirmation, le système conserve la détection locale OpenCV.
   - Les tests automatisés s'exécutent avec des mocks pour ne pas consommer de requêtes ni dépendre de la disponibilité du service en ligne.
   - Trois niveaux de vérification sont gérés : `CONFIGURED`, `CATALOG_VERIFIED_FREE` et `REAL_INFERENCE_TESTED`. Si le modèle n'est pas explicitement étiqueté gratuit ou si les métadonnées de tarification sont absentes/incomplètes, le système refuse le modèle et bascule en `OPENCV_ONLY`.
2. **Quotas et Débit du Tier Gratuit** :
   - Les modèles gratuits (ex: `qwen2.5-vl-7b-instruct:free`) imposent des plafonds stricts (10 à 20 requêtes/minute).
   - En cas de rafale d'événements, le service peut renvoyer un code HTTP 429 (*Too Many Requests*).
   - Le système résout cette limite par une file d'attente FIFO asynchrone et une bascule immédiate vers la détection locale OpenCV sans interruption de service.
3. **Latence Réseau** :
   - Une inférence d'image via API distante requiert entre 800 ms et 2.5 secondes selon la charge des serveurs xKiro.
   - Par conséquent, l'IA ne bloque jamais le déclenchement immédiat de la sirène locale, qui est pilotée à 10 Hz par OpenCV et les capteurs physiques.

---

## 6. Limites de l'Intégrité Cryptographique & Scellage SHA-256

1. **Détection d'Altération vs Protection Absolue** :
   - Le journal cryptographique chaîné ($entry\_hash = \text{SHA256}(proof\_id \parallel file\_hash \parallel prev\_hash \parallel timestamp)$) et la signature HMAC-SHA256 garantissent la **détection d'altération** et la non-répudiation relative.
   - Elles ne constituent pas une "inviolabilité absolue" ni un "certificat judiciaire".
   - La sécurité du système repose intégralement sur :
     - La confidentialité stricte de la clé secrète `INTEGRITY_SECRET_KEY` (stockée en variable d'environnement).
     - Les contrôles d'accès du système de fichiers hôte (OS Windows).
     - Si un attaquant obtient les droits administrateur sur la machine hôte et extrait la clé secrète, il pourrait recalculer une chaîne frauduleuse ou supprimer physiquement les preuves.
2. **Volume de Calcul sur Enregistrements Longs** :
   - Le calcul de l'empreinte SHA-256 par blocs de 64 Ko est très rapide sur des captures JPEG (quelques millisecondes) mais sollicite les E/S disque sur de longs clips vidéo (> 50 Mo).
   - L'intégrité est donc calculée de façon asynchrone à la finalisation du conteneur MP4.

---

## 7. Limites des Notifications Telegram

1. **Environnement de Test vs Environnement de Production** :
   - Dans la suite de tests automatisée, les notifications Telegram sont validées via des mocks HTTP afin d'éviter toute dépendance réseau externe ou émission intempestive d'alertes.
   - En exploitation réelle, l'envoi nécessite un bot Telegram actif, un token valide, un Chat ID cible configuré et une connectivité sortante HTTPS (port 443).
2. **Plafonds de l'API Telegram** :
   - Telegram limite l'envoi de messages vers un même chat à environ 1 message par seconde et 30 messages par minute. L'anti-rebond du système (cooldown de 8s) empêche tout bannissement par l'API.

---

## 8. Limites du Moteur de Base de Données SQLite

1. **Concurrence Mono-Fichier** :
   - Bien que le mode WAL (*Write-Ahead Logging*) autorise des lectures concurrentes illimitées pendant les écritures, SQLite reste un moteur embarqué mono-nœud.
   - Il convient parfaitement à un système de surveillance local de 1 à 10 smartphones, mais nécessiterait une migration vers PostgreSQL pour une architecture cloud multi-sites.

---

## 9. Limites Matérielles et Périphériques de Test

1. **Absence de Smartphone Physique dans les Tests Automatisés** :
   - Les 81 tests automatisés et le smoke test E2E s'exécutent intégralement avec le simulateur local `mock_ipwebcam.py` sur le port 8081.
   - L'utilisation avec de véritables smartphones physiques requiert un réseau Wi-Fi local sans isolation client (AP isolation désactivée ou point d'accès 4G dédié) et le lancement préalable de l'application Android IP Webcam sur chaque appareil mobile.

---

## 10. Limites Spécifiques à l'Évolution PRO-06

### 10.1 Limites de l'Edge AI Local (YOLOv8-Nano sur CPU)
1. **Charge Processeur & Temps d'Inférence** :
   - L'inférence est exécutée sur le processeur central via `onnxruntime` (`CPUExecutionProvider`) sans exiger de carte graphique dédiée (GPU CUDA).
   - Le temps d'inférence pour une image 640x640 varie typiquement entre **35 ms et 110 ms** selon la puissance du processeur de la machine hôte.
   - Cette cadence est parfaitement adaptée pour une analyse de surveillance à 5-10 FPS, mais ne permet pas un traitement temps réel à 60 FPS multi-flux 4K.
2. **Précision du Modèle Nano vs Tailles Supérieures** :
   - YOLOv8-Nano (`yolov8n.onnx`, ~12 Mo) privilégie la vitesse et la légèreté. Sa précision moyenne (mAP50-95 ~37.3%) est inférieure à celle d'un modèle YOLOv8-Medium ou Large, ce qui peut occasionner des non-détections d'objets fortement masqués ou très éloignés (> 20 mètres).
3. **Absence du Fichier de Poids** :
   - Si le fichier modèle n'est pas présent dans le dossier `models/`, le système ne bloque pas : il bascule en repli OpenCV local avec statut clair dans l'IHM.

### 10.2 Limites du Géofencing Réseau (Wi-Fi, DHCP & Veille Mobile)
1. **Randomisation des Adresses MAC** :
   - Les versions récentes d'Android (10+) et d'iOS (14+) activent par défaut la randomisation des adresses MAC par réseau Wi-Fi.
   - En conséquence, l'adresse MAC vue par le cache ARP peut varier selon les reconnexions si l'option "Adresse MAC aléatoire" est activée sur le téléphone.
   - **Recommandation opérationnelle** : Définir une réservation DHCP par adresse IP statique sur le routeur Wi-Fi ou désactiver la randomisation MAC pour le réseau Wi-Fi domestique/universitaire de test.
2. **Mise en Veille Profonde (*Doze Mode*)** :
   - Les smartphones modernes coupent périodiquement les interfaces radio Wi-Fi lors d'une inactivité prolongée écran éteint.
   - Le système absorbe ce phénomène grâce à :
     - Une tolérance de 3 pings consécutifs manqués avant déclaration d'absence.
     - Une période de grâce paramétrable de 120 secondes (*anti-flapping*) avant d'amorcer l'armement.

### 10.3 Limites du Streaming WebRTC & Fallback MJPEG
1. **Dépendance Runtime WebRTC** :
   - WebRTC offre une latence théorique inférieure à 200 ms, mais nécessite une pile native de négociation média (comme `aiortc` et ses bibliothèques C `libav/ffmpeg`).
   - Sur les postes Windows où la compilation de dépendances C++ n'est pas disponible, le composant `WebRTCManager` fournit la signalisation SDP/ICE complète mais délègue le flux au pipeline **MJPEG natif**.
   - Ce mécanisme garantit une robustesse et une compatibilité absolue à 100% sur tout navigateur (Desktop ou Mobile) sans dépendre de drivers propriétaires.

### 10.4 Limites des Notifications Web Push & PWA
1. **Contexte Sécurisé HTTPS vs Localhost** :
   - Les spécifications W3C imposent que les Service Workers et l'API Push s'exécutent dans un contexte sécurisé (`https://` ou `http://localhost`, `http://127.0.0.1`).
   - Pour un accès depuis un smartphone distant via l'adresse IP locale du PC (ex: `http://192.168.1.X:5000`), le navigateur mobile peut restreindre certaines fonctionnalités Web Push si le certificat TLS n'est pas configuré.
2. **Accès Réseau pour Serveurs Push Tiers** :
   - Les notifications Web Push s'appuient sur les passerelles push des éditeurs de navigateurs (Google FCM, Mozilla Autopush). Dans un réseau d'entreprise totalement isolé sans accès Internet, les notifications Web Push ne sont pas acheminées vers l'extérieur.

### 10.5 Limites du Journal d'Audit SIEM
1. **Absence de Serveur SIEM Externe Déployé par Défaut** :
   - Le système génère des journaux conformes aux standards **Syslog RFC 5424** et **ArcSight CEF** avec masquage strict des données sensibles.
   - Par défaut, les logs sont écrits dans un fichier local thread-safe (`storage/logs/security_audit.log`).
   - L'exportation réseau vers un concentrateur externe (Wazuh, Splunk, Elastic) est désactivée par défaut (`SIEM_EXPORT_ENABLED=false`) pour éviter des blocages réseau ou des timeouts en l'absence de serveur distant.

---

## 11. Limites Spécifiques aux Évolutions PRO-07 à PRO-11

### 11.1 Anti-Sabotage (Tamper Detection)
1. **Pénombre Naturelle vs Obstruction Optique** :
   - Dans une pièce plongée dans le noir absolu sans éclairage infrarouge, la luminance moyenne chute en-dessous de 25.0, ce qui peut simuler une obstruction.
   - Le système prévient ce faux positif en vérifiant la variance de l'image : si le bruit de capteur naturel est présent ($\sigma > 2.0$), le système attend la confirmation consécutive sur 3 trames avant de classifier en incident.

### 11.2 Classificateur Acoustique d'Urgence
1. **Échantillonnage Audio Téléphonique** :
   - Les flux audio des smartphones Android sont compressés et échantillonnés à 16 kHz ou 44.1 kHz avec filtres passe-haut constructeur.
   - Les harmoniques très aiguës de certains bris de verre peuvent être atténuées par le traitement antibruit matériel du smartphone. La sonde acoustique spectrale utilise donc une corrélation double (énergie RMS + taux de passage par zéro) pour compenser ce filtrage.

### 11.3 Recherche Vidéo Sémantique & Modèles Vectoriels
1. **Moteur Perceptuel Local vs Réseau CLIP** :
   - Par défaut, l'indexation vectorielle utilise un descripteur hybride HSV-HOG (128 dimensions) pour garantir un fonctionnement immédiat sans téléchargement de modèle de 350 Mo.
   - Ce descripteur capte fidèlement les couleurs, les orientations et les contours, mais possède une compréhension sémantique abstraite plus modeste qu'un modèle CLIP ViT-B/32 complet.

### 11.4 Détection Posturale & Déontologie
1. **Différenciation Chute vs Repos Volontaire** :
   - Une personne allongée sur un canapé présente un ratio géométrique similaire à une personne tombée au sol.
   - C'est précisément pour cette raison que notre moteur qualifie systématiquement ces alertes sous le statut déontologique neutre `NEEDS_REVIEW` (à vérifier par un opérateur humain), sans jamais affirmer automatiquement une situation d'urgence vitale.

### 11.5 Synchronisation P2P Store-and-Forward
1. **Saturation de la File Locale** :
   - La file locale Store-and-Forward sur chaque nœud est dimensionnée à 500 événements avec purge circulaire (TTL de 24h) pour éviter tout risque de saturation de la mémoire flash du smartphone lors d'une panne réseau prolongée.

### 11.6 Interphonie & Flash Stroboscopique
1. **Protection Thermique & Photosensible** :
   - La commande de flash stroboscopique est strictement bridée à 8 secondes consécutives avec une période de repos obligatoire de 15 secondes. Cette contrainte physique non-contournable protège les circuits LED du smartphone et prévient tout risque de crise photosensible.


