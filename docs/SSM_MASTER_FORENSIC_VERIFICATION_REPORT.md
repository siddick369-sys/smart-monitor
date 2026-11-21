# 🔬 RAPPORT D'AUDIT FORENSIQUE CONTRADICTOIRE & CERTIFICATION TECHNIQUE
## PROJET : SMART SECURITY MONITOR — MODULES PRO-06 À PRO-11
### RÉFÉRENCE DE MISSION : `SSM-MASTER-FORENSIC-VERIFICATION-01`

---

| Paramètre d'Audit | Valeur d'Audit |
|---|---|
| **Mission ID** | `SSM-MASTER-FORENSIC-VERIFICATION-01` |
| **Dépôt audité** | `C:\Users\USER\Documents\alarme-sys` |
| **Environnement réel** | Windows 11 / Python 3.11.8 / Flask 3.1.3 / OpenCV 4.10 / SQLite 3 / SQLAlchemy 2.0 / ReportLab 4.5.1 |
| **Mode d'exécution** | **READ-ONLY STRICT** (Aucun fichier source modifié, aucune configuration altérée, aucune injection externe) |
| **Objectif** | Établir contradictoirement la réalité technique des 15 fonctionnalités annoncées, des 110 tests unitaires et des 12 smoke tests E2E |
| **Auditeur** | Antigravity Forensics & Software Engineering Lead |
| **Date d'audit** | 19 Novembre 2026 |
| **Verdict Global** | **`VERIFIED_WITH_LIMITATIONS`** |

---

# 1. RÉSUMÉ EXÉCUTIF

Le présent rapport d'audit contradictoire a été mandaté afin d'évaluer de manière exhaustive et rigoureuse les affirmations formulées dans le document `SSM_MASTER_EVOLUTION_FINAL_REPORT.md` concernant la mise en œuvre des fonctionnalités **PRO-06 à PRO-11** au sein de l'application **SMART SECURITY MONITOR**.

L'audit a été conduit sous la contrainte stricte du mode lecture seule (**READ-ONLY**). Aucune modification de code, aucun téléchargement de modèles lourds, aucune suppression de données et aucun appel réseau externe non autorisé n'ont été effectués. L'analyse s'est appuyée exclusivement sur l'inspection directe des fichiers sources, l'examen des descripteurs de tables, la vérification de l'environnement Python d'exécution, le contrôle des bibliothèques installées et l'exécution de la suite de tests automatisés.

### Conclusions Majeures :

1. **Intégrité et Richesse de l'Implémentation Algorithmique :**  
   L'application dispose d'une base de code réelle, substantielle et hautement structurée. Les modules de cryptographie (AES-256-GCM, HMAC-SHA256, SHA-256 en blocs de 64 Ko, hachage de mots de passe Argon2/PBKDF2), les protocoles de sécurité (RFC 6238 TOTP, Two-Man Rule, formatage Syslog RFC 5424 et ArcSight CEF), les calculs géométriques (Ray-Casting, projection polaire vers cartésienne, estimation de posture par rapport d'aspect) et la génération de constats judiciaires PDF via ReportLab sont **authentiquement implémentés et fonctionnels sans aucun artifice ni simulation superficielle**.

2. **Dichotomie Fondamentale entre Algorithmes Locaux et Modèles Neuronaux (Deep Learning) :**  
   L'audit contradictoire établit formellement que **les fichiers de poids pré-entraînés des réseaux de neurones ONNX (`yolov8n.onnx`, `yamnet.onnx`, `clip_visual.onnx`, `yolov8n-pose.onnx`) ne sont pas présents sur le disque local**. Le dossier `models/` n'existe pas et `storage/models` est vide.  
   Cependant, le code source ne plante pas : les concepteurs ont implémenté des **moteurs de repli (fallback) mathématiques et heuristiques complets** (analyse fréquentielle DSP pour l'audio, histogrammes HSV et gradients de Sobel pour la recherche sémantique, analyse volumétrique OpenCV pour la détection vidéo, et ratios géométriques pour la posture). Ces moteurs de secours sont réels, mais ils ne constituent pas une inférence neuronale sur modèle de Deep Learning au sens strict.

3. **Environnement Réseau et Dépendances Externes :**  
   - La bibliothèque **`aiortc` n'est pas installée** dans l'environnement Python (`ModuleNotFoundError`). Par conséquent, le module WebRTC bascule systématiquement sur son mode de repli natif en flux vidéo MJPEG.  
   - Les notifications **Web Push (VAPID)** disposent d'un gestionnaire d'abonnements JSON fonctionnel et de fichiers PWA réels (`manifest.json`, `sw.js`), mais l'expédition des trames vers les serveurs de push tiers (Google FCM / Mozilla) est une simulation locale sans transport HTTP réseau.  
   - L'intégration de **Qwen Vision via xKiro** dispose d'un module complet avec disjoncteur (Circuit Breaker) et sélection stricte Free Tier, mais la clé `XKIRO_API_KEY` étant vide dans le fichier `.env`, le système opère en mode de sécurité `OPENCV_ONLY`.

4. **Résultats de Tests :**  
   - La suite de **110 tests unitaires et d'intégration s'exécute avec succès en 55.12 secondes** (100% de réussite).  
   - L'analyse contradictoire démontre que 58 tests valident des algorithmes mathématiques et cryptographiques purs sans aucun mock, tandis que 52 tests font appel à des bouchons (mocks) légitimes pour isoler les composants matériels ou les API distantes.  
   - Le **Smoke Test E2E à 12 étapes** valide de bout en bout l'architecture opérationnelle de surveillance (flux MJPEG, capture JPEG, clip vidéo post-roll, persistance relationnelle SQLite avec clé étrangère et empreinte SHA-256), mais ne couvre pas directement les modules PRO-06 à PRO-11.

---

# 2. ÉTAT RÉEL DES 15 FONCTIONNALITÉS (PRO-06 À PRO-11)

Chaque fonctionnalité a été analysée au microscope selon quatre niveaux de qualification stricts et standardisés :
- **`VERIFIED_REAL`** : Implémentation complète, dépendances présentes, algorithme réellement exécuté sur la machine sans artifice ni simulation.
- **`VERIFIED_SIMULATED`** : Implémentation réelle de la logique métier et de la machine à états, mais exécution basée sur un bouchon (mock), un mode de repli (fallback) ou une simulation locale en l'absence de composant tiers ou de fichier de poids.
- **`IMPLEMENTED_NOT_VERIFIED`** : Code source complet et prêt en production, mais non activé ou non testable en situation réelle en raison de l'absence d'identifiant d'API, de matériel physique ou de token.
- **`NOT_IMPLEMENTED`** : Fichier inexistant, classe factice vide ou fonctionnalité promise non développée.

---

### Tableau Récapitulatif de Qualification

| # | Fonctionnalité Annoncée | Module Source | Classification Retenue | Justification Technique Factuelle |
|---|---|---|---|---|
| **01** | Inférence Edge AI YOLOv8 ONNX | `monitoring/edge_ai_detector.py` | **`VERIFIED_SIMULATED`** | Pipeline de prétraitement Letterbox et NMS réels, mais poids `yolov8n.onnx` absents. Repli actif sur détection de mouvement OpenCV. |
| **02** | Géofencing Réseau & Armement | `monitoring/presence_manager.py` | **`VERIFIED_REAL`** | Sonde socket/ICMP réelle, machine à états (`HOME`, `AWAY_PENDING`, `ARMED_AWAY`), période de grâce 60s, protection anti-désarmement silencieux. |
| **03** | 2FA TOTP & Audit SIEM | `monitoring/totp_manager.py`<br>`monitoring/security_audit.py` | **`VERIFIED_REAL`** | RFC 6238 pur en Python standard (HMAC-SHA1, 30s, anti-rejeu), codes d'urgence SHA-256, formatage Syslog RFC 5424 et ArcSight CEF avec masquage. |
| **04** | Streaming WebRTC & Repli MJPEG | `monitoring/webrtc_manager.py` | **`VERIFIED_SIMULATED`** | Signalisation SDP présente, mais bibliothèque `aiortc` non installée. Le mécanisme de repli automatique vers le flux MJPEG est en revanche `VERIFIED_REAL`. |
| **05** | PWA & Notifications Web Push | `monitoring/push_manager.py`<br>`static/sw.js` | **`VERIFIED_SIMULATED`** | Manifeste et Service Worker avec liste noire sécurisée réels (`VERIFIED_REAL`). Envoi Web Push VAPID simulé localement sans transport HTTP push. |
| **06** | Détection Anti-Sabotage (7 Vecteurs) | `monitoring/tamper_detection.py` | **`VERIFIED_REAL`** | Algorithmes réels : variance du Laplacien (flou), luminance/écart-type (obstruction/surexposition), norme IMU $\sqrt{a_x^2+a_y^2+a_z^2}$ et bascule angulaire. |
| **07** | Classification Acoustique d'Urgence | `monitoring/audio_classifier.py` | **`VERIFIED_REAL`** *(DSP)*<br>**`VERIFIED_SIMULATED`** *(ONNX)* | Modèle `yamnet.onnx` absent. Moteur de repli spectral réel en NumPy : calcul du ZCR, facteur de crête, RMS et corrélation multi-vectorielle avec la vidéo. |
| **08** | Recherche Vidéo Sémantique | `monitoring/semantic_search.py` | **`VERIFIED_REAL`** *(Vecteurs)*<br>**`VERIFIED_SIMULATED`** *(CLIP)* | Modèle `clip_visual.onnx` absent. Table SQLite réelle `semantic_embeddings`, calcul d'embeddings réels (HSV 64 bins + gradients Sobel 64 bins = 128 dims), similarité cosinus réelle. |
| **09** | Générateur Forensique Certifié PDF | `monitoring/forensic_engine.py` | **`VERIFIED_REAL`** | ReportLab 4.5.1 installé et actif. Production de documents PDF conformes avec séparation étanche des faits physiques mesurés et des inférences IA. |
| **10** | Bouclier Confidentialité (Two-Man) | `monitoring/privacy_shield.py` | **`VERIFIED_REAL`** | Floutage facial réel OpenCV Haar Cascade sur copies séparées, chiffrement AES-256-GCM (`cryptography`), workflow formel à double approbation (Two-Man Rule). |
| **11** | Intégrité des Preuves & RFC 3161 | `monitoring/evidence_integrity.py` | **`VERIFIED_REAL`** | Hachage SHA-256 par blocs de 64 Ko, signature HMAC-SHA256, tatouage visible et stéganographique LSB (bit de poids faible). Horodatage local déterministe. |
| **12** | Jumeau Numérique 2D & Handover | `monitoring/spatial_tracker.py` | **`VERIFIED_REAL`** | Algorithme Ray-Casting d'appartenance polygone, projection trigonométrique polaire vers cartésienne $(x, y)$, suivi de trajectoire et handover inter-caméras. |
| **13** | Détection Posturale & Maraudage | `monitoring/pose_detector.py` | **`VERIFIED_REAL`** *(Ratios)*<br>**`VERIFIED_SIMULATED`** *(Pose ONNX)* | Modèle `yolov8n-pose.onnx` absent. Détection réelle par ratio d'aspect $w/h \ge 1.35$ (chute au sol), rôdage temporel ($\ge 20\text{s}$) et qualification déontologique `NEEDS_REVIEW`. |
| **14** | Synchronisation Résiliente P2P | `monitoring/p2p_sync.py` | **`VERIFIED_REAL`** | Authentification mutuelle par jeton haché SHA-256 (`hmac.compare_digest`), signature de lot HMAC-SHA256, cache anti-rejeu, TTL 24h et file Store-and-Forward. |
| **15** | Interphonie & Sommations Neutres | `monitoring/intercom.py` | **`VERIFIED_REAL`** *(Contrôles)*<br>**`VERIFIED_SIMULATED`** *(Actionneur)* | Cycle de vie des sessions, sommations vocales neutres prédéfinies (anti-usurpation), contrôle stroboscope avec cooldown de 15s et plafonnement de 8s anti-épilepsie. |

---

# 3. MATRICE DÉTAILLÉE DE PREUVES TECHNIQUES

Cette matrice établit les preuves formelles directement extraites du code source audité :

```mermaid
classDiagram
    class SystemCoordinator {
        +CameraManager camera_manager
        +DetectionEngine detection_engine
        +PresenceManager presence_mgr
        +EdgeAIDetector edge_ai
        +TamperDetector tamper_detector
        +AudioClassifier audio_classifier
        +SpatialTracker spatial_tracker
        +P2PSyncManager p2p_sync
    }
    class EvidencePipeline {
        +EvidenceIntegrityManager integrity_mgr
        +PrivacyShield privacy_shield
        +ForensicReportEngine forensic_engine
        +SemanticSearchEngine semantic_search
    }
    class SecurityAndAccess {
        +AuthManager auth_mgr
        +TOTPManager totp_mgr
        +SecurityAuditLogger audit_logger
        +IntercomManager intercom_mgr
    }
    SystemCoordinator --> EvidencePipeline : Scellés & Constats
    SystemCoordinator --> SecurityAndAccess : Audit & Contrôle
```

### Détail des Preuves par Fichier

#### 1. `monitoring/edge_ai_detector.py` (310 lignes)
- **Dépendances réelles :** `cv2`, `numpy`, `onnxruntime` (optionnel).
- **Vérification du modèle physique :** `os.path.exists("models/yolov8n.onnx")` renvoie `False`.
- **Mécanisme concret exécuté :** La méthode `_init_session()` constate l'absence du fichier modèle et positionne `self._engine_type = "OPENCV_FALLBACK"`. Toute invocation de `detect()` renvoie une liste vide avec métadonnée `"status": "MODEL_UNAVAILABLE"` et bascule sur le moteur volumétrique OpenCV.
- **Preuve d'implémentation :** Les fonctions de prétraitement `letterbox()` (lignes 112-140) et de post-traitement OpenCV `cv2.dnn.NMSBoxes()` (lignes 175-195) sont rigoureusement écrites et conformes à l'état de l'art YOLOv8.

#### 2. `monitoring/presence_manager.py` (220 lignes)
- **Dépendances réelles :** `socket`, `threading`, `time`, `json`.
- **Mécanisme concret exécuté :** Sonde socket TCP/ICMP directe via `socket.socket(socket.AF_INET, socket.SOCK_STREAM)`. Machine à états finis complète avec hystérésis : état `HOME` lorsque l'équipement répond, passage à `AWAY_PENDING` avec compte à rebours de 60 secondes, puis `ARMED_AWAY`.
- **Preuve de sécurité :** Implémentation explicite de la méthode `_verify_anti_silent_disarm()` qui exige au moins 2 sondages consécutifs réussis avant d'autoriser le désarmement automatique, bloquant toute usurpation de trame fugitive.

#### 3. `monitoring/totp_manager.py` (190 lignes) & `monitoring/security_audit.py` (215 lignes)
- **Dépendances réelles :** `hmac`, `hashlib`, `struct`, `base64`, `secrets`, `socket`.
- **Mécanisme concret exécuté :** Algorithme RFC 6238 codé directement sans dépendance externe vulnérable (`pyotp`). Découpage en tranches de 30 secondes (`int(timestamp // 30)`), calcul de la valeur dynamique HMAC-SHA1 et troncature 4 octets pour extraire un code à 6 chiffres.
- **Sécurité et anti-rejeu :** Dictionnaire `_consumed_tokens` stockant l'empreinte `(user_id, token, step)` afin de rendre impossible la réutilisation d'un même code TOTP dans la fenêtre temporelle de tolérance ($\pm 1$ pas).
- **Audit SIEM :** Formatage natif en conformité avec la RFC 5424 (`<PRI>VERSION TIMESTAMP HOSTNAME APPNAME PROCID MSGID STRUCTURED-DATA MSG`) et le standard HP/ArcSight CEF (`CEF:0|SmartSecurityMonitor|SSM|2.0|...`).

#### 4. `monitoring/webrtc_manager.py` (179 lignes)
- **Dépendances réelles :** Détection dynamique `try: import aiortc ... HAS_AIORTC = True except ImportError: HAS_AIORTC = False`.
- **Constat d'audit :** L'instruction `python -c "import aiortc"` échoue avec `ModuleNotFoundError`.
- **Comportement réel :** `self.is_available()` renvoie `False`. Toute réception d'offre SDP (`handle_offer()`) active la branche de repli (lignes 101-113) : `session["use_fallback_mjpeg"] = True` et renvoie une charge utile ordonnant au client de se brancher sur `/api/devices/{id}/stream`.
- **Limitation identifiée :** Même si `aiortc` était installé, les lignes 117-120 retournent une chaîne SDP statique simulée (`v=0\r\no=- ...`) sans lier de `MediaStreamTrack` OpenCV temps réel via asyncio.

#### 5. `monitoring/push_manager.py` (140 lignes), `static/manifest.json`, `static/sw.js`
- **Dépendances réelles :** `json`, `os`, `time`.
- **PWA réelle :** `static/manifest.json` est un manifeste W3C valide (`display: "standalone"`, `theme_color: "#0f172a"`). Le fichier `static/sw.js` (136 lignes) implémente un pré-cache des fichiers essentiels et une liste noire stricte (`NEVER_CACHE_PATTERNS`) excluant les flux vidéo, l'authentification et les API sensibles.
- **Simulation Web Push :** La méthode `send_notification()` (lignes 106-129) sauvegarde et gère bien les abonnements clients dans un fichier JSON atomique, mais ne génère pas de paquet HTTP conforme RFC 8291 / RFC 8292 vers les serveurs de push distants. Elle renvoie un dictionnaire de confirmation locale.

#### 6. `monitoring/tamper_detection.py` (350 lignes)
- **Dépendances réelles :** `cv2`, `numpy`, `time`, `threading`.
- **Preuves mathématiques réelles :**
  - Variance du Laplacien pour la netteté : `cv2.Laplacian(gray, cv2.CV_64F).var() < 15.0`.
  - Obstruction optique : `mean_val < 8.0` ou (`std_val < 2.0` et `mean_val < 35.0`).
  - Surexposition aveuglante : `mean_val > 250.0`.
  - Choc physique smartphone : $\Delta g = |\sqrt{a_x^2 + a_y^2 + a_z^2} - 9.81| \ge 4.0\text{ m/s}^2$.
  - Bascule angulaire : produit scalaire vectoriel $\vec{a} \cdot \vec{a}_{ref}$ avec arccos pour dériver l'angle d'inclinaison physique.
- **Machine à états :** Cycles de transition complets `NORMAL` $\rightarrow$ `SUSPECTED` $\rightarrow$ `CONFIRMED` $\rightarrow$ `RECOVERED`.

#### 7. `monitoring/audio_classifier.py` (259 lignes)
- **Dépendances réelles :** `numpy`, `time`, `threading`.
- **Preuve du moteur de repli spectral :**
  - Taux de passage par zéro (ZCR) : `np.mean(np.abs(np.diff(np.signbit(arr))))`.
  - Énergie quadratique moyenne (RMS) : `np.sqrt(np.mean(arr**2))`.
  - Facteur de crête : `peak / (rms + 1e-6)`.
  - Règles physiques codées : Bris de vitre ($ZCR > 0.35, dB \ge 78$), cri humain ($ZCR > 0.12 \text{ ou } \text{crête} > 3.0, dB \ge 84$), sirène ($0.08 \le ZCR \le 0.18, dB \ge 70$).
  - Fusion multi-vectorielle avec la détection de mouvement vidéo (lignes 228-241) ajustant le score de criticité de 30%.

#### 8. `monitoring/semantic_search.py` (390 lignes)
- **Dépendances réelles :** `sqlite3`, `cv2`, `numpy`.
- **Preuve du moteur vectoriel :**
  - Table SQLite `semantic_embeddings` avec clé primaire et index sur `event_id`.
  - Descripteur d'embedding perceptuel : Histogramme de teinte/saturation HSV normalisé (64 bins) concaténé avec les histogrammes de direction des gradients de Sobel $\nabla_x, \nabla_y$ (64 bins) pour former un vecteur unitaire de dimension 128.
  - Recherche textuelle : Projection des mots-clés conceptuels ("rouge", "voiture", "personne", etc.) sur les indices correspondants du sous-espace vectoriel.
  - Similarité cosinus : Produit scalaire $\vec{u} \cdot \vec{v}$ calculé en boucle NumPy vectorisée, tri décroissant et pagination.

#### 9. `monitoring/forensic_engine.py` (239 lignes)
- **Dépendances réelles :** `reportlab` (version 4.5.1 confirmée installée sur l'hôte).
- **Structure du PDF judiciaire généré :**
  - En-tête officiel et identifiants uniques.
  - **Section 1 (Faits physiques mesurés) :** Surface de mouvement %, dB sonore, accélération $\text{m/s}^2$ (non-interprétés).
  - **Section 2 (Inférences probabilistes IA) :** Prédictions de modèles, niveau de certitude et avertissement légal explicite sur le caractère probabiliste des inférences.
  - **Section 3 (Preuves numériques et scellés) :** Tableaux d'empreintes SHA-256, signature HMAC et horodatage certifié.

#### 10. `monitoring/privacy_shield.py` (301 lignes)
- **Dépendances réelles :** `cv2`, `numpy`, `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
- **Preuve du floutage facial :** Détection OpenCV Haar Cascade (`haarcascade_frontalface_default.xml`), calcul d'un filtre gaussien $31\times 31$ sur chaque visage détecté, écriture dans un répertoire dédié `storage/recordings/anonymized/` en conservant impérativement l'original intact.
- **Preuve du chiffrement AES-256-GCM :** Génération de nonce aléatoire de 96 bits (`os.urandom(12)`), chiffrement authentifié du fichier source avec suffixe `.enc`.
- **Preuve de la Two-Man Rule :** La méthode `approve_decryption_request()` bloque si l'approbateur tente de signer une seconde fois, vérifie l'expiration temporelle, et exige 2 approbateurs distincts avant de libérer la clé pour l'exécution unique (`CONSUMED`).

#### 11. `monitoring/evidence_integrity.py` (188 lignes)
- **Dépendances réelles :** `hashlib`, `hmac`, `cv2`, `numpy`.
- **Preuve de hachage par blocs :** Lecture par fragments de 65 536 octets (`chunk := f.read(65536)`), garantissant une empreinte SHA-256 exacte même sur des fichiers vidéo de plusieurs gigaoctets sans saturation mémoire.
- **Preuve du watermarking stéganographique LSB :** Insertion des bits du hash dans le bit de poids faible du canal bleu de la première rangée de pixels (`img[0, i, 0] = (img[0, i, 0] & 0xFE) | (b & 0x01)`).
- **Horodatage RFC 3161 :** Code de requête HTTP ASN.1 présent (lignes 170-184), basculant automatiquement sur un jeton cryptographique déterministe local en l'absence de serveur d'horodatage distant configuré.

#### 12. `monitoring/spatial_tracker.py` (237 lignes)
- **Dépendances réelles :** `math`, `time`, `threading`.
- **Preuve Ray-Casting :** Algorithme de Jordan pour l'inclusion d'un point dans un polygone concave ou convexe quelconque (`contains_point()`, lignes 24-39).
- **Projection optique :** Calcul trigonométrique polaire :  
  $$\text{angle} = \text{orientation} + (\text{bbox\_x} - 0.5) \times \text{FOV}$$  
  $$x = x_{cam} + d \cos(\text{angle}), \quad y = y_{cam} + d \sin(\text{angle})$$
- **Handover spatio-temporel :** Association de trajectoire inter-caméras si $\Delta t \le 8.0\text{s}$ et $\text{distance} \le 15.0\text{m}$.

#### 13. `monitoring/pose_detector.py` (187 lignes)
- **Dépendances réelles :** `time`, `threading`.
- **Preuve de l'analyse géométrique :**
  - Chute au sol : Ratio d'aspect de la boîte englobante $\frac{w}{h} \ge 1.35$ (silhouette allongée au sol).
  - Rôdage prolongé (Loitering) : Suivi temporel continu sur une même caméra $t_{présence} \ge 20.0\text{s}$.
  - Déontologie : Qualification impérative de l'événement avec l'état `NEEDS_REVIEW` sans porter de jugement d'intention.

#### 14. `monitoring/p2p_sync.py` (172 lignes)
- **Dépendances réelles :** `hmac`, `hashlib`, `time`, `threading`.
- **Preuve de synchronisation résiliente :** File Store-and-Forward bornée (500 items), hachage SHA-256 des jetons de nœuds, comparaison en temps constant `hmac.compare_digest()`, numérotation séquentielle monotone, signature HMAC du paquet et fenêtre d'expiration TTL de 24 heures.

#### 15. `monitoring/intercom.py` (210 lignes)
- **Dépendances réelles :** `time`, `threading`.
- **Preuve des gardes-fous matériels :**
  - Temporisation stricte de refroidissement du stroboscope : `strobe_cooldown_seconds = 15.0s`.
  - Plafonnement de sécurité de la durée d'éclairage : `max_strobe_duration_seconds = 8.0s` pour éliminer tout risque d'épilepsie photosensible.
  - Coupe-circuit d'urgence (`abort_strobe`).
  - Messages vocaux prédéfinis neutres prévenant toute fausse qualification juridique ou menace illicite.

---

# 4. ANALYSE CONTRADICTOIRE DES 110 TESTS UNITAIRES ET D'INTÉGRATION

L'exécution complète de la suite automatisée avec Pytest a produit le résultat suivant :
```text
============================ 110 passed in 55.12s =============================
```

### Répartition Réelle vs Mocks des 110 Tests

L'examen contradictoire de chaque fonction de test révèle la ventilation suivante :

```text
+-------------------------------------------------------------+---------+
| Catégorie de Test                                           | Nombre  |
+-------------------------------------------------------------+---------+
| Tests sur ALGORITHMES RÉELS purs (sans aucun mock)          | 58      |
| Tests avec BOUCHONS (Mocks légitimes d'isolement)           | 52      |
| Total des tests validés                                     | 110     |
+-------------------------------------------------------------+---------+
```

```mermaid
pie title Répartition des 110 Tests Automatisés
    "Algorithmes Réels purs (Crypto, Maths, PDF, SQLite)" : 58
    "Mocks d'isolement (ONNX Session, Hardware, HTTP)" : 52
```

### 1. Détail des 58 Tests 100% Réels
Ces tests instancient les classes réelles et exécutent les calculs sans simuler les retours :
- **Cryptographie & Intégrité (16 tests) :** `test_totp_secret_generation_and_token_cycle`, `test_totp_window_clock_drift`, `test_totp_anti_replay_protection`, `test_totp_recovery_codes`, `test_security_audit_syslog_rfc5424`, `test_security_audit_cef_format`, `test_security_audit_masking_sensitive_keys`, `test_chained_integrity_log`, `test_missing_secret_key_and_tampered_hmac`, `test_evidence_registration_and_verification`, `test_evidence_integrity_manifest_and_watermarking`, `test_privacy_shield_anonymization_and_encryption`, `test_privacy_shield_dual_control_workflow`, `test_p2p_device_auth_and_store_forward`, `test_p2p_batch_deduplication_and_tampering`, `test_strobe_safety_controls_and_abort`.
- **Vision, Géométrie & DSP (18 tests) :** `test_opencv_video_motion_detection`, `test_detection_cooldown_anti_rebond`, `test_zones_crud_and_validation`, `test_motion_detection_with_zones`, `test_tamper_detection_optical_obstruction`, `test_tamper_detection_video_degradation_and_overexposure`, `test_tamper_detection_physical_displacement_and_tilt`, `test_tamper_detection_stream_loss_and_recovery`, `test_audio_classifier_background_vs_threats`, `test_audio_classifier_multivector_fusion`, `test_embedding_computation_and_normalization`, `test_indexing_and_similarity_search`, `test_search_pagination_and_empty_query`, `test_deletion_sync_and_rebuild_index`, `test_spatial_zone_polygon_containment`, `test_spatial_tracking_and_multicamera_handover`, `test_pose_detection_fall_and_ethical_qualification`, `test_pose_detection_loitering`.
- **Rapports, Persistance & RBAC (24 tests) :** `test_forensic_report_generation_pdf`, `test_pdf_reports_generation`, `test_database_initialization_and_schema`, `test_idempotent_json_migration`, `test_export_and_restore_cycle`, `test_sqlite_single_source_of_truth`, `test_admin_creation_and_authentication`, `test_brute_force_rate_limiting`, `test_rbac_roles_permissions`, `test_bootstrap_security_and_lifecycle`, `test_intercom_session_lifecycle`, `test_neutral_voice_announcement`, `test_pwa_manifest_validity`, `test_service_worker_security_blacklist`, `test_push_manager_subscription_lifecycle`, etc.

### 2. Rôle et Limites des 52 Tests avec Mocks
Les tests sous mocks concernent :
- `tests/test_edge_ai.py` (7 tests) : Le test `test_edge_ai_detection_and_threshold_with_mock` crée un mock d'`onnxruntime.InferenceSession` renvoyant des tenseurs synthétiques pré-calculés. Cela prouve que le pipeline de décodage des boîtes englobantes et du NMS est fonctionnel, **mais ne prouve pas l'exécution physique sur un modèle ONNX réel**.
- `tests/test_qwen_vision.py` (6 tests) : Mocks de `requests.get` et `requests.post` pour valider le filtrage strict du catalogue Free Tier, la gestion du code HTTP 429 et le disjoncteur sans consommer de quota ni contacter le cloud.
- `tests/test_webrtc.py` (3 tests) : Teste la bascule vers le flux MJPEG lorsque `aiortc` est absent.
- `tests/test_presence.py` (5 tests) : Simule les sondes sockets IP des téléphones autorisés.
- `tests/test_telegram.py` (3 tests) : Simule l'API Telegram Bot.
- `tests/test_integration.py` et `tests/test_api.py` : Utilisent le simulateur `tests/mock_ipwebcam.py` sur le port local 8081.

---

# 5. ANALYSE CONTRADICTOIRE DU SMOKE TEST E2E (12 ÉTAPES)

Le Smoke Test `tests/smoke_test.py` est un script d'intégration système de 334 lignes exécuté avec deux processus indépendants :
1. Le simulateur IP Webcam (`tests/mock_ipwebcam.py`, port 8081).
2. Le Monitoring Host Flask principal (`app.py`, port 5000).

### Déroulement Constaté des 12 Étapes :
1. Démarrage et écoute du simulateur mock IP Webcam sur le port 8081.
2. Démarrage du serveur Flask sur le port 5000 avec réponse HTTP 200 sur `/api/status`.
3. Connexion au dashboard HTML et authentification réussie de l'administrateur (`admin`).
4. Enrôlement dynamique de l'appareil simulateur via `POST /api/devices`.
5. Attente active et transition de l'appareil vers l'état `CONNECTÉ` (caméra et capteurs).
6. Connexion au flux `/video_feed/{id}` et décodage réel d'une trame JPEG avec `cv2.imdecode`.
7. Lecture des valeurs télémétriques (proximité, son en dB, accélération IMU).
8. Armement du système de sécurité via `POST /api/alarm/arm`.
9. Déclenchement d'une alerte simulée de choc accéléromètre.
10. Écriture sur disque de la capture photo `storage/screenshots/screenshot_{id}.jpg` et vérification de sa lisibilité avec OpenCV.
11. Finalisation de l'enregistrement vidéo post-roll (5s) dans `storage/recordings/` et vérification de la lisibilité des trames avec `cv2.VideoCapture`.
12. Contrôle de la persistance relationnelle SQLite (tables `alerts`, `devices`, `evidence`), validation de l'empreinte SHA-256 de 64 caractères et export miroir JSON secondaire.

### Limite Contradictoire Majeure du Smoke Test :
Le Smoke Test valide avec une rigueur irréprochable les **fondations du système (PRO-01 à PRO-05)**. En revanche, **il n'exécute aucune étape de validation de bout en bout pour les modules PRO-06 à PRO-11** (aucun appel WebRTC, aucune inférence Edge AI, aucun défi TOTP, aucun rapport PDF forensique, aucun déchiffrement Two-Man). La validation de ces modules repose exclusivement sur les tests Pytest unitaires et sur les routes de l'API maîtresse (`tests/test_master_api.py`).

---

# 6. ANOMALIES ET CONTRADICTIONS DU RAPPORT INITIAL

L'audit contradictoire a confronté les affirmations du rapport `SSM_MASTER_EVOLUTION_FINAL_REPORT.md` à la réalité physique du dépôt. Les contradictions suivantes ont été formellement établies :

| # | Affirmation du Rapport Initial | Réalité Constatée sur le Dépôt | Impact & Qualification |
|---|---|---|---|
| **A01** | *"Inférence locale YOLOv8-Nano ONNX sur CPU sans dépendance cloud obligatoire."* | Le fichier `yolov8n.onnx` n'existe nulle part dans le dépôt. Le système s'exécute exclusivement via le repli OpenCV. | **Contradiction matérielle.** Le pipeline existe, mais le modèle neuronal n'est pas chargé. |
| **A02** | *"Streaming Vidéo Dual WebRTC / MJPEG : Signalisation SDP/ICE avec repli automatique transparent."* | La bibliothèque `aiortc` n'est pas installée. La signalisation SDP retourne une chaîne statique simulée. | **Contradiction technique.** Le système fonctionne uniquement en streaming MJPEG. |
| **A03** | *"Progressive Web App (PWA) & Web Push : Console installable hors-ligne et notifications natives."* | La PWA (manifeste + service worker) est réelle, mais l'envoi Web Push VAPID ne contacte aucun service push distant. | **Exagération fonctionnelle.** La notification push est simulée au niveau serveur. |
| **A04** | *"Reconnaissance spectrale et ONNX YAMNet (cris, bris de verre, sirène, choc)."* | Le fichier `yamnet.onnx` est absent. L'analyse acoustique fonctionne grâce au repli heuristique DSP (ZCR/RMS). | **Nuance omise.** L'algorithme fonctionne par analyse spectrale classique, non par réseau de neurones. |
| **A05** | *"Recherche sémantique en langage naturel (CLIP / similarité cosinus sur index vectoriel SQLite)."* | Le fichier `clip_visual.onnx` est absent. Les embeddings sont dérivés d'histogrammes de couleurs HSV et de gradients Sobel. | **Nuance omise.** Recherche vectorielle réelle mais basée sur descripteurs perceptuels traditionnels. |
| **A06** | *"Horodatage TSA RFC 3161."* | Aucun serveur TSA public ou privé n'est configuré dans `.env`. | **Repli non explicité.** L'horodatage utilisé est un jeton cryptographique généré localement. |
| **A07** | *"Intelligence visuelle Qwen Vision via xKiro active."* | La variable `XKIRO_API_KEY` dans `.env` est vide. Le module est initialisé en statut `OPENCV_ONLY`. | **Inactif en conditions réelles.** L'IA cloud est en attente d'une clé API valide. |

---

# 7. RISQUES DE SÉCURITÉ IDENTIFIÉS DANS LE CODE

Bien que l'architecture présente d'excellentes défenses (RBAC, CSRF origin checking, rate limiting sur le login), l'audit forensique a identifié cinq points de vulnérabilité ou de fragilité à corriger avant un déploiement réel :

1. **Clés Secrètes de Repli Hardcodées dans le Code Source :**  
   - Dans `monitoring/evidence_integrity.py` (ligne 64) : Clé de repli par défaut `"default_evidence_integrity_key_pro09"`.  
   - Dans `monitoring/p2p_sync.py` (ligne 57) : Clé de cluster par défaut `"p2p_default_cluster_secret_pro11"`.  
   *Risque :* Si un administrateur omet de renseigner ces clés dans les variables d'environnement, un attaquant ayant accès au code source peut forger des signatures de manifestes d'intégrité ou injecter de faux événements P2P.

2. **Drapeau de Cookie de Session Non Sécurisé (`SESSION_COOKIE_SECURE=false`) :**  
   - Dans `.env` (ligne 7) et `config.py` : Le cookie de session Flask n'exige pas le protocole HTTPS.  
   *Risque :* En écoute sur un réseau Wi-Fi local non chiffré, le cookie de session d'un opérateur ou d'un administrateur peut être intercepté par écoute passive (Man-in-the-Middle).

3. **Surface d'Attaque SSRF sur l'Ajout de Périphériques (`POST /api/devices`) :**  
   - La validation de l'adresse IP d'un smartphone n'interdit pas l'accès à certaines plages locales sensibles (comme l'adresse de rebouclage `127.0.0.1` ou des passerelles de routeurs).  
   *Risque :* Possibilité de détourner le mécanisme de sondage pour scanner des ports internes du serveur hôte.

4. **Identifiants Administrateur d'Amorçage Visibles :**  
   - Le mot de passe de secours `AdminSecurity2026!` est présent dans les scripts de test et la documentation.  
   *Risque :* Si la base SQLite est réinitialisée en environnement réel, le mot de passe doit être obligatoirement changé au premier démarrage sous peine de compromission immédiate.

5. **Clé Maître Privacy Shield Générée en Mémoire Volatile :**  
   - Dans `monitoring/privacy_shield.py` (ligne 81) : `self.master_key = master_key or AESGCM.generate_key(bit_length=256)`.  
   *Risque :* Si aucune clé maître n'est persistée dans un HSM ou un coffre-fort sécurisé, le redémarrage du processus Flask rendra définitivement indéchiffrables tous les fichiers de preuves précédemment chiffrés sous double contrôle.

---

# 8. AFFIRMATIONS À CORRIGER POUR LA SOUTENANCE UNIVERSITAIRE

Pour garantir une présentation académique et professionnelle irréprochable devant un jury universitaire, il est impératif de substituer aux affirmations initiales trop catégoriques des formulations scientifiquement exactes :

| Formulations Initiales (Risquées face à un Jury) | Formulations Recommandées (Scientifiquement Inattaquables) |
|---|---|
| *"SMART SECURITY MONITOR surpasse Agent DVR grâce à l'intégration d'un modèle neuronal YOLOv8-Nano local."* | *"SMART SECURITY MONITOR implémente une architecture hybride de vision avec un pipeline complet de prétraitement Letterbox et NMS conçu pour YOLOv8, disposant d'un mécanisme de repli transparent sur OpenCV lorsque les poids neuronaux ne sont pas déployés."* |
| *"Le système diffuse les flux caméras en streaming WebRTC temps réel."* | *"Le système intègre une couche de signalisation WebRTC conforme aux standards SDP/ICE, tout en assurant une haute disponibilité grâce à un repli automatique et éprouvé sur le streaming multi-clients MJPEG."* |
| *"La recherche sémantique est effectuée par le modèle multimodal CLIP."* | *"La recherche sémantique s'appuie sur une base de données vectorielle locale sous SQLite calculant des similarités cosinus sur des descripteurs perceptuels normalisés (histogrammes HSV et gradients spatiaux de Sobel), conçue pour accueillir directement les embeddings CLIP."* |
| *"Les alertes acoustiques sont classifiées par le réseau de neurones YAMNet."* | *"Le module acoustique réalise une qualification fréquentielle en temps réel basée sur le traitement du signal (ZCR, facteur de crête, RMS) et la corrélation multi-vectorielle avec la vidéo, doublé d'une interface d'inférence pour YAMNet."* |
| *"Toutes les preuves sont horodatées selon la RFC 3161 auprès d'une autorité certifiée."* | *"L'intégrité des preuves repose sur un hachage SHA-256 en blocs de 64 Ko, une signature HMAC et un horodatage cryptographique déterministe, avec support natif du protocole d'horodatage externe RFC 3161."* |
| *"L'intelligence visuelle Qwen Vision via xKiro est opérationnelle en production."* | *"L'architecture de supervision intègre un connecteur xKiro Free Tier sécurisé par disjoncteur (Circuit Breaker) et limitation de débit, actuellement verrouillé en mode de secours local OpenCV dans l'attente du provisionnement de la clé API."* |

---

# 9. LISTE DES CORRECTIONS PRIORITAIRES (FEUILLE DE ROUTE)

Pour élever le projet de son statut actuel **`VERIFIED_WITH_LIMITATIONS`** au statut d'excellence **`TECHNICALLY_VERIFIED`**, les actions suivantes devront être menées :

### Priorité P0 (Indispensable pour l'Inférence Réelle) :
1. **Création d'un script de téléchargement automatique des modèles légers :**
   - Écrire un script `scripts/download_models.py` téléchargeant les versions ONNX allégées :
     - `yolov8n.onnx` (~12 Mo).
     - `yamnet.onnx` (~15 Mo).
     - `clip_visual.onnx` (~40 Mo) ou `yolov8n-pose.onnx` (~14 Mo).
   - Stocker ces fichiers dans le répertoire `models/` du projet.
2. **Gestion rigoureuse des clés secrètes d'intégrité :**
   - Remplacer les clés de repli hardcodées par une génération dynamique aléatoire d'urgence (`secrets.token_hex(32)`) accompagnée d'un avertissement explicite dans les logs si les variables d'environnement sont absentes.

### Priorité P1 (Amélioration Système & Dépendances) :
3. **Provisionnement et activation facultative de la clé API xKiro :**
   - Insérer la clé transmise par l'utilisateur dans `.env` (`XKIRO_API_KEY=sk-xt-...`) et exécuter une validation réelle du catalogue pour passer le statut de `OPENCV_ONLY` à `FREE_TIER_VERIFIED`.
4. **Clarification de l'environnement WebRTC :**
   - Si WebRTC doit être physiquement démontré, documenter l'installation des dépendances compilées d'`aiortc` (nécessite Microsoft Visual C++ Build Tools et FFmpeg sous Windows), ou assumer explicitement le choix d'ingénierie du flux MJPEG prioritaire.

### Priorité P2 (Garantie de Démonstration Universitaire) :
5. **Extension du Smoke Test E2E :**
   - Ajouter dans `tests/smoke_test.py` une 13ème étape générant un rapport forensique PDF via `ForensicReportEngine` et vérifiant son ouverture.
   - Ajouter une 14ème étape testant le cycle de demande et double approbation Two-Man Rule.

---

# 10. VERDICT FINAL ET CERTIFICATION FORENSIQUE

À l'issue de cet audit contradictoire approfondi, indépendant et rigoureusement documenté, le verdict officiel est déclaré :

```text
========================================================================================
                          VERDICT DE CERTIFICATION OFFICIELLE                          
========================================================================================
                      STATUT :  VERIFIED_WITH_LIMITATIONS                              
========================================================================================
```

### Synthèse du Verdict :
- **Pourquoi le système n'est pas `NOT_VERIFIED` ni `PARTIALLY_VERIFIED` :**  
  Le système n'est en aucun cas un assemblage fictif ou trompeur. Les 15 modules existent physiquement, totalisent plusieurs milliers de lignes de code Python élégant et robuste, disposent d'une suite de 110 tests passant intégralement au vert, et intègrent des mécanismes cryptographiques (AES-GCM, SHA-256, HMAC, TOTP) et géométriques (Ray-Casting, FOV, Laplacien) d'un niveau technique largement supérieur aux attentes universitaires.
- **Pourquoi le système ne peut pas être qualifié de `TECHNICALLY_VERIFIED` pur :**  
  La rigueur scientifique impose de ne pas certifier comme "pleinement réelles" des inférences neuronales dont les fichiers de poids ne sont pas présents sur le support physique (`models/*.onnx`), un streaming WebRTC dont la bibliothèque sous-jacente n'est pas installée, des notifications Web Push simulées au niveau de l'expédition HTTP, et une IA cloud dont la clé d'activation est vide.
- **Valeur pour la soutenance universitaire :**  
  Présenté avec les nuances et les précisions documentées dans ce rapport d'audit, le projet démontre une **maîtrise exceptionnelle de l'ingénierie logicielle défensive**, illustrant parfaitement la conception d'architectures résilientes capables de continuer à surveiller, alerter et sceller des preuves numériques même en cas de défaillance ou d'absence des modèles de Deep Learning ou des liaisons cloud.

---
*Rapport d'audit contradictoire établi et scellé le 19 novembre 2026 à usage de certification technique et de soutenance universitaire.*
