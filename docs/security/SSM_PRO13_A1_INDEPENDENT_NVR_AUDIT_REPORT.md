# 🛡️ SMART SECURITY MONITOR — RAPPORT D'AUDIT FORENSIQUE INDÉPENDANT ET CONTRADICTOIRE
## AUDIT DE SÉCURITÉ POST-IMPLÉMENTATION DU LOT A — NVR UNIVERSEL & DISCOVERY

**Identifiant Unique :** `SSM-PRO13-A1-INDEPENDENT-NVR-SECURITY-AND-REGRESSION-AUDIT-01`  
**Mission :** Audit contradictoire, indépendant et forensique post-implémentation du Lot A  
**Périmètre :** Lot A exclusivement (Acquisition, RTSP, FFmpeg, OpenCV, ONVIF, SSDP, Sécurité réseau, API, Régressions PRO-12)  
**Mode d'Audit :** Read-Only, contradictoire, sans altération de code  
**Repository :** `C:\Users\USER\Documents\alarme-sys`  
**Environnement Constaté :** Windows 11 · Python 3.11.8 · OpenCV 4.10.0 · SQLite 3 / SQLAlchemy · pytest 9.1.1  
**Verdict Final de l'Audit :** **`PRO13_A_REQUIRES_TARGETED_REMEDIATION`**  
**Statut Gate Lot B :** **`BLOQUÉ (EN ATTENTE DE REMÉDIATION DU LOT A)`**  
**Date d'Audit :** 22 Novembre 2026  

---

## 1. RÉSUMÉ EXÉCUTIF

Cet audit a été conduit en application stricte du mandat contradictoire indépendant `SSM-PRO13-A1-INDEPENDENT-NVR-SECURITY-AND-REGRESSION-AUDIT-01`. Contrairement à une mission d'auto-certification, chaque assertion du rapport antérieur (`SSM_PRO13_A_NVR_REPORT.md`) a été confrontée à l'épreuve de l'exécution réelle, de l'inspection ligne à ligne du code et de scénarios adversariaux non couverts par la suite de tests initiale.

### Synthèse des Découvertes Majeures :
1. **Défaut Bloquant Confirmé (P1 - [A1-001]) :** La fonction centrale de validation réseau `validate_video_target()` dans [security.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/security.py#L170) plante systématiquement avec `TypeError: 'SocketKind' object is not subscriptable` dès qu'une cible réseau est **valide** et autorisée (indexation erronée `addr_info[0][1][0]` au lieu de `addr_info[0][4][0]`). Par conséquent, tout appel réel à `FFmpegRTSPAdapter.connect()` sur une caméra valide échoue avec une exception non gérée. Les tests du Lot A passaient uniquement parce qu'ils n'évaluaient que des cas de rejet ou utilisaient des sources simulées.
2. **Vulnérabilité TOCTOU / DNS Rebinding (P2 - [A1-002]) :** L'adaptateur `FFmpegRTSPAdapter` valide la cible une seule fois avant la création du thread, puis transmet le nom d'hôte original (non épinglé à l'IP validée) à FFmpeg ou OpenCV. Ces derniers effectuent leur propre résolution DNS indépendante. En cas d'attaque par DNS rebinding (TTL court), ou lors des reconnexions automatiques où aucune re-validation n'est effectuée, le flux peut contacter une IP interdite.
3. **Disparité Critique FFmpeg vs Fallback OpenCV (P2 - [A1-003]) :** Le binaire `ffmpeg.exe` est absent du `PATH` de l'hôte. Le système bascule donc exclusivement sur le fallback OpenCV `cv2.VideoCapture`. Ce fallback ne dispose d'aucun délai d'attente réseau configurable (`connect_timeout` et `read_timeout` inopérants au niveau TCP/RTSP), s'exécute dans l'espace mémoire du processus Flask (pas d'isolation sous-processus) et peut bloquer indéfiniment un thread d'acquisition sans possibilité de terminaison forcée (`proc.kill()`).
4. **Intégration ONVIF Réduite à WS-Discovery (P2 - [A1-004]) :** Il n'existe aucune implémentation des services SOAP Media ONVIF (Profile S / Profile T, `GetCapabilities`, `GetProfiles`, `GetStreamUri`). L'URI RTSP est déduite via un gabarit codé en dur (`rtsp://{ip}:554/live/ch0`).
5. **Absence de mDNS (P3 - [A1-005]) :** Bien que mentionné dans la documentation, aucun service mDNS/Zeroconf n'est implémenté.
6. **Robustesse PRO-12 Préservée :** La suite globale réussit 258/258 tests. Les contrôles de sécurité historiques (P2P `SSMP2P02`, HMAC canonique, anti-replay, Two-Man Rule, CSRF, isolation de session) demeurent opérationnels.

---

## 2. BASELINE FORENSIQUE

| Élément | Valeur Constatée | Source de Preuve |
| :--- | :--- | :--- |
| **Chemin du dépôt** | `C:\Users\USER\Documents\alarme-sys` | `git rev-parse --show-toplevel` |
| **Branche active** | `main` | `git branch --show-current` |
| **Commit HEAD** | `b339a9c82d5b410e78d1ea6d43cae556049ba2c0` | `git rev-parse HEAD` |
| **État du Working Tree** | Clean (aucun fichier modifié non commité) | `git status --short` |
| **Dernier Commit** | `docs(pro13): add Lot A NVR report and git push automation scripts` | `git log -1 --oneline` |
| **Interpréteur Python** | 3.11.8 (tags/v3.11.8:db85d51, Feb 6 2024) [MSC v.1937 64 bit] | `python -c "import sys; print(sys.version)"` |
| **OpenCV** | 4.10.0 | `python -c "import cv2; print(cv2.__version__)"` |
| **FFmpeg Système** | **ABSENT** (`where.exe ffmpeg` -> Code retour 1) | `where.exe ffmpeg` |
| **Modules Lot A** | Présents dans `monitoring/acquisition/` (8 fichiers) | `os.listdir('monitoring/acquisition')` |
| **Tests Lot A** | 21 tests dans `tests/test_pro13_lot_a_nvr.py` | `pytest tests/test_pro13_lot_a_nvr.py` |
| **Rapports PRO-13** | 4 rapports présents dans `docs/` | `os.path.exists()` |

---

## 3. PÉRIMÈTRE AUDITÉ

L'audit a couvert l'intégralité des composants ajoutés ou modifiés pour le Lot A :
- [monitoring/acquisition/interfaces.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/interfaces.py)
- [monitoring/acquisition/ffmpeg_adapter.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py)
- [monitoring/acquisition/security.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/security.py)
- [monitoring/acquisition/onvif_adapter.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/onvif_adapter.py)
- [monitoring/acquisition/discovery.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/discovery.py)
- [monitoring/acquisition/mock_adapter.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/mock_adapter.py)
- [monitoring/acquisition/android_adapter.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/android_adapter.py)
- [database.py](file:///C:/Users/USER/Documents/alarme-sys/database.py#L57-L69) (migrations NVR)
- [monitoring/camera_manager.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/camera_manager.py)
- [monitoring/system_coordinator.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/system_coordinator.py)
- [routes/devices.py](file:///C:/Users/USER/Documents/alarme-sys/routes/devices.py#L170-L238)
- [tests/test_pro13_lot_a_nvr.py](file:///C:/Users/USER/Documents/alarme-sys/tests/test_pro13_lot_a_nvr.py)

---

## 4. ARCHITECTURE RÉELLEMENT CONSTATÉE & GESTION DES BUFFERS

### 4.1 Contrat VideoSource
L'interface [interfaces.py](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/interfaces.py) est conforme aux principes SOLID, bien typée et documentée. Les méthodes sont :
- `connect() -> bool`
- `read_frame(timeout) -> Tuple[bool, Optional[VideoFrame], str]`
- `get_health() -> VideoSourceHealth`
- `get_metadata() -> VideoSourceMetadata`
- `close() -> None`
- `is_healthy() -> bool`

La politique anti-stale est formalisée : `read_frame()` renvoie un tuple `(False, placeholder_frame, error_msg)` dès que la dernière trame dépasse `timeout` (défaut : 5.0 s). Aucun consommateur ne reçoit de trame périmée comme directe.

### 4.2 Gestion des Tampons (Buffer)
**Écart constaté avec le rapport antérieur :** Le rapport affirmait l'utilisation d'un tampon circulaire non bloquant `collections.deque(maxlen=2)`.
En réalité :
- `from collections import deque` est importé à la ligne 15 de `ffmpeg_adapter.py`, mais `deque` n'est **jamais instancié ni utilisé**.
- L'adaptateur utilise une variable scalaire simple `self._latest_frame: Optional[VideoFrame]` protégée par `self._lock = threading.RLock()`.
- Ce mécanisme est thread-safe et garantit la fraîcheur de l'image (écrase la trame précédente), mais ne constitue pas une file d'attente circulaire (*ring buffer*).

---

## 5. AUDIT CRITIQUE FFMPEG ET GESTION DES PROCESSUS

### 5.1 Construction de la Commande
L'implémentation dans `_build_ffmpeg_cmd()` ([ffmpeg_adapter.py:135](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L135)) est sécurisée :
- Arguments passés sous forme de liste structurée (`List[str]`).
- Exécution avec `shell=False` dans `subprocess.Popen`.
- Paramètres imposés : `-nostdin`, `-rtsp_transport tcp`, `-stimeout <us>`, `-pix_fmt bgr24`, `-f rawvideo pipe:1`.
- Aucune injection shell n'est possible via les options ou l'URI.

### 5.2 Gestion des Tubes (Pipes) et Terminaison
- `self._process.stdout` est lu par bloc exact de `width * height * 3` octets.
- En cas d'arrêt, `_cleanup_process()` ferme explicitement `stdin`, `stdout` et `stderr`, puis tente un `proc.terminate()` avec un délai de grâce de 1.5 s, suivi d'un `proc.kill()` forcé.
- `atexit.register(self.close)` est enregistré à l'initialisation.
- **Constat :** En mode FFmpeg, la gestion des processus est robuste et étanche contre les fuites de processus orphelins.

---

## 6. AUDIT CRITIQUE DU FALLBACK OPENCV

**Constat décisif : Le fallback OpenCV ne fournit PAS les mêmes garanties de sécurité et d'isolation que FFmpeg.**

L'hôte Windows n'ayant pas `ffmpeg.exe` dans son `PATH`, le code s'exécute **exclusivement** via `_run_cv2_fallback_loop()` ([ffmpeg_adapter.py:270](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L270)).

| Propriété | Moteur FFmpeg (Subprocess) | Fallback OpenCV (`cv2.VideoCapture`) | Risque Constaté |
| :--- | :--- | :--- | :--- |
| **Isolation mémoire** | Processus OS séparé | Dans le processus Flask / Python | **CRITIQUE** : Un crash mémoire libavcodec tue SSM |
| **Timeout de connexion TCP** | Configuré via `-stimeout` | Par défaut de l'OS (souvent 30s+) | **ÉLEVÉ** : Blocage réseau indéfini possible |
| **Timeout de lecture** | Géré via non-bloquant / pipe | Bloquant dans l'appel C++ `cap.read()` | **ÉLEVÉ** : Impossible d'interrompre un read bloqué |
| **Arrêt forcé** | `proc.kill()` (signal OS) | Aucun (dépend de `cap.release()`) | **MOYEN** : Thread orphelin bloqué si socket pendante |
| **Re-résolution DNS** | Gérée par FFmpeg | Gérée par OpenCV libavformat | Risque TOCTOU identique |

---

## 7. AUDIT SSRF ET DNS REBINDING

### 7.1 Découverte du Bogue Bloquant A1-001 dans `validate_video_target()`
Dans [monitoring/acquisition/security.py:170](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/security.py#L170) :
```python
169:     # Première IP valide retenue
170:     resolved_ip = addr_info[0][1][0]
171:     return True, "Cible validée et conforme aux règles de sécurité.", resolved_ip
```
Dans l'API socket standard Python, `addr_info` est une liste de 5-tuples `(family, type, proto, canonname, sockaddr)`.
`addr_info[0][1]` est `SocketKind.SOCK_STREAM` (un entier/énumération, pas un tuple).
Tenter d'indexer `addr_info[0][1][0]` lève inévitablement :
```
TypeError: 'SocketKind' object is not subscriptable
```
**Preuve d'exécution reproductible :**
```python
>>> from monitoring.acquisition.security import validate_video_target
>>> validate_video_target("192.168.1.50", port=554)
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File "C:\Users\USER\Documents\alarme-sys\monitoring\acquisition\security.py", line 170, in validate_video_target
    resolved_ip = addr_info[0][1][0]
                  ~~~~~~~~~~~~~~~^^^
TypeError: 'SocketKind' object is not subscriptable
```
**Conséquence opérationnelle :**
Lorsqu'un opérateur ou le système tente de connecter une caméra valide via `FFmpegRTSPAdapter.connect()`, la méthode plante avant même d'instancier le thread ou la capture.
Le test n'a pas détecté ce bogue car aucun test unitaire ne vérifiait `validate_video_target()` dans le cas où elle renvoie `True` avec une cible réseau légitime.

### 7.2 Vulnérabilité TOCTOU / DNS Rebinding
Dans [monitoring/acquisition/ffmpeg_adapter.py:116-145](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L116) :
1. `validate_video_target(self.uri)` résout le nom d'hôte à $t_0$ et valide que l'IP résolue est privée.
2. `self.uri` (qui contient toujours le nom d'hôte original, ex: `rtsp://camera.attacker.com:554/live`) est transmis à FFmpeg (`-i self.uri`) ou OpenCV (`cv2.VideoCapture(self.uri)`).
3. Lors de la connexion effective à $t_1$, FFmpeg/OpenCV ré-exécute une résolution DNS indépendante.
4. Si le serveur DNS de l'attaquant renvoie `169.254.169.254` ou `127.0.0.1` à $t_1$, la connexion SSRF est établie.
5. De surcroît, dans la boucle de reconnexion continue `_supervision_loop()`, `validate_video_target()` n'est **jamais ré-exécutée**.

### 7.3 Masquage des Secrets
La fonction `sanitize_uri()` dans `security.py` traite correctement les mots de passe contenant des caractères spéciaux (`@`, `#`, etc.) et masque systématiquement le secret (`admin:***`). Aucune fuite d'identifiants n'a été constatée dans les logs ou les réponses API.

---

## 8. AUDIT ONVIF RÉEL

Grille d'évaluation des capacités ONVIF annoncées vs réellement présentes :

| Capacité ONVIF | Implémentation Réelle | Statut d'Audit |
| :--- | :--- | :---: |
| **Émission WS-Discovery UDP (239.255.255.250:3702)** | Socket multicast UDP avec timeout | `IMPLEMENTED_AND_TESTED` |
| **Parsing XML SOAP ProbeMatch** | `xml.etree.ElementTree` durci contre XXE | `IMPLEMENTED_AND_TESTED` |
| **Validation SSRF des répondeurs WS-Discovery** | Appel de `validate_video_target()` | `IMPLEMENTED_AND_TESTED` |
| **Isolation et anti-auto-enrôlement** | Statut `DISCOVERED_PENDING_APPROVAL` | `IMPLEMENTED_AND_TESTED` |
| **Authentification ONVIF (WS-UsernameToken)** | Absente | `NOT_IMPLEMENTED` |
| **Client SOAP Device (`GetCapabilities`)** | Absent | `NOT_IMPLEMENTED` |
| **Client SOAP Media (`GetProfiles`)** | Absent | `NOT_IMPLEMENTED` |
| **Récupération dynamique RTSP (`GetStreamUri`)** | Absente (URI codée en dur : `/live/ch0`) | `NOT_IMPLEMENTED` |
| **Compatibilité ONVIF Profile S** | Aucune implémentation de protocole Profile S | `NOT_IMPLEMENTED` |
| **Compatibilité ONVIF Profile T** | Aucune implémentation de protocole Profile T | `NOT_IMPLEMENTED` |

**Conclusion ONVIF :** L'intégration se limite strictement à la **découverte passive/active WS-Discovery**. L'appellation "Adaptateur ONVIF Profile S/T" dans la documentation est abusive.

---

## 9. AUDIT SSDP ET DÉCOUVERTE RÉSEAU

- **Construction M-SEARCH :** Paquet standard UPnP multicast émis vers `239.255.255.250:1900`.
- **Parsing HTTPU :** Découpage sécurisé des en-têtes sans risque de débordement mémoire.
- **Défense Anti-SSRF :** L'adresse `LOCATION` présente dans les en-têtes SSDP est stockée comme métadonnée, mais **n'est jamais requêtée par HTTP**. Il n'y a donc aucun risque d'exploitation SSRF via SSDP.
- **mDNS / Zeroconf :** Absent du code.
- **Anti-Auto-Enrôlement :** Validé. Tous les candidats restent en attente (`DISCOVERED_PENDING_APPROVAL`).

---

## 10. AUDIT API, RBAC, CSRF ET FRONTIÈRE DE CONFIANCE

- **Contrôle d'accès :** Les routes `/api/discovery/scan`, `/api/discovery/candidates`, `/api/discovery/candidates/<id>/approve`, `/api/discovery/candidates/<id>/reject` et `/api/devices` exigent formellement `@login_required` et `@roles_required("ADMIN")` (ou `OPERATOR` pour le listing).
- **Vérification côté serveur :** Le rôle est extrait de la session serveur vérifiée (`session["role"]`), jamais depuis les données soumises par le client.
- **Protection CSRF :** Le middleware global dans `app.py` applique la vérification `Sec-Fetch-Site: cross-site`, la validation des origines et la présence du jeton CSRF de session. Les routes d'enrôlement ne font partie d'aucune liste d'exemption.
- **Validation d'ajout :** L'ajout via l'API REST `/api/devices` passe par `SystemCoordinator.add_device()` qui invoque la validation de sécurité.

---

## 11. AUDIT BASE DE DONNÉES ET MIGRATIONS

- **Schéma `devices` :** Colonnes `protocol VARCHAR(32) DEFAULT 'ANDROID_IPWEBCAM'` et `rtsp_uri VARCHAR(256)`.
- **Idempotence :** Vérifiée via inspection préalable de `PRAGMA table_info(devices)`.
- **Défaut mineur :** Le bloc de migration dans `database.py:68` utilise `except Exception: pass`, masquant silencieusement d'éventuelles erreurs de verrouillage SQLite (`busy_timeout`).

---

## 12. PRÉSERVATION DES GARANTIES PRO-12

L'ensemble des exigences de sécurité de la branche PRO-12 a été audité et exécuté :
- **P2P Sync :** Protocole `SSMP2P02` strictement appliqué, signature HMAC SHA-256 sur payload canonique, rejet formel de tout downgrade.
- **Chiffrement :** AES-256-GCM avec AAD et persistance des clés dans `storage/keys/`.
- **Two-Man Rule :** Approbation duale requise pour les actions critiques.
- **Anti-Replay :** Déduplication persistante des identifiants d'événements.

---

## 13. RÉSULTATS D'EXÉCUTION DES TESTS ET COMPILATION

### 13.1 Compilation Python
Commande : `python -m compileall -q .`  
Code retour : `0` (Aucune erreur de syntaxe)

### 13.2 Suite Lot A (`tests/test_pro13_lot_a_nvr.py`)
Commande : `python -m pytest tests/test_pro13_lot_a_nvr.py -v`  
Code retour : `0`  
Résultat : **21 passed in 17.39s**

### 13.3 Suite Globale de Régression
Commande : `python -m pytest tests/ -q`  
Code retour : `0`  
Résultat : **258 passed, 1 warning in 211.00s (03:31)**  
Avertissement : `SAWarning: New instance <SystemBootstrap> conflicts with persistent instance` (teardown de test unitaire).

---

## 14. MESURES DE PERFORMANCE ET LIMITES MATÉRIELLES

- Les métriques annoncées dans le rapport précédent (4 flux, 10 FPS, 22 ms de latence, +38 Mo de RAM) proviennent **exclusivement** du test synthétique `test_nvr_multi_stream_concurrency_and_performance` qui utilise `MockVideoSource` (génération purement mémoire de matrices numpy).
- **Aucune mesure sur flux réseau RTSP réel n'a été réalisée.**
- **Aucun décodage matériel n'a été évalué.**
- Mention formelle obligatoire :  
  `HARDWARE_INTEGRATION_TEST = NOT_AVAILABLE`

---

## 15. MATRICE DES CONSTATATIONS D'AUDIT

| ID | Composant | Gravité | Nature | Preuve / Fichier & Lignes | Impact | Recommandation |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| **A1-001** | `monitoring.acquisition.security` | **P1** | Défaut Confirmé | [security.py:170](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/security.py#L170) : `addr_info[0][1][0]` | Crash `TypeError` systématique lors de la validation d'une IP valide ; rend tout raccordement de caméra réelle impossible. | Remplacer par `addr_info[0][4][0]` et ajouter un test unitaire validant le cas passant. |
| **A1-002** | `monitoring.acquisition.ffmpeg_adapter` | **P2** | Risque Plausible (TOCTOU) | [ffmpeg_adapter.py:116-178](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L116) : nom d'hôte transmis sans épinglage IP, absence de re-validation dans `_supervision_loop`. | Risque de contournement anti-SSRF par DNS Rebinding lors de la connexion initiale ou d'une reconnexion. | Réécrire l'URI avec l'IP résolue validée ou re-valider la cible dans la boucle de reconnexion avant chaque tentative. |
| **A1-003** | `monitoring.acquisition.ffmpeg_adapter` | **P2** | Risque Plausible / Défaut Architectural | [ffmpeg_adapter.py:270-334](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L270) : `_run_cv2_fallback_loop()` sans timeout réseau ni isolation de processus. | Absence de FFmpeg sur l'hôte entraîne l'exécution exclusive d'OpenCV ; blocage réseau possible du thread et instabilité du processus global. | Configurer `OPENCV_FFMPEG_CAPTURE_OPTIONS` ou installer le binaire FFmpeg officiel supervisé en sous-processus. |
| **A1-004** | `monitoring.acquisition.onvif_adapter` | **P2** | Écart de Spécification | [onvif_adapter.py:154-167](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/onvif_adapter.py#L154) : URI RTSP déduite par gabarit en dur, aucun appel SOAP Profile S/T. | Incompatibilité avec les caméras ONVIF dont le chemin RTSP diffère de `/live/ch0`. | Documenter clairement que seul WS-Discovery est supporté, ou implémenter `GetStreamUri`. |
| **A1-005** | `monitoring.acquisition.discovery` | **P3** | Écart Documentaire | [discovery.py:1-4](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/discovery.py#L1) : Docstring mentionne mDNS mais aucune implémentation n'existe. | Confusion opérationnelle sur les protocoles de découverte supportés. | Corriger la documentation ou implémenter un parseur mDNS dédié. |
| **A1-006** | `monitoring.acquisition.ffmpeg_adapter` | **P3** | Écart Documentaire | [ffmpeg_adapter.py:15](file:///C:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L15) : `deque` importé mais non utilisé ; trame unique protégée par verrou. | Divergence mineure avec l'architecture documentée. | Aligner la documentation ou implémenter explicitement le ring buffer `deque(maxlen=2)`. |
| **A1-007** | Matériel / Environnement | **INFO** | Limitation Matérielle | Absence de caméra physique et de binaire FFmpeg système. | Tests limités aux simulations et mocks. | Planifier des tests d'intégration sur réseau physique avec caméras industrielles réelles. |

---

## 16. PLAN DE REMÉDIATION CIBLÉ

Avant toute autorisation d'ouverture du Lot B, les trois remédiations ciblées suivantes doivent être validées :

1. **Remédiation A1-001 (Correction de `validate_video_target`) :**
   - Modifier la ligne 170 de `monitoring/acquisition/security.py` pour extraire correctement l'IP depuis le sockaddr : `resolved_ip = addr_info[0][4][0]`.
   - Ajouter dans `tests/test_pro13_lot_a_nvr.py` des tests unitaires validant qu'une IP privée légitime (ex: `192.168.1.50:554`) renvoie `valid == True` et l'IP résolue exacte.
2. **Remédiation A1-002 (Protection Anti-DNS Rebinding au point de connexion) :**
   - Ré-exécuter `validate_video_target()` dans `_supervision_loop()` avant chaque tentative de reconnexion.
   - En mode FFmpeg ou OpenCV, privilégier l'injection de l'IP validée avec en-tête `Host` préservé si applicable, ou lever `SSRFBlockedError` si la résolution a changé.
3. **Remédiation A1-003 & Documentation ONVIF (Clarification des limites) :**
   - Ajuster la documentation pour désigner le module comme `WS-Discovery & Découverte Réseau` plutôt que `Support complet ONVIF Profile S/T`.
   - Documenter le prérequis d'installation de `ffmpeg.exe` dans le guide de déploiement de production.

---

## 17. VERDICT FINAL DE L'AUDIT

En raison de la présence d'un défaut bloquant confirmé (**P1 - [A1-001]**) qui empêche tout raccordement réel d'une caméra valide, et de faiblesses d'isolation dans le fallback OpenCV (**P2 - [A1-003]**), le verdict final de l'audit indépendant est :

# ⚠️ `PRO13_A_REQUIRES_TARGETED_REMEDIATION`

---

## 18. GATE D'AUTORISATION DU LOT B

En réponse aux questions décisives du mandat d'audit :

1. **Le Lot A est-il réellement sécurisé ?**  
   Partiellement. Les défenses d'accès (RBAC, CSRF, Anti-Auto-Enrôlement) sont excellentes, mais la fonction de validation réseau comporte un bogue bloquant et une fenêtre TOCTOU.
2. **Le fallback OpenCV respecte-t-il les mêmes garanties que FFmpeg ?**  
   **NON.** OpenCV s'exécute in-process sans isolation mémoire ni timeouts stricts.
3. **La protection DNS rebinding est-elle démontrée au point de connexion ?**  
   **NON.** Elle n'est testée que sur un mock de résolution, pas sur la connexion réelle de l'adaptateur.
4. **L'intégration ONVIF est-elle complète ou limitée à la découverte ?**  
   **LIMITÉE À LA DÉCOUVERTE.** Il n'y a aucun client SOAP Profile S/T.
5. **SSDP est-il correctement protégé contre les URL malveillantes ?**  
   **OUI.** L'URL de description n'est jamais requêtée.
6. **Les tests complets ont-ils été exécutés et reproduits ?**  
   **OUI.** 258/258 tests réussis sur la suite globale, 21/21 sur le Lot A.
7. **Les protections PRO-12 sont-elles intactes ?**  
   **OUI.** Zéro régression constatée sur les mécanismes cryptographiques et d'autorisation.
8. **Des essais sur matériel réel restent-ils indispensables ?**  
   **OUI.** Statut : `HARDWARE_INTEGRATION_TEST = NOT_AVAILABLE`.
9. **Le Lot B peut-il commencer sans risque ?**  
   **NON.** Développer l'IA multimodale sur un socle d'acquisition dont la validation réseau plante lors des connexions réelles introduirait des dettes critiques.

### DÉCISION DE GATE :
> **LE LOT B EST FORMELLEMENT BLOQUÉ JUSQU'À L'APPLICATION ET LA VÉRIFICATION DU PLAN DE REMÉDIATION DU LOT A.**
