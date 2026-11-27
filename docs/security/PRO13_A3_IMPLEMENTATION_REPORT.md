# SSM PRO-13-A.3 — RAPPORT D'IMPLÉMENTATION ET DE DURCISSEMENT CRITIQUE
## SÉCURISATION DU TRANSPORT RTSP/FFmpeg, CONTRÔLE DES PROTOCOLES ET ÉRADICATION DES DEADLOCKS IPC

**Mission ID :** `SSM-PRO13-A3-RTSP-FFMPEG-SECURITY-AND-IPC-DEADLOCK-ELIMINATION-01`  
**Projet :** Smart Security Monitor (SSM)  
**Dépôt canonique :** `C:\Users\USER\Documents\alarme-sys`  
**Branche :** `main`  
**Commit HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Référence d'audit précédente :** `SSM-PRO13-A2.1-INDEPENDENT-RTSP-SECURITY-AND-REGRESSION-AUDIT-01`  
**Environnement de référence :** Windows 11 Professional (AMD64) · Python 3.11.8 · OpenCV 4.10.0 · pytest 9.1.1  
**Statut Global :** **IMPLÉMENTATION COMPLÈTE AVEC PORTÉE VÉRIFIÉE (`PRO13_A3_IMPLEMENTATION_COMPLETE_WITH_VERIFIED_SCOPE`)**  
**Gate Lot B :** **`LOT_B_GATE = BLOCKED_PENDING_INDEPENDENT_AUDIT`**

---

## 1. Objectifs de la Mission

La mission **PRO-13-A.3** a pour mandat d'apporter un durcissement structurel, rigoureux et vérifiable sur les deux constats résiduels identifiés lors de l'audit indépendant PRO-13-A.2.1 :

1. **A21-001 (Sécurité Protocolaire RTSP et Connexions Secondaires) :**  
   Encadrer strictement les flux d'entrée du moteur multimédia FFmpeg afin de limiter sa surface réseau aux seuls protocoles et transports autorisés, neutraliser l'évasion UDP silencieuse, empêcher l'activation de protocoles imbriqués dangereux (`file://`, `concat:`, `subfile:`, etc.) et expliciter la frontière entre le filtrage applicatif Python et le comportement interne de `libavformat`.

2. **A21-003 (Suppression Définitive du Risque d'Interblocage IPC sur `stderr`) :**  
   Éradiquer le risque de blocage (Deadlock) IPC causé par la saturation du tampon de tube anonyme du système d'exploitation (4 Ko sous Windows 11). Mettre en place un consommateur asynchrone continu de `stderr`, un tampon de diagnostic borné en mémoire, une isolation stricte des générations de processus et une procédure de nettoyage idempotent évitant toute fuite de processus ou de threads orphelins.

---

## 2. Baseline Initiale et État du Dépôt

Avant toute modification, l'état forensique du dépôt a été établi :
- **HEAD vérifié :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`
- **Modifications préexistantes :** Exactement 6 fichiers suivis modifiés par PRO-13-A.2 (`monitoring/acquisition/__init__.py`, `discovery.py`, `ffmpeg_adapter.py`, `onvif_adapter.py`, `security.py`, `tests/test_pro13_lot_a_nvr.py`).
- **Disponibilité des binaires :**  
  - Python 3.11.8 disponible.
  - OpenCV 4.10.0 disponible.
  - FFmpeg CLI : absent du `PATH` (`where.exe ffmpeg` retourne code 1).
  - Validation binaire réel : `REAL_FFMPEG_VALIDATION = NOT_AVAILABLE`.
  - Validation matérielle : `HARDWARE_VALIDATION = NOT_AVAILABLE`.

---

## 3. Architecture Retenue et Détail des Remédiations

### 3.1 Remédiation A21-001 : Sécurisation du Transport RTSP et Whitelist des Protocoles

Le module [`monitoring/acquisition/ffmpeg_adapter.py`](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py) a été enrichi avec une politique défensive stricte :

1. **Transport TCP Interleaved Forcé :**
   ```python
   DEFAULT_RTSP_TRANSPORT: str = "tcp"
   ```
   La commande FFmpeg intègre systématiquement `-rtsp_transport tcp` et `-rtsp_flags +prefer_tcp`. Aucun basculement automatique ou silencieux vers UDP n'est toléré. Si une caméra refuse le transport TCP entrelacé, le flux échoue en mode fail-closed avec un statut d'erreur explicite sans exposer l'hôte à des ouvertures de sockets UDP dynamiques.

2. **Whitelist Stricte des Protocoles (`-protocol_whitelist`) :**
   ```python
   ALLOWED_RTSP_PROTOCOLS: str = "tcp,rtp,rtsp"
   ALLOWED_RTSPS_PROTOCOLS: str = "tcp,rtp,rtsp,tls,crypto"
   ```
   L'argument `-protocol_whitelist` est positionné avant `-i` dans la commande FFmpeg.  
   - Pour les flux RTSP standards : seuls `tcp`, `rtp` et `rtsp` sont transmis à `libavformat`.
   - Pour les flux sécurisés RTSPS : `tls` et `crypto` sont adjoints.
   - Tous les autres protocoles dangereux (`file`, `concat`, `subfile`, `pipe`, `http`, `ftp`, `gopher`, etc.) sont rejetés immédiatement par `avio_open()`, empêchant tout vecteur de fuite de fichiers locaux ou de SSRF par demuxer secondaire.

3. **Préservation Intégrale du DNS Pinning :**
   L'URI transmise via `-i` demeure l'URI effective épinglée (`_effective_uri`), reliant mathématiquement l'autorité réseau à l'adresse IP numérique validée par `validate_video_target()`.

### 3.2 Remédiation A21-003 : Éradication du Deadlock IPC `stderr` et Gestion Robuste des Processus

1. **Thread Dédié à la Consommation Continue de `stderr` :**
   Dès l'instanciation de `subprocess.Popen`, un thread démon dédié (`_stderr_drain_worker`) est démarré pour lire `proc.stderr` ligne par ligne via un itérateur `iter(proc.stderr.readline, b"")`. Le tube ne peut ainsi jamais saturer le tampon de 4 Ko de Windows.

2. **Tampon de Diagnostic Borné en Mémoire et Expurgation des Secrets :**
   - Plafonds configurés : `MAX_DIAGNOSTIC_LINES = 100` et `MAX_DIAGNOSTIC_BYTES = 64 * 1024` (64 Ko).
   - Chaque ligne lue est immédiatement filtrée par `sanitize_uri()`, masquant tout mot de passe ou jeton (`***`).
   - Les lignes sont conservées dans un `deque(maxlen=MAX_DIAGNOSTIC_LINES)`. Si le volume total en octets dépasse 64 Ko, les lignes les plus anciennes sont évincées en FIFO/LIFO, garantissant une empreinte mémoire strictement bornée face aux flux corrompus ou bavards.

3. **Isolation des Générations de Processus (`_process_generation`) :**
   Chaque démarrage de sous-processus incrémente un compteur atomique `self._process_generation`. Le worker `_stderr_drain_worker` vérifie continuellement cette valeur : si une reconnexion a été initiée et qu'une nouvelle génération a débuté, le lecteur de l'ancienne génération s'arrête immédiatement et ne peut altérer l'état de la nouvelle session.

4. **Lecture Exacte de `stdout` (`_read_exact`) :**
   Pour éviter qu'une trame partielle ne soit interprétée à tort comme une trame corrompue lors de temporisations réseau, le helper statique `_read_exact(stream, n_bytes)` lit les blocs jusqu'à complétion exacte de `self._frame_bytes` ou détection EOF.

5. **Cycle d'Arrêt Idempotent et Sans Orphelins (`_cleanup_process`) :**
   - Fermeture sécurisée de `stdin` pour signaler la fin de flux.
   - Envoi de `terminate()` assorti d'un délai de grâce (1.0 s).
   - En cas de non-réponse, appel forcé de `kill()` (1.0 s).
   - Fermeture explicite des descripteurs `stdout` et `stderr`.
   - Attente bornée (`join(timeout=1.0)`) du thread lecteur de diagnostics.
   - Protection globale confirmée par `atexit.register(self.close)`.

---

## 4. Tests et Preuves de Validation

### 4.1 Nouveaux Tests Adversariaux PRO-13-A.3 (6 tests dédiés)
Ajoutés dans [`tests/test_pro13_lot_a_nvr.py`](file:///c:/Users/USER/Documents/alarme-sys/tests/test_pro13_lot_a_nvr.py) :
- `test_a3_command_construction_protocol_whitelist_and_transport` : **PASS** (vérifie `-protocol_whitelist`, `-rtsp_transport tcp`, `-rtsp_flags +prefer_tcp`).
- `test_a3_ipc_stderr_drain_and_credential_sanitization` : **PASS** (vérifie le masquage des mots de passe dans les diagnostics).
- `test_a3_ipc_stderr_bounded_memory_under_heavy_logging` : **PASS** (vérifie le maintien du plafond <= 64 Ko sous une injection de 500 lignes).
- `test_a3_ipc_stderr_saturation_synthetic_subprocess_no_deadlock` : **PASS** (test physique : un sous-processus injecte 100 Ko sur stderr tout en émettant des trames sur stdout ; exécution terminée en < 1 s sans aucun blocage).
- `test_a3_process_generation_isolation_on_reconnect` : **PASS** (vérifie l'étanchéité inter-générations lors des reconnexions).
- `test_a3_concurrent_cleanup_and_close_idempotent` : **PASS** (vérifie 8 threads concurrents appelant `close()` sans exception).

### 4.2 Résultats des Suites de Tests Globales
- **Suite Lot A NVR :** **35 / 35 tests passés (100%)** en 47,30 s.
- **Suite Historique PRO-12 :** **127 / 127 tests passés (100%)** en 96,45 s.
- **Suite Globale Complète :** **272 / 272 tests passés, 1 warning (100%)** en 487,93 s.
- **Compilation Statique (`compileall`) :** **Code retour 0 (0 erreur)**.
- **Contrôle Git Whitespace (`git diff --check`) :** **Code retour 0 (Clean)**.

---

## 5. Limites et Risques Résiduels Non Résolus

1. **Frontière Applicative vs Moteur C (`libavformat`) :**  
   L'injection de `-protocol_whitelist` et le DNS Pinning protègent efficacement l'hôte contre l'évasion de protocoles et le DNS rebinding. Toutefois, l'analyse des descripteurs SDP post-handshake s'exécute au sein du code C de FFmpeg. Une étanchéité egress absolue nécessitera une isolation réseau système (conteneur Docker ou pare-feu de sortie WFP/iptables) lors du déploiement industriel.
2. **Absence de Caméra Physique :**  
   `HARDWARE_VALIDATION = NOT_AVAILABLE`. Les tests ont été menés sur simulateurs locaux et processus synthétiques.

---

## 6. Décision de Jalon

Le Lot B (IA multimodale) demeure **strictement verrouillé** :
```
LOT_B_GATE = BLOCKED_PENDING_INDEPENDENT_AUDIT
```
Toute transition vers le Lot B requiert l'audit contradictoire indépendant PRO-13-A.3.1 et l'autorisation formelle de l'opérateur humain.
