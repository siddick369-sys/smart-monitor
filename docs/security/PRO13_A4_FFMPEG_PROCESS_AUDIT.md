# 🛡️ SSM PRO-13-A.4 — FFMPEG PROCESS BOUNDARY & SUPERVISION AUDIT
## INDEPENDENT SOURCE AUDIT OF THE SUPERVISED SUBPROCESS LIFECYCLE, PROTOCOL RESTRICTIONS, AND EGRESS INTEGRATION

**Mission ID :** `SSM-PRO13-A4-FFMPEG-EGRESS-CONFINEMENT-AND-LOT-A-FINAL-GATE-01`  
**Composant audité :** `monitoring/acquisition/ffmpeg_adapter.py`  
**Focus :** Durcissements A.4 (Chemin absolu, Protocol Whitelist, Transport TCP, Bounded Lifetime, Diagnostics, Egress Fail-Closed)  
**Classification :** READ-ONLY AUDIT · PROCESS BOUNDARY EVALUATION · CODE REVIEW  
**Date :** 2026-11-24

---

## 1. AUDIT DE LA FRONTIÈRE DU SOUS-PROCESSUS FFMPEG

L'adaptateur `FFmpegRTSPAdapter` a été audité ligne à ligne pour vérifier le strict respect des garanties de sécurité exigées dans la phase 5 de la spécification PRO-13-A.4.

---

### 1.1 Résolution du binaire et chemin absolu
```python
resolved_bin = shutil.which(self.ffmpeg_bin)
if resolved_bin:
    self.ffmpeg_bin = os.path.abspath(resolved_bin)
    self._has_ffmpeg_binary = True
else:
    self._has_ffmpeg_binary = False
```
- **Conformité :** Le chemin du binaire est résolu de manière absolue (`os.path.abspath`), neutralisant toute attaque par substitution de chemin relatif ou détournement de répertoire de travail (CWD path hijacking).

---

### 1.2 Absence formelle d'invocation de shell
Dans `_run_ffmpeg_subprocess_loop()` :
```python
self._process = subprocess.Popen(
    cmd,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    stdin=subprocess.DEVNULL,
    bufsize=self._frame_bytes * 2,
    shell=False
)
```
- **Conformité :** `shell=False` est impérativement positionné. Les arguments sont transmis sous forme de liste de chaînes (`List[str]`). Aucun shell (`cmd.exe`, `sh`) n'est invoqué, éliminant totalement l'injection de commandes par métacaractères (`&`, `|`, `;`, `>`, `<`).

---

### 1.3 Paramètres de sécurité de la commande FFmpeg (`_build_ffmpeg_cmd`)
La commande structurée contient les options critiques suivantes :
1. **`-nostdin` :** Empêche FFmpeg de lire stdin, évitant tout blocage en attente de commande utilisateur.
2. **`-protocol_whitelist` :** Restreint strictement les protocoles d'entrée acceptés par libavformat (`tcp,rtp,rtsp` pour RTSP, `tcp,rtp,rtsp,tls,crypto` pour RTSPS). Tout protocole local ou dangereux (`file:`, `pipe:`, `concat:`, `http:`, `data:`) est rejeté.
3. **`-rtsp_transport tcp` :** Force le transport entrelacé RTP-over-RTSP sur TCP.
4. **`-rtsp_flags +prefer_tcp` :** Interdit la négociation de fallback UDP.
5. **`-stimeout <microsecondes>` :** Déclare un délai d'expiration réseau strict calculé à partir de `config.connect_timeout`.
6. **`-an` et `-sn` :** Supprime explicitement les flux audio et sous-titres, éliminant tout appel réseau secondaire lié aux métadonnées.
7. **`-f rawvideo -pix_fmt bgr24 pipe:1` :** Encadre strictement le format de sortie vers le tube anonyme `stdout`.

---

### 1.4 Bornage des diagnostics et vidange continue de stderr (Anti-Deadlock)
- **Consommation continue :** `_stderr_drain_worker` itère sur `proc.stderr.readline` via un thread dédié.
- **Plafond mémoire strict :** `MAX_DIAGNOSTIC_LINES = 100` et `MAX_DIAGNOSTIC_BYTES = 64 * 1024` (64 Ko maximum).
- **Assainissement des secrets :** Chaque ligne de diagnostic est assainie via `sanitize_uri()` pour masquer les mots de passe et jetons (`***`).
- **Isolation des générations :** Le compteur `_process_generation` assure qu'aucun thread lecteur d'une connexion précédente ne pollue les diagnostics d'un nouveau processus.

---

### 1.5 Lecture exacte de stdout et intégrité des trames
- La méthode statique `_read_exact(stream, n_bytes)` itère jusqu'à collecter exactement le nombre d'octets requis pour une image brute ($640 \times 480 \times 3 = 921\,600$ octets).
- Elle prévient les erreurs de redimensionnement NumPy et gère proprement les interruptions de flux (retourne `None` lors de la fermeture du tube).

---

### 1.6 Nettoyage, cycle de vie et politique Fail-Closed
- **Ordre de clôture des descripteurs (`_cleanup_process`) :** Fermeture explicite de `stdin`, `stdout` et `stderr` avant l'émission des signaux de fin de processus.
- **Terminaison ordonnée :** `proc.terminate()` puis repli sur `proc.kill()` sous timeout de 1.0s.
- **Attente bornée du thread lecteur :** `reader_t.join(timeout=1.0)`.
- **Politique de repli OpenCV :** Strictement interdite en environnement de production (`IS_PRODUCTION = True`). En l'absence de binaire FFmpeg, le statut bascule en `VideoSourceStatus.ERROR` (politique fail-closed).
- **Intégration d'Egress Fail-Closed :** Si `require_os_egress_confinement=True` est exigé et que l'environnement ne dispose pas d'un pare-feu ou d'un conteneur actif, la connexion est bloquée immédiatement (`VideoSourceStatus.BLOCKED_SSRF`).

---

## 2. SYNTHÈSE D'AUDIT DU PROCESSUS FFMPEG

| Propriété auditée | Exigence PRO-13 A.4 | Statut forensique |
|---|---|:---:|
| Chemin du binaire | Absolu et validé par `shutil.which` | **CONFORME** |
| Invocation de shell | `shell=False` impératif | **CONFORME** |
| Absence d'entrée interactive | `-nostdin` présent | **CONFORME** |
| Whitelist des protocoles | `tcp,rtp,rtsp` restreint | **CONFORME** |
| Transport réseau | TCP entrelacé forcé | **CONFORME** |
| Fuite UDP | Éliminée | **CONFORME** |
| Timeout réseau | `-stimeout` paramétré | **CONFORME** |
| Consommation stderr | Thread de drain asynchrone continu | **CONFORME** |
| Empreinte mémoire diagnostic | Plafonnée à 64 Ko | **CONFORME** |
| Intégrité trames stdout | Lecture exacte par `_read_exact` | **CONFORME** |
| Terminaison des processus | `terminate` puis `kill` sous 1.0s | **CONFORME** |
| Confinement Egress | Fail-closed si requis et absent | **CONFORME** |

L'implémentation de la frontière de processus FFmpeg dans `monitoring/acquisition/ffmpeg_adapter.py` satisfait l'intégralité des exigences de sécurité de la phase 5.
