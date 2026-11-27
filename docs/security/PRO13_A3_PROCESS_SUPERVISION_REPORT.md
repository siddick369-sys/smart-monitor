# SSM PRO-13-A.3 — RAPPORT SUR LA SUPERVISION DES PROCESSUS, LA GESTION DES TUBES IPC ET L'ÉRADICATION DES DEADLOCKS

**Mission ID :** `SSM-PRO13-A3-RTSP-FFMPEG-SECURITY-AND-IPC-DEADLOCK-ELIMINATION-01`  
**Composant audité :** Adaptateur FFmpeg & OpenCV (`monitoring/acquisition/ffmpeg_adapter.py`)  
**Date d'audit :** 23 novembre 2026  
**Auditeur :** Principal Application Security & Concurrent Systems Engineer  
**Classification :** IPC RESILIENCE · DEADLOCK ELIMINATION · THREAD SAFETY · PROCESS LIFECYCLE  

---

## 1. Contexte et Mécanisme du Deadlock Antérieur (Constat A21-003)

Dans les versions antérieures à PRO-13-A.3, le sous-processus FFmpeg était instancié avec :
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
Cependant, la boucle de capture principale lisait exclusivement le tube `stdout` (`self._process.stdout.read(...)`). Le tube `stderr` n'était lu qu'après la détection de la mort du sous-processus via `self._process.poll()`.

### 1.1 Vulnérabilité Structurelle sur Tube Système OS
Sous Windows 11, un tube anonyme non configuré possède une capacité tampon limitée par le noyau à 4 096 octets (4 Ko).  
Lorsqu'un flux vidéo RTSP présente des désynchronisations de paquets, des pertes de trames I ou des macroblocs corrompus, FFmpeg émet des alertes sur sa sortie d'erreur standard (`stderr`). Dès que le cumul des messages d'erreur dépasse 4 096 octets :
1. L'appel système interne `write(2, ...)` de FFmpeg sur `stderr` devient bloquant, dans l'attente qu'un lecteur vide le tube.
2. Le sous-processus FFmpeg est suspendu par le noyau Windows.
3. Étant suspendu, FFmpeg ne produit plus aucune trame sur `stdout`.
4. Le thread Python de SSM reste bloqué indéfiniment sur `self._process.stdout.read()`.
5. **Résultat : Interblocage réciproque total (Deadlock) sans aucune reprise possible.**

---

## 2. Architecture Retenue pour l'Éradication du Deadlock (PRO-13-A.3)

Pour éliminer définitivement ce risque sans introduire de fuites de mémoire ou de threads orphelins, une architecture à quatre piliers a été conçue et déployée dans [`monitoring/acquisition/ffmpeg_adapter.py`](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py) :

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 ARCHITECTURE DE DRAIN IPC ET DE DIAGNOSTIC                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Sous-Processus FFmpeg (ffmpeg.exe)                                        │
│   ├── stdout (pipe) ──> [_read_exact] ──> Décodage NumPy ──> Buffer deque(2)│
│   └── stderr (pipe) ──> [_stderr_drain_worker] (Thread dédié asynchrone)    │
│                                  │                                          │
│                                  ▼                                          │
│                         [sanitize_uri]                                      │
│                                  │ (Masquage immédiat des mots de passe)    │
│                                  ▼                                          │
│                 Tampon Borné : deque(maxlen=100)                            │
│                 Contrôle de taille : bytes <= 64 Ko                         │
│                                  │                                          │
│                                  ▼                                          │
│                      [get_recent_diagnostics]                               │
│                   (Télémétrie en cas de crash/stall)                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Consommation Asynchrone Continue (`_stderr_drain_worker`)
Dès l'appel de `subprocess.Popen()`, un thread dédié est instancié :
```python
self._stderr_thread = threading.Thread(
    target=self._stderr_drain_worker,
    args=(self._process, generation),
    name=f"FFmpegStderr-{self.source_id}-gen{generation}",
    daemon=True
)
self._stderr_thread.start()
```
Le worker consomme `proc.stderr` ligne par ligne via `iter(proc.stderr.readline, b"")`. Le tube ne peut plus jamais se saturer, quelle que soit la quantité de données émises par FFmpeg.

### 2.2 Tampon de Diagnostic Borné en Mémoire
Pour prévenir toute fuite de mémoire (Memory Leak) si un flux hostile ou dégradé génère des millions de lignes de logs :
- Plafond en nombre de lignes : `MAX_DIAGNOSTIC_LINES = 100`.
- Plafond en volume mémoire : `MAX_DIAGNOSTIC_BYTES = 64 * 1024` (64 Ko).
- Si `_diagnostic_bytes` dépasse 64 Ko, les lignes les plus anciennes sont dépilées en FIFO (`_diagnostic_lines.popleft()`), maintenant une empreinte mémoire strictement constante.

### 2.3 Hygiène des Secrets dans les Logs de Diagnostic
Toute ligne issue de `stderr` est systématiquement expurgée avant stockage :
```python
sanitized_text = sanitize_uri(text)
```
Si un message d'erreur de FFmpeg contient l'URL complète avec identifiants (ex: `rtsp://admin:P@ssword@192.168.1.10/live`), le mot de passe est masqué (`rtsp://admin:***@192.168.1.10/live`) avant son enregistrement dans le buffer de diagnostic.

---

## 3. Isolation des Générations de Processus (`_process_generation`)

Lorsqu'un flux vidéo est interrompu et qu'une reconnexion s'opère :
1. Un ancien thread lecteur de `stderr` peut être en train d'attendre un retour d'appel système bloquant.
2. Un nouveau sous-processus FFmpeg est instancié avec ses propres descripteurs de fichiers.
3. Si le thread de l'ancienne session se réveille au même moment, il ne doit pas écrire ses logs dans le contexte de la nouvelle session ni modifier son statut.

### 3.1 Mécanisme Déployé
- Un entier `self._process_generation` est incrémenté atomiquement sous verrou `self._lock` lors de chaque création de processus.
- Le thread lecteur est étiqueté avec son numéro de génération (`generation`).
- À chaque ligne lue, le worker compare son étiquette avec `self._process_generation` :
  ```python
  with self._lock:
      if generation != self._process_generation:
          break
  ```
- Dès qu'une nouvelle génération apparaît, l'ancien thread lecteur s'interrompt immédiatement sans interférence avec le nouveau cycle.

---

## 4. Lecture Fiable de `stdout` (`_read_exact`)

La lecture de données vidéo brutes non compressées (BGR24, taille fixe `width * height * 3`) sur un tube IPC peut être fragmentée par le planificateur de tâches de l'OS.  
L'utilisation directe de `stream.read(self._frame_bytes)` pouvait renvoyer un nombre d'octets inférieur à la taille attendue si le tampon était temporairement vide, provoquant des faux positifs de flux bloqué (`StreamStalledError`).

Le helper statique `_read_exact` résout ce comportement :
```python
@staticmethod
def _read_exact(stream, n_bytes: int) -> Optional[bytes]:
    chunks = []
    bytes_read = 0
    while bytes_read < n_bytes:
        chunk = stream.read(n_bytes - bytes_read)
        if not chunk:
            return None  # Fin de flux (EOF)
        chunks.append(chunk)
        bytes_read += len(chunk)
    return b"".join(chunks)
```
Ce mécanisme garantit une lecture complète et déterministe de chaque trame vidéo.

---

## 5. Protocole de Nettoyage et Extinction Idempotente (`_cleanup_process`)

La méthode `_cleanup_process()` applique une séquence ordonnée :
1. **Fermeture de `stdin` :** Signale à FFmpeg qu'aucune entrée supplémentaire ne sera fournie.
2. **Arrêt gracieux (`terminate()`) :** Envoi d'un signal SIGTERM (ou appel de `TerminateProcess` sous Windows) assorti d'un délai de grâce borné à 1,0 seconde.
3. **Arrêt forcé (`kill()`) :** En cas d'invalidation du délai de grâce (processus bloqué dans un driver noyau), appel immédiat de `kill()` avec attente bornée à 1,0 seconde.
4. **Fermeture des descripteurs de tubes :** Fermeture explicite de `proc.stdout` et `proc.stderr` sous protection `try/except`.
5. **Attente bornée du thread lecteur :** `reader_t.join(timeout=1.0)` garantit que le thread consommateur de diagnostics est terminé avant de rendre la main.

**Idempotence démontrée :** Le test adversarial `test_a3_concurrent_cleanup_and_close_idempotent` confirme que 8 threads concurrents appelant simultanément `close()` et `_cleanup_process()` s'exécutent sans aucune exception, double fermeture de descripteur ou blocage mutuel.

---

## 6. Preuve Empirique de Non-Deadlock sous Saturation

Le test adversarial physique `test_a3_ipc_stderr_saturation_synthetic_subprocess_no_deadlock` a démontré l'efficacité de la solution :
- Un sous-processus Python synthétique a injecté **100 Ko de texte sur `stderr`** (soit 25 fois la capacité maximale du tampon système Windows) tout en écrivant des trames vidéo sur `stdout`.
- Sous l'ancienne architecture A21-003, ce test aurait figé le sous-processus après les 4 premiers Ko et provoqué un gel infini de l'interpréteur.
- Sous l'architecture PRO-13-A.3, l'ensemble des 100 Ko a été drainé en continu, 3 trames vidéo ont été acquises sur `stdout`, et le sous-processus s'est achevé proprement en **moins d'une seconde**.
