# SSM PRO-13-A.2.1 — RAPPORT D'AUDIT SUR LA GESTION DES PROCESSUS FFmpeg, LES RISQUES D'INTERBLOCAGE DE TUBES ET L'ISOLATION OPENCV

**Mission ID :** `SSM-PRO13-A2.1-INDEPENDENT-RTSP-SECURITY-AND-REGRESSION-AUDIT-01`  
**Composant audité :** Adaptateur FFmpeg & OpenCV (`monitoring/acquisition/ffmpeg_adapter.py`)  
**Type d'audit :** Analyse de robustesse multithread/multiprocessus, inspection de descripteurs de fichiers, résilience IPC et modélisation de déni de service (DoS)  
**Date d'audit :** 22 novembre 2026  
**Auditeur :** Senior Application Security & Forensics Auditor (Indépendant)  
**Constats principaux :** `A21-003 (P3 - RISQUE DE DEADLOCK SUR PIPE STDERR FFmpeg)` & `A21-004 (P3 - ABSENCE D'ISOLATION MÉMOIRE DU FALLBACK OPENCV)`

---

## 1. Architecture de Supervision et Cycle de Vie des Sous-Processus FFmpeg

L'architecture NVR universelle PRO-13 repose sur l'exécution d'un binaire FFmpeg dédié par caméra active, supervisé depuis un thread travailleur Python ([`monitoring/acquisition/ffmpeg_adapter.py`](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py)).

### 1.1 Instanciation Sécurisée (`subprocess.Popen`)
L'instanciation s'effectue dans `_run_ffmpeg_subprocess_loop()` ([lignes 256-263](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L256-L263)) :
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
**Éléments validés par l'audit :**
1. **Immunité à l'injection de commandes :** `shell=False` est strictement respecté. La commande `cmd` est une liste ordonnée d'arguments élémentaires. Même si un mot de passe ou un paramètre d'URI contenait des métacaractères shell (`&`, `|`, `;`, `$`, `` ` ``), aucun interpréteur de commande (`cmd.exe` ou `powershell.exe`) n'est invoqué.
2. **Fermeture de l'entrée standard :** `stdin=subprocess.DEVNULL` prévient tout blocage si FFmpeg attendait une confirmation interactive (complété par `-nostdin` dans les arguments).
3. **Dimensionnement du buffer stdout :** `bufsize=self._frame_bytes * 2` alloue une mémoire tampon suffisante pour absorber deux trames vidéo brutes sans congestion immédiate.

### 1.2 Cycle de Nettoyage et Éradication des Processus Zombies
La méthode `_cleanup_process()` ([lignes 408-438](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L408-L438)) applique une séquence d'extinction rigoureuse :
1. **Fermeture des descripteurs :** Fermeture explicite de `proc.stdin`, `proc.stdout`, et `proc.stderr` sous protection de bloc `try/except`.
2. **Arrêt gracieux (`SIGTERM` / `TerminateProcess`) :** Appel de `proc.terminate()` assorti d'un délai de grâce `proc.wait(timeout=1.5)`.
3. **Arrêt forcé immédiat (`SIGKILL`) :** En cas d'expiration du délai (processus figé dans un appel système noyau non interruptible), appel de `proc.kill()` assorti d'un délai de 1.0s.
4. **Protection à l'extinction globale :** La fonction `atexit.register(self.close)` ([ligne 89](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L89)) garantit la destruction systématique des sous-processus actifs si l'application Flask ou le serveur Python s'arrête brutalement, évitant l'accumulation de processus orphelins sur l'hôte Windows.

---

## 2. Analyse Forensique du Risque d'Interblocage de Tube (Pipe Deadlock — A21-003)

### 2.1 Mécanisme du Risque Identifié
Dans `_run_ffmpeg_subprocess_loop()` :
- Le descripteur `stderr` est ouvert en mode tube : `stderr=subprocess.PIPE`.
- La boucle de traitement ([lignes 281-334](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L281-L334)) lit continuellement depuis `stdout` :
  ```python
  raw_frame = self._process.stdout.read(self._frame_bytes)
  ```
- En revanche, **le tube `stderr` n'est JAMAIS lu pendant l'exécution continue de la boucle**.
- Il n'est lu qu'une seule fois, de façon synchrone, après la détection de terminaison du processus ([lignes 285-286](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L285-L286)) :
  ```python
  if self._process.poll() is not None:
      rc = self._process.returncode
      err_bytes = self._process.stderr.read() if self._process.stderr else b""
  ```

### 2.2 Conséquence sur les Tubes Système OS (Windows / Linux)
Les tubes anonymes gérés par le noyau Windows (ainsi que les pipes POSIX sous Linux) disposent d'une taille de tampon mémoire limitée :
- Sous Windows 11, la taille standard d'un pipe anonyme non dimensionné est de 4 096 octets (4 Ko).
- Si le flux vidéo RTSP présente des dégradations de trames ou des erreurs de décodage répétées (ex: paquets perdus, macroblocs H.264 corrompus, perte de synchronisation de trame I/P), FFmpeg écrit des avertissements et des messages d'erreur sur `stderr`.
- Lorsque le volume de texte émis sur `stderr` dépasse 4 Ko :
  1. L'appel système interne `write()` de FFmpeg vers `stderr` **devient bloquant**.
  2. FFmpeg est suspendu par le planificateur de tâches de l'OS en attente de libération du tampon `stderr`.
  3. Étant suspendu, FFmpeg ne produit plus aucune trame sur `stdout`.
  4. Le thread Python de SSM reste bloqué indéfiniment sur `stdout.read(self._frame_bytes)`.
  5. **Résultat : Interblocage mutuel (Deadlock) et gel complet de la caméra**.

### 2.3 Facteur Atténuant Actuel et Classification de Risque
Dans `_build_ffmpeg_cmd()`, l'option `-loglevel error` est spécifiée ([ligne 188](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L188)). Cela supprime les messages de niveau `info` et `warning`, réduisant fortement le volume de texte émis sur `stderr`.
Cependant, face à un flux vidéo corrompu ou hostile générant des dizaines d'erreurs de décodage par seconde, la limite de 4 Ko peut être atteinte en quelques secondes.

**Classification de risque :** Constat **A21-003** (Priorité P3 — Faible à Modéré en environnement de test, mais critique pour la stabilité 24/7 en production).

### 2.4 Remédiation Recommandée
Deux solutions architecturales simples éliminent définitivement ce risque :
- **Option 1 (Simple et robuste) :** Rediriger stderr vers un fichier journal circulaire ou vers `subprocess.DEVNULL` si les logs FFmpeg ne sont pas inspectés en continu.
- **Option 2 (Idéale pour la télémétrie) :** Instancier un thread travailleur dédié chargé de consommer `stderr` en continu de manière non-bloquante et de stocker les 20 dernières lignes dans un `deque(maxlen=20)`.

---

## 3. Analyse du Fallback OpenCV et Comportement en Production (A1-003)

### 3.1 Vérification de la Politique Fail-Closed en Production
L'audit initial PRO-13-A.1 avait relevé le risque d'activation silencieuse d'OpenCV in-process si le binaire FFmpeg était absent ou défaillant.
La remédiation PRO-13-A.2 a verrouillé ce comportement ([lignes 82-86](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L82-L86)) :
```python
is_prod = getattr(config, "IS_PRODUCTION", False)
allow_opencv_opt = bool(getattr(self.config, "custom_params", {}).get("allow_opencv_fallback", False))
self._allow_opencv_fallback = allow_opencv_opt and (not is_prod)
```
Et lors de la tentative de connexion ([lignes 155-163](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L155-L163)) :
```python
if not self._has_ffmpeg_binary:
    if not self._allow_opencv_fallback:
        self._status = VideoSourceStatus.ERROR
        self._last_error = (
            f"Binaire FFmpeg introuvable ('{self.ffmpeg_bin}'). "
            "Le fallback OpenCV in-process est désactivé par sécurité pour garantir l'isolation des processus."
        )
        return False
```

**Preuve d'audit :**
En environnement de production (`IS_PRODUCTION = True`), même si l'administrateur configurait explicitement `allow_opencv_fallback = True` sur une caméra, le paramètre est écrasé à `False`. Si `ffmpeg.exe` est absent, l'adaptateur refuse catégoriquement d'ouvrir le flux et passe en état `ERROR`.
La conformité avec la politique fail-closed et la résolution du constat A1-003 sont **parfaitement démontrées**.

---

## 4. Analyse Comparative : Sous-Processus FFmpeg vs Fallback In-Process OpenCV (A21-004)

Le tableau suivant illustre la différence fondamentale entre les deux moteurs en matière de cyber-résilience et de stabilité système :

| Critère de Robustesse | Moteur Primaire : Sous-Processus FFmpeg | Moteur de Secours : In-Process OpenCV |
| :--- | :--- | :--- |
| **Espace Mémoire** | Isolé dans un espace d'adressage distinct (`ffmpeg.exe`) | Partagé avec l'interpréteur Python et Flask |
| **Corruption Mémoire / Exploit C++** | Le sous-processus plante sans corrompre Python | Crash complet immédiat ou compromission du serveur SSM |
| **Gel Réseau / Blocage Socket** | `proc.terminate()` ou `proc.kill()` interrompt le binaire | `cap.read()` bloque le thread Python ; impossible à tuer proprement |
| **Gestion des Timeouts** | Pilotée par l'OS (`proc.wait(timeout=...)`) | Dépendant du paramètre d'environnement `OPENCV_FFMPEG_CAPTURE_OPTIONS` |
| **Charge CPU & Fuites Mémoire** | Récupération intégrale de la mémoire à la mort du process | Dépend du garbage collector Python et des allocateurs C++ OpenCV |
| **Politique d'Exécution** | Requis et obligatoire en Production | Interdit en Production (toléré en Dev/Mock uniquement) |

### 4.2 Constat A21-004 (Limites du Fallback OpenCV en Dev/Test)
Dans l'environnement de développement et de test actuel, le binaire FFmpeg n'est pas présent dans le `PATH` système Windows. Par conséquent, les tests locaux s'exécutent avec le fallback OpenCV activé pour les cibles de simulation.
Bien que `os.environ["OPENCV_FFMPEG_CAPTURE_OPTIONS"] = "timeout;5000000"` ([ligne 343](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L343)) configure le timeout de capture à 5 secondes, il est rappelé que la bibliothèque OpenCV sous Windows ne garantit pas la stricte interruptibilité des boucles d'attente natives.
Le maintien de l'interdiction d'OpenCV en production est donc une condition de sécurité vitale.

---

## 5. Synthèse de Conformité et Recommandations

1. **Isolation des Processus :** L'exécution de FFmpeg en sous-processus sans shell (`shell=False`) respecte les standards de durcissement les plus élevés.
2. **Nettoyage des Ressources :** La chaîne `terminate() -> wait() -> kill()` et la gestion `atexit` garantissent l'absence de processus orphelins.
3. **Fail-Closed en Production :** L'interdiction absolue d'OpenCV en production est active et vérifiée par test unitaire.
4. **Correction Préventive Recommandée pour A21-003 :**
   Dans une sous-mission de durcissement ultérieure (PRO-13-A.3) ou avant passage en production industrielle, modifier la gestion de `stderr` de FFmpeg pour drainer le tampon de manière asynchrone ou le diriger vers `subprocess.DEVNULL`.
