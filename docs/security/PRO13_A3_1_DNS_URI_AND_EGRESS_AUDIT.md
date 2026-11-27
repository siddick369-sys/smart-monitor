# 🛡️ SSM PRO-13-A.3.1 — DNS PINNING, URI & EGRESS AUDIT
## INDEPENDENT FORENSIC EVALUATION OF SSRF MITIGATION, DNS REBINDING DEFENSES, AND NETWORK BOUNDARIES

**Mission ID :** `SSM-PRO13-A3.1-INDEPENDENT-FFMPEG-RTSP-AND-PROCESS-SECURITY-AUDIT-01`  
**Composants audités :** `monitoring/acquisition/security.py`, `monitoring/acquisition/ffmpeg_adapter.py`  
**Focus :** Durcissements A1-001, A1-002, A1-003, A21-001 (Validation des cibles, DNS Pinning, Rebinding, Ports interdits, Isolation OpenCV)  
**Classification :** READ-ONLY AUDIT · NETWORK SECURITY · DEFENSIVE DESIGN · FORENSIC INSPECTION

---

## 1. ARCHITECTURE ET OBJECTIFS DE LA BARRIÈRE DE SORTIE (EGRESS)

L'acquisition vidéo NVR implique la connexion vers des flux réseau définis soit par configuration explicite, soit par découverte automatique (WS-Discovery / SSDP). Ces opérations introduisent une surface critique d'attaques de type **Server-Side Request Forgery (SSRF)** et **DNS Rebinding** :
- Tentatives d'accès aux services de métadonnées des fournisseurs Cloud (`169.254.169.254`, `fe80::/10`).
- Tentatives de rebond vers les services internes d'administration ou bases de données (Docker daemon, MySQL, Redis, SSH).
- Attaques par DNS Rebinding exploitant la fenêtre TOCTOU (Time-Of-Check to Time-Of-Use) entre la validation de l'URL et son ouverture par le décodeur vidéo.

---

## 2. AUDIT TECHNIQUE DE LA VALIDATION DES CIBLES (`validate_video_target`)

### 2.1 Parsing robuste et résistant aux obfusquations
La fonction `validate_video_target` n'utilise pas aveuglément `urllib.parse.urlsplit` (qui échoue ou corrompt l'autorité lorsqu'un mot de passe contient le caractère `@` non encodé). Elle met en œuvre une extraction canonique :
- Détection du délimiteur d'autorité `@` par `rsplit("@", 1)`.
- Prise en charge des adresses IPv6 littérales entre crochets `[2001:db8::1]:554`.
- Extraction précise du port de destination avec valeur par défaut stricte (554 pour `rtsp://`, 80 pour `http://`).

### 2.2 Liste noire des ports sensibles (`PROHIBITED_PORTS`)
```python
PROHIBITED_PORTS: Set[int] = {
    21, 22, 23, 25, 53, 110, 143, 389, 445, 636, 2049,
    2375, 2376, 3306, 5000, 5432, 6379, 9200, 11211, 27017
}
```
**Analyse forensique :**
L'interdiction des ports standard (SSH, Telnet, bases de données, cache, Docker API, port local 5000 du Monitoring Host lui-même) empêche l'utilisation de la sonde RTSP comme vecteur de port scanning ou de SSRF vers les services d'infrastructure.

### 2.3 Résolution DNS exhaustive et politique Fail-Closed
```python
addr_info = socket.getaddrinfo(hostname, target_port, socket.AF_UNSPEC, socket.SOCK_STREAM)
```
Pour chaque tuple retourné par l'appel système :
1. **Nettoyage de l'identifiant de zone IPv6 :** `ip_str.split("%")[0]` prévient les erreurs de parsing sur les adresses avec interface locale (`fe80::1%eth0`).
2. **Gestion des IPv4 mappées en IPv6 :** Si une adresse IPv6 est sous forme `::ffff:127.0.0.1` ou `::ffff:169.254.169.254`, elle est convertie en son équivalent IPv4 via `ip_obj.ipv4_mapped`. Les attaquants ne peuvent donc pas contourner le filtre IPv4 en utilisant la notation mappée IPv6.
3. **Examen exhaustif (Politique Fail-Closed) :** Si un nom d'hôte résout vers plusieurs adresses IP (ex: round-robin DNS), la boucle valide **CHAQUE** adresse individuellement. Si **une seule** des adresses résolues est une adresse interdite (link-local, cloud metadata, loopback en production, multicast, publique non autorisée), la cible est **REJETÉE DANS SON INTÉGRALITÉ**.

---

## 3. AUDIT DU DNS PINNING ET RÉÉCRITURE D'URI (`pin_uri_to_ip`)

### 3.1 Neutralisation de la fenêtre TOCTOU
Lors d'une attaque classique par DNS Rebinding, l'attaquant configure un serveur DNS avec un TTL de 0 seconde :
1. Premier appel DNS (lors du check Python) -> renvoie `192.168.1.50` (IP valide acceptée).
2. Deuxième appel DNS (quelques millisecondes plus tard par FFmpeg) -> renvoie `169.254.169.254` (IP cible de l'attaque).

### 3.2 Implémentation du Pinning
La fonction `pin_uri_to_ip(uri, resolved_ip)` reconstruit l'URI complète en substituant directement le nom d'hôte par l'adresse IP validée :
```python
formatted_ip = f"[{ip}]" if ":" in ip else ip
return f"{scheme}://{userinfo_prefix}{formatted_ip}{port_str}{suffix}"
```
- **Préservation des attributs :** Les identifiants (`user:pass`), le port explicite (`:554`), le chemin (`/live/ch0`) et les paramètres de requête (`?token=123`) sont intégralement préservés.
- **Utilisation effective :** Dans `FFmpegRTSPAdapter`, la commande FFmpeg est construite avec `self._effective_uri` (l'URI épinglée). FFmpeg n'effectue donc aucune résolution DNS initiale et se connecte immédiatement à la socket IP auditée.
- **Re-validation périodique :** Dans la boucle `_supervision_loop`, avant chaque tentative de reconnexion, `validate_video_target` est réinvoquée. Si l'enregistrement DNS change entre-temps vers une IP illégitime, la reconnexion est avortée (`VideoSourceStatus.BLOCKED_SSRF`).

---

## 4. ISOLATION DES PROCESSUS ET FALLBACK OPENCV

### 4.1 Politique en environnement de production (A1-003)
Dans `FFmpegRTSPAdapter.__init__` :
```python
is_prod = getattr(config, "IS_PRODUCTION", False)
allow_opencv_opt = bool(getattr(self.config, "custom_params", {}).get("allow_opencv_fallback", False))
self._allow_opencv_fallback = allow_opencv_opt and (not is_prod)
```
Dans `connect()` et `_supervision_loop()` :
```python
if not self._has_ffmpeg_binary:
    if not self._allow_opencv_fallback:
        self._status = VideoSourceStatus.ERROR
        self._last_error = "Binaire FFmpeg introuvable et fallback OpenCV non autorisé."
        return False
```
**Analyse forensique :**
- En production (`IS_PRODUCTION = True`), `self._allow_opencv_fallback` est forcé à `False` de façon inconditionnelle.
- Si le binaire FFmpeg est absent, le système adopte un comportement **fail-closed** : l'adaptateur bascule en erreur, refuse d'ouvrir le flux et n'exécute aucun appel `cv2.VideoCapture` in-process.
- Cela protège le processus principal Flask contre les failles de mémoire (Buffer Overflows, Heap Corruptions) inhérentes aux décodeurs vidéo C++ d'OpenCV exécutés dans l'espace d'adressage du serveur web.

---

## 5. MATRICE FORENSIQUE DES TESTS DE SÉCURITÉ RÉSEAU

| Test automatisé vérifié | Propriété validée | Résultat d'audit |
|---|---|---|
| `test_anti_ssrf_blocks_cloud_metadata` | Blocage de `169.254.169.254` et `fe80::1` | `PASSED` (Rejet avec motif link-local/cloud) |
| `test_anti_ssrf_blocks_loopback_in_production` | Rejet de `127.0.0.1` et `::1` quand `IS_PRODUCTION=True` | `PASSED` (Rejet inconditionnel en prod) |
| `test_anti_ssrf_blocks_prohibited_ports` | Rejet des ports 22, 3306, 6379, 5000 | `PASSED` (Rejet port interdit) |
| `test_anti_ssrf_blocks_ipv4_mapped_ipv6` | Blocage de `::ffff:169.254.169.254` | `PASSED` (Normalisation et rejet fail-closed) |
| `test_anti_ssrf_dns_rebinding_simulation` | Simulation d'alternance DNS rapide | `PASSED` (Pinning effectif) |
| `test_remediation_a1_001_multi_ip_dns_fail_closed` | Résolution renvoyant `192.168.1.50` ET `169.254.169.254` | `PASSED` (Rejet total du nom d'hôte) |
| `test_remediation_a1_002_dns_pinning_and_uri_rewrite` | Substitution d'hôte avec caractères `@#` dans credentials | `PASSED` (URI préservée et pinée) |
| `test_remediation_a1_003_opencv_fallback_disabled_in_production` | Absence de FFmpeg avec `IS_PRODUCTION=True` | `PASSED` (Statut ERROR, pas de cv2) |

---

## 6. CONCLUSION ET RISQUES RÉSIDUELS

La couche défensive anti-SSRF et de DNS Pinning est **CONFORME ET TRÈS ÉLEVÉE** pour l'ensemble des flux gérés en couche applicative.

**Rappel de la limitation structurelle d'évasion réseau :**  
Comme documenté dans le rapport `PRO13_A3_1_FFMPEG_RTSP_PROTOCOL_AUDIT.md`, le DNS Pinning ne peut pas contraindre les sockets créées en interne par FFmpeg en cas de redirection RTSP C. L'isolation réseau périphérique par conteneur reste un prérequis indispensable pour l'accréditation finale en environnement hostile.
