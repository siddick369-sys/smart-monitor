# 🛡️ SSM PRO-13-A.3.1 — FFMPEG RTSP PROTOCOL & EGRESS AUDIT
## INDEPENDENT FORENSIC EVALUATION OF PROTOCOL WHITELISTING, TRANSPORT CONTROLS, AND SECONDARY CONNECTION RISKS

**Mission ID :** `SSM-PRO13-A3.1-INDEPENDENT-FFMPEG-RTSP-AND-PROCESS-SECURITY-AUDIT-01`  
**Composant audité :** `monitoring/acquisition/ffmpeg_adapter.py`  
**Focus :** Durcissement A21-001 (Protocole RTSP, Transport TCP, Whitelist libavformat, Contrôle des connexions secondaires)  
**Classification :** READ-ONLY AUDIT · SOURCE CODE ANALYSIS · PROTOCOL CONFORMANCE

---

## 1. OBJECTIFS DE SÉCURITÉ DE LA MISSION A.3 (RAPPEL)

La mission précédente (PRO-13-A.3) visait à remédier aux vulnérabilités identifiées sous la référence **A21-001** :
1. Forcer le transport RTSP en TCP exclusif (éliminer le basculement silencieux en UDP non connecté).
2. Restreindre drastiquement les protocoles libavformat via `-protocol_whitelist` pour interdire les protocoles dangereux (`file:`, `pipe:`, `concat:`, `http:`, `data:`).
3. Contrôler les risques d'évasion réseau via les redirections RTSP ou les descriptions SDP malveillantes.

---

## 2. AUDIT STATIQUE DU CODE DE CONSTRUCTION DES COMMANDES

### 2.1 Déclaration des constantes (`ffmpeg_adapter.py`, lignes 37-41)
```python
DEFAULT_RTSP_TRANSPORT: str = "tcp"
ALLOWED_RTSP_PROTOCOLS: str = "tcp,rtp,rtsp"
ALLOWED_RTSPS_PROTOCOLS: str = "tcp,rtp,rtsp,tls,crypto"
```
**Analyse forensique :**
- Les protocoles autorisés pour RTSP non chiffré sont restreints au strict minimum nécessaire : `tcp` (transport réseau de base), `rtp` (format des paquets média) et `rtsp` (protocole de contrôle de session).
- Pour RTSPS (`rtsps://`), les protocoles `tls` et `crypto` sont ajoutés de façon granulaire via la propriété dynamique `allowed_protocols`.
- Les protocoles arbitraires (`udp`, `http`, `https`, `file`, `pipe`, `concat`, `subfile`, `ftp`, `gopher`) sont formellement exclus de la chaîne de whitelisting.

### 2.2 Mécanisme de sélection dynamique (`allowed_protocols`)
```python
@property
def allowed_protocols(self) -> str:
    """Détermine la whitelist stricte des protocoles libavformat selon le schéma."""
    if self.uri and self.uri.lower().startswith("rtsps://"):
        return ALLOWED_RTSPS_PROTOCOLS
    return ALLOWED_RTSP_PROTOCOLS
```
**Analyse forensique :**
L'évaluation se base sur le schéma de l'URI initiale. Aucun paramètre utilisateur non assaini ne peut altérer cette sélection.

### 2.3 Assemblage des arguments structurés (`_build_ffmpeg_cmd`)
```python
cmd = [
    self.ffmpeg_bin,
    "-hide_banner",
    "-loglevel", "error",
    "-nostdin",
    "-protocol_whitelist", self.allowed_protocols,
    "-rtsp_transport", DEFAULT_RTSP_TRANSPORT,
    "-rtsp_flags", "+prefer_tcp",
    "-stimeout", str(timeout_us),
    "-i", target_input,
    "-an",
    "-sn",
    "-vf", f"scale={self._width}:{self._height}",
    "-r", str(self._target_fps),
    "-f", "rawvideo",
    "-pix_fmt", "bgr24",
    "pipe:1"
]
```
**Évaluation de conformité des options :**
1. **`-nostdin` :** Désactive toute écoute interactive sur stdin par FFmpeg, empêchant tout blocage attendant une entrée clavier.
2. **`-protocol_whitelist` :** Placé AVANT `-i target_input`, ce paramètre s'applique rigoureusement à l'ouverture du flux d'entrée principal.
3. **`-rtsp_transport tcp` :** Configure le démultiplexeur RTSP de libavformat pour utiliser le transport entrelacé sur le canal TCP de contrôle (RTP-over-RTSP / RFC 2326 section 10.12). Cela élimine l'ouverture de ports UDP aléatoires et empêche les attaques par injection de paquets RTP UDP spoofés.
4. **`-rtsp_flags +prefer_tcp` :** Renforce la directive en interdisant à FFmpeg de tenter une négociation UDP fallback si le serveur tente de rejeter le mode entrelacé.
5. **`-stimeout` :** Configure un timeout réseau explicite en microsecondes, prévenant les blocages indéfinis de la socket de connexion.
6. **`shell=False` :** La commande est transmise sous forme de liste de chaînes à `subprocess.Popen(..., shell=False)`. Aucun shell (`cmd.exe` ou `powershell.exe`) n'est invoqué, rendant impossible l'injection d'opérateurs shell (`&`, `|`, `;`, `>`, `<`).

---

## 3. AUDIT ADVERSARIAL : CONNEXIONS SECONDAIRES, SDP ET REDIRECTIONS

### 3.1 Risque d'évasion via descripteur SDP (`a=control:`)
Dans le protocole RTSP, la commande `DESCRIBE` renvoie un document SDP contenant des attributs de contrôle :
```text
m=video 0 RTP/AVP 96
a=control:rtsp://169.254.169.254:80/track1
```
Ou des redirections RTSP (codes HTTP/RTSP 301, 302, 303, 307) :
```text
RTSP/1.0 302 Moved Temporarily
Location: rtsp://10.0.0.1:554/live
```

### 3.2 Confrontation avec les protections applicatives
- **DNS Pinning (`pin_uri_to_ip`) :** Cette fonction intervient dans le code Python avant le lancement de FFmpeg. Elle remplace le nom d'hôte de l'URI fournie en ligne de commande par son adresse IP résolue et validée.
- **Limitation intrinsèque du processus FFmpeg :** Une fois le sous-processus FFmpeg lancé, libavformat exécute sa propre boucle réseau en langage C. Si libavformat interprète une redirection RTSP ou une URI absolue dans un attribut `a=control:`, libavformat effectuera directement une nouvelle résolution DNS ou une nouvelle connexion socket depuis le code C interne.
- **Rôle de `-protocol_whitelist` :** Si la redirection tente d'orienter le flux vers un protocole non autorisé (ex: `http://169.254.169.254/latest/meta-data/` ou `file:///etc/passwd`), libavformat **BLOQUE** immédiatement la tentative car `http` et `file` ne sont pas dans `tcp,rtp,rtsp`.
- **Faiblesse résiduelle démontrée :** Si la redirection ou l'attribut SDP pointe vers un protocole `rtsp://` mais vers une adresse IP interne non autorisée (ex: `rtsp://169.254.169.254:80/` ou `rtsp://127.0.0.1:554/`), libavformat considérera le protocole comme valide (`rtsp`), et la connexion réseau sera tentée.

### 3.3 Qualification forensique du risque
```
[RTSP_EGRESS_CONFINEMENT] = NOT_PROVEN (au niveau applicatif pur)
```
**Conclusion technique de l'auditeur :**  
Aucune solution purement logicielle en espace utilisateur Python ne peut intercepter de manière déterministe les sockets créées en interne par les bibliothèques C compilées d'un sous-processus sans modification du code source de FFmpeg ou injection de bibliothèque dynamique (LD_PRELOAD / AppInit_DLLs, proscrite en environnement de sécurité standard).  
Le confinement réseau effectif doit être assuré par la couche d'infrastructure :
1. Déploiement en conteneur Docker avec un réseau bridge dédié sans accès au sous-réseau hôte ou aux métadonnées cloud.
2. Règles de filtrage pare-feu au niveau du système d'exploitation (Windows Filtering Platform / iptables) limitant les flux sortants des sous-processus FFmpeg aux seules adresses IP des caméras autorisées.

---

## 4. VÉRIFICATION DES TESTS AUTOMATISÉS

Le test `test_a3_command_construction_protocol_whitelist_and_transport` a été exécuté et audité dans `tests/test_pro13_lot_a_nvr.py` :
- **Entrées testées :** Flux RTSP standard et flux RTSPS chiffré.
- **Assertions vérifiées :**
  - Présence obligatoire de `-protocol_whitelist` avec les chaînes exactes `tcp,rtp,rtsp` et `tcp,rtp,rtsp,tls,crypto`.
  - Présence de `-rtsp_transport tcp` et `-rtsp_flags +prefer_tcp`.
  - Présence de `-nostdin`.
  - Utilisation de l'URI épinglée `_effective_uri`.
- **Résultat :** `PASSED` (Exécution unitaire et en suite complète).

---

## 5. SYNTHÈSE FORENSIQUE ET RECOMMANDATIONS

| Point de contrôle | Statut | Commentaire de l'auditeur |
|---|---|---|
| Injection de paramètres shell | **ÉLIMINÉ** | `shell=False`, arguments en liste distincte. |
| Injection de protocoles dangereux (`file:`, `pipe:`, `http:`) | **ÉLIMINÉ** | Neutralisé par `-protocol_whitelist`. |
| Évasion vers protocoles non-connectés (UDP) | **ÉLIMINÉ** | Forcé en TCP entrelacé via `-rtsp_transport tcp`. |
| Re-résolution DNS malveillante initiale (TOCTOU) | **ÉLIMINÉ** | Neutralisé par le DNS Pinning Python (`pin_uri_to_ip`). |
| Redirections secondaires internes libavformat (SDP/3xx) | **RÉSIDUEL** | Risque résiduel inhérent au sous-processus C. Confinement OS/conteneur obligatoire. |

**Recommandation opérationnelle pour le déploiement :**  
Consigner dans la documentation d'architecture industrielle la directive suivante :  
*« L'isolation réseau des flux vidéo RTSP repose sur la double barrière : filtrage des protocoles FFmpeg en couche applicative et confinement pare-feu (Egress Filtering) au niveau de l'orchestrateur de conteneurs. »*
