# SSM PRO-13-A.3 — RAPPORT D'INGÉNIERIE SÉCURITÉ DU TRANSPORT RTSP ET CONTRÔLE DES DESTINATIONS SECONDAIRES

**Mission ID :** `SSM-PRO13-A3-RTSP-FFMPEG-SECURITY-AND-IPC-DEADLOCK-ELIMINATION-01`  
**Composants audités :** `monitoring/acquisition/ffmpeg_adapter.py`, `monitoring/acquisition/security.py`  
**Date d'audit :** 23 novembre 2026  
**Auditeur :** Principal Application Security & Video Systems Engineer  
**Classification :** DEFENSIVE HARDENING · NETWORK SURFACE REDUCTION · SSRF MITIGATION  

---

## 1. Politique de Transport RTSP et Forçage du Mode TCP Interleaved

### 1.1 Contexte et Risques du Transport UDP Non Maîtrisé
Dans le standard RTSP (RFC 2326 / RFC 7826), la négociation de transport peut emprunter deux voies distinctes :
1. **RTP/AVP over UDP :** Les commandes de contrôle (OPTIONS, DESCRIBE, SETUP, PLAY) transitent sur une connexion TCP (port 554), tandis que les flux média RTP (vidéo) et RTCP (contrôle de qualité) transitent sur deux ports UDP dynamiques négociés lors du SETUP.
   - *Risque de sécurité :* Le client doit ouvrir des ports UDP en écoute locale et envoyer des paquets UDP vers les ports annoncés par le serveur. Cela expose l'hôte à des scans de ports UDP locaux, à l'injection de paquets forgés et à des flux sortants vers des adresses distantes non maîtrisées.
2. **RTP interleaved over RTSP/TCP :** Les paquets RTP et RTCP sont encapsulés directement dans le flux TCP existant de la session RTSP (sur les canaux logiques 0 et 1), préfixés par l'octet `$` (0x24) et un en-tête de 4 octets.

### 1.2 Décision Technique et Implémentation SSM
Dans [`monitoring/acquisition/ffmpeg_adapter.py`](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L228-L229), SSM impose désormais de façon inconditionnelle :
```python
DEFAULT_RTSP_TRANSPORT: str = "tcp"
...
"-rtsp_transport", DEFAULT_RTSP_TRANSPORT,
"-rtsp_flags", "+prefer_tcp",
```
**Bénéfices de sécurité démontrés :**
- **Aucune bascule silencieuse vers UDP :** Si le serveur distant refuse l'entrelacement TCP ou tente d'imposer UDP, la connexion échoue de façon contrôlée (fail-closed) sans ouvrir de sockets UDP.
- **Surface d'attaque réseau minimale :** Aucun port d'écoute UDP local n'est créé sur la machine hôte.
- **Traversée déterministe des pare-feux :** L'intégralité du trafic transite sur le port TCP unique spécifié dans l'URI validée.

---

## 2. Analyse Détaillée des Redirections RTSP (Codes 301 / 302)

### 2.1 Évaluation Critique de l'Option `-max_redirects 0`
L'audit PRO-13-A.2.1 avait suggéré l'option `-max_redirects 0`. Une inspection approfondie du code source de FFmpeg (`libavformat/options_table.h` et `libavformat/rtsp.c`) révèle que :
- `-max_redirects` est une option déclarée spécifiquement pour les protocoles HTTP, HTTPS et HLS (`libavformat/http.c`).
- Le démultiplexeur natif RTSP 1.0 (`rtsp.c`) ne possède pas d'option `max_redirects`.
- Si `-max_redirects 0` est passé avant un descripteur RTSP pur, les versions récentes de FFmpeg émettent un avertissement (`Option max_redirects not found`) ou rejettent l'initialisation selon le contexte de compilation.

### 2.2 Comportement Réel de `libavformat/rtsp.c` face aux Redirections
Dans l'implémentation de référence de FFmpeg :
- Lors de l'envoi de la commande `DESCRIBE`, si le serveur RTSP répond avec un statut `301 Moved Permanently` ou `302 Moved Temporarily`, FFmpeg ne suit **pas** automatiquement la redirection vers une nouvelle cible RTSP arbitraire, sauf si le flux est tunnelé explicitement via HTTP (`rtsp_transport http`).
- En mode TCP natif, une réponse 3xx provoque le retour d'une erreur de démultiplexage (`AVERROR(EIO)` ou code de statut non supporté).
- **Postulat fail-closed :** SSM capture cette fin prématurée du processus, consigne l'erreur dans son tampon de diagnostic expurgé et refuse de basculer vers une autre cible sans validation explicite par l'opérateur.

---

## 3. Analyse des Descripteurs de Session SDP et Attributs `a=control`

### 3.1 Problématique des Cibles Secondaires dans le SDP
Lors de la négociation RTSP :
1. Le client reçoit un corps SDP décrivant les pistes média.
2. Chaque piste comporte un champ `a=control:<uri>`.
3. Dans un flux standard, l'URI est relative (`a=control:trackID=1`).
4. Dans une attaque SSRF ciblée, un serveur distant malveillant pourrait renvoyer une URI absolue :
   `a=control:rtsp://169.254.169.254:80/` ou `a=control:file:///etc/passwd`.

### 3.2 Frontière de Contrôle et Protection par Whitelist de Protocoles
- **Constat d'honnêteté technique :** Le parsing du SDP s'effectue intégralement en mémoire dans la couche C de FFmpeg. Le code applicatif Python ne peut pas intercepter ni modifier les paquets SDP en transit sur la socket TCP gérée par `libavformat`.
- **Contre-mesure active de SSM (Durcissement PRO-13-A.3) :**  
  L'application de `-protocol_whitelist "tcp,rtp,rtsp"` garantit que si une URI absolue injectée dans le SDP tente d'invoquer un protocole non autorisé (`file:`, `http:`, `pipe:`, `concat:`, `subfile:`), FFmpeg bloque immédiatement l'ouverture de la sous-ressource avec le message :
  `Protocol '<nom>' not on whitelist 'tcp,rtp,rtsp'`.

---

## 4. Whitelist des Protocoles FFmpeg (`-protocol_whitelist`)

### 4.1 Configuration Implémentée
Dans `FFmpegRTSPAdapter` :
```python
ALLOWED_RTSP_PROTOCOLS: str = "tcp,rtp,rtsp"
ALLOWED_RTSPS_PROTOCOLS: str = "tcp,rtp,rtsp,tls,crypto"
```
L'option est injectée en début de ligne de commande :
```python
"-protocol_whitelist", self.allowed_protocols,
```

### 4.2 Démarcation Impérative : Whitelist de Protocoles vs Filtrage IP
> [!IMPORTANT]
> **Une whitelist de protocoles ne constitue en aucun cas un filtrage d'adresses IP.**
> - `protocol_whitelist` empêche FFmpeg d'instancier des protocoles et pilotes d'entrées/sorties interdits (prévention des CVE historiques de lecture de fichiers locaux ou d'injection de protocoles).
> - Le filtrage d'adresses IP (anti-SSRF, blocage des métadonnées cloud `169.254.0.0/16`, interdiction du loopback en production) est assuré en amont par la fonction Python `validate_video_target()` et scellé par le DNS Pinning `pin_uri_to_ip()`.
> - Ces deux mécanismes sont complémentaires et forment une défense en profondeur à deux étages.

---

## 5. Synthèse des Niveaux de Contrôle de Sécurité

Le tableau ci-dessous explicite précisément la répartition des responsabilités de contrôle :

| Vecteur d'Attaque / Risque | Contrôle Assuré par le Code Python (SSM) | Contrôle Assuré par FFmpeg (`libavformat`) | Contrôle Assuré par le Système d'Exploitation (OS) |
| :--- | :--- | :--- | :--- |
| **DNS Rebinding initial** | `validate_video_target()` + `pin_uri_to_ip()` (URI réécrite avec IP numérique) | Reçoit une IP littérale (aucun appel DNS externe émis) | Résolution de socket standard |
| **Scan de ports locaux** | Filtrage immédiat via `PROHIBITED_PORTS` (22, 3306, 5000, etc.) | N/A | Filtrage de pare-feu si configuré |
| **Métadonnées Cloud (169.254.169.254)** | Bloqué inconditionnellement (`is_link_local`) | Rejeté car non contacté initialement | Table de routage locale |
| **Injections Shell / Command Injection** | `shell=False` + arguments sous forme de `list` stricte | N/A (aucun parseur shell invoqué) | Création de processus Win32 standard |
| **Protocoles imbriqués malveillants** | Contrôle de schéma d'URI initiale (`rtsp://`) | Bloqué via `-protocol_whitelist tcp,rtp,rtsp` | N/A |
| **Évasion par transport UDP** | Non configuré | Forçage `-rtsp_transport tcp` + `+prefer_tcp` | Ports UDP fermés |
| **Redirection 301/302 post-handshake** | Re-validation à chaque reconnexion supervisée | Échec I/O en mode TCP natif (non suivi automatique) | Nécessite un pare-feu egress pour étanchéité totale |
| **SDP `a=control` vers IP arbitraire** | Pinning de la socket initiale | Whitelist bloque protocoles non RTSP | Nécessite un pare-feu egress pour étanchéité totale |

---

## 6. Recommandations pour le Déploiement Industriel

Pour atteindre un niveau de garantie étanche au-delà des contrôles applicatifs et multimédias :
1. **Conteneurisation (Docker / Podman) :** Exécuter le service d'acquisition SSM dans un conteneur dédié doté d'une interface réseau bridge isolée, sans accès aux plages d'adresses de métadonnées cloud ni aux réseaux d'administration interne.
2. **Filtrage Egress OS (Windows Filtering Platform / iptables) :** Définir une règle de pare-feu système interdisant aux processus enfants de `ffmpeg.exe` tout trafic sortant vers les sous-réseaux autres que le VLAN dédié aux caméras IP.
