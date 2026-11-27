# 🛡️ SSM PRO-13-A.4.1 — FFMPEG SECONDARY SOCKET THREAT MODEL
## FORENSIC AUDIT OF LIBAVFORMAT C-LEVEL SOCKET EMISSION, RTSP REDIRECTS, AND SDP DESCRIPTORS

**Mission ID :** `SSM-PRO13-A4.1-INDEPENDENT-EGRESS-ENFORCEMENT-AUDIT-01`  
**Composants audités :** `monitoring/acquisition/ffmpeg_adapter.py`, Moteur libavformat FFmpeg (RTSP Demuxer)  
**HEAD audité :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Date d'audit :** 2026-11-24

---

## 1. NATURE ET COMPORTEMENT DES SOCKETS SECONDAIRES DANS LIBAVFORMAT

Dans une session RTSP standard (RFC 2326), la négociation suit une séquence d'échanges textuels :
1. `OPTIONS` : Échange des capacités supportées.
2. `DESCRIBE` : Demande de description de session. Le serveur renvoie un document SDP (Session Description Protocol).
3. `SETUP` : Initialisation des canaux de transport pour chaque piste média (vidéo, audio).
4. `PLAY` : Démarrage du flux de paquets RTP.

### 1.1 Le mécanisme interne en langage C (`libavformat/rtsp.c`)
Lorsque FFmpeg est exécuté en sous-processus via `subprocess.Popen`, l'espace d'adressage du processus Python et celui de FFmpeg sont strictement étanches :
- **Absence de hook applicatif :** libavformat ne fournit aucun callback vers Python lors de l'exécution de son binaire autonome compilé.
- **Gestion des redirections RTSP (3xx) :** Si un serveur RTSP répond avec `RTSP/1.0 302 Moved Temporarily` et fournit un en-tête `Location: rtsp://10.0.0.1:554/stream`, le code C de libavformat referme la socket initiale et **ouvre directement une nouvelle socket TCP vers l'adresse indiquée**.
- **Gestion des attributs SDP `a=control:` :** Si le descripteur SDP renvoyé par la caméra spécifie une URL de contrôle absolue pour une piste (ex: `a=control:rtsp://169.254.169.254:80/track1`), libavformat ouvre la connexion réseau vers cette cible pour la commande `SETUP`.

---

## 2. ÉVALUATION DES PROTECTIONS LOGICIELLES ACTUELLES

L'audit contradictoire examine ce que chacune des protections actuelles fait et ne fait pas :

### 2.1 Directive `-protocol_whitelist tcp,rtp,rtsp`
- **Ce qu'elle fait :** Elle interdit l'ouverture de protocoles libavformat non autorisés (`file:`, `pipe:`, `http:`, `concat:`, `data:`). Si une redirection tente de basculer vers `http://169.254.169.254/latest/meta-data/` ou `file:///etc/shadow`, **FFmpeg refuse la connexion et s'arrête en erreur**.
- **Ce qu'elle ne fait pas :** Elle ne filtre **en aucun cas** les adresses IP de destination. Si la redirection pointe vers `rtsp://169.254.169.254:554/` ou `rtsp://10.0.0.1:554/`, libavformat considère le protocole `rtsp` comme légitime et émet la trame TCP SYN.

### 2.2 Directive `-rtsp_transport tcp` et `-rtsp_flags +prefer_tcp`
- **Ce qu'elle fait :** Elle force les paquets RTP à transiter de manière entrelacée dans le canal TCP existant, empêchant l'ouverture de ports UDP aléatoires non connectés.
- **Ce qu'elle ne fait pas :** Elle n'empêche pas l'ouverture d'une nouvelle connexion TCP secondaire vers une destination RTSP tierce spécifiée dans le SDP.

### 2.3 DNS Pinning Python (`pin_uri_to_ip`)
- **Ce qu'elle fait :** Elle réécrit l'URL initiale passée sur la ligne de commande (`-i rtsp://[IP_VALIDÉE]:554/...`). Cela neutralise l'attaque par DNS Rebinding sur le premier point de contact.
- **Ce qu'elle ne fait pas :** Elle n'a aucun pouvoir sur les URLs imbriquées reçues ultérieurement par le binaire FFmpeg au sein du protocole réseau.

---

## 3. ANALYSE ADVERSARIALE DES VECTEURS D'ÉVASION SECONDAIRES

| Vecteur d'attaque | Comportement libavformat C | Protection applicative Python | Barrière obligatoire requise |
|---|---|---|---|
| **RTSP 302 vers HTTP** | Tente ouverture `http://` | **BLOQUÉ** par `-protocol_whitelist` | Couche applicative suffisante. |
| **RTSP 302 vers RTSP privé** | Ouvre socket TCP vers la nouvelle IP | **NON BLOQUÉ** par Python | **Pare-feu OS / Conteneur Egress obligatoire.** |
| **SDP `a=control` absolu vers IP sensible** | Ouvre socket TCP vers la cible SDP | **NON BLOQUÉ** par Python | **Pare-feu OS / Conteneur Egress obligatoire.** |
| **SDP `a=control` relatif (`track1`)** | Réutilise la socket TCP initiale | **CONFINÉ** à l'IP validée | Confiné par le DNS Pinning initial. |
| **SDP avec nom d'hôte non résolu** | Résout via le résolveur C du système | **NON INTERCEPTÉ** par Python | **Pare-feu OS / Conteneur Egress obligatoire.** |
| **Négociation UDP fallback** | Tente d'écouter sur des ports UDP | **BLOQUÉ** par `-rtsp_flags +prefer_tcp` | Couche applicative suffisante. |

---

## 4. CONCLUSION FORENSIQUE

L'analyse technique démontre de manière irréfutable que :
1. **Aucune configuration logicielle en espace utilisateur Python ne peut contraindre les sockets TCP ouvertes directement en langage C par libavformat.**
2. Par conséquent, l'affirmation selon laquelle le sous-processus FFmpeg serait confiné au niveau réseau sans pare-feu externe actif est **techniquement inexacte**.
3. Le confinement d'egress de FFmpeg repose **impérativement** sur une politique de filtrage réseau de niveau noyau (Windows Defender Firewall avec règle de blocage ou iptables hôte Linux).
