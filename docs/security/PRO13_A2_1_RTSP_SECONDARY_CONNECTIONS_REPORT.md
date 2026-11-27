# SSM PRO-13-A.2.1 — RAPPORT D'AUDIT SUR LES CONNEXIONS SECONDAIRES RTSP ET LA FRONTIÈRE RÉSEAU FFmpeg

**Mission ID :** `SSM-PRO13-A2.1-INDEPENDENT-RTSP-SECURITY-AND-REGRESSION-AUDIT-01`  
**Composants audités :** `monitoring/acquisition/ffmpeg_adapter.py`, `monitoring/acquisition/security.py`  
**Type d'audit :** Modélisation de menaces protocolaire, analyse des interactions C/libavformat, audit d'architecture réseau  
**Date d'audit :** 22 novembre 2026  
**Auditeur :** Senior Application Security & Forensics Auditor (Indépendant)  
**Constat principal :** `A21-001 (P2 - RISQUE RÉSIDUEL PROTOCOLAIRE NON COUVERT PAR LE DNS PINNING)`

---

## 1. Problématique et Architecture de la Frontière Réseau

Le système Smart Security Monitor (SSM) a introduit dans PRO-13-A.2 un mécanisme rigoureux de **DNS Pinning** ([`monitoring/acquisition/security.py`](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/security.py#L99-L140)) :
1. Le code applicatif Python résout et valide l'adresse IP de destination.
2. L'URI est réécrite sous la forme `rtsp://<IP_NUMÉRIQUE>:<PORT>/<CHEMIN>`.
3. Le binaire `ffmpeg.exe` est invoqué avec cette URI réécrite via l'argument `-i`.

Ce mécanisme garantit que la socket initiale établie par FFmpeg contacte exclusivement l'adresse IP auditée par SSM, neutralisant ainsi le DNS Rebinding direct.

Cependant, le protocole **RTSP (RFC 2326 / RFC 7826)** et le moteur de démultiplexage multimédia sous-jacent **FFmpeg `libavformat`** constituent des systèmes autonomes opérant en code natif C. Une fois la connexion TCP initiale établie, le serveur distant communique des métadonnées applicatives pouvant contraindre FFmpeg à initier des flux réseau secondaires de manière totalement transparente pour le code Python de SSM.

Ce rapport analyse en profondeur quatre vecteurs d'évasion réseau post-handshake.

---

## 2. Analyse Détaillée des Redirections RTSP (Codes 301 / 302)

### 2.1 Mécanisme du Protocole RTSP
Selon la RFC 2326 (section 11.3), un serveur RTSP peut répondre à une requête `OPTIONS` ou `DESCRIBE` par un code de redirection :
- `301 Moved Permanently`
- `302 Moved Temporarily`

Ces réponses comportent un en-tête `Location: <nouvelle_uri>`.

### 2.2 Comportement de FFmpeg `libavformat/rtsp.c`
Par défaut, lorsque `libavformat` reçoit une redirection HTTP ou RTSP :
1. La bibliothèque C parse l'en-tête `Location`.
2. Elle ferme la socket existante et ré-instancie un contexte de connexion vers la nouvelle cible.
3. Si la nouvelle URI contient un nom de domaine (ex: `rtsp://evil.local/live`) ou une adresse IP interne sensible (ex: `rtsp://169.254.169.254:80/` ou `rtsp://127.0.0.1:3306/`), **c'est la bibliothèque C interne de FFmpeg qui effectue la résolution DNS et l'ouverture de la socket TCP**.

### 2.3 Constat Forensique (Finding A21-001)
- Dans [`monitoring/acquisition/ffmpeg_adapter.py`](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L185-L201), la commande construite par `_build_ffmpeg_cmd()` est la suivante :
```python
cmd = [
    self.ffmpeg_bin,
    "-hide_banner",
    "-loglevel", "error",
    "-nostdin",
    "-rtsp_transport", "tcp",
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
- **Aucune option d'interdiction de redirection n'est spécifiée** (ex: `-max_redirects 0`).
- Par conséquent, si un serveur de caméra compromis ou malveillant répond par une redirection RTSP 302 vers une cible interne prohibée, le binaire FFmpeg suivra cette redirection de manière autonome, contournant entièrement le contrôle anti-SSRF et le DNS Pinning applicatif de SSM.

---

## 3. Analyse des Descripteurs de Session SDP (`a=control`)

### 3.1 Négociation RTSP et Payloads SDP
Lors du cycle RTSP usuel :
1. Le client émet `DESCRIBE rtsp://192.168.1.50:554/live`.
2. Le serveur répond `200 OK` avec un corps SDP (Session Description Protocol).
3. Le SDP spécifie les pistes médias (audio, vidéo) et associe à chaque piste un attribut de contrôle : `a=control:<uri>`.
4. Le client émet ensuite la commande `SETUP <uri> RTSP/1.0` pour chaque piste.

### 3.2 Vecteur d'Attaque par URI Absolue dans `a=control`
Dans un flux conforme standard :
- L'attribut est relatif : `a=control:trackID=1`.
- Le client concatène l'URI de base de la session : `SETUP rtsp://192.168.1.50:554/live/trackID=1`.

Dans un scénario adversarial :
- Le serveur malveillant injecte une URI absolue dans le corps SDP :
  `a=control:rtsp://127.0.0.1:6379/` ou `a=control:rtsp://169.254.169.254:80/latest/meta-data/`
- La RFC 2326 stipule que si `a=control` contient une URI absolue, celle-ci doit être utilisée directement pour la requête `SETUP`.
- `libavformat` va alors tenter d'ouvrir une connexion TCP vers l'URI spécifiée dans `a=control`.
- Le contrôle de sécurité initial de SSM est ainsi contourné au niveau de la couche applicative média.

---

## 4. Analyse du Transport RTP / RTCP et Paramètre `-rtsp_transport tcp`

### 4.1 Évaluation Positive de la Décision Technique
Dans `_build_ffmpeg_cmd()` ([ligne 190](file:///c:/Users/USER/Documents/alarme-sys/monitoring/acquisition/ffmpeg_adapter.py#L190)), SSM impose explicitement :
```python
"-rtsp_transport", "tcp"
```

### 4.2 Bénéfices Forensiques de Sécurité
1. **Élimination des ports UDP éphémères :**
   En mode standard UDP, le client doit ouvrir deux ports UDP dynamiques par piste média (un pour RTP, un pour RTCP) et indiquer ces ports dans l'en-tête `Transport: RTP/AVP;client_port=50000-50001`. Cela ouvre des sockets d'écoute locales susceptibles d'être sondées ou abusées.
2. **Entrelacement strict (Interleaved Framing) :**
   En mode TCP, les paquets RTP et RTCP sont encapsulés directement dans le flux TCP existant de la session RTSP (sur les canaux logiques 0 et 1) via le caractère ASCII `$` (0x24).
3. **Absence de flux UDP sortants non maîtrisés :**
   Aucun paquet UDP n'est envoyé à l'aveugle par FFmpeg vers des adresses distantes arbitraires.

*Conclusion sur le transport :* Le forçage de `-rtsp_transport tcp` est une excellente pratique défensive, pleinement validée par l'audit.

---

## 5. Protocoles Imbriqués et Absence de `-protocol_whitelist`

### 5.1 Vulnérabilités Connues de FFmpeg Dérivées des Protocoles
FFmpeg supporte nativement plus de 80 protocoles de transport et conteneurs virtuels (ex: `file`, `http`, `https`, `tcp`, `udp`, `rtp`, `rtsp`, `crypto`, `data`, `concat`, `subfile`, `pipe`).
Par le passé, de multiples vulnérabilités critiques (CVE-2016-1897, CVE-2016-1898, etc.) ont permis à des fichiers ou flux malveillants d'induire la lecture de fichiers locaux (`/etc/passwd`, fichiers système Windows) via des conteneurs virtuels comme `subfile` ou `concat` référençant le protocole `file://`.

### 5.2 Analyse de la Commande SSM
La commande FFmpeg exécutée par SSM ne restreint pas la liste des protocoles autorisés via l'option standard `-protocol_whitelist`.
- Si un flux RTSP renvoie une playlist HLS imbriquée ou un descripteur redirigeant vers une URL `file://` ou `http://169.254.169.254/`, FFmpeg pourrait tenter de l'activer selon les modules compilés dans le binaire.
- *Recommandation d'audit :* Ajouter explicitement l'argument `-protocol_whitelist "tcp,rtp"` (ou `"tcp,rtp,tls"` si RTSPS est activé ultérieurement).

---

## 6. Analyse de l'Isolation Réseau au Niveau Système (OS / Egress Filtering)

### 6.1 Environnement Hôte Actuel
- **Système d'exploitation :** Windows 11.
- **Contexte d'exécution :** Processus utilisateur standard non conteneurisé.
- **Pare-feu :** Aucune règle Windows Filtering Platform (WFP) ni règle de pare-feu Windows n'est appliquée spécifiquement au sous-processus FFmpeg.

### 6.2 Conséquence Architecturale
Tant que FFmpeg s'exécute dans le même espace réseau que l'hôte sans isolation de namespace (comme un réseau Docker bridge restreint ou des cgroups Linux), **la seule barrière de sécurité repose sur le contrôle applicatif Python**.
Tout ce que Python ne filtre pas (ou ne peut pas intercepter dans la couche C de FFmpeg) atteint directement la pile réseau de l'hôte.

---

## 7. Plan de Remédiation Recommandé (Priorité P2 — Avant Lot B)

Pour étanchéifier la frontière réseau NVR contre les attaques protocolaires secondaires sans perturber le fonctionnement opérationnel, les mesures suivantes doivent être implémentées :

### 7.1 Durcissement des Arguments FFmpeg (`ffmpeg_adapter.py`)
Ajouter dans `_build_ffmpeg_cmd()` les options suivantes :
```python
"-max_redirects", "0",                          # Interdiction totale des redirections 301/302
"-protocol_whitelist", "tcp,rtp,rtsp",          # Restriction stricte aux protocoles nécessaires
```
Ces deux ajouts simples :
1. Neutralisent immédiatement le suivi de redirections 301/302 non auditées par Python.
2. Empêchent FFmpeg d'invoquer des protocoles dangereux (`file:`, `concat:`, `http:`, etc.) en cours de streaming.

### 7.2 Validation SDP Préventive (Évolution Long Terme)
Pour les environnements hautement hostiles, un analyseur syntaxique SDP léger peut être exécuté sur le paquet `DESCRIBE` avant d'autoriser la négociation `SETUP`, afin de vérifier que tous les champs `a=control:` sont strictement relatifs.

---

## 8. Synthèse Forensique du Risque

| Vecteur Analysé | Risque Théorique | Couverture Actuelle | Niveau de Risque Résiduel |
| :--- | :--- | :--- | :--- |
| **DNS Rebinding initial** | Prise de contrôle IP | Éliminé par DNS Pinning (`pin_uri_to_ip`) | **NUL (MAÎTRISÉ)** |
| **Scan de ports locaux** | Énumération de services | Bloqué par `PROHIBITED_PORTS` | **NUL (MAÎTRISÉ)** |
| **RTP/RTCP UDP Scanning** | Écoute et injection UDP | Neutralisé par `-rtsp_transport tcp` | **NUL (MAÎTRISÉ)** |
| **Redirection RTSP 301/302** | Re-connexion vers IP interdite | Non restreint (`max_redirects` absent) | **P2 (MOYEN / À CORRIGER)** |
| **SDP `a=control` absolu** | Connexion SETUP vers IP arbitraire | Non filtré par libavformat | **P2 (MOYEN / À CORRIGER)** |
| **Protocoles imbriqués** | Fuite de fichiers via demuxers | Non restreint (`protocol_whitelist` absent) | **P3 (FAIBLE / DURCISSEMENT)** |

**Conclusion de l'Auditeur :** La protection initiale contre le SSRF et le DNS rebinding est solide et démontrée. Les risques résiduels protocolaires (A21-001) identifiés ci-dessus relèvent de la défense en profondeur et ne remettent pas en cause la robustesse des correctifs A1-001/A1-002, mais constituent une condition sine qua non de durcissement avant toute exposition en production ou passage au Lot B.
