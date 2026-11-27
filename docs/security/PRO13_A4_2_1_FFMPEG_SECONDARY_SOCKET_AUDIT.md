# 🛡️ SSM PRO-13-A.4.2.1 — FFMPEG SECONDARY SOCKET AUDIT
## ANALYSE DES RISQUES LIBAVFORMAT, CONNEXIONS SECONDAIRES ET FRONTIÈRE DE FILTRAGE

**Mission ID :** `SSM-PRO13-A4.2.1-INDEPENDENT-AUDIT-AND-LIVE-END-TO-END-QUALIFICATION-01`  
**Composants audités :** `monitoring/acquisition/ffmpeg_adapter.py`, `monitoring/acquisition/security.py`  
**Date d'audit :** 2026-11-26T16:07:00+01:00  

---

## 1. NATURE DU RISQUE DES SOCKETS SECONDAIRES

Dans un flux vidéo IP (RTSP / RTSPS / HTTP / HLS) :
- La connexion initiale TCP est contrôlée par Python (`validate_video_target`, `pin_uri_to_ip`).
- En cours d'échange, le serveur distant peut retourner une réponse **RTSP 302 Redirect** ou un fichier SDP contenant un attribut **`a=control:rtsp://ip_tierce:port/...`**.
- Lorsque `ffmpeg.exe` (libavformat écrit en C) traite ces commandes, il ouvre une socket TCP/UDP secondaire directement depuis le sous-processus sans ré-exécuter le code de validation Python.

---

## 2. AUDIT DES GARANTIES DÉFENSIVES

1. **Restriction des schémas d'URI :**
   Dans `monitoring/acquisition/security.py`, `validate_video_target` impose une liste blanche stricte de schémas (`rtsp://`, `rtsps://`, `http://`, `https://`). Tout schéma arbitraire (`file://`, `gopher://`, `javascript:`) est bloqué avant l'appel FFmpeg (test `A42-05`).
2. **Drapeaux FFmpeg imposés :**
   Dans `_build_ffmpeg_cmd()` :
   `-nostdin`, `-rtsp_transport tcp`, `-rtsp_flags +prefer_tcp`, `-protocol_whitelist tcp,rtp,rtsp`.
   Ces drapeaux empêchent le basculement vers UDP ou des protocoles dangereux (`concat`, `subfile`).
3. **Responsabilité du confinement des sockets secondaires :**
   Il est formellement acté qu'aucun code Python ne peut intercepter les appels socket `connect()` internes à `libavformat`. Le blocage des redirections hostiles vers des IP non autorisées dépend exclusivement du pare-feu OS (WFP sous Windows) ou du filtrage hôte Docker (iptables/nftables).
