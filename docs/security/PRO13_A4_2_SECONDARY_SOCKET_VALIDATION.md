# 🛡️ SSM PRO-13-A.4.2 — SECONDARY SOCKET VALIDATION
## ANALYSE DES SOCKETS SECONDAIRES LIBAVFORMAT, RTSP 302, SDP A=CONTROL ET CONFINEMENT RÉSEAU

**Mission ID :** `SSM-PRO13-A4.2-CORRECTIVE-EGRESS-ENFORCEMENT-AND-VERIFICATION-01`  
**Branche :** `main` | **HEAD initial/final :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Timestamp :** `2026-11-26T06:41:00+01:00`

---

## 1. FRONTIÈRE PYTHON / C (LIBAVFORMAT)

Conformément à la section 6 de la mission, il est explicitement acté que :
- Python (`validate_video_target`, `pin_uri_to_ip`, `EgressPolicy`) maîtrise **uniquement l'URI initiale** et les **reconnexions initiées par `_supervision_loop()`**.
- Une whitelist de protocoles (`-protocol_whitelist tcp,rtp,rtsp`) ne contrôle **pas** les adresses IP de destination.
- Lorsque `ffmpeg.exe` (`libavformat` en C) reçoit un redirect **RTSP 302** ou un attribut **SDP `a=control:rtsp://...`** absolu, la socket secondaire est ouverte directement en espace C sans repasser par Python.

---

## 2. PROTECTIONS PRÉSERVÉES DANS `FFmpegRTSPAdapter`

Les mécanismes de durcissement de `monitoring/acquisition/ffmpeg_adapter.py` sont intégralement conservés :
- `-nostdin`
- `-rtsp_transport tcp`
- `-rtsp_flags +prefer_tcp`
- `-protocol_whitelist tcp,rtp,rtsp`
- Drainage asynchrone borné de `stderr`
- Timeouts et supervision de sous-processus (`_terminate_process_safely`)
- Re-validation DNS à chaque tentative de reconnexion
- Blocage des schémas non vidéo (`gopher://`, `file://`, `javascript:`) ajouté dans `monitoring/acquisition/security.py`.

---

## 3. COUCHE DE CONFINEMENT DES SOCKETS SECONDAIRES

Le confinement effectif des sockets secondaires C repose sur l'application de la couche OS / conteneur :
- **Windows :** règles WFP/Firewall créées par `scripts/setup_ffmpeg_egress_firewall.ps1` (`AllowCameras` + `BlockProhibited`).
- **Linux / Docker :** règles hôtes `DOCKER-USER` / `nftables` créées par `scripts/setup_docker_egress_host.sh`.
- **Statut réel sur ce poste :** Binaire `ffmpeg.exe` absent du PATH (`NOT_AVAILABLE`) et privilèges Administrateur absents (`NOT_AVAILABLE`) ; la logique est validée en `UNIT` et `LOCAL_SOCKET_INTEGRATION` (tests `A42-35` à `A42-42`).
