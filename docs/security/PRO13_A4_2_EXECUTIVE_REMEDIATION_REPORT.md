# 🛡️ SSM PRO-13-A.4.2 — EXECUTIVE REMEDIATION REPORT
## CORRECTIVE EGRESS ENFORCEMENT, PROVIDER ARCHITECTURE & SECURITY GATE

**Mission ID :** `SSM-PRO13-A4.2-CORRECTIVE-EGRESS-ENFORCEMENT-AND-VERIFICATION-01`  
**Branche :** `main`  
**HEAD initial :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**HEAD final :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0` *(aucun commit, push ou déploiement)*  
**Timestamp :** `2026-11-26T06:38:00+01:00`  
**Environnement :** `Microsoft Windows 11 AMD64 · Python 3.11.8 · pytest 9.1.1 · Session utilisateur non-administrateur · Docker daemon arrêté · Binaire ffmpeg absent du PATH`  

---

## 1. SYNTHÈSE EXÉCUTIVE DE LA REMÉDIATION

La mission `PRO-13-A.4.2` a corrigé les défauts structurels identifiés par l'audit indépendant `PRO-13-A.4.1` dans le mécanisme de confinement réseau sortant (Egress) du worker NVR FFmpeg :

1. **Suppression de la confiance dans les variables d'environnement (`SSM_EGRESS_FIREWALL_ACTIVE`, `SSM_EGRESS_CONTAINER_ISOLATED`) :**
   Remplacement de l'inspection naïve de variables d'environnement dans `check_egress_enforcement_status()` par une hiérarchie formelle de fournisseurs d'inspection (`EgressEnforcementProvider` : `WindowsEgressProvider`, `LinuxEgressProvider`, `DockerEgressProvider`, `UnsupportedEgressProvider`).
2. **Correction de la précédence Windows Defender Firewall :**
   `scripts/setup_ffmpeg_egress_firewall.ps1` ne crée plus une simple règle `-Action Allow` inopérante sous `DefaultOutboundAction = Allow`. Il déploie désormais des règles explicites `-Action Block` (`SSM_NVR_FFmpeg_Egress_BlockProhibited`) couvrant les métadonnées cloud (`169.254.0.0/16`, `fe80::/10`), loopback (`127.0.0.0/8`, `::1/128`), multicast/broadcast et les plages privées non approuvées, ou configure `DefaultOutboundAction = Block` sur opt-in explicite.
3. **Mode Fail-Closed renforcé dans `FFmpegRTSPAdapter` :**
   Lorsque `require_os_egress_confinement = True`, `FFmpegRTSPAdapter.connect()` ré-évalue dynamiquement le statut et rejette tout démarrage (`VideoSourceStatus.BLOCKED_SSRF`) si le statut est différent de `ENFORCED` (`PARTIAL`, `NOT_ENFORCED`, `UNKNOWN`, `UNSUPPORTED`).
4. **Durcissement des schémas URI dans `validate_video_target()` :**
   Ajout d'une liste blanche stricte de protocoles vidéo (`rtsp`, `rtsps`, `http`, `https`), bloquant les schémas arbitraires (`gopher://`, `file://`, `javascript:`).
5. **Réconciliation Docker / Linux :**
   Suppression de `SSM_EGRESS_CONTAINER_ISOLATED=true` de `docker-compose.nvr-egress.yml`, retrait d'`iptables` du conteneur non-privilégié (`Dockerfile.nvr-worker`), et fourniture de `scripts/setup_docker_egress_host.sh` pour le filtrage hôte (`DOCKER-USER` / `nftables`).

---

## 2. INVENTAIRE DES FICHIERS

### Fichiers inspectés
- `monitoring/acquisition/egress_policy.py`
- `monitoring/acquisition/ffmpeg_adapter.py`
- `monitoring/acquisition/security.py`
- `scripts/setup_ffmpeg_egress_firewall.ps1`
- `scripts/teardown_ffmpeg_egress_firewall.ps1`
- `docker/docker-compose.nvr-egress.yml`
- `docker/Dockerfile.nvr-worker`
- `tests/test_pro13_lot_a_nvr.py`

### Fichiers modifiés
- `monitoring/acquisition/egress_policy.py`
- `monitoring/acquisition/ffmpeg_adapter.py`
- `monitoring/acquisition/security.py`
- `scripts/setup_ffmpeg_egress_firewall.ps1`
- `scripts/teardown_ffmpeg_egress_firewall.ps1`
- `docker/docker-compose.nvr-egress.yml`
- `docker/Dockerfile.nvr-worker`
- `tests/test_pro13_lot_a_nvr.py`

### Fichiers créés
- `scripts/check_ffmpeg_egress_firewall.ps1`
- `scripts/test_ffmpeg_egress_connectivity.ps1`
- `scripts/setup_docker_egress_host.sh`
- `tests/test_pro13_a4_2_egress_enforcement.py`
- Les 10 rapports sous `docs/security/PRO13_A4_2_*.md`

---

## 3. LIMITES ET RISQUES NON RÉSOLUS

- **Privilèges Administrateur absents sur le poste de test (`IsInRole(Administrator) == False`) :** les règles Windows Defender Firewall n'ont pas été appliquées ni testées en blocage noyau réel sur cet hôte (vérifiées uniquement en `-DryRun` et par diagnostic non destructif `check_ffmpeg_egress_firewall.ps1`).
- **Démon Docker arrêté (`NOT_AVAILABLE`) :** l'isolation conteneur et `setup_docker_egress_host.sh` n'ont pas été exécutés sur un noyau Linux réel.
- **Binaire `ffmpeg.exe` absent du PATH (`NOT_AVAILABLE`)** et **caméra IP physique absente (`NOT_AVAILABLE`)**.

---

## 4. STATUT DE QUALIFICATION

- **Verdict Gate A4.2 :** `A4_2_EGRESS_ENFORCEMENT_NOT_VERIFIED` *(architecture logicielle et scripts corrigés et validés par tests unitaires/mockés, mais vérification système réelle non exécutable sans privilèges administrateur / démon Docker / binaire FFmpeg).*
- **Lot B Gate :** `LOT_B_GATE = BLOCKED_PENDING_EXPLICIT_HUMAN_APPROVAL`
