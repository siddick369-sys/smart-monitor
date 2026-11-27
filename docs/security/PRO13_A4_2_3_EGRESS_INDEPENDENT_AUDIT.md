# PRO13-A.4.2.3 — INDEPENDENT EGRESS & NETWORK CONFINEMENT AUDIT REPORT

**Mission ID :** `SSM-PRO13-A4-2-3-FINAL-EVIDENCE-RECONCILIATION-AND-INDEPENDENT-CLOSURE-AUDIT-01`  
**Classification :** SSRF DEFENSE / OS FIREWALL / CONTAINER ISOLATION AUDIT  
**Date / Horodatage :** 2026-11-27T06:47:30+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys`  
**Branche :** `main`  
**HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  

---

## 1. DISTINCTION ENTRE POLITIQUE APPLICATIVE ET APPLICATION SYSTÈME

L'audit distingue strictement :
1. **Politique applicative Python (`monitoring/acquisition/egress_policy.py` & `security.py`) :**
   - `EgressPolicy` applique une validation deny-by-default des IP/CIDR, bloque les réseaux réservés (métadonnées cloud `169.254.169.254/32`, link-local, loopback en production, IPv4-mapped IPv6, multicast, broadcast).
   - `EgressEnforcementProvider` refuse tout contournement par variable d'environnement.
   - `FFmpegAdapter` impose `-rtsp_transport tcp` et `-protocol_whitelist`, et échoue en mode fail-closed (`BLOCKED_SSRF`) si `require_os_egress_confinement=True` alors que le fournisseur OS n'est pas actif.
2. **État réel du pare-feu système Windows (vérification non destructive) :**
   - Commande exécutée : `powershell -ExecutionPolicy Bypass -File scripts/check_ffmpeg_egress_firewall.ps1`
   - Profils Windows Firewall : `Domain`, `Private`, `Public` -> `Enabled=True, DefaultOutboundAction=NotConfigured`
   - Constat explicite : `[DIAGNOSTIC] Règle Allow 'SSM_NVR_FFmpeg_Egress_AllowCameras' introuvable.`
   - Résultat retourné : `WINDOWS_EGRESS_NOT_ENFORCED` (Code retour `1`).
3. **État du service Docker sur l'hôte :**
   - `Get-Service *docker*` : `com.docker.service` -> `Stopped` (`NOT_AVAILABLE`).

---

## 2. ANALYSE DE RISQUE RÉSIDUEL

- Tant que les règles de pare-feu Windows (`scripts/setup_ffmpeg_egress_firewall.ps1`) ne sont pas déployées avec élévation administrateur (ou que le conteneur n'est pas isolé sous Linux via `scripts/setup_docker_egress_host.sh`), **aucun confinement noyau/OS réel n'empêche un binaire externe lancé hors mode fail-closed strict d'établir des connexions sortantes**.
- Conformément aux règles strictes de gouvernance, ce constat **n'est pas** rétrogradé artificiellement en risque mineur accepté : il demeure un écart système ouvert.

---

## 3. VERDICT EGRESS

```text
EGRESS_GATE = NOT_VERIFIED
APPLICATION_POLICY_AND_FAIL_CLOSED = VERIFIED_IN_CODE_AND_MOCKED_TESTS
OS_KERNEL_FIREWALL_ENFORCEMENT = NOT_ENFORCED_ON_HOST
DOCKER_NETWORK_ISOLATION = NOT_AVAILABLE
```
