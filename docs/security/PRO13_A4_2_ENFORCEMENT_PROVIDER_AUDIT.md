# 🛡️ SSM PRO-13-A.4.2 — ENFORCEMENT PROVIDER AUDIT
## AUDIT DE EgressEnforcementProvider ET ÉLIMINATION DU CONTOURNEMENT PAR VARIABLE D'ENVIRONNEMENT

**Mission ID :** `SSM-PRO13-A4.2-CORRECTIVE-EGRESS-ENFORCEMENT-AND-VERIFICATION-01`  
**Branche :** `main` | **HEAD initial/final :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Timestamp :** `2026-11-26T06:40:00+01:00`

---

## 1. REMÉDIATION DANS `monitoring/acquisition/egress_policy.py`

Le défaut critique `A41-002` (confiance aveugle dans `SSM_EGRESS_FIREWALL_ACTIVE` et `SSM_EGRESS_CONTAINER_ISOLATED`) a été intégralement supprimé.

### Hiérarchie implémentée :
- **`EgressEnforcementStatus`** : `ENFORCED`, `PARTIAL`, `NOT_ENFORCED`, `UNKNOWN`, `UNSUPPORTED` (+ alias de rétrocompatibilité).
- **`EgressEnforcementProvider`** (classe abstraite) :
  - **`WindowsEgressProvider`** : interroge `netsh advfirewall show allprofiles` et `netsh advfirewall firewall show rule`. Vérifie :
    1. L'activation d'au moins un profil pare-feu ;
    2. L'existence et l'activation (`Enabled=Oui/Yes`) de `SSM_NVR_FFmpeg_Egress_AllowCameras` ;
    3. La correspondance du chemin d'exécutable (`Programme :` / `Program:`) ;
    4. La politique sortante effective : si `DefaultOutbound=Allow` sans règle `SSM_NVR_FFmpeg_Egress_BlockProhibited`, retourne **`PARTIAL`** (et jamais `ENFORCED`).
    5. Si une variable `SSM_EGRESS_*` est positionnée sans règle système réelle, positionne `diagnostics["env_spoofing_detected"] = True` et retourne `NOT_ENFORCED`.
  - **`LinuxEgressProvider`** : inspecte `nft list ruleset` puis `iptables -L OUTPUT -n`.
  - **`DockerEgressProvider`** : vérifie `/.dockerenv`, l'utilisateur non-root et la présence d'une preuve hôte `/run/ssm_egress_enforced.marker` ; à défaut retourne `PARTIAL`.
  - **`UnsupportedEgressProvider`** : retourne `UNSUPPORTED`.

---

## 2. COMPORTEMENT FAIL-CLOSED DANS `FFmpegRTSPAdapter.connect()`

Dans `monitoring/acquisition/ffmpeg_adapter.py` (lignes 189-203) :
Lorsque `require_os_egress_confinement = True`, `connect()` ré-évalue dynamiquement `check_egress_enforcement_status(expected_executable=self.ffmpeg_bin, ...)` et rejette le démarrage (`VideoSourceStatus.BLOCKED_SSRF`, retour `False`) pour tout statut différent de `ENFORCED` (`PARTIAL`, `NOT_ENFORCED`, `UNKNOWN`, `UNSUPPORTED`).
