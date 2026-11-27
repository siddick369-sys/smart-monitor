# 🛡️ SSM PRO-13-A.4.2 — WINDOWS EFFECTIVE POLICY AUDIT
## AUDIT DE LA POLITIQUE EFFECTIVE WINDOWS, DIAGNOSTIC NON DESTRUCTIF ET ROLLBACK

**Mission ID :** `SSM-PRO13-A4.2-CORRECTIVE-EGRESS-ENFORCEMENT-AND-VERIFICATION-01`  
**Branche :** `main` | **HEAD initial/final :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Timestamp :** `2026-11-26T06:40:00+01:00`  
**Environnement :** `Microsoft Windows 11 AMD64 · Session non-administrateur`

---

## 1. DIAGNOSTIC NON DESTRUCTIF DE L'HÔTE (`check_ffmpeg_egress_firewall.ps1`)

Le script `scripts/check_ffmpeg_egress_firewall.ps1` a été exécuté sur le poste d'audit sans aucune modification système :

- **Commande :** `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\check_ffmpeg_egress_firewall.ps1`
- **Sortie observée :**
  - `Profil Domain : Enabled=True, DefaultOutboundAction=NotConfigured`
  - `Profil Private : Enabled=True, DefaultOutboundAction=NotConfigured`
  - `Profil Public : Enabled=True, DefaultOutboundAction=NotConfigured`
  - `[DIAGNOSTIC] Règle Allow 'SSM_NVR_FFmpeg_Egress_AllowCameras' introuvable.`
  - Verdict émis : `WINDOWS_EGRESS_NOT_ENFORCED`
- **Code retour :** `1` (non-enforced)

---

## 2. AUDIT DU ROLLBACK (`teardown_ffmpeg_egress_firewall.ps1`)

- Utilise `Set-StrictMode -Version Latest` et `$ErrorActionPreference = "Stop"`.
- Cible exclusivement le préfixe `SSM_NVR_FFmpeg_Egress*`.
- Ne modifie jamais `Set-NetFirewallProfile` ni les règles étrangères au projet.
- Vérifie post-suppression qu'aucune règle SSM ne subsiste.
- Testé en mode `-DryRun` (code retour `0`).

---

## 3. PROCÉDURE MANUELLE POUR L'OPÉRATEUR ADMINISTRATEUR

Pour activer et vérifier réellement le pare-feu Windows sur un poste administrateur :
```powershell
# 1. Installation (en PowerShell Administrateur)
.\scripts\setup_ffmpeg_egress_firewall.ps1 -ExecutablePath "C:\chemin\vers\ffmpeg.exe" -AllowedDestinations @("192.168.1.50/32")

# 2. Diagnostic non destructif
.\scripts\check_ffmpeg_egress_firewall.ps1 -ExecutablePath "C:\chemin\vers\ffmpeg.exe"

# 3. Tests contrôlés de connectivité
.\scripts\test_ffmpeg_egress_connectivity.ps1 -AllowedCameraIp "192.168.1.50"

# 4. Rollback si nécessaire
.\scripts\teardown_ffmpeg_egress_firewall.ps1
```

**Statut de qualification :** Diagnostic et scripts vérifiés ; exécution réelle `NOT_AVAILABLE` sans privilèges administrateur.
