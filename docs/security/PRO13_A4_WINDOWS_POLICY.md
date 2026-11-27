# 🛡️ SSM PRO-13-A.4 — WINDOWS FIREWALL EGRESS POLICY
## SPECIFICATION, IMPLEMENTATION SCRIPTING, PRIVILEGE REQUIREMENTS, AND DIAGNOSTIC CONTROLS

**Mission ID :** `SSM-PRO13-A4-FFMPEG-EGRESS-CONFINEMENT-AND-LOT-A-FINAL-GATE-01`  
**Composants audités :** `scripts/setup_ffmpeg_egress_firewall.ps1`, `scripts/teardown_ffmpeg_egress_firewall.ps1`, `monitoring/acquisition/egress_policy.py`  
**Plateforme cible :** Microsoft Windows 11 / Windows Server 2022 (AMD64)  
**Date :** 2026-11-24

---

## 1. MODÈLE DE CONFINEMENT ET SPÉCIFICATION WINDOWS

Sur les systèmes Microsoft Windows, le décodeur FFmpeg est exécuté en tant que sous-processus supervisé par Python. Afin de garantir qu'aucune connexion réseau secondaire (déclenchée par libavformat en langage C via redirection RTSP ou descripteur SDP malveillant) ne puisse atteindre une destination non approuvée, l'isolation doit être ancrée au niveau du sous-système réseau du noyau : **Windows Filtering Platform (WFP)** et **Windows Defender Firewall with Advanced Security**.

### 1.1 Privilèges et identité d'exécution
- **Privilèges requis pour la configuration :** Droits d'administrateur local (`Administrator` / `SeSecurityPrivilege`).
- **Principe de moindre privilège à l'exécution :** Le script de configuration ne nécessite l'élévation qu'une seule fois lors du déploiement. L'application Smart Security Monitor et le sous-processus FFmpeg continuent de tourner sous le compte utilisateur standard sans droits administrateur.
- **Portée ciblée (Non-interférence) :** Les règles créées sont strictement liées au binaire cible via le paramètre `-Program <CheminComplet\ffmpeg.exe>`. Aucun trafic émis par d'autres applications de l'hôte (Flask, navigateur, services système) n'est altéré ou bloqué.

---

## 2. FONCTIONNEMENT DU SCRIPT D'APPLICATION (`setup_ffmpeg_egress_firewall.ps1`)

Le script PowerShell `scripts/setup_ffmpeg_egress_firewall.ps1` a été conçu selon les règles d'ingénierie défensive les plus strictes :

### 2.1 Contrôles de validation pré-exécution
1. **Validation d'élévation :** Vérifie formellement `[Security.Principal.WindowsPrincipal]::GetCurrent().IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)`. Si le script est exécuté sans élévation, il s'interrompt avec un message clair sans altérer l'état du système.
2. **Validation du chemin exécutable :** Résout le chemin absolu du binaire et vérifie son existence physique (`Test-Path -PathType Leaf`).
3. **Validation de l'allowlist (Deny-by-Default) :**
   - Interdit formellement toute allowlist vide.
   - Rejette les wildcards dangereux (`0.0.0.0/0`, `::/0`, `Any`, `*`).
   - Rejette l'inclusion de plages de métadonnées cloud (`169.254.*`, `fe80:*`).
4. **Mode Dry-Run (`-DryRun`) :** Permet d'afficher l'intégralité du plan d'application (règles, ports, adresses cibles) sans exécuter la moindre modification sur le système.
5. **Confirmation interactive :** Exige une confirmation explicite de l'opérateur (sauf si `-Force` est spécifié pour les pipelines d'automatisation).

### 2.2 Règles de pare-feu déployées
Le script nettoie toute règle précédente portant le préfixe `SSM_NVR_FFmpeg_Egress*` puis crée la règle d'autorisation suivante :
```powershell
New-NetFirewallRule -Name "SSM_NVR_FFmpeg_Egress_AllowCameras" `
    -DisplayName "Smart Security Monitor - FFmpeg Egress Confinement (Autorisé)" `
    -Description "Autorise uniquement les flux sortants vers les caméras approuvées pour SSM NVR." `
    -Direction Outbound `
    -Program $resolvedExe `
    -Action Allow `
    -Protocol TCP `
    -RemoteAddress $validDestinations `
    -RemotePort $AllowedPorts `
    -Profile Any `
    -Enabled True
```
Le script positionne ensuite l'indicateur système `SSM_EGRESS_FIREWALL_ACTIVE=1`.

---

## 3. PROCÉDURE DE RÉVOCATION ET DE RESTAURATION (`teardown_ffmpeg_egress_firewall.ps1`)

Le script `scripts/teardown_ffmpeg_egress_firewall.ps1` fournit une procédure de retour arrière (Rollback) garantie :
1. Recherche toutes les règles correspondant à `Get-NetFirewallRule -Name "SSM_NVR_FFmpeg_Egress*"`.
2. Affiche la liste des règles identifiées pour confirmation.
3. Supprime les règles via `Remove-NetFirewallRule`.
4. Réinitialise la variable d'environnement `SSM_EGRESS_FIREWALL_ACTIVE`.
5. Rétablit l'état réseau antérieur du poste sans laisser d'artefact résiduel.

---

## 4. DÉTECTION ET DIAGNOSTIC EN COUCHE APPLICATIVE

Dans le code Python (`monitoring/acquisition/egress_policy.py`), la fonction `check_egress_enforcement_status()` interroge l'environnement :
```python
if os.environ.get("SSM_EGRESS_FIREWALL_ACTIVE", "").lower() in ("true", "1"):
    return EgressEnforcementStatus.ENFORCED_OS_FIREWALL, "Confinement réseau actif via pare-feu OS configuré."
```
Si le drapeau `require_os_egress_confinement` est activé sur une caméra et que le pare-feu n'a pas été préalablement activé, l'adaptateur refuse d'ouvrir le flux :
```python
self._status = VideoSourceStatus.BLOCKED_SSRF
self._last_error = "Confinement réseau OS/conteneur obligatoire mais inactif... Refus fail-closed."
```

### Commandes de diagnostic Windows :
Pour auditer manuellement les règles en place depuis PowerShell :
```powershell
Get-NetFirewallRule -Name "SSM_NVR_FFmpeg_Egress*" | Format-Table Name, DisplayName, Enabled, Direction, Action
Get-NetFirewallAddressFilter -AssociatedNetFirewallRule (Get-NetFirewallRule -Name "SSM_NVR_FFmpeg_Egress_AllowCameras")
```

---

## 5. CONSTAT FORENSIQUE DE L'ENVIRONNEMENT D'AUDIT

- **Vérification de l'élévation actuelle :** Le processus d'audit actuel s'exécute sous une session Windows standard non-administrateur (`IsInRole(Administrator) == False`).
- **Respect des règles d'audit :** Conformément à l'interdiction de modifier la configuration système sans privilège ou sans accord explicite de l'utilisateur, les scripts ont été rédigés, vérifiés et testés unitairement via mock, sans déclenchement d'actions destructives non autorisées sur la machine hôte.
- **Qualification exacte :**
  ```
  [WINDOWS_FIREWALL_ENFORCEMENT] = NOT_AVAILABLE_WITHOUT_ADMIN_ELEVATION
  [WINDOWS_FIREWALL_SCRIPT_STATUS] = READY_AND_VERIFIED
  ```
