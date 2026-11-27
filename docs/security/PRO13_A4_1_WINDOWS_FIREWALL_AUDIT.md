# 🛡️ SSM PRO-13-A.4.1 — WINDOWS FIREWALL SCRIPT AUDIT
## CRITICAL SECURITY EVALUATION OF SETUP/TEARDOWN POWERSHELL SCRIPTS AND WINDOWS DEFENDER FIREWALL BEHAVIOR

**Mission ID :** `SSM-PRO13-A4.1-INDEPENDENT-EGRESS-ENFORCEMENT-AUDIT-01`  
**Composants audités :** `scripts/setup_ffmpeg_egress_firewall.ps1`, `scripts/teardown_ffmpeg_egress_firewall.ps1`  
**HEAD audité :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Plateforme d'audit :** Microsoft Windows 11 AMD64  
**Date d'audit :** 2026-11-24

---

## 1. AUDIT DU SCRIPT DE CONFIGURATION (`setup_ffmpeg_egress_firewall.ps1`)

L'auditeur indépendant a examiné le script PowerShell `scripts/setup_ffmpeg_egress_firewall.ps1` en tant que code sensible d'infrastructure.

### 1.1 Points forts et contrôles de sécurité validés
1. **Contrôle d'élévation strict (Lignes 54-59) :**
   Le script teste explicitement l'appartenance au groupe `Administrator` via l'API .NET :
   ```powershell
   $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
   if (-not $isAdmin -and -not $DryRun) { Write-Error "..."; exit 1 }
   ```
2. **Canonicalisation du chemin (Lignes 62-66) :**
   Le chemin de l'exécutable est résolu par le fournisseur PowerShell (`GetUnresolvedProviderPathFromPSPath`), et l'existence du fichier est testée (`Test-Path -PathType Leaf`).
3. **Validation pré-exécution de l'Allowlist (Lignes 69-92) :**
   Le script rejette les listes vides, les chaînes génériques (`0.0.0.0/0`, `::/0`, `Any`, `*`) et les plages de métadonnées cloud (`169.254.*`, `fe80:*`).
4. **Idempotence et nettoyage (Lignes 120-121) :**
   Avant toute création, les anciennes règles préfixées `SSM_NVR_FFmpeg_Egress*` sont supprimées.

---

### 1.2 DÉFAUT ARCHITECTURAL CRITIQUE MIS EN ÉVIDENCE

L'examen approfondi des règles Windows Defender Firewall créées révèle une lacune majeure dans le mécanisme de restriction :

#### Règle créée (Lignes 125-135) :
```powershell
New-NetFirewallRule -Name $allowRuleName `
    -Program $resolvedExe `
    -Action Allow `
    -Protocol TCP `
    -RemoteAddress $validDestinations `
    -RemotePort $AllowedPorts `
    -Direction Outbound
```

#### Mécanisme réel de Windows Defender Firewall :
1. Sur les installations Microsoft Windows standard (Windows 10/11, Windows Server), le profil de pare-feu est configuré par défaut en **Sortie Autorisée** (`DefaultOutboundAction: Allow`).
2. Lorsqu'un paquet réseau sortant est émis par `ffmpeg.exe` :
   - Si la destination est dans `$validDestinations`, elle correspond à la règle et est autorisée.
   - Si la destination est une adresse non approuvée (ex: `10.0.0.1` ou `169.254.169.254`), elle **ne correspond à aucune règle spécifique** et est par conséquent **AUTORISÉE PAR LA POLITIQUE PAR DÉFAUT DU PARE-FEU**.
3. **Le piège de la précédence Block vs Allow sous Windows :**  
   Pour empêcher ce trafic non autorisé, une règle `-Action Block` générale sur l'exécutable ne peut pas simplement être ajoutée, car sous Windows Defender Firewall, **les règles BLOCK sont prioritaires sur les règles ALLOW** (`Block overrides Allow`). Une règle `Block -RemoteAddress Any` bloquerait indistinctement les caméras autorisées !

#### Solution d'ingénierie requise pour un confinement effectif :
Pour qu'une liste blanche soit réellement restrictive sous Windows sans altérer le profil global de la machine, il faut soit :
- Configurer une règle de blocage pour l'exécutable dont le paramètre `-RemoteAddress` couvre les plages interdites explicites (ex: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` privé résiduel, `169.254.0.0/16`, Internet).
- Ou utiliser l'API native Windows Filtering Platform (WFP) avec une sous-couche dédiée configurée avec un poids supérieur pour l'autorisation.
- Ou configurer le sous-processus dans un compte de service ou conteneur Windows Sandbox avec profil sortant par défaut à `Block`.

---

## 2. AUDIT DU SCRIPT DE RÉVOCATION (`teardown_ffmpeg_egress_firewall.ps1`)

L'audit de `scripts/teardown_ffmpeg_egress_firewall.ps1` confirme sa parfaite innocuité :
1. **Portée ciblée :** La suppression est restreinte au préfixe `SSM_NVR_FFmpeg_Egress*`. Aucune règle tierce ou système n'est affectée.
2. **Nettoyage d'état :** La variable `SSM_EGRESS_FIREWALL_ACTIVE` est purgée de la table Machine.
3. **Idempotence :** Si aucune règle n'est présente, le script quitte avec succès sans erreur.

---

## 3. CONSTAT SUR L'ENVIRONNEMENT D'AUDIT

- Le compte de la session d'audit est non-administrateur (`Administrator: False`).
- Les scripts n'ont pas été appliqués sur la machine hôte conformément au mandat Read-Only.
- **Verdict :** Le script de configuration est syntaxiquement valide et sécurisé contre les injections de commandes, mais **son modèle de filtrage actuel n'est pas suffisant pour assurer un Deny-by-Default sur Windows** tant qu'une règle de blocage inverse ou un profil sortant par défaut à Block n'est pas configuré.
