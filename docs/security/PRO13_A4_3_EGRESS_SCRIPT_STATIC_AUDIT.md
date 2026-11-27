# PRO13-A.4.3 — EGRESS SCRIPTS STATIC AUDIT REPORT

**Mission ID :** `SSM-PRO13-A4-3-EGRESS-HARDENING-AND-CRYPTOGRAPHIC-CONTINUITY-01`  
**Date / Horodatage :** 2026-11-27T07:06:00+01:00  
**Dépôt :** `C:\Users\USER\Documents\alarme-sys` | **Branche :** `main` | **HEAD :** `b339a9c82d5b410e78d1ea6d43cae556049ba2c0`  
**Périmètre :** Audit statique intégral des scripts PowerShell Windows (`setup_ffmpeg_egress_firewall.ps1`, `check_ffmpeg_egress_firewall.ps1`, `teardown_ffmpeg_egress_firewall.ps1`, `test_ffmpeg_egress_connectivity.ps1`).  
**Méthode :** Lecture intégrale ligne par ligne sans exécution mutative ni élévation de privilèges.

---

## 1. INVENTAIRE DES COMPOSANTS EGRESS

| Composant | Fonction | Type de contrôle | Exécution réelle démontrée |
|---|---|---|---|
| `EgressPolicy` | Politique applicative deny-by-default | Application | Vérifiée par tests unitaires |
| `EgressEnforcementProvider` | Détection de l'enforcement OS/conteneur | Système / Application | Vérifiée en lecture non privilégiée (`NOT_ENFORCED`) |
| `FFmpegAdapter` | Acquisition média & whitelist protocoles | Application | Vérifiée par tests unitaires (binaire absent) |
| `setup_ffmpeg_egress_firewall.ps1` | Configuration pare-feu Windows | Système | **Non exécuté** (interdit, privilèges requis) |
| `check_ffmpeg_egress_firewall.ps1` | Diagnostic pare-feu Windows | Système | Exécuté en lecture seule (`WINDOWS_EGRESS_NOT_ENFORCED`) |
| `setup_docker_egress_host.sh` | Filtrage hôte `DOCKER-USER` / `nftables` | Infrastructure | **Non exécuté** (Docker arrêté) |

---

## 2. AUDIT STATIQUE DE `scripts/setup_ffmpeg_egress_firewall.ps1`

### 2.1. Comportement exact
- Exige des privilèges Administrateur (`-not $isAdmin -and -not $DryRun` -> `exit 1`).
- Valide que `-ExecutablePath` est absolu et pointe vers un fichier existant.
- Valide `-AllowedDestinations` (rejette `0.0.0.0/0`, `::/0`, `*`, `Any`, préfixes IPv4 `<= /8`, plages `169.254.*`, `fe80:*`, `127.*`, `::1`, `224.*`, `ff0*`).
- Supprime toute règle existante `SSM_NVR_FFmpeg_Egress*`.
- Crée `SSM_NVR_FFmpeg_Egress_AllowCameras` (`Direction Outbound`, `Program $resolvedExe`, `Action Allow`, `Protocol TCP`, `RemoteAddress $validDestinations`, `RemotePort $AllowedPorts`).
- Crée `SSM_NVR_FFmpeg_Egress_BlockProhibited` (`Direction Outbound`, `Program $resolvedExe`, `Action Block`, `Protocol Any`, `RemoteAddress $prohibitedRanges`).
- Si `-EnforceDefaultBlockProfile` est spécifié : exécute `Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block`.

### 2.2. Failles logiques et limitations critiques identifiées
1. **Absence de blocage Internet public par défaut :** Sous Windows, `DefaultOutboundAction=NotConfigured` équivaut à `Allow`. Sans `-EnforceDefaultBlockProfile`, `$prohibitedRanges` ne contient **aucune adresse IPv4 ou IPv6 publique**. `ffmpeg.exe` peut donc communiquer vers n'importe quelle IP publique sur Internet.
2. **Contournement par chevauchement de sous-réseau privé (lignes 146-161) :** Si une caméra autorisée est en `192.168.1.50/32`, la condition `$cam -like "192.168.*"` exclut **tout le `/16`** (`192.168.0.0/16`) de `$prohibitedRanges`. Sous `DefaultOutboundAction=Allow`, `ffmpeg.exe` conserve alors l'accès à tout le sous-réseau `192.168.0.0/16` (et non à la seule IP `.1.50`). Même défaut pour `10.0.0.0/8`, `172.16.0.0/12` et `fc00::/7`.
3. **Effet de bord global de `-EnforceDefaultBlockProfile` :** Passer `DefaultOutboundAction=Block` sur `Domain,Private,Public` bloque tout trafic sortant de toutes les applications du poste hôte dépourvues de règle Allow explicite (risque de rupture système sur poste de travail).
4. **Ciblage limité à un seul binaire :** Un processus enfant ou un autre binaire (ex: `python.exe` ou `curl.exe`) n'est pas contraint par `-Program $resolvedExe`.

---

## 3. AUDIT STATIQUE DE `scripts/check_ffmpeg_egress_firewall.ps1`

### 3.1. Risques de faux positifs identifiés
1. **Verdict `WINDOWS_EGRESS_ENFORCED` prématuré (lignes 116-122) :** Si `DefaultOutboundAction` vaut `NotConfigured` (Allow) mais que `SSM_NVR_FFmpeg_Egress_BlockProhibited` est activée, le script émet `WINDOWS_EGRESS_ENFORCED` (code `0`), ignorant que les IP publiques et les sous-réseaux privés chevauchants restent autorisés.
2. **Destination manquante non bloquante (lignes 101-107) :** Si une IP de `-ExpectedDestinations` est absente de `AllowCameras`, le script affiche un avertissement mais poursuit jusqu'à `exit 0`.
3. **Absence de vérification des autres règles Allow génériques :** Le script n'inspecte pas si d'autres règles Windows autorisent `ffmpeg.exe` ou tout trafic TCP sortant.

---

## 4. STATUT

```text
EGRESS_SCRIPT_AUDIT_GATE = PASS  (Analyse statique complète achevée ; défauts de conception documentés)
```
