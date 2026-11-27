<#
.SYNOPSIS
    Script de configuration du pare-feu Windows Defender pour le confinement réseau sortant (Egress) de FFmpeg.
    Programme PRO-13 — Lot A.4.2 (Remédiation Deny-by-Default et Precedence Block/Allow).

.DESCRIPTION
    Crée des règles de filtrage de sortie dédiées à l'exécutable FFmpeg afin d'interdire le trafic
    vers des destinations non approuvées (métadonnées cloud, loopback, multicast, plages privées non autorisées).
    Corrige le défaut PRO-13-A.4.1 : sous Windows avec DefaultOutboundAction=Allow, une règle Allow isolée
    ne bloque pas les autres destinations. Ce script installe donc des règles Block complémentaires
    ou active le profil sortant Block si -EnforceDefaultBlockProfile est spécifié.
    Nécessite des privilèges Administrateur. Ne modifie pas la configuration globale sans confirmation.

.PARAMETER ExecutablePath
    Chemin absolu vers le binaire ffmpeg.exe (obligatoire).

.PARAMETER AllowedDestinations
    Tableau des adresses IP ou sous-réseaux CIDR autorisés pour les caméras (ex: "192.168.1.50/32").

.PARAMETER AllowedPorts
    Ports TCP autorisés (par défaut: 554, 8554, 80, 443, 8080, 8081).

.PARAMETER EnforceDefaultBlockProfile
    Optionnel. Configure DefaultOutboundAction=Block sur les profils actifs (avec confirmation explicite).

.PARAMETER DryRun
    Affiche les règles planifiées sans les appliquer.

.PARAMETER Force
    Applique les règles sans demande de confirmation interactive.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExecutablePath,

    [Parameter(Mandatory = $true)]
    [string[]]$AllowedDestinations,

    [Parameter(Mandatory = $false)]
    [int[]]$AllowedPorts = @(554, 8554, 80, 443, 8080, 8081),

    [Parameter(Mandatory = $false)]
    [switch]$EnforceDefaultBlockProfile,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "SMART SECURITY MONITOR — CONFIGURATION DU CONFINEMENT EGRESS FFMPEG (PRO-13 A.4.2)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Vérification des privilèges Administrateur
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $DryRun) {
    Write-Error "Privilèges Administrateur requis. Veuillez exécuter PowerShell en tant qu'administrateur."
    exit 1
}

# 2. Validation du chemin de l'exécutable
$resolvedExe = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExecutablePath)
if (-not [System.IO.Path]::IsPathRooted($resolvedExe)) {
    Write-Error "Le chemin de l'exécutable doit être absolu : '$resolvedExe'."
    exit 1
}
if (-not (Test-Path -Path $resolvedExe -PathType Leaf) -and -not $DryRun) {
    Write-Error "Le binaire spécifié est introuvable : '$resolvedExe'."
    exit 1
}

# 3. Validation stricte des destinations autorisées (Deny-by-Default)
if ($AllowedDestinations.Count -eq 0) {
    Write-Error "La liste des destinations autorisées ne peut pas être vide."
    exit 1
}

$validDestinations = @()
foreach ($dest in $AllowedDestinations) {
    $trimmed = $dest.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }

    # Rejet des masques génériques dangereux
    if ($trimmed -in @("0.0.0.0/0", "::/0", "*", "Any", "0.0.0.0", "::")) {
        Write-Error "Destination trop large ou non spécifiée interdite dans la politique d'egress : '$trimmed'."
        exit 1
    }

    # Rejet des préfixes IPv4 <= /8
    if ($trimmed -match "^(\d{1,3}\.){3}\d{1,3}/(\d{1,2})$") {
        $prefix = [int]$Matches[2]
        if ($prefix -le 8) {
            Write-Error "Masque réseau trop large interdit (/$prefix <= /8) : '$trimmed'."
            exit 1
        }
    }

    # Rejet des métadonnées cloud, link-local, loopback, multicast
    if ($trimmed -like "169.254.*" -or $trimmed -like "fe80:*" -or $trimmed -like "127.*" -or $trimmed -eq "::1" -or $trimmed -like "224.*" -or $trimmed -like "ff0*") {
        Write-Error "Inclusion interdite d'adresses réservées / link-local / métadonnées / loopback : '$trimmed'."
        exit 1
    }

    $validDestinations += $trimmed
}

if ($validDestinations.Count -eq 0) {
    Write-Error "Aucune destination valide après filtrage."
    exit 1
}

# 4. Validation des ports
foreach ($p in $AllowedPorts) {
    if ($p -lt 1 -or $p -gt 65535) {
        Write-Error "Port TCP invalide : $p"
        exit 1
    }
}

# 5. Calcul exact des plages CIDR complémentaires (PRO-13 A.4.4 Lot C)
# Élimine toute exclusion naïve par classe (/8, /12, /16) et couvre IPv4 + IPv6 publics et privés
$rulePrefix = "SSM_NVR_FFmpeg_Egress"
$allowRuleName = "${rulePrefix}_AllowCameras"
$blockRuleName = "${rulePrefix}_BlockProhibited"

$destCsv = $validDestinations -join ","
$cidrCalcScript = @"
import json, sys
from monitoring.acquisition.egress_policy import compute_complementary_block_cidrs
res = compute_complementary_block_cidrs(sys.argv[1].split(','))
print(json.dumps(res))
"@
$cidrResultRaw = python -c $cidrCalcScript $destCsv
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($cidrResultRaw)) {
    Write-Error "Échec du calcul CIDR complémentaire (IPv4/IPv6)."
    exit 1
}
$cidrResult = $cidrResultRaw | ConvertFrom-Json
$validDestinations = @($cidrResult.allowed_ipv4) + @($cidrResult.allowed_ipv6)
$explicitReserved = @("169.254.169.254/32", "169.254.0.0/16", "fe80::/10", "127.0.0.0/8", "::1/128", "224.0.0.0/4", "ff00::/8", "255.255.255.255/32")
if ($cidrResult.allowed_ipv6.Count -eq 0) {
    $explicitReserved += "fc00::/7"
}
$prohibitedRanges = @($explicitReserved + @($cidrResult.block_ipv4) + @($cidrResult.block_ipv6) | Select-Object -Unique)

Write-Host "`nPlan de configuration du pare-feu :" -ForegroundColor Yellow
Write-Host "  Exécutable cible     : $resolvedExe"
Write-Host "  Règle autorisée      : $allowRuleName"
Write-Host "  Destinations (Allow) : $($validDestinations -join ', ')"
Write-Host "  Ports TCP admis      : $($AllowedPorts -join ', ')"
Write-Host "  Règle blocage        : $blockRuleName"
Write-Host "  Plages bloquées      : $($prohibitedRanges -join ', ')"
Write-Host "  Profil DefaultBlock  : $EnforceDefaultBlockProfile"

if ($DryRun) {
    Write-Host "`n[DRY-RUN] Aucune modification effectuée sur le pare-feu système." -ForegroundColor Green
    exit 0
}

# 6. Demande de confirmation si non forcé
if (-not $Force) {
    $confirm = Read-Host "`nConfirmez-vous l'application de ces règles sur Windows Defender Firewall ? (O/N)"
    if ($confirm -notmatch "^[oOyY]$") {
        Write-Host "Opération annulée par l'opérateur." -ForegroundColor Yellow
        exit 0
    }
}

# 7. Nettoyage idempotent des anciennes règles SSM
Write-Host "`nNettoyage des règles précédentes..." -ForegroundColor Gray
Get-NetFirewallRule -Name "${rulePrefix}*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# 8. Création de la règle d'autorisation explicite
Write-Host "Création de la règle de sortie autorisée ($allowRuleName)..." -ForegroundColor Green
$allowRule = New-NetFirewallRule -Name $allowRuleName `
    -DisplayName "Smart Security Monitor - FFmpeg Egress Confinement (Allow)" `
    -Description "Autorise uniquement les flux sortants vers les caméras approuvées pour SSM NVR." `
    -Direction Outbound `
    -Program $resolvedExe `
    -Action Allow `
    -Protocol TCP `
    -RemoteAddress $validDestinations `
    -RemotePort $AllowedPorts `
    -Profile Any `
    -Enabled True

# 9. Création de la règle de blocage explicite des plages interdites
Write-Host "Création de la règle de blocage explicite ($blockRuleName)..." -ForegroundColor Yellow
$blockRule = New-NetFirewallRule -Name $blockRuleName `
    -DisplayName "Smart Security Monitor - FFmpeg Egress Confinement (Block Prohibited)" `
    -Description "Bloque explicitement métadonnées cloud, loopback, multicast et plages privées non autorisées." `
    -Direction Outbound `
    -Program $resolvedExe `
    -Action Block `
    -Protocol Any `
    -RemoteAddress $prohibitedRanges `
    -Profile Any `
    -Enabled True

# 10. Application optionnelle du profil DefaultOutboundAction=Block
if ($EnforceDefaultBlockProfile) {
    Write-Host "Application de DefaultOutboundAction=Block sur les profils actifs..." -ForegroundColor Yellow
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
}

# 11. Vérification post-installation
$verifiedRules = Get-NetFirewallRule -Name "${rulePrefix}*" -ErrorAction SilentlyContinue
if (-not $verifiedRules -or ($verifiedRules | Measure-Object).Count -lt 2) {
    Write-Error "Échec de vérification post-installation : toutes les règles n'ont pas été créées."
    exit 1
}

Write-Host "`nConfiguration du pare-feu appliquée et vérifiée avec succès !" -ForegroundColor Green
foreach ($r in $verifiedRules) {
    Write-Host "  - [$($r.Action)] $($r.Name) (Enabled=$($r.Enabled))"
}
Write-Host "Pour diagnostiquer l'état : .\check_ffmpeg_egress_firewall.ps1 -ExecutablePath `"$resolvedExe`""
Write-Host "Pour annuler              : .\teardown_ffmpeg_egress_firewall.ps1"
