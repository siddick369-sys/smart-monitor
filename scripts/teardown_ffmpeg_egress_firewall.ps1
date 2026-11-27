<#
.SYNOPSIS
    Script de révocation et de restauration du pare-feu Windows pour le confinement Egress de FFmpeg.
    Programme PRO-13 — Lot A.4.2.

.DESCRIPTION
    Supprime proprement toutes les règles Windows Defender Firewall créées par setup_ffmpeg_egress_firewall.ps1
    sous le préfixe exclusif 'SSM_NVR_FFmpeg_Egress*'.
    Ne modifie jamais le profil global du pare-feu ni les règles étrangères au projet.
    Idempotent et vérifie la suppression effective. Nécessite des privilèges Administrateur.

.PARAMETER Force
    Supprime les règles sans demande de confirmation interactive.

.PARAMETER DryRun
    Simule la révocation sans supprimer les règles.

.EXAMPLE
    .\teardown_ffmpeg_egress_firewall.ps1 -Force
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "SMART SECURITY MONITOR — RÉVOCATION DU PARE-FEU EGRESS FFMPEG (PRO-13 A.4.2)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $DryRun) {
    Write-Error "Privilèges Administrateur requis pour supprimer les règles de pare-feu."
    exit 1
}

$rulePrefix = "SSM_NVR_FFmpeg_Egress"
$existingRules = @(Get-NetFirewallRule -Name "${rulePrefix}*" -ErrorAction SilentlyContinue)

if ($existingRules.Count -eq 0) {
    Write-Host "Aucune règle active sous le préfixe '$rulePrefix' n'a été trouvée (état déjà propre)." -ForegroundColor Yellow
    if (-not $DryRun) {
        [Environment]::SetEnvironmentVariable("SSM_EGRESS_FIREWALL_ACTIVE", $null, "Machine")
    }
    exit 0
}

Write-Host "`nRègles SSM identifiées pour suppression :" -ForegroundColor Yellow
foreach ($rule in $existingRules) {
    Write-Host "  - $($rule.Name) ($($rule.DisplayName))"
}

if ($DryRun) {
    Write-Host "`n[DRY-RUN] Aucune règle supprimée." -ForegroundColor Green
    exit 0
}

if (-not $Force) {
    $confirm = Read-Host "`nConfirmez-vous la suppression de ces $($existingRules.Count) règles de pare-feu SSM ? (O/N)"
    if ($confirm -notmatch "^[oOyY]$") {
        Write-Host "Opération annulée par l'opérateur." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host "`nSuppression des règles SSM en cours..." -ForegroundColor Gray
$existingRules | Remove-NetFirewallRule

# Nettoyage de l'ancienne variable héritée
[Environment]::SetEnvironmentVariable("SSM_EGRESS_FIREWALL_ACTIVE", $null, "Machine")

# Vérification post-suppression
$remaining = @(Get-NetFirewallRule -Name "${rulePrefix}*" -ErrorAction SilentlyContinue)
if ($remaining.Count -gt 0) {
    Write-Error "Échec partiel du rollback : $($remaining.Count) règle(s) SSM subsiste(nt)."
    exit 1
}

Write-Host "Règles SSM révoquées et vérifiées avec succès. Aucune règle tierce affectée." -ForegroundColor Green
