<#
.SYNOPSIS
    Script de diagnostic non destructif du confinement réseau sortant (Egress) Windows pour FFmpeg.
    Programme PRO-13 — Lot A.4.4 (Suppression des faux positifs, couverture IPv4/IPv6 et proxy).

.DESCRIPTION
    Inspecte l'état réel de Windows Defender Firewall, les profils actifs, DefaultOutboundAction,
    les règles SSM_NVR_FFmpeg_Egress*, la couverture IPv4/IPv6 et les variables proxy.
    Ne modifie rien sur le système.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ExecutablePath = "",

    [Parameter(Mandatory = $false)]
    [string[]]$ExpectedDestinations = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$rulePrefix = "SSM_NVR_FFmpeg_Egress"
$allowRuleName = "${rulePrefix}_AllowCameras"
$blockRuleName = "${rulePrefix}_BlockProhibited"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "SMART SECURITY MONITOR — DIAGNOSTIC PARE-FEU EGRESS WINDOWS (PRO-13 A.4.4)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# Vérification des variables proxy dans l'environnement courant
$proxyVars = @("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
$proxyDetected = $false
foreach ($pv in $proxyVars) {
    $val = [Environment]::GetEnvironmentVariable($pv)
    if (-not [string]::IsNullOrWhiteSpace($val)) {
        $proxyDetected = $true
        Write-Host "[DIAGNOSTIC] Variable proxy détectée dans l'environnement : $pv" -ForegroundColor Yellow
        Write-Output "PROXY_CONFIGURATION_UNSAFE"
    }
}

try {
    # 1. Inspection des profils actifs
    $profiles = Get-NetFirewallProfile -ErrorAction Stop
    $activeProfiles = @($profiles | Where-Object { $_.Enabled -eq $true })

    if ($activeProfiles.Count -eq 0) {
        Write-Host "[DIAGNOSTIC] Aucun profil Windows Defender Firewall actif." -ForegroundColor Red
        Write-Output "PROFILE_DISABLED"
        Write-Output "WINDOWS_EGRESS_NOT_ENFORCED"
        exit 2
    }

    if ($activeProfiles.Count -lt 3) {
        Write-Output "PROFILE_DISABLED"
    }

    $allDefaultBlock = $true
    foreach ($prof in $profiles) {
        $outboundStr = $prof.DefaultOutboundAction
        if ($prof.Enabled -and $outboundStr -ne "Block") {
            $allDefaultBlock = $false
        }
        Write-Host "  Profil $($prof.Name) : Enabled=$($prof.Enabled), DefaultOutboundAction=$outboundStr"
    }

    if ($allDefaultBlock) {
        Write-Output "DEFAULT_OUTBOUND_BLOCK"
    }
    else {
        Write-Output "DEFAULT_OUTBOUND_ALLOW"
    }

    # 2. Inspection des règles SSM
    $allowRule = Get-NetFirewallRule -Name $allowRuleName -ErrorAction SilentlyContinue
    $blockRule = Get-NetFirewallRule -Name $blockRuleName -ErrorAction SilentlyContinue

    if (-not $allowRule) {
        Write-Host "[DIAGNOSTIC] Règle Allow '$allowRuleName' introuvable." -ForegroundColor Red
        Write-Output "WINDOWS_EGRESS_NOT_ENFORCED"
        exit 2
    }

    Write-Output "RULES_PRESENT"

    if ($allowRule.Enabled -ne "True") {
        Write-Host "[DIAGNOSTIC] Règle Allow '$allowRuleName' désactivée." -ForegroundColor Red
        Write-Output "RULES_DISABLED"
        Write-Output "WINDOWS_EGRESS_NOT_ENFORCED"
        exit 2
    }

    # 3. Vérification de l'exécutable associé
    $appFilter = $allowRule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
    $addrFilter = $allowRule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
    $portFilter = $allowRule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue

    Write-Host "  Règle Allow : Enabled=$($allowRule.Enabled), Program=$($appFilter.Program)"
    Write-Host "    RemoteAddress=$($addrFilter.RemoteAddress -join ', ')"
    Write-Host "    RemotePort=$($portFilter.RemotePort -join ', '), Protocol=$($portFilter.Protocol)"

    if ([string]::IsNullOrWhiteSpace($appFilter.Program) -or $appFilter.Program -eq "Any") {
        Write-Output "EXECUTABLE_SCOPE_INCOMPLETE"
        Write-Output "WINDOWS_EGRESS_NOT_ENFORCED"
        exit 2
    }

    if (-not [string]::IsNullOrWhiteSpace($ExecutablePath)) {
        $normExpected = [System.IO.Path]::GetFullPath($ExecutablePath).ToLowerInvariant()
        $normActual = if ($appFilter.Program) { $appFilter.Program.ToLowerInvariant() } else { "" }
        if ($normExpected -ne $normActual) {
            Write-Host "[DIAGNOSTIC] Discordance d'exécutable : attendu '$normExpected', trouvé '$normActual'." -ForegroundColor Red
            Write-Output "EXECUTABLE_SCOPE_INCOMPLETE"
            Write-Output "WINDOWS_EGRESS_NOT_ENFORCED"
            exit 2
        }
    }

    # 4. Vérification des destinations attendues
    $allowlistIncomplete = $false
    if ($ExpectedDestinations.Count -gt 0) {
        $addrs = @($addrFilter.RemoteAddress)
        foreach ($dest in $ExpectedDestinations) {
            $bare = $dest -replace "/32$", ""
            if ($addrs -notcontains $dest -and $addrs -notcontains $bare) {
                Write-Host "[DIAGNOSTIC] Destination attendue absente de la règle Allow : $dest" -ForegroundColor Red
                $allowlistIncomplete = $true
            }
        }
    }
    if ($allowlistIncomplete) {
        Write-Output "ALLOWLIST_INCOMPLETE"
        Write-Output "WINDOWS_EGRESS_NOT_ENFORCED"
        exit 2
    }

    # 5. Vérification stricte IPv4 / IPv6 et précédence effective
    if ($allDefaultBlock) {
        if ($proxyDetected) {
            Write-Output "WINDOWS_EGRESS_NOT_ENFORCED"
            exit 1
        }
        Write-Host "[DIAGNOSTIC] Politique DefaultOutbound=Block active avec règle Allow ciblée." -ForegroundColor Green
        Write-Output "WINDOWS_EGRESS_ENFORCED"
        exit 0
    }

    if (-not $blockRule -or $blockRule.Enabled -ne "True") {
        Write-Host "[DIAGNOSTIC] DefaultOutbound=Allow sans règle Block active." -ForegroundColor Red
        Write-Output "IPV4_COVERAGE_INCOMPLETE"
        Write-Output "IPV6_COVERAGE_INCOMPLETE"
        Write-Output "WINDOWS_EGRESS_NOT_ENFORCED"
        exit 1
    }

    $blockAddr = @($blockRule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue).RemoteAddress
    $hasIpv4PublicCoverage = ($blockAddr | Where-Object { $_ -match "^(0\.|128\.|192\.0\.|224\.|1\.|8\.)" -or $_ -match "/[1-4]$" }).Count -gt 0
    $hasIpv6Coverage = ($blockAddr | Where-Object { $_ -match ":" }).Count -gt 0

    if (-not $hasIpv4PublicCoverage) {
        Write-Output "IPV4_COVERAGE_INCOMPLETE"
    }
    if (-not $hasIpv6Coverage) {
        Write-Output "IPV6_COVERAGE_INCOMPLETE"
    }

    if ($hasIpv4PublicCoverage -and $hasIpv6Coverage -and -not $proxyDetected) {
        Write-Host "[DIAGNOSTIC] Couverture complémentaire IPv4 + IPv6 complète vérifiée." -ForegroundColor Green
        Write-Output "WINDOWS_EGRESS_ENFORCED"
        exit 0
    }

    Write-Host "[DIAGNOSTIC] Couverture Egress incomplète sous DefaultOutbound=Allow." -ForegroundColor Yellow
    Write-Output "WINDOWS_EGRESS_NOT_ENFORCED"
    exit 1
}
catch {
    Write-Host "[DIAGNOSTIC] Erreur d'inspection du pare-feu : $_" -ForegroundColor Red
    Write-Output "WINDOWS_EGRESS_UNKNOWN"
    exit 3
}
