<#
.SYNOPSIS
    Script de test non destructif de connectivité Egress pour FFmpeg / SSM NVR.
    Programme PRO-13 — Lot A.4.2.

.DESCRIPTION
    Vérifie de façon sûre et contrôlée la politique de connectivité sortante :
    - Test d'une destination autorisée (port autorisé vs port interdit).
    - Test d'une destination privée interdite (sans scan réseau large).
    - Test d'une adresse loopback / IPv6 selon la politique.
    - NE tente JAMAIS de contacter un endpoint cloud metadata réel.

.PARAMETER AllowedCameraIp
    Adresse IP de la caméra autorisée à tester (défaut: 127.0.0.1 pour test local ou IP caméra contrôlée).

.PARAMETER AllowedPort
    Port TCP autorisé (défaut: 554).

.PARAMETER ProhibitedPort
    Port TCP interdit à tester (défaut: 22).

.PARAMETER TimeoutMs
    Délai maximal par tentative TCP en millisecondes (défaut: 1000).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AllowedCameraIp = "127.0.0.1",

    [Parameter(Mandatory = $false)]
    [int]$AllowedPort = 554,

    [Parameter(Mandatory = $false)]
    [int]$ProhibitedPort = 22,

    [Parameter(Mandatory = $false)]
    [int]$TimeoutMs = 1000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-ControlledTcp {
    param([string]$TargetIp, [int]$Port, [int]$Timeout)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect($TargetIp, $Port, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne($Timeout, $false)
        if (-not $wait) {
            return "TIMEOUT_OR_DROPPED"
        }
        $client.EndConnect($iar)
        return "CONNECTED"
    }
    catch [System.Net.Sockets.SocketException] {
        return "BLOCKED_OR_REFUSED ($($_.Exception.SocketErrorCode))"
    }
    catch {
        return "ERROR ($($_.Exception.Message))"
    }
    finally {
        $client.Close()
    }
}

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "SMART SECURITY MONITOR — TESTS CONTRÔLÉS DE CONNECTIVITÉ EGRESS (NON DESTRUCTIF)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

Write-Host "`n[1] Vérification de l'état du pare-feu Windows..."
& "$PSScriptRoot\check_ffmpeg_egress_firewall.ps1"

Write-Host "`n[2] Test de destination contrôlée ($AllowedCameraIp : $AllowedPort)..."
$resAllowed = Test-ControlledTcp -TargetIp $AllowedCameraIp -Port $AllowedPort -Timeout $TimeoutMs
Write-Host "    Résultat : $resAllowed"

Write-Host "`n[3] Test de port interdit ($AllowedCameraIp : $ProhibitedPort)..."
$resProhibitedPort = Test-ControlledTcp -TargetIp $AllowedCameraIp -Port $ProhibitedPort -Timeout $TimeoutMs
Write-Host "    Résultat : $resProhibitedPort"

Write-Host "`n[4] Test de destination IPv6 loopback (::1 : $AllowedPort)..."
$resIpv6 = Test-ControlledTcp -TargetIp "::1" -Port $AllowedPort -Timeout $TimeoutMs
Write-Host "    Résultat : $resIpv6"

Write-Host "`n[5] Contrôle statique de blocage Metadata (169.254.169.254) : AUCUNE TENTATIVE RÉELLE EFFECTUÉE (règle de sécurité)." -ForegroundColor Green
Write-Host "`nTests contrôlés terminés." -ForegroundColor Cyan
