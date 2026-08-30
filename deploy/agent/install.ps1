<#
.SYNOPSIS
    Installs the CertManager agent as a Windows Service.
.DESCRIPTION
    Creates a Windows Service using NSSM (Non-Sucking Service Manager)
    or the built-in New-Service cmdlet. NSSM is preferred for proper
    process monitoring and restart behavior.

    Usage (Administrator PowerShell):
        .\install.ps1 -ConfigPath "C:\ProgramData\CertManager\agent_config.json"
#>
param(
    [string]$ConfigPath = "agent_config.json",
    [string]$PythonPath = "",
    [int]$Port = 8443
)

$ErrorActionPreference = "Stop"

# Resolve Python
if (-not $PythonPath) {
    $PythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $PythonPath) {
        $PythonPath = (Get-Command python3 -ErrorAction SilentlyContinue).Source
    }
}

if (-not $PythonPath) {
    Write-Error "Python not found. Install Python 3.12+ or specify -PythonPath"
    exit 1
}

$AgentModule = "certmanager.agent.agent"
$ServiceName = "CertManagerAgent"
$DisplayName = "CertManager Datacenter Agent"
$Description = "Certificate discovery agent for CertManager — scans AD CS and/or TLS endpoints in this datacenter."
$WorkDir = Split-Path $ConfigPath -Parent

Write-Host "=== CertManager Agent Windows Service Installer ==="
Write-Host "Python:    $PythonPath"
Write-Host "Config:    $ConfigPath"
Write-Host "WorkDir:   $WorkDir"
Write-Host ""

# Check if NSSM is available (preferred)
$nssm = Get-Command nssm -ErrorAction SilentlyContinue

if ($nssm) {
    Write-Host "Using NSSM for service management..."

    # Stop existing service if running
    & nssm stop $ServiceName 2>$null
    & nssm remove $ServiceName confirm 2>$null

    # Install
    & nssm install $ServiceName $PythonPath "-m $AgentModule"
    & nssm set $ServiceName AppDirectory $WorkDir
    & nssm set $ServiceName DisplayName $DisplayName
    & nssm set $ServiceName Description $Description
    & nssm set $ServiceName Start SERVICE_AUTO_START
    & nssm set $ServiceName AppRestartDelay 10000
    & nssm set $ServiceName AppStdout "$WorkDir\agent_stdout.log"
    & nssm set $ServiceName AppStderr "$WorkDir\agent_stderr.log"
    & nssm set $ServiceName AppRotateFiles 1
    & nssm set $ServiceName AppRotateOnline 1
    & nssm set $ServiceName AppRotateSeconds 86400
    & nssm set $ServiceName AppRotateBytes 10485760

    Write-Host "Service installed. Starting..."
    & nssm start $ServiceName

} else {
    Write-Host "NSSM not found. Download: https://nssm.cc/download"
    Write-Host "Falling back to New-Service (limited restart behavior)..."

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-Service $ServiceName -Force
        sc.exe delete $ServiceName
    }

    $binPath = "`"$PythonPath`" -m $AgentModule"

    New-Service `
        -Name $ServiceName `
        -BinaryPathName $binPath `
        -DisplayName $DisplayName `
        -Description $Description `
        -StartupType Automatic

    # Set recovery options: restart on failure
    sc.exe failure $ServiceName reset=86400 actions=restart/10000/restart/30000/restart/60000

    Start-Service $ServiceName
}

Write-Host ""
Write-Host "Service '$ServiceName' installed and started."
Write-Host "Check status: Get-Service $ServiceName"
Write-Host "View logs:  Get-EventLog -LogName Application -Source $ServiceName"
Write-Host "Uninstall:  nssm remove $ServiceName confirm   (or: sc.exe delete $ServiceName)"
