<#
.SYNOPSIS
    Installs the CertManager agent as a Windows Service.

.DESCRIPTION
    Registers a Windows Service using NSSM (Non-Sucking Service Manager).
    NSSM is required: python.exe is not a service binary, so the built-in
    New-Service cmdlet cannot host the agent (the service would fail to
    start with error 1053).

    The agent is run as:

        python -m certmanager.cli agent run --config <config> --data-dir <data-dir>

    If the config file does not exist yet, a placeholder is written and
    hardened (ACLs restricted to SYSTEM and Administrators). Fill in the
    real values with an elevated editor or regenerate it with:

        certmanager agent init --config-path "<config>"

    Usage (Administrator PowerShell):

        .\install.ps1 -ConfigPath "C:\ProgramData\CertManager\agent_config.json"
#>
param(
    [string]$ConfigPath = "agent_config.json",
    [string]$DataDir = "",
    [string]$PythonPath = ""
)

$ErrorActionPreference = "Stop"

# --- Validate config path (must be absolute) -----------------------------
if (-not [System.IO.Path]::IsPathRooted($ConfigPath)) {
    Write-Error "ConfigPath must be an absolute path, e.g. C:\ProgramData\CertManager\agent_config.json"
    exit 1
}
$ConfigPath = [System.IO.Path]::GetFullPath($ConfigPath)
$InstallDir = Split-Path $ConfigPath -Parent

# --- Data directory ------------------------------------------------------
if (-not $DataDir) {
    $DataDir = Join-Path $InstallDir "agent_data"
}
if (-not [System.IO.Path]::IsPathRooted($DataDir)) {
    Write-Error "DataDir must be an absolute path, e.g. C:\ProgramData\CertManager\agent_data"
    exit 1
}
$DataDir = [System.IO.Path]::GetFullPath($DataDir)

# --- Resolve Python ------------------------------------------------------
if (-not $PythonPath) {
    $PythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $PythonPath) {
        $PythonPath = (Get-Command python3 -ErrorAction SilentlyContinue).Source
    }
    if (-not $PythonPath) {
        $PythonPath = (Get-Command py -ErrorAction SilentlyContinue).Source
    }
}

if (-not $PythonPath) {
    Write-Error "Python not found. Install Python 3.12+ or specify -PythonPath"
    exit 1
}

# Verify the certmanager package is importable in that interpreter
& $PythonPath -c "import certmanager" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "The 'certmanager' package is not installed for $PythonPath. Install it first (e.g. `"$PythonPath`" -m pip install certmanager) or point -PythonPath at the correct interpreter."
    exit 1
}

$ServiceName = "CertManagerAgent"
$DisplayName = "CertManager Datacenter Agent"
$Description = "Certificate discovery agent for CertManager - scans AD CS and/or TLS endpoints in this datacenter."

Write-Host "=== CertManager Agent Windows Service Installer ==="
Write-Host "Python:    $PythonPath"
Write-Host "Config:    $ConfigPath"
Write-Host "DataDir:   $DataDir"
Write-Host ""

# --- Prepare directories -------------------------------------------------
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

# --- Config file ---------------------------------------------------------
if (-not (Test-Path -LiteralPath $ConfigPath)) {
    Write-Host "Config file not found - writing placeholder $ConfigPath"
    $defaultConfig = [ordered]@{
        api_url            = "https://api.certmanager.example.com"
        psk                = ""
        agent_name         = ""
        agent_type         = "adcs"
        datacenter_code    = ""
        agent_token        = $null
        agent_id           = $null
        api_token          = $null
        poll_interval      = 30
        heartbeat_interval = 30
        local_db_path      = "agent_data/agent.db"
        tls_cidr_ranges    = @()
        tls_ports          = @(443, 8443, 636, 993, 995)
        tls_timeout        = 5.0
        adcs_ca_server     = ""
        adcs_ca_name       = ""
        log_level          = "INFO"
    }
    # UTF-8 without BOM (the agent's json.load chokes on a BOM)
    [System.IO.File]::WriteAllText($ConfigPath, ($defaultConfig | ConvertTo-Json -Depth 4))
    Write-Host "Run 'certmanager agent init --config-path `"$ConfigPath`"' (as Administrator) to fill in real values."
}

# --- Harden the config file: SYSTEM and Administrators read-only ---------
Write-Host "Hardening ACLs on $ConfigPath ..."

function Invoke-Icacls {
    param([string[]]$Arguments)
    & icacls.exe $Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "icacls failed: icacls $($Arguments -join ' ')"
        exit 1
    }
}

# Remove inherited ACEs, then grant read-only to SYSTEM and Administrators
# (SID form so it works on localized Windows installs).
Invoke-Icacls -Arguments @($ConfigPath, "/inheritance:r")
Invoke-Icacls -Arguments @($ConfigPath, "/grant:r", "*S-1-5-18:(R)", "*S-1-5-32-544:(R)")

# --- Install service -----------------------------------------------------
$AgentCommand = "-m certmanager.cli agent run --config `"$ConfigPath`" --data-dir `"$DataDir`""

$nssm = Get-Command nssm -ErrorAction SilentlyContinue

if ($nssm) {
    Write-Host "Using NSSM for service management..."

    # Stop existing service if running
    & nssm stop $ServiceName 2>$null
    & nssm remove $ServiceName confirm 2>$null

    # Install
    & nssm install $ServiceName $PythonPath $AgentCommand
    if ($LASTEXITCODE -ne 0) { Write-Error "nssm install failed"; exit 1 }

    & nssm set $ServiceName AppDirectory $InstallDir
    & nssm set $ServiceName DisplayName $DisplayName
    & nssm set $ServiceName Description $Description
    & nssm set $ServiceName Start SERVICE_AUTO_START
    & nssm set $ServiceName AppRestartDelay 10000
    & nssm set $ServiceName AppStdout "$InstallDir\agent_stdout.log"
    & nssm set $ServiceName AppStderr "$InstallDir\agent_stderr.log"
    & nssm set $ServiceName AppRotateFiles 1
    & nssm set $ServiceName AppRotateOnline 1
    & nssm set $ServiceName AppRotateSeconds 86400
    & nssm set $ServiceName AppRotateBytes 10485760

    # Set recovery options: restart on failure
    sc.exe failure $ServiceName reset=86400 actions=restart/10000/restart/30000/restart/60000 | Out-Null

    Write-Host "Service installed. Starting..."
    & nssm start $ServiceName
    if ($LASTEXITCODE -ne 0) { Write-Error "nssm start failed - check the agent logs in $InstallDir\agent_stderr.log"; exit 1 }

} else {
    # Do NOT fall back to New-Service: python.exe is not a service binary,
    # and registering it would create a broken service (error 1053).
    Write-Error @"

NSSM was not found on this machine, and the CertManager agent cannot be
registered as a Windows service without it (python.exe is not a service
binary, so New-Service/sc.exe would create a broken service).

To fix:
  1. Download NSSM from https://nssm.cc/download
  2. Copy win64\nssm.exe to a directory on PATH (e.g. C:\Windows\System32)
  3. Re-run this script.

Alternatively, run the agent in the foreground (e.g. from Task Scheduler):

  "$PythonPath" -m certmanager.cli agent run --config "$ConfigPath" --data-dir "$DataDir"

"@
    exit 1
}

Write-Host ""
Write-Host "Service '$ServiceName' installed and started."
Write-Host "Check status: Get-Service $ServiceName"
Write-Host "View logs:   $InstallDir\agent_stdout.log / agent_stderr.log"
Write-Host "Uninstall:   nssm remove $ServiceName confirm"
