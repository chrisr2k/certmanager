<#
.SYNOPSIS
    AD CS Certificate Enumeration Script
.DESCRIPTION
    Enumerates issued certificates from an Active Directory Certificate Services CA.
    Used by the CertManager datacenter agent's AD CS scanner.
.PARAMETER CAServer
    Hostname of the CA server (default: localhost).
.PARAMETER CAName
    Common name of the Certificate Authority.
.PARAMETER Templates
    Comma-separated list of certificate templates to filter (optional).
.PARAMETER Since
    Only include certificates issued after this date (optional, ISO format).
.PARAMETER IncludeExpired
    Include expired certificates (default: false).
.PARAMETER IncludeRevoked
    Include revoked certificates (default: false).
.PARAMETER OutputFormat
    Output format: JSON or CSV (default: JSON).
.EXAMPLE
    .\adcs_cert_enum.ps1 -CAName "Enterprise CA" -Templates "WebServer,User"
#>

param(
    [string]$CAServer = $env:COMPUTERNAME,
    [string]$CAName = "",
    [string]$Templates = "",
    [string]$Since = "",
    [switch]$IncludeExpired = $false,
    [switch]$IncludeRevoked = $false,
    [string]$OutputFormat = "JSON"
)

$ErrorActionPreference = "Stop"
$result = @()
$errors = @()

try {
    # Resolve the CA
    if ($CAName) {
        $ca = Get-CertificationAuthority -Name $CAName -ErrorAction SilentlyContinue
    } else {
        $ca = Get-CertificationAuthority -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    if (-not $ca) {
        # Try certutil to find CA
        $caName = certutil -CAInfo 2>$null | Select-String "Name:" | ForEach-Object { $_ -replace ".*Name:\s*", "" }
        if ($caName) {
            $CAName = $caName.Trim()
        }
    }

    # Build the query
    $restrictions = @()
    $restrictions += "Disposition=20"  # Issued

    if ($IncludeExpired) {
        $restrictions = @("Disposition>=20")
    }
    if ($IncludeRevoked) {
        $restrictions = @("Disposition>=20")
    }

    if ($Templates) {
        $templateList = $Templates -split ","
        $templateFilter = ($templateList | ForEach-Object { "CertificateTemplate=$_" }) -join " OR "
        $restrictions += $templateFilter
    }

    if ($Since) {
        $restrictions += "NotBefore>=$Since"
    }

    $restrictString = $restrictions -join " AND "

    # Columns to retrieve
    $columns = @(
        "RequestID",
        "SerialNumber",
        "CommonName",
        "NotBefore",
        "NotAfter",
        "CertificateTemplate",
        "RequesterName",
        "CertificateSubNameString",
        "CertificateIssuerNameString",
        "CertificateHash",
        "CertificateSerialNumber",
        "RequestDisposition",
        "RequestDispositionMessage"
    ) -join ","

    # Run certutil
    $certutilOutput = certutil -view -restrict "$restrictString" -out "$columns" CSV 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0 -and $exitCode -ne 1) {
        # Exit code 1 = no rows found, which is OK
        if ($certutilOutput -match "error|failed") {
            throw "certutil failed with exit code $exitCode: $certutilOutput"
        }
    }

    # Parse certutil CSV output
    $lines = $certutilOutput -split "`n" | ForEach-Object { $_.Trim() }
    $headerLine = $lines | Where-Object { $_ -match "^RequestID," } | Select-Object -First 1

    if (-not $headerLine) {
        # No results
        $result = @()
    } else {
        $headers = $headerLine -split "," | ForEach-Object { $_.Trim('"').Trim() }

        $dataLines = $lines | Where-Object {
            $_ -notmatch "^---" -and
            $_ -notmatch "^Row" -and
            $_ -notmatch "^RequestID," -and
            $_ -notmatch "^Displayed" -and
            $_ -notmatch "^CertUtil" -and
            $_ -ne ""
        }

        foreach ($line in $dataLines) {
            $values = $line -split "," | ForEach-Object { $_.Trim('"').Trim() }
            if ($values.Count -ge $headers.Count) {
                $cert = @{}
                for ($i = 0; $i -lt $headers.Count; $i++) {
                    $cert[$headers[$i]] = $values[$i]
                }
                $result += $cert
            }
        }
    }

} catch {
    $errors += $_.Exception.Message
}

# Output
$output = @{
    certificates = $result
    errors = $errors
    count = $result.Count
    generated_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    ca_server = $CAServer
    ca_name = $CAName
}

if ($OutputFormat -eq "CSV") {
    if ($result.Count -gt 0) {
        $result | Select-Object RequestID, SerialNumber, CommonName, NotBefore, NotAfter, CertificateTemplate | ConvertTo-Csv -NoTypeInformation
    } else {
        Write-Output "No certificates found"
    }
} else {
    $output | ConvertTo-Json -Depth 4
}
