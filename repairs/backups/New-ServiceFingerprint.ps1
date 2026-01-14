<#
.SYNOPSIS
    Creates fingerprint baselines for service directories.

.DESCRIPTION
    Generates SHA256 hashes of all files in service directories to create
    a baseline for integrity monitoring. Supports auto-detection of services.

.PARAMETER Service
    Service to fingerprint: 'IIS', 'SMB', 'All', or 'Auto' (default)

.PARAMETER OutputDir
    Directory to store baseline files (default: C:\BlueTeam\Baselines)

.EXAMPLE
    .\New-ServiceFingerprint.ps1 -Service Auto
    Creates fingerprints for all detected services

.EXAMPLE
    .\New-ServiceFingerprint.ps1 -Service IIS
    Creates fingerprints for IIS directories only
#>

param(
    [ValidateSet('IIS', 'SMB', 'All', 'Auto')]
    [string]$Service = 'Auto',
    
    [string]$OutputDir = "C:\BlueTeam\Baselines"
)

# --- SERVICE DETECTION FUNCTIONS ---
# (Shared with Backup-ServiceData.ps1)

function Test-IISInstalled {
    $iisService = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
    return ($null -ne $iisService)
}

function Get-IISPaths {
    $paths = @()
    
    $wwwroot = "C:\inetpub\wwwroot"
    if (Test-Path $wwwroot) { $paths += $wwwroot }
    
    $iisConfig = "C:\Windows\System32\inetsrv\config"
    if (Test-Path $iisConfig) { $paths += $iisConfig }
    
    if (Get-Module -ListAvailable -Name WebAdministration) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        try {
            $sites = Get-Website -ErrorAction SilentlyContinue
            foreach ($site in $sites) {
                $expandedPath = [Environment]::ExpandEnvironmentVariables($site.physicalPath)
                if ((Test-Path $expandedPath) -and ($expandedPath -notin $paths)) {
                    $paths += $expandedPath
                }
            }
        }
        catch { }
    }
    
    return $paths
}

function Test-SMBSharesExist {
    $defaultShares = @('ADMIN$', 'C$', 'D$', 'E$', 'IPC$', 'print$')
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -notin $defaultShares -and $_.Path -ne '' 
    }
    return ($null -ne $shares -and $shares.Count -gt 0)
}

function Get-SMBPaths {
    $paths = @()
    $defaultShares = @('ADMIN$', 'C$', 'D$', 'E$', 'IPC$', 'print$')
    
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -notin $defaultShares -and $_.Path -ne '' 
    }
    
    foreach ($share in $shares) {
        if (Test-Path $share.Path) {
            $paths += $share.Path
        }
    }
    
    # Check known competition paths
    if ((Test-Path "C:\Hanger") -and ("C:\Hanger" -notin $paths)) {
        $paths += "C:\Hanger"
    }
    
    return $paths
}

function Get-DetectedServices {
    $services = @()
    
    if (Test-IISInstalled) {
        Write-Host "[+] IIS detected" -ForegroundColor Green
        $services += @{ Name = 'IIS'; Paths = Get-IISPaths }
    }
    
    if (Test-SMBSharesExist) {
        Write-Host "[+] Custom SMB shares detected" -ForegroundColor Green
        $services += @{ Name = 'SMB'; Paths = Get-SMBPaths }
    }
    elseif (Test-Path "C:\Hanger") {
        Write-Host "[+] Known SMB path C:\Hanger exists" -ForegroundColor Green
        $services += @{ Name = 'SMB'; Paths = @("C:\Hanger") }
    }
    
    return $services
}

# --- FINGERPRINT FUNCTION ---

function New-DirectoryFingerprint {
    param(
        [string]$SourcePath,
        [string]$ServiceName,
        [string]$BaselineDir
    )
    
    if (-not (Test-Path $SourcePath)) {
        Write-Warning "Path does not exist: $SourcePath"
        return $null
    }
    
    if (-not (Test-Path $BaselineDir)) {
        New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $safeName = (Split-Path $SourcePath -Leaf) -replace '[^\w\-\.]', '_'
    $baselineFile = Join-Path $BaselineDir "$ServiceName-$safeName-baseline-$timestamp.json"
    
    Write-Host "  Fingerprinting: $SourcePath" -ForegroundColor Yellow
    
    $files = Get-ChildItem -Path $SourcePath -Recurse -File -ErrorAction SilentlyContinue
    $hashes = @()
    $errorCount = 0
    
    foreach ($file in $files) {
        try {
            $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
            $hashes += @{
                Path         = $file.FullName
                RelativePath = $file.FullName.Replace($SourcePath, '').TrimStart('\')
                Hash         = $hash.Hash
                Size         = $file.Length
                LastModified = $file.LastWriteTime.ToString('o')
            }
        }
        catch {
            $errorCount++
        }
    }
    
    $baseline = @{
        Service    = $ServiceName
        SourcePath = $SourcePath
        Created    = (Get-Date).ToString('o')
        Hostname   = $env:COMPUTERNAME
        FileCount  = $hashes.Count
        ErrorCount = $errorCount
        Files      = $hashes
    }
    
    $baseline | ConvertTo-Json -Depth 10 | Out-File -FilePath $baselineFile -Encoding UTF8
    Write-Host "  [OK] Baseline: $baselineFile ($($hashes.Count) files)" -ForegroundColor Green
    
    return $baselineFile
}

# --- MAIN SCRIPT ---

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Service Fingerprint Generator" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Determine which services to fingerprint
$servicesToProcess = @()

switch ($Service) {
    'Auto' {
        Write-Host "[*] Auto-detecting installed services..." -ForegroundColor Yellow
        $servicesToProcess = Get-DetectedServices
        
        if ($servicesToProcess.Count -eq 0) {
            Write-Warning "No supported services detected."
            exit 1
        }
    }
    'All' {
        $iisPaths = Get-IISPaths
        if ($iisPaths.Count -gt 0) {
            $servicesToProcess += @{ Name = 'IIS'; Paths = $iisPaths }
        }
        $smbPaths = Get-SMBPaths
        if ($smbPaths.Count -gt 0) {
            $servicesToProcess += @{ Name = 'SMB'; Paths = $smbPaths }
        }
    }
    'IIS' {
        $paths = Get-IISPaths
        if ($paths.Count -gt 0) {
            $servicesToProcess += @{ Name = 'IIS'; Paths = $paths }
        }
        else {
            Write-Warning "IIS not found"
            exit 1
        }
    }
    'SMB' {
        $paths = Get-SMBPaths
        if ($paths.Count -gt 0) {
            $servicesToProcess += @{ Name = 'SMB'; Paths = $paths }
        }
        else {
            Write-Warning "No SMB paths found"
            exit 1
        }
    }
}

Write-Host ""

# Create fingerprints
$results = @()

foreach ($svc in $servicesToProcess) {
    Write-Host "--- Fingerprinting $($svc.Name) ---" -ForegroundColor Magenta
    
    foreach ($path in $svc.Paths) {
        $result = New-DirectoryFingerprint -SourcePath $path -ServiceName $svc.Name -BaselineDir $OutputDir
        if ($result) {
            $results += $result
        }
    }
    Write-Host ""
}

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Fingerprint Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Baselines created: $($results.Count)" -ForegroundColor Green
Write-Host "Output directory: $OutputDir" -ForegroundColor White
Write-Host ""
Write-Host "[DONE] Fingerprinting completed" -ForegroundColor Green
