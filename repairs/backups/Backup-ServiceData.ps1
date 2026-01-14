<#
.SYNOPSIS
    Creates timestamped backups of important service directories with auto-detection.

.DESCRIPTION
    Unified backup script that automatically detects installed services (IIS, SMB)
    and backs up their critical directories. Supports both auto-detection and 
    manual service specification.

.PARAMETER Service
    Service to backup: 'IIS', 'SMB', 'All', or 'Auto' (default - detects installed services)

.PARAMETER BackupDir
    Directory to store backups (default: $env:USERPROFILE\Desktop\Backups)

.PARAMETER CreateFingerprint
    If specified, also creates a fingerprint baseline of the backed-up directories

.EXAMPLE
    .\Backup-ServiceData.ps1 -Service Auto
    Detects and backs up all installed services

.EXAMPLE
    .\Backup-ServiceData.ps1 -Service IIS -CreateFingerprint
    Backs up IIS directories and creates a fingerprint baseline
#>

param(
    [ValidateSet('IIS', 'SMB', 'All', 'Auto')]
    [string]$Service = 'Auto',
    
    [string]$BackupDir = "$env:USERPROFILE\Desktop\Backups",
    
    [switch]$CreateFingerprint
)

# --- SERVICE DETECTION FUNCTIONS ---

function Test-IISInstalled {
    <#
    .SYNOPSIS
        Checks if IIS is installed on the system
    #>
    $iisService = Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue
    return ($null -ne $iisService)
}

function Get-IISPaths {
    <#
    .SYNOPSIS
        Returns paths that should be backed up for IIS
    #>
    $paths = @()
    
    # Default wwwroot
    $wwwroot = "C:\inetpub\wwwroot"
    if (Test-Path $wwwroot) {
        $paths += $wwwroot
    }
    
    # IIS configuration directory
    $iisConfig = "C:\Windows\System32\inetsrv\config"
    if (Test-Path $iisConfig) {
        $paths += $iisConfig
    }
    
    # Try to get additional sites from IIS if WebAdministration module is available
    if (Get-Module -ListAvailable -Name WebAdministration) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        try {
            $sites = Get-Website -ErrorAction SilentlyContinue
            foreach ($site in $sites) {
                $physicalPath = $site.physicalPath
                # Expand environment variables in the path
                $expandedPath = [Environment]::ExpandEnvironmentVariables($physicalPath)
                if ((Test-Path $expandedPath) -and ($expandedPath -notin $paths)) {
                    $paths += $expandedPath
                }
            }
        }
        catch {
            Write-Warning "Could not enumerate IIS sites: $_"
        }
    }
    
    return $paths
}

function Test-SMBSharesExist {
    <#
    .SYNOPSIS
        Checks if there are any non-default SMB shares
    #>
    $defaultShares = @('ADMIN$', 'C$', 'D$', 'E$', 'IPC$', 'print$')
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -notin $defaultShares -and 
        $_.Path -ne '' 
    }
    return ($null -ne $shares -and $shares.Count -gt 0)
}

function Get-SMBPaths {
    <#
    .SYNOPSIS
        Returns paths for SMB shares that should be backed up
    #>
    $paths = @()
    $defaultShares = @('ADMIN$', 'C$', 'D$', 'E$', 'IPC$', 'print$')
    
    # Get custom SMB shares
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -notin $defaultShares -and 
        $_.Path -ne '' 
    }
    
    foreach ($share in $shares) {
        if (Test-Path $share.Path) {
            Write-Host "  Found SMB share: $($share.Name) -> $($share.Path)" -ForegroundColor Cyan
            $paths += $share.Path
        }
    }
    
    # Also check for known competition paths
    $knownPaths = @(
        "C:\Hanger"  # Known from previous ISTS competitions
    )
    
    foreach ($knownPath in $knownPaths) {
        if ((Test-Path $knownPath) -and ($knownPath -notin $paths)) {
            Write-Host "  Found known share path: $knownPath" -ForegroundColor Cyan
            $paths += $knownPath
        }
    }
    
    return $paths
}

function Get-DetectedServices {
    <#
    .SYNOPSIS
        Detects which services are installed and returns their info
    #>
    $services = @()
    
    if (Test-IISInstalled) {
        Write-Host "[+] IIS detected" -ForegroundColor Green
        $services += @{
            Name  = 'IIS'
            Paths = Get-IISPaths
        }
    }
    
    if (Test-SMBSharesExist) {
        Write-Host "[+] Custom SMB shares detected" -ForegroundColor Green
        $services += @{
            Name  = 'SMB'
            Paths = Get-SMBPaths
        }
    }
    elseif (Test-Path "C:\Hanger") {
        # Even if no shares configured, check for known paths
        Write-Host "[+] Known SMB path C:\Hanger exists" -ForegroundColor Green
        $services += @{
            Name  = 'SMB'
            Paths = @("C:\Hanger")
        }
    }
    
    return $services
}

# --- BACKUP FUNCTIONS ---

function Backup-Directory {
    <#
    .SYNOPSIS
        Creates a compressed backup of a directory
    #>
    param(
        [string]$SourcePath,
        [string]$ServiceName,
        [string]$BackupDirectory
    )
    
    if (-not (Test-Path $SourcePath)) {
        Write-Warning "Source path does not exist: $SourcePath"
        return $null
    }
    
    # Create backup directory if needed
    if (-not (Test-Path $BackupDirectory)) {
        New-Item -ItemType Directory -Path $BackupDirectory -Force | Out-Null
    }
    
    # Create timestamped backup filename
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $safeName = (Split-Path $SourcePath -Leaf) -replace '[^\w\-\.]', '_'
    $zipFileName = "$ServiceName-$safeName-backup-$timestamp.zip"
    $backupPath = Join-Path $BackupDirectory $zipFileName
    
    Write-Host "  Backing up: $SourcePath" -ForegroundColor Yellow
    Write-Host "  Destination: $backupPath" -ForegroundColor Yellow
    
    try {
        Compress-Archive -Path "$SourcePath\*" -DestinationPath $backupPath -Force
        Write-Host "  [OK] Backup created successfully" -ForegroundColor Green
        return $backupPath
    }
    catch {
        Write-Error "Failed to create backup: $_"
        return $null
    }
}

function New-Fingerprint {
    <#
    .SYNOPSIS
        Creates a fingerprint (hash baseline) for a directory
    #>
    param(
        [string]$SourcePath,
        [string]$ServiceName
    )
    
    $baselineDir = "C:\BlueTeam\Baselines"
    if (-not (Test-Path $baselineDir)) {
        New-Item -ItemType Directory -Path $baselineDir -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $safeName = (Split-Path $SourcePath -Leaf) -replace '[^\w\-\.]', '_'
    $baselineFile = Join-Path $baselineDir "$ServiceName-$safeName-baseline-$timestamp.json"
    
    Write-Host "  Creating fingerprint for: $SourcePath" -ForegroundColor Cyan
    
    $files = Get-ChildItem -Path $SourcePath -Recurse -File -ErrorAction SilentlyContinue
    $hashes = @()
    
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
            Write-Warning "Could not hash file: $($file.FullName)"
        }
    }
    
    $baseline = @{
        Service    = $ServiceName
        SourcePath = $SourcePath
        Created    = (Get-Date).ToString('o')
        FileCount  = $hashes.Count
        Files      = $hashes
    }
    
    $baseline | ConvertTo-Json -Depth 10 | Out-File -FilePath $baselineFile -Encoding UTF8
    Write-Host "  [OK] Fingerprint saved: $baselineFile" -ForegroundColor Green
    
    return $baselineFile
}

# --- MAIN SCRIPT ---

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Service Backup Script" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Determine which services to backup
$servicesToBackup = @()

switch ($Service) {
    'Auto' {
        Write-Host "[*] Auto-detecting installed services..." -ForegroundColor Yellow
        $servicesToBackup = Get-DetectedServices
        
        if ($servicesToBackup.Count -eq 0) {
            Write-Warning "No supported services detected on this system."
            Write-Host "Supported services: IIS, SMB (custom shares or C:\Hanger)"
            exit 1
        }
    }
    'All' {
        Write-Host "[*] Gathering paths for all supported services..." -ForegroundColor Yellow
        
        $iisPaths = Get-IISPaths
        if ($iisPaths.Count -gt 0) {
            $servicesToBackup += @{ Name = 'IIS'; Paths = $iisPaths }
        }
        
        $smbPaths = Get-SMBPaths
        if ($smbPaths.Count -gt 0) {
            $servicesToBackup += @{ Name = 'SMB'; Paths = $smbPaths }
        }
    }
    'IIS' {
        $paths = Get-IISPaths
        if ($paths.Count -gt 0) {
            $servicesToBackup += @{ Name = 'IIS'; Paths = $paths }
        }
        else {
            Write-Warning "IIS not found or no IIS paths detected"
            exit 1
        }
    }
    'SMB' {
        $paths = Get-SMBPaths
        if ($paths.Count -gt 0) {
            $servicesToBackup += @{ Name = 'SMB'; Paths = $paths }
        }
        else {
            Write-Warning "No SMB shares or known SMB paths detected"
            exit 1
        }
    }
}

Write-Host ""
Write-Host "[*] Services to backup:" -ForegroundColor Yellow
foreach ($svc in $servicesToBackup) {
    Write-Host "    - $($svc.Name): $($svc.Paths.Count) path(s)" -ForegroundColor White
}
Write-Host ""

# Perform backups
$backupResults = @()

foreach ($svc in $servicesToBackup) {
    Write-Host "--- Backing up $($svc.Name) ---" -ForegroundColor Magenta
    
    foreach ($path in $svc.Paths) {
        $result = Backup-Directory -SourcePath $path -ServiceName $svc.Name -BackupDirectory $BackupDir
        
        if ($result) {
            $backupResults += @{
                Service    = $svc.Name
                SourcePath = $path
                BackupFile = $result
            }
            
            # Create fingerprint if requested
            if ($CreateFingerprint) {
                New-Fingerprint -SourcePath $path -ServiceName $svc.Name | Out-Null
            }
        }
    }
    Write-Host ""
}

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Backup Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Backups created: $($backupResults.Count)" -ForegroundColor Green
Write-Host "Backup location: $BackupDir" -ForegroundColor White

if ($CreateFingerprint) {
    Write-Host "Fingerprints saved to: C:\BlueTeam\Baselines" -ForegroundColor White
}

Write-Host ""
Write-Host "[DONE] Backup completed at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Green
