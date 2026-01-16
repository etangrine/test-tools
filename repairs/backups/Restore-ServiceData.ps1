<#
.SYNOPSIS
    Restores service directories from timestamped backups with auto-detection.

.DESCRIPTION
    Unified restore script that works with Backup-ServiceData.ps1 backups.
    Automatically detects which services have backups available and restores
    them to their original locations.

.PARAMETER Service
    Service to restore: 'IIS', 'SMB', 'All', or 'Auto' (default - finds available backups)

.PARAMETER BackupDir
    Directory where backups are stored (default: $env:USERPROFILE\Desktop\Backups)

.PARAMETER BackupFile
    Optional: Path to a specific backup zip file to restore

.PARAMETER NoConfirm
    Skip confirmation prompts (use in scripts)

.EXAMPLE
    .\Restore-ServiceData.ps1 -Service Auto
    Finds and restores all available service backups

.EXAMPLE
    .\Restore-ServiceData.ps1 -Service IIS
    Restores the latest IIS backup (wwwroot and config)

.EXAMPLE
    .\Restore-ServiceData.ps1 -BackupFile "C:\Backups\IIS-wwwroot-backup-20260114.zip"
    Restores a specific backup file
#>

param(
    [ValidateSet('IIS', 'SMB', 'All', 'Auto')]
    [string]$Service = 'Auto',
    
    [string]$BackupDir = "$env:USERPROFILE\Desktop\Backups",
    
    [string]$BackupFile,
    
    [switch]$NoConfirm
)

# --- SERVICE PATH MAPPINGS ---
# Maps backup name patterns to their restore destinations

$ServicePaths = @{
    'IIS' = @{
        'wwwroot' = 'C:\inetpub\wwwroot'
        'config'  = 'C:\Windows\System32\inetsrv\config'
    }
    'SMB' = @{
        'Hanger' = 'C:\Hanger'
    }
}

# --- HELPER FUNCTIONS ---

function Get-AvailableBackups {
    param(
        [string]$BackupDirectory,
        [string]$ServiceFilter = '*'
    )
    
    if (-not (Test-Path $BackupDirectory)) {
        return @()
    }
    
    $backups = Get-ChildItem -Path $BackupDirectory -Filter "$ServiceFilter-*-backup-*.zip" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending
    
    return $backups
}

function Get-RestoreDestination {
    <#
    .SYNOPSIS
        Determines the restore destination based on backup filename
    #>
    param([string]$BackupFileName)
    
    # Parse the backup filename: SERVICE-DIRNAME-backup-TIMESTAMP.zip
    if ($BackupFileName -match '^(IIS|SMB)-(.+)-backup-\d{8}-\d{6}\.zip$') {
        $serviceName = $Matches[1]
        $dirName = $Matches[2]
        
        if ($ServicePaths.ContainsKey($serviceName)) {
            $paths = $ServicePaths[$serviceName]
            if ($paths.ContainsKey($dirName)) {
                return $paths[$dirName]
            }
            
            # Try case-insensitive match
            foreach ($key in $paths.Keys) {
                if ($key -ieq $dirName) {
                    return $paths[$key]
                }
            }
        }
        
        # Fallback: Check known paths
        switch ($dirName) {
            'wwwroot' { return 'C:\inetpub\wwwroot' }
            'config' { return 'C:\Windows\System32\inetsrv\config' }
            'Hanger' { return 'C:\Hanger' }
        }
    }
    
    return $null
}

function Restore-FromBackup {
    param(
        [string]$BackupPath,
        [string]$RestoreDir,
        [switch]$SkipConfirm
    )
    
    if (-not (Test-Path $BackupPath)) {
        Write-Error "Backup file not found: $BackupPath"
        return $false
    }
    
    $backupName = Split-Path $BackupPath -Leaf
    
    Write-Host ""
    Write-Host "  Backup: $backupName" -ForegroundColor Yellow
    Write-Host "  Destination: $RestoreDir" -ForegroundColor Yellow
    
    # Confirm unless skipped
    if (-not $SkipConfirm) {
        Write-Host ""
        Write-Host "  [!] WARNING: This will DELETE current contents of $RestoreDir" -ForegroundColor Red
        $confirm = Read-Host "  Proceed with restore? (y/N)"
        if ($confirm -ne 'y' -and $confirm -ne 'Y') {
            Write-Host "  Skipped." -ForegroundColor Gray
            return $false
        }
    }
    
    # Create destination if it doesn't exist
    if (-not (Test-Path $RestoreDir)) {
        Write-Host "  Creating directory: $RestoreDir" -ForegroundColor Cyan
        New-Item -ItemType Directory -Path $RestoreDir -Force | Out-Null
    }
    else {
        # Clear existing contents
        Write-Host "  Clearing current contents..." -ForegroundColor Cyan
        Remove-Item -Path "$RestoreDir\*" -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Extract backup
    try {
        Write-Host "  Extracting backup..." -ForegroundColor Cyan
        Expand-Archive -Path $BackupPath -DestinationPath $RestoreDir -Force
        Write-Host "  [OK] Restore completed!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to extract backup: $_"
        return $false
    }
}

# --- MAIN SCRIPT ---

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Service Restore Script" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Handle specific backup file
if ($BackupFile) {
    if (-not (Test-Path $BackupFile)) {
        Write-Error "Backup file not found: $BackupFile"
        exit 1
    }
    
    $fileName = Split-Path $BackupFile -Leaf
    $restoreDest = Get-RestoreDestination -BackupFileName $fileName
    
    if (-not $restoreDest) {
        Write-Warning "Could not auto-detect restore destination for: $fileName"
        $restoreDest = Read-Host "Enter restore destination path"
    }
    
    Write-Host "[*] Restoring specific backup" -ForegroundColor Yellow
    $result = Restore-FromBackup -BackupPath $BackupFile -RestoreDir $restoreDest -SkipConfirm:$NoConfirm
    
    if ($result) {
        Write-Host ""
        Write-Host "[DONE] Restore completed successfully!" -ForegroundColor Green
    }
    exit 0
}

# Check backup directory exists
if (-not (Test-Path $BackupDir)) {
    Write-Error "Backup directory not found: $BackupDir"
    Write-Host "Run Backup-ServiceData.ps1 first to create backups." -ForegroundColor Yellow
    exit 1
}

# Find available backups based on service selection
$backupsToRestore = @()

switch ($Service) {
    'Auto' {
        Write-Host "[*] Scanning for available backups in: $BackupDir" -ForegroundColor Yellow
        
        # Find IIS backups for paths that exist
        if (Test-Path 'C:\inetpub\wwwroot') {
            $iisBackups = Get-AvailableBackups -BackupDirectory $BackupDir -ServiceFilter 'IIS'
            foreach ($backup in $iisBackups) {
                $dest = Get-RestoreDestination -BackupFileName $backup.Name
                if ($dest) {
                    $backupsToRestore += @{
                        Backup      = $backup.FullName
                        Destination = $dest
                        Service     = 'IIS'
                        FileName    = $backup.Name
                    }
                }
            }
        }
        
        # Find SMB backups for paths that exist or could exist
        if ((Test-Path 'C:\Hanger') -or (Get-AvailableBackups -BackupDirectory $BackupDir -ServiceFilter 'SMB').Count -gt 0) {
            $smbBackups = Get-AvailableBackups -BackupDirectory $BackupDir -ServiceFilter 'SMB'
            foreach ($backup in $smbBackups) {
                $dest = Get-RestoreDestination -BackupFileName $backup.Name
                if ($dest) {
                    $backupsToRestore += @{
                        Backup      = $backup.FullName
                        Destination = $dest
                        Service     = 'SMB'
                        FileName    = $backup.Name
                    }
                }
            }
        }
    }
    'All' {
        $allBackups = Get-AvailableBackups -BackupDirectory $BackupDir
        foreach ($backup in $allBackups) {
            $dest = Get-RestoreDestination -BackupFileName $backup.Name
            if ($dest) {
                $backupsToRestore += @{
                    Backup      = $backup.FullName
                    Destination = $dest
                    Service     = if ($backup.Name -match '^(IIS|SMB)') { $Matches[1] } else { 'Unknown' }
                    FileName    = $backup.Name
                }
            }
        }
    }
    default {
        # Specific service
        $serviceBackups = Get-AvailableBackups -BackupDirectory $BackupDir -ServiceFilter $Service
        foreach ($backup in $serviceBackups) {
            $dest = Get-RestoreDestination -BackupFileName $backup.Name
            if ($dest) {
                $backupsToRestore += @{
                    Backup      = $backup.FullName
                    Destination = $dest
                    Service     = $Service
                    FileName    = $backup.Name
                }
            }
        }
    }
}

if ($backupsToRestore.Count -eq 0) {
    Write-Warning "No restorable backups found in: $BackupDir"
    Write-Host ""
    Write-Host "Available backup files:" -ForegroundColor Yellow
    Get-ChildItem -Path $BackupDir -Filter "*.zip" | ForEach-Object {
        Write-Host "  - $($_.Name)" -ForegroundColor Gray
    }
    exit 1
}

# Group by destination and show latest for each
$grouped = $backupsToRestore | Group-Object Destination | ForEach-Object {
    $_.Group | Sort-Object FileName -Descending | Select-Object -First 1
}

Write-Host "[*] Found $($grouped.Count) restore target(s):" -ForegroundColor Yellow
foreach ($item in $grouped) {
    Write-Host "    $($item.Service): $($item.Destination)" -ForegroundColor White
    Write-Host "      Latest: $($item.FileName)" -ForegroundColor Gray
}
Write-Host ""

# Perform restores
$successCount = 0
foreach ($item in $grouped) {
    Write-Host "--- Restoring $($item.Service) ---" -ForegroundColor Magenta
    $result = Restore-FromBackup -BackupPath $item.Backup -RestoreDir $item.Destination -SkipConfirm:$NoConfirm
    if ($result) { $successCount++ }
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Restore Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Successfully restored: $successCount / $($grouped.Count)" -ForegroundColor $(if ($successCount -eq $grouped.Count) { 'Green' } else { 'Yellow' })
Write-Host ""
Write-Host "[DONE] Restore operation completed" -ForegroundColor Green
