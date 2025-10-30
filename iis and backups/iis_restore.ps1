# SCRIPT: Restore-Wwwroot.ps1
# PURPOSE: Restores the IIS root folder from a specified backup zip file.

# --- CONFIGURATION ---
# The directory where backups are stored.
$backupDir = "C:\BlueTeam\Backups"

# Find the latest backup file automatically.
$latestBackup = Get-ChildItem -Path $backupDir -Filter "wwwroot-backup-*.zip" |
                Sort-Object Name -Descending |
                Select-Object -First 1

if (-not $latestBackup) {
    Write-Error "No backup files found in '$backupDir'. Cannot proceed with restore."
    return
}

# The full path to the .zip backup file you want to restore.
$backupFile = $latestBackup.FullName

# The target directory for the restore.
$restoreDirectory = "C:\inetpub\wwwroot"

# --- SCRIPT BODY ---
if (-not (Test-Path $backupFile)) {
    Write-Error "Backup file not found at '$backupFile'. Please check the path and try again."
    return
}

# --- !!! WARNING !!! ---
# The next step deletes the current contents of wwwroot before restoring.
# This ensures all malicious files are removed. Use with caution.
# To disable, comment out the 'Remove-Item' line.
Write-Host "Clearing current contents of '$restoreDirectory'..."
Remove-Item -Path "$restoreDirectory\*" -Recurse -Force

# Expand the backup archive to the target directory.
Write-Host "Restoring from '$backupFile'..."
Expand-Archive -Path $backupFile -DestinationPath $restoreDirectory -Force

Write-Host "Restore completed successfully!"