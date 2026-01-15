# SCRIPT: Restore-Wwwroot.ps1
# PURPOSE: Restores the IIS root folder from the latest backup zip file in a directory.

# --- CONFIGURATION ---
# Define optional parameters for the backup and restore directories.
#try to only use restoreDir
param(
    [string]$backupDir = "$env:USERPROFILE\Desktop\Backups",
    [string]$restoreDir = "C:\inetpub\wwwroot"
)

# --- SCRIPT BODY ---
# Find the latest backup file automatically.
$latestBackup = Get-ChildItem -Path $backupDir -Filter "*-backup-*.zip" |
Sort-Object Name -Descending |
Select-Object -First 1

if (-not $latestBackup) {
    Write-Error "No backup files matching '*-backup-*.zip' found in '$backupDir'. Cannot proceed with restore."
    return
}

# The full path to the .zip backup file you want to restore.
$backupFile = $latestBackup.FullName
Write-Host "Found latest backup: $backupFile"

# --- !!! WARNING !!! ---
# The next step deletes the current contents of wwwroot before restoring.
# This ensures all malicious files are removed. Use with caution.
# To disable, comment out the 'Remove-Item' line.
Write-Host "Clearing current contents of '$restoreDir'..."
Remove-Item -Path "$restoreDir\*" -Recurse -Force

# Expand the backup archive to the target directory.
Write-Host "Restoring from '$backupFile' to '$restoreDir'..."
Expand-Archive -Path $backupFile -DestinationPath $restoreDir -Force

Write-Host "Restore completed successfully!"