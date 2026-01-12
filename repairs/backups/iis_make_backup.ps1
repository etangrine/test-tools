# SCRIPT: Backup-Wwwroot.ps1
# PURPOSE: Creates a timestamped, compressed (.zip) backup of the IIS root folder.

# --- CONFIGURATION ---
# The source folder to back up.
param(
    [string]$sourceDir = "C:\inetpub\wwwroot",
    [string]$backupDir = "$env:USERPROFILE\Desktop\Backups"
)

# --- SCRIPT BODY ---
# Create the backup destination directory if it doesn't exist.
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir | Out-Null
}

# Create a timestamp for a unique backup file name.
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$zipFileName = "$(Split-Path $sourceDir -Leaf)-backup-$timestamp.zip"
$fullBackupPath = Join-Path -Path $backupDir -ChildPath $zipFileName

# Create the compressed backup.
Write-Host "Backing up '$sourceDir' to '$fullBackupPath'..."
Compress-Archive -Path "$sourceDir\*" -DestinationPath $fullBackupPath

Write-Host "Backup completed successfully!"