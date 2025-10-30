# SCRIPT: Backup-Wwwroot.ps1
# PURPOSE: Creates a timestamped, compressed (.zip) backup of the IIS root folder.

# --- CONFIGURATION ---
# The source folder to back up.
param(
    [string]$sourceDirectory = "C:\inetpub\wwwroot",
    [string]$backupDestination = "C:\BlueTeam\Backups"
)

# --- SCRIPT BODY ---
# Create the backup destination directory if it doesn't exist.
if (-not (Test-Path $backupDestination)) {
    New-Item -ItemType Directory -Path $backupDestination | Out-Null
}

# Create a timestamp for a unique backup file name.
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$zipFileName = "$(Split-Path $sourceDirectory -Leaf)-backup-$timestamp.zip"
$fullBackupPath = Join-Path -Path $backupDestination -ChildPath $zipFileName

# Create the compressed backup.
Write-Host "Backing up '$sourceDirectory' to '$fullBackupPath'..."
Compress-Archive -Path "$sourceDirectory\*" -DestinationPath $fullBackupPath

Write-Host "Backup completed successfully!"