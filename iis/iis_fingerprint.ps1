# SCRIPT: Create-BaselineHashes.ps1
# PURPOSE: Recursively finds all files in a directory, calculates their SHA256 hash,
#          and saves the list to a text file for future comparison.

# --- CONFIGURATION ---
# The folder you want to monitor.
$targetDirectory = "C:\inetpub\wwwroot" 

# Where to save the baseline hash file.
$outputFile = "C:\BlueTeam\wwwroot_baseline_hashes.txt"

# --- SCRIPT BODY ---
# Ensure the output directory exists.
$outputDirectory = Split-Path $outputFile
if (-not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
}

# Get all files, calculate hashes, and save to the output file.
Write-Host "Generating baseline hashes for '$targetDirectory'..."
Get-ChildItem -Path $targetDirectory -Recurse -File | Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $outputFile

Write-Host "Baseline created successfully at '$outputFile'"