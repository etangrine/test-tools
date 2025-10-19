# SCRIPT: Compare-CurrentHashes.ps1
# PURPOSE: Compares the current file hashes in a directory against a saved baseline file.

# --- CONFIGURATION ---
# The folder you are monitoring.
$targetDirectory = "C:\inetpub\wwwroot"

# The location of the baseline file you created earlier.
$baselineFile = "C:\BlueTeam\wwwroot_baseline_hashes.txt"

# --- SCRIPT BODY ---
if (-not (Test-Path $baselineFile)) {
    Write-Error "Baseline file not found at '$baselineFile'. Please run the Create-BaselineHashes.ps1 script first."
    return
}

# Import the baseline hashes.
$baselineHashes = Import-Csv -Path $baselineFile

# Generate the current hashes.
Write-Host "Generating current hashes to compare against the baseline..."
$currentHashes = Get-ChildItem -Path $targetDirectory -Recurse -File | Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash

# Compare the two sets of hashes.
# The 'SideIndicator' property shows where the difference is:
#   => indicates a file is in the current scan but not the baseline (new file).
#   <= indicates a file is in the baseline but not the current scan (deleted or changed file).
Write-Host "Comparing current state with baseline. Any differences will be listed below:"
Compare-Object -ReferenceObject $baselineHashes -DifferenceObject $currentHashes -Property Path, Hash