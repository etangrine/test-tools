<#
.SYNOPSIS
    Compares current files against a saved fingerprint baseline to detect changes.

.DESCRIPTION
    Loads a previously saved fingerprint baseline and compares it against the
    current state of the directory to identify added, removed, or modified files.

.PARAMETER BaselineFile
    Path to a specific baseline JSON file to compare against

.PARAMETER Service
    Service to check: 'IIS', 'SMB'. Uses the latest baseline for that service.

.PARAMETER BaselineDir
    Directory where baselines are stored (default: C:\BlueTeam\Baselines)

.PARAMETER ExportResults
    If specified, exports the comparison results to a file

.EXAMPLE
    .\Compare-ServiceFingerprint.ps1 -Service IIS
    Compares current IIS state against the latest IIS baseline

.EXAMPLE
    .\Compare-ServiceFingerprint.ps1 -BaselineFile "C:\BlueTeam\Baselines\IIS-wwwroot-baseline-20260114.json"
    Compares against a specific baseline file
#>

param(
    [string]$BaselineFile,
    
    [ValidateSet('IIS', 'SMB')]
    [string]$Service,
    
    [string]$BaselineDir = "C:\BlueTeam\Baselines",
    
    [switch]$ExportResults
)

# --- HELPER FUNCTIONS ---

function Get-LatestBaseline {
    param(
        [string]$ServiceName,
        [string]$BaselineDirectory
    )
    
    $baselines = Get-ChildItem -Path $BaselineDirectory -Filter "$ServiceName-*-baseline-*.json" -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending
    
    if ($baselines.Count -eq 0) {
        return $null
    }
    
    return $baselines[0].FullName
}

function Compare-FileHashes {
    param(
        [array]$BaselineFiles,
        [array]$CurrentFiles
    )
    
    $results = @{
        Added     = @()
        Removed   = @()
        Modified  = @()
        Unchanged = 0
    }
    
    # Create lookup tables
    $baselineByPath = @{}
    foreach ($file in $BaselineFiles) {
        $baselineByPath[$file.RelativePath] = $file
    }
    
    $currentByPath = @{}
    foreach ($file in $CurrentFiles) {
        $currentByPath[$file.RelativePath] = $file
    }
    
    # Check for removed and modified files
    foreach ($relPath in $baselineByPath.Keys) {
        if (-not $currentByPath.ContainsKey($relPath)) {
            $results.Removed += @{
                RelativePath = $relPath
                OriginalHash = $baselineByPath[$relPath].Hash
            }
        }
        elseif ($baselineByPath[$relPath].Hash -ne $currentByPath[$relPath].Hash) {
            $results.Modified += @{
                RelativePath = $relPath
                OriginalHash = $baselineByPath[$relPath].Hash
                CurrentHash  = $currentByPath[$relPath].Hash
                OriginalSize = $baselineByPath[$relPath].Size
                CurrentSize  = $currentByPath[$relPath].Size
            }
        }
        else {
            $results.Unchanged++
        }
    }
    
    # Check for added files
    foreach ($relPath in $currentByPath.Keys) {
        if (-not $baselineByPath.ContainsKey($relPath)) {
            $results.Added += @{
                RelativePath = $relPath
                CurrentHash  = $currentByPath[$relPath].Hash
                Size         = $currentByPath[$relPath].Size
            }
        }
    }
    
    return $results
}

function Get-CurrentHashes {
    param([string]$SourcePath)
    
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
        catch { }
    }
    
    return $hashes
}

# --- MAIN SCRIPT ---

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Service Fingerprint Comparison" -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Determine which baseline to use
if ($BaselineFile) {
    if (-not (Test-Path $BaselineFile)) {
        Write-Error "Baseline file not found: $BaselineFile"
        exit 1
    }
    $targetBaseline = $BaselineFile
}
elseif ($Service) {
    $targetBaseline = Get-LatestBaseline -ServiceName $Service -BaselineDirectory $BaselineDir
    if (-not $targetBaseline) {
        Write-Error "No baseline found for service: $Service in $BaselineDir"
        Write-Host "Run New-ServiceFingerprint.ps1 -Service $Service first." -ForegroundColor Yellow
        exit 1
    }
}
else {
    # List available baselines
    Write-Host "Available baselines in $BaselineDir :" -ForegroundColor Yellow
    $baselines = Get-ChildItem -Path $BaselineDir -Filter "*-baseline-*.json" -ErrorAction SilentlyContinue
    if ($baselines.Count -eq 0) {
        Write-Warning "No baselines found. Run New-ServiceFingerprint.ps1 first."
        exit 1
    }
    foreach ($b in $baselines) {
        Write-Host "  - $($b.Name)" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Usage: .\Compare-ServiceFingerprint.ps1 -Service IIS" -ForegroundColor Cyan
    Write-Host "   or: .\Compare-ServiceFingerprint.ps1 -BaselineFile <path>" -ForegroundColor Cyan
    exit 0
}

Write-Host "[*] Loading baseline: $targetBaseline" -ForegroundColor Yellow

# Validate it's a JSON file
if (-not $targetBaseline.EndsWith('.json')) {
    Write-Error "Baseline file must be a .json file created by New-ServiceFingerprint.ps1"
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  1. First create a baseline:  .\New-ServiceFingerprint.ps1 -Service IIS" -ForegroundColor Cyan
    Write-Host "  2. Then compare against it:  .\Compare-ServiceFingerprint.ps1 -Service IIS" -ForegroundColor Cyan
    exit 1
}

try {
    $baseline = Get-Content $targetBaseline -Raw | ConvertFrom-Json
}
catch {
    Write-Error "Failed to parse baseline file as JSON: $_"
    Write-Host ""
    Write-Host "The baseline file must be a valid JSON file created by New-ServiceFingerprint.ps1" -ForegroundColor Yellow
    exit 1
}

# Validate baseline has required fields
if (-not $baseline.SourcePath -or -not $baseline.Files) {
    Write-Error "Invalid baseline file - missing required fields (SourcePath, Files)"
    Write-Host ""
    Write-Host "The file does not appear to be a valid fingerprint baseline." -ForegroundColor Yellow
    Write-Host "Run New-ServiceFingerprint.ps1 to create a proper baseline first." -ForegroundColor Yellow
    exit 1
}

Write-Host "    Service: $($baseline.Service)" -ForegroundColor White
Write-Host "    Source: $($baseline.SourcePath)" -ForegroundColor White
Write-Host "    Created: $($baseline.Created)" -ForegroundColor White
Write-Host "    Files in baseline: $($baseline.FileCount)" -ForegroundColor White
Write-Host ""

# Verify source path still exists
if (-not (Test-Path $baseline.SourcePath)) {
    Write-Error "Source path no longer exists: $($baseline.SourcePath)"
    exit 1
}

Write-Host "[*] Scanning current state of: $($baseline.SourcePath)" -ForegroundColor Yellow
$currentHashes = Get-CurrentHashes -SourcePath $baseline.SourcePath
Write-Host "    Files found: $($currentHashes.Count)" -ForegroundColor White
Write-Host ""

# Convert baseline files to proper format for comparison
$baselineFiles = @()
foreach ($f in $baseline.Files) {
    $baselineFiles += @{
        Path         = $f.Path
        RelativePath = $f.RelativePath
        Hash         = $f.Hash
        Size         = $f.Size
        LastModified = $f.LastModified
    }
}

# Compare
$comparison = Compare-FileHashes -BaselineFiles $baselineFiles -CurrentFiles $currentHashes

# Display results
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Comparison Results" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$hasChanges = $false

if ($comparison.Added.Count -gt 0) {
    $hasChanges = $true
    Write-Host "[!] ADDED FILES ($($comparison.Added.Count)):" -ForegroundColor Red
    foreach ($file in $comparison.Added) {
        Write-Host "    + $($file.RelativePath)" -ForegroundColor Red
    }
    Write-Host ""
}

if ($comparison.Removed.Count -gt 0) {
    $hasChanges = $true
    Write-Host "[!] REMOVED FILES ($($comparison.Removed.Count)):" -ForegroundColor Yellow
    foreach ($file in $comparison.Removed) {
        Write-Host "    - $($file.RelativePath)" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($comparison.Modified.Count -gt 0) {
    $hasChanges = $true
    Write-Host "[!] MODIFIED FILES ($($comparison.Modified.Count)):" -ForegroundColor Magenta
    foreach ($file in $comparison.Modified) {
        Write-Host "    ~ $($file.RelativePath)" -ForegroundColor Magenta
        Write-Host "      Old hash: $($file.OriginalHash.Substring(0,16))..." -ForegroundColor DarkGray
        Write-Host "      New hash: $($file.CurrentHash.Substring(0,16))..." -ForegroundColor DarkGray
    }
    Write-Host ""
}

if (-not $hasChanges) {
    Write-Host "[OK] No changes detected! All $($comparison.Unchanged) files match baseline." -ForegroundColor Green
}
else {
    Write-Host "Summary:" -ForegroundColor White
    Write-Host "  Added: $($comparison.Added.Count)" -ForegroundColor Red
    Write-Host "  Removed: $($comparison.Removed.Count)" -ForegroundColor Yellow
    Write-Host "  Modified: $($comparison.Modified.Count)" -ForegroundColor Magenta
    Write-Host "  Unchanged: $($comparison.Unchanged)" -ForegroundColor Green
}

# Export results if requested
if ($ExportResults -and $hasChanges) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $exportFile = Join-Path $BaselineDir "changes-$($baseline.Service)-$timestamp.json"
    
    @{
        Baseline   = $targetBaseline
        ComparedAt = (Get-Date).ToString('o')
        SourcePath = $baseline.SourcePath
        Results    = $comparison
    } | ConvertTo-Json -Depth 10 | Out-File $exportFile -Encoding UTF8
    
    Write-Host ""
    Write-Host "Results exported to: $exportFile" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "[DONE] Comparison completed" -ForegroundColor Green
