<#
.SYNOPSIS
    Downloads essential Sysinternals tools for incident response.

.DESCRIPTION
    Downloads specific Sysinternals tools from live.sysinternals.com.
    Can work offline if tools are pre-staged in the tools directory.
    Adds tools to PATH for the current session.

.PARAMETER Offline
    Use pre-staged local tools instead of downloading.

.PARAMETER ToolsPath
    Directory to store tools. Defaults to setup\tools.

.EXAMPLE
    .\Install-Tools.ps1
    Downloads tools to setup\tools directory.

.EXAMPLE
    .\Install-Tools.ps1 -Offline
    Uses pre-staged tools from setup\tools directory.
#>

param(
    [switch]$Offline,
    [string]$ToolsPath = "$PSScriptRoot\tools"
)

# Tools to download - add/remove as needed
$SysinternalsTools = @(
    # --- Your familiar tools ---
    "Autoruns.exe",       # GUI: Startup/persistence analysis
    "autorunsc.exe",      # CLI version of Autoruns (scriptable)
    "PsExec.exe",         # Remote command execution
    "TCPView.exe",        # GUI: Live network connections
    "procexp.exe",        # GUI: Advanced task manager
    "Procmon.exe",        # GUI: Real-time system activity monitor
    
    # --- Recommended additions ---
    "handle.exe",         # CLI: Find what process has a file locked
    "Sigcheck.exe",       # CLI: Verify digital signatures (detect tampering)
    "Listdlls.exe",       # CLI: List DLLs loaded by processes (find injections)
    "accesschk.exe",      # CLI: Check permissions on files/services/registry
    "PsService.exe",      # CLI: Service management (view, start, stop, config)
    "strings.exe"         # CLI: Extract readable strings from binaries
)

$BaseUrl = "https://live.sysinternals.com"

# Create tools directory
if (-not (Test-Path $ToolsPath)) {
    New-Item -ItemType Directory -Path $ToolsPath -Force | Out-Null
    Write-Host "Created tools directory: $ToolsPath" -ForegroundColor Cyan
}

if ($Offline) {
    Write-Host "`n=== OFFLINE MODE ===" -ForegroundColor Yellow
    Write-Host "Using pre-staged tools from: $ToolsPath" -ForegroundColor Cyan
    
    $missing = @()
    foreach ($tool in $SysinternalsTools) {
        $toolPath = Join-Path $ToolsPath $tool
        if (-not (Test-Path $toolPath)) {
            $missing += $tool
        }
    }
    
    if ($missing.Count -gt 0) {
        Write-Warning "Missing tools: $($missing -join ', ')"
        Write-Warning "Run without -Offline to download, or manually place tools in $ToolsPath"
    }
    else {
        Write-Host "All tools present!" -ForegroundColor Green
    }
}
else {
    Write-Host "`n=== DOWNLOADING SYSINTERNALS TOOLS ===" -ForegroundColor Cyan
    Write-Host "Source: $BaseUrl`n" -ForegroundColor DarkGray
    
    $success = 0
    $failed = @()
    
    foreach ($tool in $SysinternalsTools) {
        $url = "$BaseUrl/$tool"
        $dest = Join-Path $ToolsPath $tool
        
        Write-Host "  Downloading $tool... " -NoNewline
        try {
            Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -ErrorAction Stop
            Write-Host "OK" -ForegroundColor Green
            $success++
        }
        catch {
            Write-Host "FAILED" -ForegroundColor Red
            $failed += $tool
        }
    }
    
    Write-Host "`nDownloaded: $success/$($SysinternalsTools.Count) tools" -ForegroundColor Cyan
    if ($failed.Count -gt 0) {
        Write-Warning "Failed: $($failed -join ', ')"
    }
}

# Add to PATH for this session
$env:PATH = "$ToolsPath;$env:PATH"
Write-Host "`nTools directory added to PATH for this session." -ForegroundColor Green
Write-Host "You can now run tools directly, e.g.: handle.exe -a" -ForegroundColor DarkGray

# Quick reference
Write-Host "`n=== QUICK REFERENCE ===" -ForegroundColor Yellow
Write-Host @"
  GUI Tools:
    Autoruns.exe   - View/disable startup items and persistence
    TCPView.exe    - Live network connections (like netstat but better)
    procexp.exe    - Process Explorer (advanced task manager)
    Procmon.exe    - Real-time file, registry, process, network activity

  CLI Tools (great for scripting):
    autorunsc.exe -accepteula -a * -c    # Export autoruns to CSV
    handle.exe -a                         # List all handles
    Sigcheck.exe -e -u C:\Windows\*       # Find unsigned executables
    Listdlls.exe -u                       # Find unsigned DLLs in processes
    accesschk.exe -ucqv "ServiceName"     # Check service permissions
    PsService.exe query                   # List all services
    strings.exe -n 8 suspicious.exe       # Extract strings from binary
"@
