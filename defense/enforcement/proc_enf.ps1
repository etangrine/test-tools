# --- CONFIGURATION ---
param(
    [Parameter(HelpMessage = "Set this switch to actually KILL processes. Default is reporting only.")]
    [switch]$KillMode
) 

# specific processes to ignore (ISTS Quals compliant)
$Whitelist = @(
    # DataDog (Out of Scope per ISTS rules)
    "ddagent", "datadog-agent", "trace-agent", "process-agent", "security-agent",
    # Whiteteam (Out of Scope)
    "whiteteam",
    # IIS
    "w3wp",
    # DNS
    "dns",
    # WinRM
    "wsmprovhost",
    # AD Web Services
    "Microsoft.ActiveDirectory.WebServices",
    # Wazuh Agent (Windows)
    "wazuh-agent", "ossec-agent",
    # Admin Tools
    "powershell", "pwsh", "powershell_ise", "explorer", "code", "mmc", "taskmgr", "regedit"
) 

# --- THE SCRIPT ---
Write-Host "Starting Signature Scan..." -ForegroundColor Cyan

# Get all running processes that have a file path (skips system protected ones)
$procs = Get-Process | Where-Object { $_.Path -ne $null }

foreach ($p in $procs) {
    # Skip whitelisted names
    if ($Whitelist -contains $p.ProcessName) { continue }

    try {
        # Check the digital signature of the executable on disk
        $sig = Get-AuthenticodeSignature -FilePath $p.Path

        # LOGIC: If the status is NOT Valid OR the signer is NOT Microsoft
        # Note: We use -notmatch because "Microsoft Windows" and "Microsoft Corporation" vary
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch "Microsoft") {
            
            Write-Host "SUSPECT FOUND: $($p.Name)" -ForegroundColor Red
            Write-Host "   Path:   $($p.Path)" -ForegroundColor Yellow
            Write-Host "   Signer: $($sig.SignerCertificate.Subject)"
            Write-Host "   Status: $($sig.Status)"
            
            # Auto-kill if KillMode is on OR if it's a critical binary impersonator
            # Check for critical binary impersonation (processes that should only run from System32)
            $CriticalBinaries = @("svchost", "lsass", "csrss", "services", "winlogon", "smss", "wininit", "spoolsv")
            $IsTargetBinary = ($CriticalBinaries -contains $p.ProcessName)

            if ($KillMode) {
                Write-Host "   [!] KILLING PROCESS..." -BackgroundColor Red -ForegroundColor White
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                
                if ($IsTargetBinary) {
                    Start-Sleep -Milliseconds 200
                    Write-Host "   [!] DELETING FAKE CRITICAL BINARY..." -BackgroundColor Red -ForegroundColor White
                    Remove-Item -LiteralPath $p.Path -Force -ErrorAction SilentlyContinue
                }
            }
            elseif ($IsTargetBinary) {
                Write-Host "   [!] WOULD KILL & DELETE (Run with -KillMode to execute)" -ForegroundColor Magenta
            }
            Write-Host "------------------------------------------------"
        }
    }
    catch {
        # Sometimes you can't read the signature of a system process due to permissions
        Write-Host "Could not scan: $($p.Name) (Access Denied)" -ForegroundColor Gray
    }
}

Write-Host "Scan Complete." -ForegroundColor Cyan