# initial_recon.ps1
# Creates a timestamped log file on the current user's Desktop
$LogFile = "$env:USERPROFILE\Desktop\InitialRecon-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"

# --- Function to write output to both the screen and the log file ---
function Write-Log {
    param(
        [string]$Message
    )
    # Write to the console host
    Write-Host $Message
    # Append to the log file
    Add-Content -Path $LogFile -Value $Message
}

# --- Start of Script ---
Write-Log "=================================================="
Write-Log "Initial Windows System Reconnaissance"
Write-Log "Timestamp: $(Get-Date)"
Write-Log "=================================================="

Write-Log "`n[+] Basic System Information:"
# Fix is here: Wrapped the command in () and passed it to the function
Write-Log (Get-ComputerInfo | Select-Object OsName, OsVersion, CsName, OsUptime | Format-List | Out-String)

Write-Log "`n[+] Network Configuration and Open Ports:"
Write-Log (Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress | Format-Table | Out-String)
Write-Log (Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table | Out-String)

Write-Log "`n[+] Local User Accounts:"
Write-Log (Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table | Out-String)

Write-Log "`n[+] Currently Running Processes:"
Write-Log (Get-Process | Select-Object Name, Id, Path | Format-Table | Out-String)

Write-Log "`n[+] Autorun Programs (from Registry):"
# Checks registry keys where malware often places persistence
Write-Log (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Get-ItemProperty | Select-Object * | Format-List | Out-String)
Write-Log (Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" | Get-ItemProperty | Select-Object * | Format-List | Out-String)
Write-Log (Get-Item "HKCU\Software\Microsoft\Command Processor\AutoRun" | Get-ItemProperty | Select-Object * | Format-List | Out-String)


Write-Log "`n[+] Installed Services:"
Write-Log (Get-Service | Select-Object Name, DisplayName, Status, StartType | Format-Table | Out-String)

Write-Log "`n=================================================="
Write-Log "Reconnaissance Complete. Log saved to $LogFile"
Write-Log "=================================================="