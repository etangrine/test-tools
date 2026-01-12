<#
.SYNOPSIS
    Tests WinRM service health and connectivity for scoring verification.
.DESCRIPTION
    Checks if WinRM is properly configured and listening on expected ports (5985/5986).
    Useful for verifying First Olympics (10.x.1.2) scoring readiness.
.PARAMETER RemoteHost
    Optional remote host to test WinRM connectivity against.
.EXAMPLE
    .\Test-WinRMHealth.ps1
    Checks local WinRM configuration.
.EXAMPLE
    .\Test-WinRMHealth.ps1 -RemoteHost "10.2.1.2"
    Tests WinRM connectivity to remote host.
#>
param(
    [string]$RemoteHost
)

Write-Host "`n=== WinRM Health Check ===" -ForegroundColor Cyan

# 1. Check WinRM Service Status
$WinRMService = Get-Service -Name WinRM -ErrorAction SilentlyContinue
if ($WinRMService) {
    $Color = if ($WinRMService.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Host "[*] WinRM Service: $($WinRMService.Status)" -ForegroundColor $Color
    Write-Host "    Start Type: $($WinRMService.StartType)" -ForegroundColor Gray
}
else {
    Write-Host "[-] WinRM Service not found!" -ForegroundColor Red
    return
}

# 2. Check WinRM Listener Configuration
Write-Host "`n[*] WinRM Listeners:" -ForegroundColor Cyan
try {
    $Listeners = Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -ErrorAction Stop
    foreach ($Listener in $Listeners) {
        Write-Host "    Transport: $($Listener.Transport)" -ForegroundColor Green
        Write-Host "    Port: $($Listener.Port)"
        Write-Host "    Address: $($Listener.Address)"
        Write-Host "    Enabled: $($Listener.Enabled)"
        Write-Host ""
    }
}
catch {
    Write-Host "    [!] Could not enumerate listeners: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 3. Check Port Listening Status
Write-Host "[*] Port Status:" -ForegroundColor Cyan
$Ports = @(5985, 5986)
foreach ($Port in $Ports) {
    $Listening = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($Listening) {
        Write-Host "    Port $Port : LISTENING" -ForegroundColor Green
    }
    else {
        Write-Host "    Port $Port : NOT LISTENING" -ForegroundColor Red
    }
}

# 4. Check Firewall Rules
Write-Host "`n[*] Firewall Rules for WinRM:" -ForegroundColor Cyan
$FwRules = Get-NetFirewallRule -DisplayName "*WinRM*" -ErrorAction SilentlyContinue
if ($FwRules) {
    foreach ($Rule in $FwRules) {
        $Color = if ($Rule.Enabled -eq 'True' -and $Rule.Action -eq 'Allow') { 'Green' } else { 'Yellow' }
        Write-Host "    $($Rule.DisplayName): Enabled=$($Rule.Enabled), Action=$($Rule.Action)" -ForegroundColor $Color
    }
}
else {
    Write-Host "    [!] No WinRM firewall rules found" -ForegroundColor Yellow
}

# 5. Test Remote Connectivity (if RemoteHost specified)
if ($RemoteHost) {
    Write-Host "`n[*] Testing connectivity to $RemoteHost..." -ForegroundColor Cyan
    
    # Test TCP connectivity first
    $TcpTest = Test-NetConnection -ComputerName $RemoteHost -Port 5985 -WarningAction SilentlyContinue
    if ($TcpTest.TcpTestSucceeded) {
        Write-Host "    TCP 5985: OPEN" -ForegroundColor Green
        
        # Try WinRM session
        try {
            $Session = New-PSSession -ComputerName $RemoteHost -ErrorAction Stop
            Write-Host "    [+] WinRM Session: SUCCESS" -ForegroundColor Green
            Remove-PSSession $Session
        }
        catch {
            Write-Host "    [!] WinRM Session Failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "    TCP 5985: CLOSED/FILTERED" -ForegroundColor Red
    }
}

# 6. Quick Configuration Status
Write-Host "`n[*] WinRM Configuration:" -ForegroundColor Cyan
try {
    $Config = Get-WSManInstance -ResourceURI winrm/config -ErrorAction Stop
    Write-Host "    MaxEnvelopeSizekb: $($Config.MaxEnvelopeSizekb)"
    Write-Host "    MaxTimeoutms: $($Config.MaxTimeoutms)"
    Write-Host "    MaxBatchItems: $($Config.MaxBatchItems)"
}
catch {
    Write-Host "    [!] Could not read config: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host "`n=== WinRM Health Check Complete ===" -ForegroundColor Cyan
