<#
.SYNOPSIS
    Attempts to repair and start critical services.
.DESCRIPTION
    Takes a list of services, sets their StartType to Automatic, and attempts to Start them.
    Useful for quickly bringing services back up during a competition.
.PARAMETER Services
    List of service names to repair. Defaults to a standard critical list if not provided.
.EXAMPLE
    .\Repair-ServiceHealth.ps1
    Repairs default critical services.
.EXAMPLE
    .\Repair-ServiceHealth.ps1 -Services "W3SVC"
#>
param(
    [string[]]$Services = @(
        "DNS",
        "Dhcp",
        "ADWS",
        "NTDS",
        "W3SVC",
        "LanmanServer",
        "LanmanWorkstation",
        "WinRM",
        "MpsSvc",
        "EventLog",
        "TermService"
    )
)

Write-Host "Starting Service Repair..." -ForegroundColor Cyan

foreach ($ServiceName in $Services) {
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if (-not $Service) {
        Write-Host "[-] Service '$ServiceName' not found or not installed." -ForegroundColor DarkGray
        continue
    }

    Write-Host "[*] Processing: $($Service.Name) ($($Service.Status))"

    # 1. Fix Startup Type
    if ($Service.StartType -ne "Automatic") {
        try {
            Set-Service -Name $ServiceName -StartupType Automatic -ErrorAction Stop
            Write-Host "    [+] Set StartType to Automatic" -ForegroundColor Green
        }
        catch {
            Write-Host "    [!] Failed to set StartType: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "    [=] StartType is already Automatic" -ForegroundColor Gray
    }

    # 2. Start Service if Stopped
    if ($Service.Status -ne "Running") {
        try {
            Start-Service -Name $ServiceName -ErrorAction Stop
            Write-Host "    [+] Service Started Successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "    [!] Failed to start service: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "    [=] Service is already Running" -ForegroundColor Gray
    }
}

Write-Host "Service Repair Complete." -ForegroundColor Cyan
