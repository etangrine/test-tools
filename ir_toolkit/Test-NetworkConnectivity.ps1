<#
.SYNOPSIS
    Tests basic network connectivity and DNS resolution.
.DESCRIPTION
    Pings critical targets (Gateway, DNS, Internet, specific internal IPs) to diagnose connectivity issues.
.PARAMETER Targets
    Additional IPs or Hostnames to ping.
.EXAMPLE
    .\Test-NetworkConnectivity.ps1
.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -Targets "192.168.1.10", "DC01"
#>
param(
    [string[]]$Targets = @()
)

$Results = @()

Write-Host "Starting Network Connectivity Test..." -ForegroundColor Cyan

# 1. Check Interface Status
$Interfaces = Get-NetAdapter | Where-Object Status -eq "Up"
if ($Interfaces) {
    Write-Host "[+] Active Network Interfaces found:" -ForegroundColor Green
    $Interfaces | ForEach-Object { Write-Host "    - $($_.Name): $($_.MacAddress) ($($_.LinkSpeed))" }
}
else {
    Write-Host "[!] No UP network interfaces found!" -ForegroundColor Red
}

# 2. Check IP Configuration
$IPConfig = Get-NetIPConfiguration
foreach ($config in $IPConfig) {
    if ($config.IPv4Address) {
        Write-Host "    Interface: $($config.InterfaceAlias)"
        Write-Host "      IP: $($config.IPv4Address.IPAddress)"
        Write-Host "      Gateway: $($config.IPv4DefaultGateway.NextHop)"
        Write-Host "      DNS: $($config.DNSServer.ServerAddresses)"
        
        # Add Gateway and DNS to Targets
        if ($config.IPv4DefaultGateway) { $Targets += $config.IPv4DefaultGateway.NextHop }
        if ($config.DNSServer) { $Targets += $config.DNSServer.ServerAddresses }
    }
}

# 3. Add Standard External Targets
$Targets += "8.8.8.8" # Google DNS
$Targets += "google.com" # External Domain

# Deduplicate
$Targets = $Targets | Select-Object -Unique

# 4. Ping Test
foreach ($Target in $Targets) {
    # Skip empty targets
    if ([string]::IsNullOrWhiteSpace($Target)) { continue }

    $Test = Test-Connection -ComputerName $Target -Count 1 -ErrorAction SilentlyContinue
    
    if ($Test) {
        $Status = "UP"
        $Color = "Green"
        $MS = $Test.ResponseTime
    }
    else {
        $Status = "DOWN"
        $Color = "Red"
        $MS = "N/A"
    }
    
    Write-Host "  Pinging $Target ... [$Status] ($MS ms)" -ForegroundColor $Color
    
    $Results += [PSCustomObject]@{
        Target       = $Target
        Status       = $Status
        ResponseTime = $MS
    }
}

# 5. DNS Resolution Test
Write-Host "`nTesting DNS Resolution..." -ForegroundColor Cyan
$DomainToCheck = "google.com"
try {
    $IP = [System.Net.Dns]::GetHostAddresses($DomainToCheck)
    Write-Host "  [+] Resolved $DomainToCheck to $($IP[0])" -ForegroundColor Green
}
catch {
    Write-Host "  [!] Failed to resolve $DomainToCheck" -ForegroundColor Red
}

return $Results
