<#
.SYNOPSIS
    Gathers comprehensive system inventory for Incident Response.
.DESCRIPTION
    Collects information about OS, Network, Users, Installed Software, and Listening Ports.
    Exports to a consolidated object or text file.
.PARAMETER OutputFile
    Optional path to save the inventory report.
.EXAMPLE
    .\Get-FullInventory.ps1
    returns an object
.EXAMPLE
    .\Get-FullInventory.ps1 -OutputFile "C:\Users\Public\Inventory.txt"
#>
param(
    [string]$OutputFile
)

$Inventory = [ordered]@{}

Write-Host "Gathering System Inventory..." -ForegroundColor Cyan

# 1. OS Info
$Inventory["OS"] = Get-ComputerInfo | Select-Object OsName, OsVersion, CsName, OsUptime

# 2. Network Config
$Inventory["Network"] = Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer

# 3. Local Users (Admins)
$Admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
$Inventory["LocalAdmins"] = $Admins

# 4. Listening Ports (mapped to processes)
# Requires high privileges for process mapping
$Ports = Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, @{N = "ProcessName"; E = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
$Inventory["ListeningPorts"] = $Ports

# 5. Installed Software (Basic Registry Check)
$Software = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher
$Inventory["Software"] = $Software

$Results = [PSCustomObject]$Inventory

if ($OutputFile) {
    $Results | Out-String | Set-Content -Path $OutputFile
    Write-Host "[+] Inventory saved to $OutputFile" -ForegroundColor Green
}
else {
    return $Results
}
