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

# --- Context Detection (Robust) ---
function Test-IsDomainController {
    # Primary check: CIM (modern, preferred for PowerShell 3.0+)
    try {
        $ComputerInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        return $ComputerInfo.DomainRole -ge 4
    }
    catch {
        # Fallback: WMI (legacy, widely available)
        try {
            $ComputerInfo = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
            return $ComputerInfo.DomainRole -ge 4
        }
        catch {
            # Final fallback: Check for NTDS service (only exists on DCs)
            try {
                $ntds = Get-Service -Name 'NTDS' -ErrorAction Stop
                return $ntds.Status -eq 'Running'
            }
            catch {
                return $false
            }
        }
    }
}

$IsDC = Test-IsDomainController
$Inventory = [ordered]@{}

Write-Host "Gathering System Inventory..." -ForegroundColor Cyan
Write-Host "Context: $(if ($IsDC) {'Domain Controller'} else {'Workstation/Server'})" -ForegroundColor Cyan

# 1. OS Info
$Inventory["OS"] = Get-ComputerInfo | Select-Object OsName, OsVersion, CsName, OsUptime

# 2. Network Config
$Inventory["Network"] = Get-NetIPConfiguration | Select-Object InterfaceAlias,
@{N = "IPv4Address"; E = { ($_.IPv4Address.IPAddress) -join ", " } },
@{N = "IPv4DefaultGateway"; E = { ($_.IPv4DefaultGateway.NextHop) -join ", " } },
@{N = "DNSServer"; E = { ($_.DNSServer.ServerAddresses) -join ", " } }

# 3. Users (Context-Aware)
if ($IsDC) {
    # Domain Controller: Get domain users and privileged group members
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $Inventory["DomainUsers"] = Get-ADUser -Filter * | Select-Object SamAccountName, Name, Enabled
        $Inventory["DomainAdmins"] = Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction SilentlyContinue | Select-Object Name, SamAccountName
        $Inventory["EnterpriseAdmins"] = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction SilentlyContinue | Select-Object Name, SamAccountName
        $Inventory["SchemaAdmins"] = Get-ADGroupMember -Identity "Schema Admins" -Recursive -ErrorAction SilentlyContinue | Select-Object Name, SamAccountName
    }
    catch {
        Write-Warning "Could not query Active Directory: $_"
        $Inventory["DomainUsers"] = "Error querying AD"
    }
}
else {
    # Workstation/Server: Get local admins
    $Admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    $Inventory["LocalAdmins"] = $Admins
}

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
