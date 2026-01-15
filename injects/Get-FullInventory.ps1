<#
.SYNOPSIS
    Gathers comprehensive system inventory for Incident Response.
.DESCRIPTION
    Collects information about OS, Network, Users, Installed Software, and Listening Ports.
    Outputs a formatted report or saves to file.
.PARAMETER OutputFile
    Optional path to save the inventory report.
.EXAMPLE
    .\Get-FullInventory.ps1
    Displays formatted inventory report
.EXAMPLE
    .\Get-FullInventory.ps1 -OutputFile "C:\Users\Public\Inventory.txt"
#>
param(
    [string]$OutputFile
)

# --- Context Detection (Robust) ---
function Test-IsDomainController {
    try {
        $ComputerInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        return $ComputerInfo.DomainRole -ge 4
    }
    catch {
        try {
            $ComputerInfo = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
            return $ComputerInfo.DomainRole -ge 4
        }
        catch {
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
$Output = [System.Text.StringBuilder]::new()

# --- Helper to build output ---
function Add-Section {
    param([string]$Title, [string]$Content)
    [void]$Output.AppendLine("")
    [void]$Output.AppendLine("=" * 60)
    [void]$Output.AppendLine("  $Title")
    [void]$Output.AppendLine("=" * 60)
    [void]$Output.AppendLine($Content)
}

Write-Host "Gathering System Inventory..." -ForegroundColor Cyan

# 1. Host & OS Info
$OSInfo = Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, OsUptime
$Hostname = $OSInfo.CsName
$SystemType = if ($IsDC) { "Domain Controller" } else { "Workstation/Server" }

$HostSection = @"
Hostname:    $Hostname
System Type: $SystemType
OS Name:     $($OSInfo.OsName)
OS Version:  $($OSInfo.OsVersion)
Uptime:      $($OSInfo.OsUptime)
"@
Add-Section "HOST INFORMATION" $HostSection

# 2. Network Config
$NetConfig = Get-NetIPConfiguration | ForEach-Object {
    [PSCustomObject]@{
        Interface = $_.InterfaceAlias
        IPv4      = ($_.IPv4Address.IPAddress) -join ", "
        Gateway   = ($_.IPv4DefaultGateway.NextHop) -join ", "
        DNS       = ($_.DNSServer.ServerAddresses) -join ", "
    }
}
$NetSection = ($NetConfig | Format-Table -AutoSize | Out-String).Trim()
Add-Section "NETWORK CONFIGURATION" $NetSection

# 3. Users (Context-Aware - simplified, no admin group breakdown)
if ($IsDC) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $Users = Get-ADUser -Filter * | Select-Object SamAccountName, Name, Enabled
        $UserSection = ($Users | Format-Table -AutoSize | Out-String).Trim()
    }
    catch {
        $UserSection = "Error querying Active Directory: $_"
    }
}
else {
    $Users = Get-LocalUser | Select-Object Name, Enabled, LastLogon
    $UserSection = ($Users | Format-Table -AutoSize | Out-String).Trim()
}
Add-Section "USERS" $UserSection

# 4. All Listening Ports (simplified - just ports)
$Ports = Get-NetTCPConnection -State Listen | 
Select-Object LocalAddress, LocalPort |
Sort-Object LocalPort -Unique
$PortSection = ($Ports | Format-Table -AutoSize | Out-String).Trim()
Add-Section "LISTENING PORTS" $PortSection

# 5. Installed Software (filter out empty entries)
$Software = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | 
Where-Object { $_.DisplayName } |
Select-Object DisplayName, DisplayVersion, Publisher |
Sort-Object DisplayName
$SoftwareSection = ($Software | Format-Table -AutoSize | Out-String).Trim()
Add-Section "INSTALLED SOFTWARE" $SoftwareSection

# --- Output ---
$FinalOutput = $Output.ToString()

if ($OutputFile) {
    $FinalOutput | Set-Content -Path $OutputFile
    Write-Host "[+] Inventory saved to $OutputFile" -ForegroundColor Green
}
else {
    Write-Host $FinalOutput
}
