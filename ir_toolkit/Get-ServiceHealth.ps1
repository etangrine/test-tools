<#
.SYNOPSIS
    Retrieves the status of critical services for Incident Response.
.DESCRIPTION
    Checks a list of critical services (DNS, DHCP, AD, IIS, SMB, WinRM) and reports their status.
    Can be used to quickly identify services that have been stopped by attackers.
.PARAMETER Services
    Optional list of specific service names to check.
.EXAMPLE
    .\Get-ServiceHealth.ps1
    Checks default critical services.
.EXAMPLE
    .\Get-ServiceHealth.ps1 -Services "Spooler","W3SVC"
#>
param(
    [string[]]$Services = @(
        "DNS",              # DNS Server
        "Dhcp",             # DHCP Server
        "ADWS",             # Active Directory Web Services
        "NTDS",             # Active Directory Domain Services
        "W3SVC",            # IIS World Wide Web Publishing Service
        "LanmanServer",     # SMB Server
        "LanmanWorkstation",# SMB Client
        "WinRM",            # Windows Remote Management
        "MpsSvc",           # Windows Firewall
        "EventLog",         # Windows Event Log
        "TermService"       # Remote Desktop Services
    )
)

$Results = @()

foreach ($ServiceName in $Services) {
    $ServiceObj = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if ($ServiceObj) {
        $Results += [PSCustomObject]@{
            ServiceName = $ServiceObj.Name
            DisplayName = $ServiceObj.DisplayName
            Status      = $ServiceObj.Status
            StartType   = $ServiceObj.StartType
            CanStop     = $ServiceObj.CanStop
        }
    }
    else {
        $Results += [PSCustomObject]@{
            ServiceName = $ServiceName
            DisplayName = "NOT FOUND / NOT INSTALLED"
            Status      = "Missing"
            StartType   = "Unknown"
            CanStop     = $null
        }
    }
}

# Display Table
$Results | Format-Table -AutoSize

# Return Object for further processing if needed
return $Results
