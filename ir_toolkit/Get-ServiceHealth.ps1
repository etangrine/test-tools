<#
.SYNOPSIS
    Retrieves the deep health status of critical services for Incident Response.
.DESCRIPTION
    Checks a list of critical services and performs deep inspection including:
    - Service Status and Start Type
    - Registry Permissions (ACLs)
    - Registry 'Start' value integrity
    - Service Security Descriptor (SDDL) for Admin access
    - File Image Path validation
    - Service Dependencies health
    - IIS Specific checks (wwwroot visibility)
    - Global Firewall Blocking Rules check
.PARAMETER Services
    Optional list of specific service names to check.
.EXAMPLE
    .\Get-ServiceHealth.ps1
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
        "TermService",      # Remote Desktop Services
        "Spooler"           # Printer Spooler (often targeted)
    )
)

function Test-ServiceDeepHealth {
    param (
        [string]$ServiceName
    )

    $Result = [PSCustomObject]@{
        ServiceName   = $ServiceName
        Status        = "Missing"
        StartType     = "Unknown"
        RegistryACL   = "Unknown" # Safe/Unsafe/Error
        RegistryStart = "Unknown" # Correct/Mismatch/Error
        SDDL          = "Unknown" # Safe/Restricted/Error
        ImagePath     = "Unknown" # Valid/Missing/Error
        Dependencies  = "Unknown" # OK/Broken
        ExtraChecks   = ""        # For IIS or other specific checks
    }

    $ServiceObj = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if ($ServiceObj) {
        $Result.Status = $ServiceObj.Status
        $Result.StartType = $ServiceObj.StartType
    }

    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

    # 1. Check Registry ACLs
    if (Test-Path $RegPath) {
        try {
            $Acl = Get-Acl -Path $RegPath -ErrorAction Stop
            $AdminAccess = $Acl.Access | Where-Object { 
                ($_.IdentityReference -match "Administrators" -or $_.IdentityReference.Value -match "S-1-5-32-544") -and 
                ($_.RegistryRights -match "FullControl") 
            }
            if ($AdminAccess) { $Result.RegistryACL = "Safe" } else { $Result.RegistryACL = "RESTRICTED" }
        }
        catch {
            $Result.RegistryACL = "AccessDenied"
        }

        # 2. Check Registry Start Value
        try {
            $StartProp = Get-ItemProperty -Path $RegPath -Name "Start" -ErrorAction SilentlyContinue
            if ($StartProp) {
                if ($StartProp.Start -eq 4) { $Result.RegistryStart = "DISABLED(4)" }
                elseif ($ServiceObj -and $ServiceObj.StartType -eq "Automatic" -and $StartProp.Start -ne 2) { $Result.RegistryStart = "Mismatch" }
                else { $Result.RegistryStart = "OK" }
            }
        }
        catch { $Result.RegistryStart = "Error" }

        # 3. Check Image Path
        try {
            $ImgProp = Get-ItemProperty -Path $RegPath -Name "ImagePath" -ErrorAction SilentlyContinue
            if ($ImgProp) {
                $ExpandedPath = [System.Environment]::ExpandEnvironmentVariables($ImgProp.ImagePath)
                # Remove quotes and arguments for basic file check
                $ExePath = ($ExpandedPath -split ' ')[0] -replace '"', ''
                if (Test-Path $ExePath) { $Result.ImagePath = "Valid" }
                else { $Result.ImagePath = "FILE MISSING" }
            }
        }
        catch { $Result.ImagePath = "Error" }
    }
    else {
        $Result.RegistryACL = "RegKeyMissing"
        $Result.RegistryStart = "RegKeyMissing"
    }

    # 4. Check SDDL (Service Permissions)
    try {
        $SDDL = sc.exe sdshow $ServiceName | Out-String
        if ($SDDL -match "BA") { $Result.SDDL = "Safe" }
        elseif ($SDDL -match "Access is denied") { $Result.SDDL = "AccessDenied" }
        elseif ($null -eq $ServiceObj) { $Result.SDDL = "N/A" } # Service doesn't exist
        else { $Result.SDDL = "RESTRICTED(NoAdmin)" }
    }
    catch { $Result.SDDL = "Error" }

    # 5. Check Dependencies
    if ($ServiceObj) {
        $DepStatus = @()
        foreach ($Dep in $ServiceObj.RequiredServices) {
            if ($Dep.Status -ne "Running") { $DepStatus += "$($Dep.Name):$($Dep.Status)" }
        }
        if ($DepStatus.Count -gt 0) { $Result.Dependencies = "Issues: $($DepStatus -join ', ')" }
        else { $Result.Dependencies = "OK" }
    }

    # 6. IIS Specific Checks
    if ($ServiceName -eq "W3SVC") {
        $wwwHealth = @()
        $WebRoot = "C:\inetpub\wwwroot"
        if (Test-Path $WebRoot) {
            $Item = Get-Item $WebRoot
            if ($Item.Attributes -match "Hidden") { $wwwHealth += "WWWROOT HIDDEN" }
            else { $wwwHealth += "wwwroot OK" }
        }
        else {
            $wwwHealth += "wwwroot MISSING"
        }
        $Result.ExtraChecks = $wwwHealth -join "; "
    }

    return $Result
}

Write-Host "Gathering deep service health metrics..." -ForegroundColor Cyan

$TotalResults = @()

foreach ($Svc in $Services) {
    $TotalResults += Test-ServiceDeepHealth -ServiceName $Svc
}

# Global Firewall Check
$FwBlockRules = Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue
$FwStatus = if ($FwBlockRules) { "WARNING: Found $($FwBlockRules.Count) Inbound Block Rules" } else { "OK" }
Write-Host "Firewall Status: $FwStatus" -ForegroundColor $(if ($FwStatus -eq "OK") { "Green" } else { "Red" })

$TotalResults | Format-Table -AutoSize

return $TotalResults
