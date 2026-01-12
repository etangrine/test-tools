<#
.SYNOPSIS
    Comprehensive service health check with baseline validation for IR competitions.
.DESCRIPTION
    Consolidated script that performs deep service inspection including:
    - Service Status and Start Type
    - Registry Permissions (ACLs) and Start value integrity
    - Service Security Descriptor (SDDL) for Admin access
    - File Image Path validation with digital signature check
    - Service Dependencies health
    - Baseline validation (ports, image paths, logon accounts)
    - Service-specific checks (IIS wwwroot, WinRM listeners, etc.)
    - Global Firewall Blocking Rules check
    
    Merges functionality from: Get-ServiceHealth, Test-ServiceBaseline, Test-WinRMHealth
.PARAMETER Services
    Optional list of specific service names to check. Defaults to critical services.
.PARAMETER BaselinePath
    Optional path to ServiceBaselines.psd1. If provided, validates against baselines.
.PARAMETER SkipBaseline
    Skip baseline validation even if baseline file exists.
.EXAMPLE
    .\Get-ServiceHealth.ps1
    Checks all default services with deep inspection.
.EXAMPLE
    .\Get-ServiceHealth.ps1 -Services "WinRM"
    Checks only WinRM with deep inspection + WinRM-specific checks.
.EXAMPLE
    .\Get-ServiceHealth.ps1 -BaselinePath ".\ServiceBaselines.psd1"
    Checks services and validates against baseline expectations.
#>
param(
    [string[]]$Services = @(
        "DNS",              # DNS Server (Pyramids)
        "ADWS",             # Active Directory Web Services
        "NTDS",             # Active Directory Domain Services
        "W3SVC",            # IIS World Wide Web Publishing Service (Moon Landing)
        "LanmanServer",     # SMB Server (Wright Brothers)
        "WinRM",            # Windows Remote Management (First Olympics)
        "MpsSvc",           # Windows Firewall
        "EventLog",         # Windows Event Log
        "TermService"       # Remote Desktop Services
    ),
    [string]$BaselinePath,
    [switch]$SkipBaseline
)

# --- Load Baseline Data (if available) ---
$Baselines = $null
if (-not $SkipBaseline) {
    if (-not $BaselinePath) {
        $BaselinePath = Join-Path $PSScriptRoot "ServiceBaselines.psd1"
    }
    if (Test-Path $BaselinePath) {
        $Baselines = Import-PowerShellDataFile -Path $BaselinePath
        Write-Host "[INFO] Loaded baseline data from: $BaselinePath" -ForegroundColor DarkGray
    }
}

# --- Helper Functions ---
function Get-ServiceProcessId {
    param([string]$ServiceName)
    try {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        return $svc.ProcessId
    }
    catch { return $null }
}

function Test-WinRMSpecificHealth {
    <# WinRM-specific checks for listeners, WSMan config, ports #>
    $WinRMHealth = [PSCustomObject]@{
        Listeners     = @()
        PortStatus    = @{}
        ConfigIssues  = @()
        OverallStatus = "Unknown"
    }
    
    # Check Listeners
    try {
        $Listeners = Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -ErrorAction Stop
        foreach ($L in $Listeners) {
            $WinRMHealth.Listeners += [PSCustomObject]@{
                Transport = $L.Transport
                Port      = $L.Port
                Enabled   = $L.Enabled
                Address   = $L.Address
            }
        }
    }
    catch {
        $WinRMHealth.ConfigIssues += "Cannot enumerate listeners: $($_.Exception.Message)"
    }
    
    # Check Port Listening
    foreach ($Port in @(5985, 5986)) {
        $Listening = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        $WinRMHealth.PortStatus[$Port] = if ($Listening) { "LISTENING" } else { "NOT_LISTENING" }
    }
    
    # Check common config issues
    try {
        $IPv4Filter = Get-Item WSMan:\localhost\Service\IPv4Filter -ErrorAction SilentlyContinue
        if ($IPv4Filter -and $IPv4Filter.Value -ne "*" -and $IPv4Filter.Value -ne "") {
            $WinRMHealth.ConfigIssues += "IPv4Filter restricted to: $($IPv4Filter.Value)"
        }
        
        $MaxShells = Get-Item WSMan:\localhost\Shell\MaxShellsPerUser -ErrorAction SilentlyContinue
        if ($MaxShells -and [int]$MaxShells.Value -eq 0) {
            $WinRMHealth.ConfigIssues += "MaxShellsPerUser is 0 (connections blocked)"
        }
    }
    catch {
        $WinRMHealth.ConfigIssues += "Cannot read WSMan config"
    }
    
    # Determine overall status
    $HasListenerOnHTTP = $WinRMHealth.Listeners | Where-Object { $_.Transport -eq "HTTP" -and $_.Enabled -eq "true" }
    $Port5985Listening = $WinRMHealth.PortStatus[5985] -eq "LISTENING"
    
    if ($HasListenerOnHTTP -and $Port5985Listening -and $WinRMHealth.ConfigIssues.Count -eq 0) {
        $WinRMHealth.OverallStatus = "OK"
    }
    elseif (-not $HasListenerOnHTTP) {
        $WinRMHealth.OverallStatus = "CRITICAL:NoHTTPListener"
    }
    elseif (-not $Port5985Listening) {
        $WinRMHealth.OverallStatus = "CRITICAL:Port5985NotListening"
    }
    else {
        $WinRMHealth.OverallStatus = "WARNING:ConfigIssues"
    }
    
    return $WinRMHealth
}

function Test-ServiceDeepHealth {
    param (
        [string]$ServiceName,
        [hashtable]$Baseline
    )

    $Result = [PSCustomObject]@{
        ServiceName     = $ServiceName
        Status          = "Missing"
        StartType       = "Unknown"
        RegistryACL     = "Unknown"
        RegistryStart   = "Unknown"
        LogOnAs         = "Unknown"
        SDDL            = "Unknown"
        ImagePath       = "Unknown"
        Dependencies    = "Unknown"
        # Baseline validation fields
        PortStatus      = "N/A"
        ImagePathMatch  = "N/A"
        LogOnAsMatch    = "N/A"
        DependencyMatch = "N/A"
        # Service-specific
        ExtraChecks     = ""
        Issues          = @()
    }

    $ServiceObj = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if ($ServiceObj) {
        $Result.Status = $ServiceObj.Status.ToString()
        $Result.StartType = $ServiceObj.StartType.ToString()
    }
    else {
        $Result.Issues += "Service not installed"
        return $Result
    }

    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

    # === DEEP HEALTH CHECKS ===
    
    # 1. Check Registry ACLs
    if (Test-Path $RegPath) {
        try {
            $Acl = Get-Acl -Path $RegPath -ErrorAction Stop
            $AdminAccess = $Acl.Access | Where-Object { 
                ($_.IdentityReference -match "Administrators" -or $_.IdentityReference.Value -match "S-1-5-32-544") -and 
                ($_.RegistryRights -match "FullControl") 
            }
            if ($AdminAccess) { $Result.RegistryACL = "Safe" } 
            else { 
                $Result.RegistryACL = "RESTRICTED"
                $Result.Issues += "Registry ACLs restrict admin access"
            }
        }
        catch {
            $Result.RegistryACL = "AccessDenied"
            $Result.Issues += "Cannot read registry ACLs"
        }

        # 2. Check Registry Start Value
        try {
            $StartProp = Get-ItemProperty -Path $RegPath -Name "Start" -ErrorAction SilentlyContinue
            if ($StartProp) {
                if ($StartProp.Start -eq 4) { 
                    $Result.RegistryStart = "DISABLED(4)"
                    $Result.Issues += "Service disabled in registry"
                }
                elseif ($ServiceObj.StartType -eq "Automatic" -and $StartProp.Start -ne 2) { 
                    $Result.RegistryStart = "Mismatch" 
                }
                else { $Result.RegistryStart = "OK" }
            }
        }
        catch { $Result.RegistryStart = "Error" }

        # 3. Check Service User (LogOnAs)
        try {
            $ObjName = Get-ItemProperty -Path $RegPath -Name "ObjectName" -ErrorAction SilentlyContinue
            if ($ObjName) { $Result.LogOnAs = $ObjName.ObjectName }
        }
        catch { $Result.LogOnAs = "Error" }

        # 4. Check Image Path and Digital Signature
        try {
            $ImgProp = Get-ItemProperty -Path $RegPath -Name "ImagePath" -ErrorAction SilentlyContinue
            if ($ImgProp) {
                $ExpandedPath = [System.Environment]::ExpandEnvironmentVariables($ImgProp.ImagePath)
                $ExePath = ($ExpandedPath -split ' ')[0] -replace '"', ''
                if (Test-Path $ExePath) { 
                    $Sig = Get-AuthenticodeSignature -FilePath $ExePath -ErrorAction SilentlyContinue
                    if ($Sig) {
                        switch ($Sig.Status) {
                            "Valid" {
                                if ($Sig.SignerCertificate.Subject -match "O=Microsoft Corporation") {
                                    $Result.ImagePath = "Valid(MS)"
                                }
                                else {
                                    $SignerName = ($Sig.SignerCertificate.Subject -split ',')[0] -replace 'CN=', ''
                                    $Result.ImagePath = "Valid(3P:$SignerName)"
                                }
                            }
                            "NotSigned" { $Result.ImagePath = "WARN:NotSigned"; $Result.Issues += "Binary not signed" }
                            "HashMismatch" { $Result.ImagePath = "CRITICAL:Tampered"; $Result.Issues += "Binary tampered!" }
                            default { $Result.ImagePath = "WARN:$($Sig.Status)" }
                        }
                    }
                    else { $Result.ImagePath = "Valid(NoSig)" }
                }
                else { 
                    $Result.ImagePath = "MISSING"
                    $Result.Issues += "Binary file missing"
                }
            }
        }
        catch { $Result.ImagePath = "Error" }
    }
    else {
        $Result.RegistryACL = "RegKeyMissing"
        $Result.RegistryStart = "RegKeyMissing"
        $Result.Issues += "Registry key missing"
    }

    # 5. Check SDDL (Service Permissions)
    try {
        $SDDL = sc.exe sdshow $ServiceName 2>&1 | Out-String
        if ($SDDL -match "BA") { $Result.SDDL = "Safe" }
        elseif ($SDDL -match "Access is denied") { $Result.SDDL = "AccessDenied"; $Result.Issues += "SDDL access denied" }
        else { $Result.SDDL = "RESTRICTED"; $Result.Issues += "SDDL missing admin access" }
    }
    catch { $Result.SDDL = "Error" }

    # 6. Check Dependencies
    $DepStatus = @()
    foreach ($Dep in $ServiceObj.RequiredServices) {
        if ($Dep.Status -ne "Running") { $DepStatus += "$($Dep.Name):$($Dep.Status)" }
    }
    if ($DepStatus.Count -gt 0) { 
        $Result.Dependencies = "Issues"
        $Result.Issues += "Deps not running: $($DepStatus -join ', ')"
    }
    else { $Result.Dependencies = "OK" }

    # === BASELINE VALIDATION ===
    if ($Baseline) {
        # Port Check
        if ($Baseline.ExpectedPorts -and $Baseline.ExpectedPorts.Count -gt 0 -and $ServiceObj.Status -eq 'Running') {
            $Protocol = if ($Baseline.PortCheckProtocol -eq 'UDP') { 'UDP' } else { 'TCP' }
            $CheckByPID = if ($null -eq $Baseline.PortCheckByPID) { $true } else { $Baseline.PortCheckByPID }
            
            $ListeningPorts = @()
            if ($CheckByPID) {
                $ProcessId = Get-ServiceProcessId -ServiceName $ServiceName
                if ($ProcessId -and $ProcessId -gt 0) {
                    if ($Protocol -eq 'TCP') {
                        $ListeningPorts = Get-NetTCPConnection -State Listen -OwningProcess $ProcessId -ErrorAction SilentlyContinue | 
                        Select-Object -ExpandProperty LocalPort -Unique
                    }
                    else {
                        $ListeningPorts = Get-NetUDPEndpoint -OwningProcess $ProcessId -ErrorAction SilentlyContinue | 
                        Select-Object -ExpandProperty LocalPort -Unique
                    }
                }
            }
            else {
                foreach ($ExpPort in $Baseline.ExpectedPorts) {
                    if ($Protocol -eq 'TCP') {
                        $PortOpen = Get-NetTCPConnection -LocalPort $ExpPort -State Listen -ErrorAction SilentlyContinue
                    }
                    else {
                        $PortOpen = Get-NetUDPEndpoint -LocalPort $ExpPort -ErrorAction SilentlyContinue
                    }
                    if ($PortOpen) { $ListeningPorts += $ExpPort }
                }
            }
            
            $MissingPorts = $Baseline.ExpectedPorts | Where-Object { $_ -notin $ListeningPorts }
            if ($MissingPorts.Count -eq 0) { $Result.PortStatus = "OK" }
            else { 
                $Result.PortStatus = "MISSING:$($MissingPorts -join ',')"
                $Result.Issues += "Ports not listening: $($MissingPorts -join ', ')"
            }
        }
        elseif ($ServiceObj.Status -ne 'Running') {
            $Result.PortStatus = "SVC_STOPPED"
        }

        # ImagePath Match
        if ($Baseline.ExpectedImagePath) {
            $CurrentImg = (Get-ItemProperty -Path $RegPath -Name "ImagePath" -ErrorAction SilentlyContinue).ImagePath
            $NormCurrent = [System.Environment]::ExpandEnvironmentVariables($CurrentImg).ToLower().Trim() -replace '\s+', ' '
            $NormExpected = [System.Environment]::ExpandEnvironmentVariables($Baseline.ExpectedImagePath).ToLower().Trim() -replace '\s+', ' '
            if ($NormCurrent -eq $NormExpected) { $Result.ImagePathMatch = "OK" }
            else { 
                $Result.ImagePathMatch = "MISMATCH"
                $Result.Issues += "ImagePath mismatch from baseline"
            }
        }

        # LogOnAs Match
        if ($Baseline.ExpectedLogOnAs) {
            $NormCurrent = $Result.LogOnAs.ToLower().Trim() -replace '^\\.\\', '' -replace '^nt authority\\', ''
            $NormExpected = $Baseline.ExpectedLogOnAs.ToLower().Trim() -replace '^\\.\\', '' -replace '^nt authority\\', ''
            $NormCurrent = $NormCurrent -replace 'network service', 'networkservice' -replace 'local service', 'localservice' -replace 'local system', 'localsystem'
            $NormExpected = $NormExpected -replace 'network service', 'networkservice' -replace 'local service', 'localservice' -replace 'local system', 'localsystem'
            if ($NormCurrent -eq $NormExpected) { $Result.LogOnAsMatch = "OK" }
            else { 
                $Result.LogOnAsMatch = "MISMATCH"
                $Result.Issues += "LogOnAs mismatch: expected $($Baseline.ExpectedLogOnAs)"
            }
        }
    }

    # === SERVICE-SPECIFIC CHECKS ===
    
    # IIS Specific
    if ($ServiceName -eq "W3SVC") {
        $wwwHealth = @()
        $WebRoot = "C:\inetpub\wwwroot"
        if (Test-Path $WebRoot) {
            $Item = Get-Item $WebRoot
            if ($Item.Attributes -match "Hidden") { $wwwHealth += "WWWROOT_HIDDEN"; $Result.Issues += "wwwroot is hidden" }
            else { $wwwHealth += "wwwroot:OK" }
        }
        else { $wwwHealth += "WWWROOT_MISSING"; $Result.Issues += "wwwroot missing" }
        $Result.ExtraChecks = $wwwHealth -join "; "
    }
    
    # WinRM Specific
    if ($ServiceName -eq "WinRM") {
        $WinRMDetail = Test-WinRMSpecificHealth
        $ExtraInfo = @()
        $ExtraInfo += "Listeners:$($WinRMDetail.Listeners.Count)"
        $ExtraInfo += "5985:$($WinRMDetail.PortStatus[5985])"
        $ExtraInfo += "Status:$($WinRMDetail.OverallStatus)"
        $Result.ExtraChecks = $ExtraInfo -join "; "
        
        if ($WinRMDetail.OverallStatus -notmatch "OK") {
            $Result.Issues += "WinRM: $($WinRMDetail.OverallStatus)"
        }
        foreach ($Issue in $WinRMDetail.ConfigIssues) {
            $Result.Issues += "WinRM: $Issue"
        }
    }

    return $Result
}

# === MAIN EXECUTION ===
Write-Host "`n=== Service Health Check ===" -ForegroundColor Cyan
Write-Host "Checking $($Services.Count) services..." -ForegroundColor DarkGray

$AllResults = @()

foreach ($SvcName in $Services) {
    $Baseline = if ($Baselines -and $Baselines.ContainsKey($SvcName)) { $Baselines[$SvcName] } else { $null }
    $Result = Test-ServiceDeepHealth -ServiceName $SvcName -Baseline $Baseline
    $AllResults += $Result
    
    # Color-coded output
    $HasIssues = $Result.Issues.Count -gt 0
    $Color = if ($HasIssues) { "Red" } elseif ($Result.Status -ne "Running") { "Yellow" } else { "Green" }
    
    Write-Host "[*] $SvcName" -ForegroundColor $Color -NoNewline
    Write-Host " ($($Result.Status))" -ForegroundColor Gray
    
    if ($HasIssues) {
        foreach ($Issue in $Result.Issues) {
            Write-Host "    [!] $Issue" -ForegroundColor Yellow
        }
    }
}

# Global Firewall Check
$FwBlockRules = Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue
$FwStatus = if ($FwBlockRules) { "WARNING: Found $($FwBlockRules.Count) Inbound Block Rules" } else { "OK" }
Write-Host "`nFirewall Status: $FwStatus" -ForegroundColor $(if ($FwStatus -eq "OK") { "Green" } else { "Red" })

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$OKCount = ($AllResults | Where-Object { $_.Issues.Count -eq 0 -and $_.Status -eq "Running" }).Count
$ProblemCount = $AllResults.Count - $OKCount
Write-Host "OK: $OKCount | Problems: $ProblemCount" -ForegroundColor $(if ($ProblemCount -gt 0) { "Yellow" } else { "Green" })

# Display table (key fields only for readability)
$AllResults | Select-Object ServiceName, Status, RegistryACL, SDDL, PortStatus, ExtraChecks | Format-Table -AutoSize

return $AllResults
