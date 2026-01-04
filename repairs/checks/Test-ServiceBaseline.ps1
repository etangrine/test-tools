<#
.SYNOPSIS
    Validates service configurations against expected baselines for competition readiness.
.DESCRIPTION
    Compares critical service settings (ports, image paths, logon accounts, dependencies)
    against expected baseline values to detect tampering that could break score checks.
    
    Uses ServiceBaselines.psd1 for expected values - update that file when you receive
    the competition packet.
.PARAMETER Services
    Optional list of specific service names to check. Defaults to all services in baseline.
.PARAMETER BaselinePath
    Optional path to ServiceBaselines.psd1. Defaults to same directory as script.
.EXAMPLE
    .\Test-ServiceBaseline.ps1
    Tests all services defined in the baseline file.
.EXAMPLE
    .\Test-ServiceBaseline.ps1 -Services "W3SVC", "DNS"
    Tests only IIS and DNS services.
#>
param(
    [string[]]$Services,
    [string]$BaselinePath
)

# Load baseline data
if (-not $BaselinePath) {
    $BaselinePath = Join-Path $PSScriptRoot "ServiceBaselines.psd1"
}

if (-not (Test-Path $BaselinePath)) {
    Write-Error "Baseline file not found: $BaselinePath"
    return
}

$Baselines = Import-PowerShellDataFile -Path $BaselinePath

# If no services specified, check all in baseline
if (-not $Services) {
    $Services = $Baselines.Keys
}

function Get-ServiceProcessId {
    param([string]$ServiceName)
    try {
        $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        return $svc.ProcessId
    }
    catch {
        return $null
    }
}

function Test-ServiceBaseline {
    param (
        [string]$ServiceName,
        [hashtable]$Baseline
    )

    $Result = [PSCustomObject]@{
        ServiceName      = $ServiceName
        ServiceExists    = $false
        Status           = "Unknown"
        PortStatus       = "Unknown"     # OK / MISSING:<port> / WRONG_PORT / NOT_LISTENING
        ImagePathStatus  = "Unknown"     # OK / MISMATCH / ERROR
        LogOnAsStatus    = "Unknown"     # OK / MISMATCH / ERROR
        DependencyStatus = "Unknown"     # OK / MISSING:<dep> / ERROR
        Issues           = @()
    }

    # Check if service exists
    $ServiceObj = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $ServiceObj) {
        $Result.ServiceExists = $false
        $Result.Status = "NOT_INSTALLED"
        $Result.PortStatus = "N/A"
        $Result.ImagePathStatus = "N/A"
        $Result.LogOnAsStatus = "N/A"
        $Result.DependencyStatus = "N/A"
        return $Result
    }

    $Result.ServiceExists = $true
    $Result.Status = $ServiceObj.Status.ToString()

    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

    # 1. Check Image Path
    try {
        $ImgProp = Get-ItemProperty -Path $RegPath -Name "ImagePath" -ErrorAction SilentlyContinue
        if ($ImgProp -and $Baseline.ExpectedImagePath) {
            $CurrentImagePath = $ImgProp.ImagePath
            $ExpectedImagePath = $Baseline.ExpectedImagePath
            
            # Normalize for comparison (expand env vars, lowercase, trim)
            $NormalizedCurrent = [System.Environment]::ExpandEnvironmentVariables($CurrentImagePath).ToLower().Trim()
            $NormalizedExpected = [System.Environment]::ExpandEnvironmentVariables($ExpectedImagePath).ToLower().Trim()
            
            # Remove -p flag variations and extra spaces for more flexible matching
            $NormalizedCurrent = $NormalizedCurrent -replace '\s+-p\b', '' -replace '\s+', ' '
            $NormalizedExpected = $NormalizedExpected -replace '\s+-p\b', '' -replace '\s+', ' '
            
            if ($NormalizedCurrent -eq $NormalizedExpected) {
                $Result.ImagePathStatus = "OK"
            }
            else {
                $Result.ImagePathStatus = "MISMATCH"
                $Result.Issues += "ImagePath: Expected '$ExpectedImagePath', Got '$CurrentImagePath'"
            }
        }
        else {
            $Result.ImagePathStatus = "NO_BASELINE"
        }
    }
    catch {
        $Result.ImagePathStatus = "ERROR"
        $Result.Issues += "ImagePath check error: $($_.Exception.Message)"
    }

    # 2. Check LogOn As (ObjectName)
    try {
        $ObjName = Get-ItemProperty -Path $RegPath -Name "ObjectName" -ErrorAction SilentlyContinue
        if ($ObjName -and $Baseline.ExpectedLogOnAs) {
            $CurrentLogOn = $ObjName.ObjectName
            $ExpectedLogOn = $Baseline.ExpectedLogOnAs
            
            # Normalize both to lowercase and standardize common account names
            # Handle: LocalSystem, .\LocalSystem, NT AUTHORITY\SYSTEM, NT Authority\LocalService, etc.
            $NormalizedCurrent = $CurrentLogOn.ToLower().Trim() -replace '^\.\\', '' -replace '^nt authority\\', ''
            $NormalizedExpected = $ExpectedLogOn.ToLower().Trim() -replace '^\.\\', '' -replace '^nt authority\\', ''
            
            # Standardize common service account name variations
            # networkservice / network service -> networkservice
            # localservice / local service -> localservice
            # localsystem / local system -> localsystem
            $NormalizedCurrent = $NormalizedCurrent -replace 'network service', 'networkservice' -replace 'local service', 'localservice' -replace 'local system', 'localsystem'
            $NormalizedExpected = $NormalizedExpected -replace 'network service', 'networkservice' -replace 'local service', 'localservice' -replace 'local system', 'localsystem'
            
            if ($NormalizedCurrent -eq $NormalizedExpected) {
                $Result.LogOnAsStatus = "OK"
            }
            else {
                $Result.LogOnAsStatus = "MISMATCH"
                $Result.Issues += "LogOnAs: Expected '$ExpectedLogOn', Got '$CurrentLogOn'"
            }
        }
        else {
            $Result.LogOnAsStatus = "NO_BASELINE"
        }
    }
    catch {
        $Result.LogOnAsStatus = "ERROR"
        $Result.Issues += "LogOnAs check error: $($_.Exception.Message)"
    }

    # 3. Check Dependencies
    try {
        if ($Baseline.ExpectedDependencies -and $Baseline.ExpectedDependencies.Count -gt 0) {
            $CurrentDeps = @()
            if ($ServiceObj.RequiredServices) {
                $CurrentDeps = $ServiceObj.RequiredServices | ForEach-Object { $_.Name }
            }
            
            $MissingDeps = @()
            foreach ($ExpDep in $Baseline.ExpectedDependencies) {
                if ($ExpDep -notin $CurrentDeps) {
                    $MissingDeps += $ExpDep
                }
            }
            
            if ($MissingDeps.Count -eq 0) {
                $Result.DependencyStatus = "OK"
            }
            else {
                $Result.DependencyStatus = "MISSING"
                $Result.Issues += "Missing dependencies: $($MissingDeps -join ', ')"
            }
        }
        else {
            $Result.DependencyStatus = "NO_BASELINE"
        }
    }
    catch {
        $Result.DependencyStatus = "ERROR"
        $Result.Issues += "Dependency check error: $($_.Exception.Message)"
    }

    # 4. Check Ports (only if service is running)
    if ($ServiceObj.Status -eq 'Running' -and $Baseline.ExpectedPorts -and $Baseline.ExpectedPorts.Count -gt 0) {
        try {
            $Protocol = if ($Baseline.PortCheckProtocol -eq 'UDP') { 'UDP' } else { 'TCP' }
            $CheckByPID = if ($null -eq $Baseline.PortCheckByPID) { $true } else { $Baseline.PortCheckByPID }
            
            $ListeningPorts = @()
            
            if ($CheckByPID) {
                # Strict check: verify port is owned by service's process
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
                else {
                    $Result.PortStatus = "NO_PID"
                    $Result.Issues += "Could not determine service process ID"
                    return $Result
                }
            }
            else {
                # Relaxed check: just verify the port is listening on the system (for shared svchost/HTTP.sys services)
                foreach ($ExpPort in $Baseline.ExpectedPorts) {
                    if ($Protocol -eq 'TCP') {
                        $PortOpen = Get-NetTCPConnection -LocalPort $ExpPort -State Listen -ErrorAction SilentlyContinue
                    }
                    else {
                        $PortOpen = Get-NetUDPEndpoint -LocalPort $ExpPort -ErrorAction SilentlyContinue
                    }
                    if ($PortOpen) {
                        $ListeningPorts += $ExpPort
                    }
                }
            }
            
            if (-not $ListeningPorts) {
                $ListeningPorts = @()
            }
            
            $MissingPorts = @()
            foreach ($ExpPort in $Baseline.ExpectedPorts) {
                if ($ExpPort -notin $ListeningPorts) {
                    $MissingPorts += $ExpPort
                }
            }
            
            if ($MissingPorts.Count -eq 0) {
                $Result.PortStatus = "OK"
            }
            else {
                $Result.PortStatus = "NOT_LISTENING"
                $Result.Issues += "Expected ports not listening: $($MissingPorts -join ', ')"
            }
        }
        catch {
            $Result.PortStatus = "ERROR"
            $Result.Issues += "Port check error: $($_.Exception.Message)"
        }
    }
    elseif ($ServiceObj.Status -ne 'Running') {
        $Result.PortStatus = "SVC_STOPPED"
    }
    else {
        $Result.PortStatus = "NO_BASELINE"
    }

    return $Result
}

# --- Main Execution ---
Write-Host "`n=== Service Baseline Validation ===" -ForegroundColor Cyan
Write-Host "Baseline file: $BaselinePath" -ForegroundColor Gray
Write-Host ""

$AllResults = @()
$IssueCount = 0

foreach ($SvcName in $Services) {
    if (-not $Baselines.ContainsKey($SvcName)) {
        Write-Host "[-] $SvcName - No baseline defined, skipping" -ForegroundColor DarkGray
        continue
    }
    
    $Baseline = $Baselines[$SvcName]
    $Result = Test-ServiceBaseline -ServiceName $SvcName -Baseline $Baseline
    $AllResults += $Result
    
    # Color-coded output
    $HasIssues = $Result.Issues.Count -gt 0 -or $Result.Status -eq "NOT_INSTALLED"
    $Color = if ($HasIssues) { "Red" } elseif ($Result.Status -ne "Running") { "Yellow" } else { "Green" }
    
    Write-Host "[*] $SvcName" -ForegroundColor $Color -NoNewline
    Write-Host " ($($Result.Status))" -ForegroundColor Gray
    
    # Quick status line
    $StatusLine = "    Port:$($Result.PortStatus) | Image:$($Result.ImagePathStatus) | LogOn:$($Result.LogOnAsStatus) | Deps:$($Result.DependencyStatus)"
    Write-Host $StatusLine -ForegroundColor $(if ($HasIssues) { "Yellow" } else { "Gray" })
    
    # Show issues if any
    if ($Result.Issues.Count -gt 0) {
        $IssueCount += $Result.Issues.Count
        foreach ($Issue in $Result.Issues) {
            Write-Host "      [!] $Issue" -ForegroundColor Red
        }
    }
}

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Services checked: $($AllResults.Count)"
$OKCount = ($AllResults | Where-Object { $_.Issues.Count -eq 0 -and $_.ServiceExists }).Count
$ProblemCount = $AllResults.Count - $OKCount
Write-Host "OK: $OKCount | Problems: $ProblemCount | Total Issues: $IssueCount" -ForegroundColor $(if ($ProblemCount -gt 0) { "Yellow" } else { "Green" })

# Return results for pipeline use
return $AllResults
