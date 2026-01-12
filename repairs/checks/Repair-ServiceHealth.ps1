<#
.SYNOPSIS
    Comprehensive service repair for IR competitions.
.DESCRIPTION
    Repairs services by fixing common Red Team attack vectors:
    - Registry ACL lockouts
    - Registry Start value (disabled services)
    - Service Security Descriptor (SDDL) restrictions
    - Service startup and running state
    - Firewall block rules
    - Service-specific repairs (WinRM listeners, IIS, SMB)
    
    All repairs are service-aware - specify -Services "WinRM" for focused repair.
.PARAMETER Services
    List of service names to repair. Defaults to critical services if not specified.
.PARAMETER SkipFirewall
    Skip firewall repair (block rule removal, ICMP enabling).
.EXAMPLE
    .\Repair-ServiceHealth.ps1
    Repairs all default critical services.
.EXAMPLE
    .\Repair-ServiceHealth.ps1 -Services "WinRM"
    Repairs only WinRM including listener recreation.
.EXAMPLE
    .\Repair-ServiceHealth.ps1 -Services "W3SVC","LanmanServer"
    Repairs IIS and SMB services.
#>
param(
    [string[]]$Services = @(
        "DNS",              # DNS Server (Pyramids)
        "ADWS",             # Active Directory Web Services
        "NTDS",             # Active Directory Domain Services
        "W3SVC",            # IIS (Moon Landing)
        "LanmanServer",     # SMB Server (Wright Brothers)
        "WinRM",            # Windows Remote Management (First Olympics)
        "MpsSvc",           # Windows Firewall
        "EventLog",         # Windows Event Log
        "TermService"       # Remote Desktop Services
    ),
    [switch]$SkipFirewall
)

# === SERVICE-SPECIFIC REPAIR FUNCTIONS ===

function Repair-WinRMService {
    <# Repairs WinRM listeners, configuration, and common attack vectors #>
    Write-Host "    [*] Running WinRM-specific repairs..." -ForegroundColor Cyan
    
    $Repaired = @()
    
    # 1. Ensure HTTP Listener exists on port 5985
    try {
        $Listeners = Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate -ErrorAction SilentlyContinue
        $HTTPListener = $Listeners | Where-Object { $_.Transport -eq "HTTP" }
        
        if (-not $HTTPListener) {
            Write-Host "    [!] HTTP Listener missing. Recreating..." -ForegroundColor Yellow
            # Delete any existing HTTP listener first (in case corrupted)
            try { winrm delete winrm/config/Listener?Address=*+Transport=HTTP 2>$null } catch {}
            # Create new HTTP listener
            winrm create winrm/config/Listener?Address=*+Transport=HTTP 2>$null
            $Repaired += "Created HTTP listener"
            Write-Host "    [+] Created HTTP listener on port 5985" -ForegroundColor Green
        }
        elseif ($HTTPListener.Port -ne 5985) {
            Write-Host "    [!] HTTP Listener on wrong port ($($HTTPListener.Port)). Fixing..." -ForegroundColor Yellow
            winrm set winrm/config/Listener?Address=*+Transport=HTTP '@{Port="5985"}' 2>$null
            $Repaired += "Fixed listener port"
            Write-Host "    [+] Set HTTP listener to port 5985" -ForegroundColor Green
        }
        elseif ($HTTPListener.Enabled -ne "true") {
            Write-Host "    [!] HTTP Listener disabled. Enabling..." -ForegroundColor Yellow
            winrm set winrm/config/Listener?Address=*+Transport=HTTP '@{Enabled="true"}' 2>$null
            $Repaired += "Enabled HTTP listener"
            Write-Host "    [+] Enabled HTTP listener" -ForegroundColor Green
        }
        else {
            Write-Host "    [=] HTTP Listener OK (port 5985, enabled)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "    [!] Listener check failed: $($_.Exception.Message)" -ForegroundColor Red
        # Fallback: run Enable-PSRemoting
        Write-Host "    [*] Running Enable-PSRemoting as fallback..." -ForegroundColor Yellow
        try {
            Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction Stop
            $Repaired += "Enable-PSRemoting fallback"
            Write-Host "    [+] Enable-PSRemoting completed" -ForegroundColor Green
        }
        catch {
            Write-Host "    [!] Enable-PSRemoting failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # 2. Reset common config tampering
    try {
        # Reset IPv4Filter (allow all)
        $IPv4Filter = Get-Item WSMan:\localhost\Service\IPv4Filter -ErrorAction SilentlyContinue
        if ($IPv4Filter -and $IPv4Filter.Value -ne "*" -and $IPv4Filter.Value -ne "") {
            Set-Item -Path WSMan:\localhost\Service\IPv4Filter -Value "*" -Force -ErrorAction Stop
            $Repaired += "Reset IPv4Filter"
            Write-Host "    [+] Reset IPv4Filter to allow all" -ForegroundColor Green
        }
        
        # Reset MaxShellsPerUser
        $MaxShells = Get-Item WSMan:\localhost\Shell\MaxShellsPerUser -ErrorAction SilentlyContinue
        if ($MaxShells -and [int]$MaxShells.Value -lt 5) {
            Set-Item -Path WSMan:\localhost\Shell\MaxShellsPerUser -Value 25 -Force -ErrorAction Stop
            $Repaired += "Reset MaxShellsPerUser"
            Write-Host "    [+] Reset MaxShellsPerUser to 25" -ForegroundColor Green
        }
        
        # Reset MaxConcurrentUsers
        $MaxUsers = Get-Item WSMan:\localhost\Shell\MaxConcurrentUsers -ErrorAction SilentlyContinue
        if ($MaxUsers -and [int]$MaxUsers.Value -lt 5) {
            Set-Item -Path WSMan:\localhost\Shell\MaxConcurrentUsers -Value 10 -Force -ErrorAction Stop
            $Repaired += "Reset MaxConcurrentUsers"
            Write-Host "    [+] Reset MaxConcurrentUsers to 10" -ForegroundColor Green
        }
        
        # Ensure AllowRemoteAccess is enabled
        Set-Item -Path WSMan:\localhost\Service\AllowRemoteAccess -Value $true -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "    [!] Config reset error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # 3. Ensure WinRM firewall rules exist
    try {
        $WinRMRule = Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -ErrorAction SilentlyContinue
        if (-not $WinRMRule -or $WinRMRule.Enabled -eq "False") {
            # Create/enable WinRM firewall rule
            if (-not $WinRMRule) {
                New-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -DisplayName "WinRM HTTP Inbound" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any | Out-Null
                $Repaired += "Created WinRM firewall rule"
            }
            else {
                Set-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -Enabled True
                $Repaired += "Enabled WinRM firewall rule"
            }
            Write-Host "    [+] WinRM firewall rule enabled" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [!] Firewall rule error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    if ($Repaired.Count -eq 0) {
        Write-Host "    [=] No WinRM-specific repairs needed" -ForegroundColor Gray
    }
    
    return $Repaired
}

function Repair-IISService {
    <# IIS-specific repairs #>
    Write-Host "    [*] Running IIS-specific repairs..." -ForegroundColor Cyan
    
    $Repaired = @()
    
    # Check wwwroot visibility
    $WebRoot = "C:\inetpub\wwwroot"
    if (Test-Path $WebRoot) {
        $Item = Get-Item $WebRoot -Force
        if ($Item.Attributes -match "Hidden") {
            Write-Host "    [!] wwwroot is hidden. Unhiding..." -ForegroundColor Yellow
            $Item.Attributes = $Item.Attributes -band (-bnot [System.IO.FileAttributes]::Hidden)
            $Repaired += "Unhid wwwroot"
            Write-Host "    [+] Removed hidden attribute from wwwroot" -ForegroundColor Green
        }
    }
    
    # Ensure HTTP.sys is running
    try {
        $HTTP = Get-Service -Name "HTTP" -ErrorAction SilentlyContinue
        if ($HTTP -and $HTTP.Status -ne "Running") {
            Start-Service -Name "HTTP" -ErrorAction Stop
            $Repaired += "Started HTTP.sys"
            Write-Host "    [+] Started HTTP.sys driver" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [!] HTTP.sys error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Ensure WAS (Windows Process Activation Service) is running
    try {
        $WAS = Get-Service -Name "WAS" -ErrorAction SilentlyContinue
        if ($WAS -and $WAS.Status -ne "Running") {
            Set-Service -Name "WAS" -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name "WAS" -ErrorAction Stop
            $Repaired += "Started WAS"
            Write-Host "    [+] Started Windows Process Activation Service" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [!] WAS error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    if ($Repaired.Count -eq 0) {
        Write-Host "    [=] No IIS-specific repairs needed" -ForegroundColor Gray
    }
    
    return $Repaired
}

function Repair-SMBService {
    <# SMB-specific repairs #>
    Write-Host "    [*] Running SMB-specific repairs..." -ForegroundColor Cyan
    
    $Repaired = @()
    
    # Ensure SMB1 is disabled (security) but SMB2 is enabled
    try {
        $SMB2 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -ErrorAction SilentlyContinue
        if ($SMB2 -and $SMB2.SMB2 -eq 0) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Value 1
            $Repaired += "Enabled SMB2"
            Write-Host "    [+] Enabled SMB2 (was disabled)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [!] SMB2 check error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Ensure srv2 driver is running
    try {
        $Srv2 = Get-Service -Name "srv2" -ErrorAction SilentlyContinue
        if ($Srv2 -and $Srv2.Status -ne "Running") {
            Start-Service -Name "srv2" -ErrorAction Stop
            $Repaired += "Started srv2"
            Write-Host "    [+] Started srv2 driver" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "    [!] srv2 error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    if ($Repaired.Count -eq 0) {
        Write-Host "    [=] No SMB-specific repairs needed" -ForegroundColor Gray
    }
    
    return $Repaired
}

# === MAIN REPAIR LOGIC ===

Write-Host "`n=== Service Repair ===" -ForegroundColor Cyan

foreach ($ServiceName in $Services) {
    $Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if (-not $Service) {
        Write-Host "[-] Service '$ServiceName' not found or not installed." -ForegroundColor DarkGray
        continue
    }

    Write-Host "[*] Processing: $($Service.Name) ($($Service.Status))" -ForegroundColor White

    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

    # === GENERIC REPAIRS (all services) ===
    
    # 1. Fix Registry ACLs
    try {
        if (Test-Path $RegPath) {
            $Acl = Get-Acl -Path $RegPath -ErrorAction Stop
            $AdminAccess = $Acl.Access | Where-Object { 
                ($_.IdentityReference -match "Administrators" -or $_.IdentityReference.Value -match "S-1-5-32-544") -and 
                ($_.RegistryRights -match "FullControl") 
            }
             
            if (-not $AdminAccess) {
                Write-Host "    [!] Registry ACLs restricted. Repairing..." -ForegroundColor Yellow
                $NewAcl = New-Object System.Security.AccessControl.RegistrySecurity
                $AdminRule = New-Object System.Security.AccessControl.RegistryAccessRule ("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                $SystemRule = New-Object System.Security.AccessControl.RegistryAccessRule ("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                $NewAcl.SetAccessRule($AdminRule)
                $NewAcl.SetAccessRule($SystemRule)
                Set-Acl -Path $RegPath -AclObject $NewAcl -ErrorAction Stop
                Write-Host "    [+] Reset Registry ACLs" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "    [!] ACL repair failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 2. Fix Registry Start value
    try {
        if (Test-Path $RegPath) {
            $StartValue = Get-ItemProperty -Path $RegPath -Name "Start" -ErrorAction SilentlyContinue
            if ($StartValue.Start -eq 4) {
                Set-ItemProperty -Path $RegPath -Name "Start" -Value 2 -ErrorAction Stop
                Write-Host "    [+] Fixed registry Start value (4->2)" -ForegroundColor Green
                $Service = Get-Service -Name $ServiceName
            }
        }
    }
    catch {
        Write-Host "    [!] Start value fix failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 3. Fix Service SDDL
    try {
        $SDDL = sc.exe sdshow $ServiceName 2>&1 | Out-String
        if ($SDDL -notmatch "BA" -and $SDDL -notmatch "Access is denied") {
            Write-Host "    [!] SDDL restricted. Resetting..." -ForegroundColor Yellow
            $DefaultSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
            $proc = Start-Process -FilePath "sc.exe" -ArgumentList "sdset $ServiceName `"$DefaultSDDL`"" -PassThru -Wait -WindowStyle Hidden
            if ($proc.ExitCode -eq 0) {
                Write-Host "    [+] Reset SDDL" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "    [!] SDDL fix failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 4. Set StartType to Automatic
    if ($Service.StartType -ne "Automatic") {
        try {
            Set-Service -Name $ServiceName -StartupType Automatic -ErrorAction Stop
            Write-Host "    [+] Set StartType to Automatic" -ForegroundColor Green
        }
        catch {
            Write-Host "    [!] StartType fix failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # 5. Start Service
    $Service = Get-Service -Name $ServiceName
    if ($Service.Status -ne "Running") {
        try {
            Start-Service -Name $ServiceName -ErrorAction Stop
            Write-Host "    [+] Service started" -ForegroundColor Green
        }
        catch {
            Write-Host "    [!] Service start failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "    [=] Service already running" -ForegroundColor Gray
    }

    # === SERVICE-SPECIFIC REPAIRS ===
    switch ($ServiceName) {
        "WinRM" { $null = Repair-WinRMService }
        "W3SVC" { $null = Repair-IISService }
        "LanmanServer" { $null = Repair-SMBService }
    }
}

# === FIREWALL REPAIRS ===
if (-not $SkipFirewall) {
    Write-Host "`n[*] Firewall Repairs..." -ForegroundColor Cyan

    # 1. Remove Inbound Block Rules
    try {
        $BlockRules = Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue
        if ($BlockRules) {
            $Count = $BlockRules.Count
            $BlockRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-Host "    [+] Removed $Count Inbound Block Rules" -ForegroundColor Green
        }
        else {
            Write-Host "    [=] No Inbound Block Rules found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "    [!] Block rule removal failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    # 2. Enable ICMP (for Silk Road scoring)
    try {
        if (-not (Get-NetFirewallRule -DisplayName "IR-Allow-ICMPv4" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName "IR-Allow-ICMPv4" -Direction Inbound -Protocol ICMPv4 -Action Allow -Profile Any -Description "Created by IR Toolkit" | Out-Null
            Write-Host "    [+] Created ICMP allow rule" -ForegroundColor Green
        }
        else {
            Write-Host "    [=] ICMP rule already exists" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "    [!] ICMP rule error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n=== Repair Complete ===" -ForegroundColor Cyan
