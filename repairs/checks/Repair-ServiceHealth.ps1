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
        "TermService"#Only important for cloud boxes
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

    # 1. Security Descriptor & Registry Hardening Checks
    
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

    # A. Check Registry Permissions (ACLs) - Ensure Admins are not locked out
    try {
        if (Test-Path $RegPath) {
            # Check if we can get the ACL and if Admins have FullControl
            $Acl = Get-Acl -Path $RegPath -ErrorAction Stop
             
            # Check for 'Administrators' (or well-known SID) with 'FullControl' or at least 'Write'
            # We look for simple string matching for robustness in this quick script
            $AdminAccess = $Acl.Access | Where-Object { 
                ($_.IdentityReference -match "Administrators" -or $_.IdentityReference.Value -match "S-1-5-32-544") -and 
                ($_.RegistryRights -match "FullControl") 
            }
             
            if (-not $AdminAccess) {
                Write-Host "    [!] Registry ACLs restricted (Admins missing FullControl). Attempting repair..." -ForegroundColor Yellow
                 
                # Create new generic ACL: Admins=Full, System=Full
                $NewAcl = New-Object System.Security.AccessControl.RegistrySecurity
                $AdminRule = New-Object System.Security.AccessControl.RegistryAccessRule ("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                $SystemRule = New-Object System.Security.AccessControl.RegistryAccessRule ("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                 
                $NewAcl.SetAccessRule($AdminRule)
                $NewAcl.SetAccessRule($SystemRule)
                 
                Set-Acl -Path $RegPath -AclObject $NewAcl -ErrorAction Stop
                Write-Host "    [+] Successfully reset Registry ACLs." -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "    [!] Failed to check/fix Registry ACLs (Access Denied?): $($_.Exception.Message)" -ForegroundColor Red
        # If we failed to even read it, we might want to try to overwrite blindly if we had rights, but strict error handling is safer for now.
    }

    # B. Check Registry 'Start' value directly (handles value 4/Disabled which Set-Service sometimes struggles with if locked)
    try {
        if (Test-Path $RegPath) {
            $StartValue = Get-ItemProperty -Path $RegPath -Name "Start" -ErrorAction SilentlyContinue
            if ($StartValue.Start -eq 4) {
                Set-ItemProperty -Path $RegPath -Name "Start" -Value 2 -ErrorAction Stop
                Write-Host "    [+] Registry: Fixed 'Start' value from 4 (Disabled) to 2 (Automatic)" -ForegroundColor Green
                # Re-fetch service object to reflect changes
                $Service = Get-Service -Name $ServiceName
            }
        }
    }
    catch {
        Write-Host "    [!] Failed to check/fix Registry Start value: $($_.Exception.Message)" -ForegroundColor Red
    }

    # C. Check Service Security Descriptor (SDDL) 
    # Look for missing 'BA' (Builtin Admin) access in the SDDL string. 
    # If missing, it implies the service has been hardened to lock out admins (System Only).
    try {
        $SDDL = sc.exe sdshow $ServiceName | Out-String
        if ($SDDL -notmatch "BA") {
            Write-Host "    [!] Detected restricted Security Descriptor (System Only/No Admin Access). Attempting repair..." -ForegroundColor Yellow
            # Default SDDL granting LocalSystem (SY) and Administrators (BA) full control
            # This is a generic 'safe' SDDL for standard services.
            $DefaultSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
            
            # Use cmd /c to run sc.exe to ensure proper argument parsing if needed, though direct invoke usually works.
            $proc = Start-Process -FilePath "sc.exe" -ArgumentList "sdset $ServiceName `"$DefaultSDDL`"" -PassThru -Wait -WindowStyle Hidden
            
            if ($proc.ExitCode -eq 0) {
                Write-Host "    [+] Successfully reset Security Descriptor." -ForegroundColor Green
            }
            else {
                Write-Host "    [!] Failed to reset Security Descriptor. Exit Code: $($proc.ExitCode)" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Host "    [!] Failed to check/fix Security Descriptor: $($_.Exception.Message)" -ForegroundColor Red
    }

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


Write-Host "`nStarting Firewall Repair..." -ForegroundColor Cyan

# 1. Remove Blocking Rules (Focus on Inbound)
try {
    # Remove all Inbound Block rules (Common Red Team tactic to kill services) Might change if we implement firewall rules
    $BlockRules = Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue
    if ($BlockRules) {
        $Count = $BlockRules.Count
        $BlockRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Host "    [+] Removed $Count Inbound Block Firewall Rules" -ForegroundColor Green
    }
    else {
        Write-Host "    [=] No Inbound Block Rules found" -ForegroundColor Gray
    }
}
catch {
    Write-Host "    [!] Failed to remove block rules: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Unblock/Allow ICMP (Ping)
try {
    # Ensure standard File and Printer Sharing ICMP rules are enabled
    $ICMPRules = Get-NetFirewallRule -DisplayGroup "File and Printer Sharing" | Where-Object { $_.Protocol -like "*ICMP*" }
    if ($ICMPRules) {
        $ICMPRules | Set-NetFirewallRule -Enabled True -Action Allow
        Write-Host "    [+] Enabled standard File & Printer Sharing ICMP rules" -ForegroundColor Green
    }
    
    # Create explicit Allow ICMP rule if it doesn't exist
    if (-not (Get-NetFirewallRule -DisplayName "IR-Allow-ICMPv4" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "IR-Allow-ICMPv4" -Direction Inbound -Protocol ICMPv4 -Action Allow -Profile Any -Description "Created by IR Toolkit" | Out-Null
        Write-Host "    [+] Created explicit 'IR-Allow-ICMPv4' rule" -ForegroundColor Green
    }
}
catch {
    Write-Host "    [!] Failed to enable ICMP: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Service Repair Complete." -ForegroundColor Cyan
