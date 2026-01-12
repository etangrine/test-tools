<#
.SYNOPSIS
    Comprehensive Windows hardening script for incident response competitions.

.DESCRIPTION
    Combines logging configuration, SMB/IIS hardening, and registry security
    into a single script. Each section can be skipped via switches.

.PARAMETER SkipLogging
    Skip PowerShell logging and audit configuration.

.PARAMETER SkipSMB
    Skip SMB hardening (SMBv1 disable, null session block).

.PARAMETER SkipIIS
    Skip IIS hardening (even if IIS is detected).

.PARAMETER SkipRegistry
    Skip registry hardening and audit rules.

.EXAMPLE
    .\Invoke-Hardening.ps1
    Run all hardening sections.

.EXAMPLE
    .\Invoke-Hardening.ps1 -SkipIIS
    Run all sections except IIS hardening (for non-web servers).

.EXAMPLE
    .\Invoke-Hardening.ps1 -SkipRegistry
    Skip registry hardening if already applied via GPO.
#>

param(
    [switch]$SkipLogging,
    [switch]$SkipSMB,
    [switch]$SkipIIS,
    [switch]$SkipRegistry
)

$ErrorActionPreference = "Continue"

# --- DataDog Protection (ISTS Quals Rules - Out of Scope) ---
# These paths and processes must not be modified per competition rules
$DataDogPaths = @(
    "C:\ProgramData\Datadog",
    "C:\Program Files\Datadog",
    "/etc/datadog-agent"  # Linux path for reference
)
$DataDogUsers = @("datadog", "dd-dog", "dd-agent")

function Test-IsDataDogPath {
    param([string]$Path)
    foreach ($ddPath in $DataDogPaths) {
        if ($Path -like "$ddPath*") { return $true }
    }
    return $false
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  WINDOWS HARDENING SCRIPT" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
Write-Host "[INFO] DataDog paths and users are protected (out-of-scope)" -ForegroundColor DarkGray

#region ==================== LOGGING ====================
if (-not $SkipLogging) {
    Write-Host "[SECTION] Enhanced Logging Configuration" -ForegroundColor Yellow
    Write-Host "==========================================="
    
    # --- PowerShell Logging (via Registry) ---
    $psLogKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"
    
    # Script Block Logging
    $sbLogKey = "$psLogKey\ScriptBlockLogging"
    if (-not (Test-Path $sbLogKey)) { New-Item -Path $sbLogKey -Force | Out-Null }
    Set-ItemProperty -Path $sbLogKey -Name "EnableScriptBlockLogging" -Value 1
    Write-Host "  [+] Enabled PowerShell Script Block Logging" -ForegroundColor Green
    
    # Module Logging
    $modLogKey = "$psLogKey\ModuleLogging"
    if (-not (Test-Path $modLogKey)) { New-Item -Path $modLogKey -Force | Out-Null }
    Set-ItemProperty -Path $modLogKey -Name "EnableModuleLogging" -Value 1
    Set-ItemProperty -Path $modLogKey -Name "ModuleNames" -Value @("*") -Type MultiString
    Write-Host "  [+] Enabled PowerShell Module Logging (all modules)" -ForegroundColor Green
    
    # --- Process Creation Auditing (Event ID 4688) ---
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>$null
    Write-Host "  [+] Enabled Process Creation auditing (Event ID 4688)" -ForegroundColor Green
    
    # --- Increase Security Log Size ---
    try {
        Limit-EventLog -LogName Security -MaximumSize 1GB -ErrorAction Stop
        Write-Host "  [+] Increased Security Event Log to 1GB" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] Could not increase log size: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host ""
}
else {
    Write-Host "[SKIPPED] Logging Configuration" -ForegroundColor DarkGray
}
#endregion

#region ==================== SMB HARDENING ====================
if (-not $SkipSMB) {
    Write-Host "[SECTION] SMB Hardening" -ForegroundColor Yellow
    Write-Host "========================"
    
    # Disable SMBv1 (Wannacry/EternalBlue vulnerability)
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Type DWORD -Value 0 -Force
        Write-Host "  [+] Disabled SMBv1 (EternalBlue mitigation)" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] Could not disable SMBv1: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Disable Null Session enumeration
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Type DWORD -Value 1 -Force
        Write-Host "  [+] Blocked null session enumeration" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] Could not restrict anonymous access: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host ""
}
else {
    Write-Host "[SKIPPED] SMB Hardening" -ForegroundColor DarkGray
}
#endregion

#region ==================== IIS HARDENING ====================
if (-not $SkipIIS) {
    $iisService = Get-Service "W3SVC" -ErrorAction SilentlyContinue
    
    if ($iisService) {
        Write-Host "[SECTION] IIS Hardening (IIS Detected)" -ForegroundColor Yellow
        Write-Host "========================================"
        
        try {
            Import-Module WebAdministration -ErrorAction Stop
            
            # Disable Directory Browsing
            Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value False -PSPath 'IIS:\' -ErrorAction SilentlyContinue
            Write-Host "  [+] Disabled directory browsing" -ForegroundColor Green
            
            # Add Hidden Segments for sensitive folders
            $BadSegments = @("bin", "App_Code", ".git", ".env", "backup", ".vs", "node_modules")
            foreach ($Segment in $BadSegments) {
                Add-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering/hiddenSegments -Name "." -Value @{segment = $Segment } -PSPath 'IIS:\' -ErrorAction SilentlyContinue
            }
            Write-Host "  [+] Added hidden segments: $($BadSegments -join ', ')" -ForegroundColor Green
            
            # Enhanced IIS Logging
            $logFlags = "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer"
            Set-ItemProperty -Path "IIS:\Sites\Default Web Site" -Name logFile.logExtFileFlags -Value $logFlags -ErrorAction SilentlyContinue
            Write-Host "  [+] Enhanced IIS logging enabled" -ForegroundColor Green
        }
        catch {
            Write-Host "  [!] IIS hardening error: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        Write-Host ""
    }
    else {
        Write-Host "[SKIPPED] IIS Hardening (IIS not installed)" -ForegroundColor DarkGray
    }
}
else {
    Write-Host "[SKIPPED] IIS Hardening (user requested)" -ForegroundColor DarkGray
}
#endregion

#region ==================== REGISTRY HARDENING ====================
if (-not $SkipRegistry) {
    Write-Host "[SECTION] Registry Hardening & Auditing" -ForegroundColor Yellow
    Write-Host "========================================="
    
    # --- Disable AppInit_DLLs (major persistence mechanism) ---
    $appInitPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    )
    
    foreach ($path in $appInitPaths) {
        if (Test-Path $path) {
            try {
                Set-ItemProperty -Path $path -Name "LoadAppInit_DLLs" -Value 0 -Type DWord -Force
                Set-ItemProperty -Path $path -Name "AppInit_DLLs" -Value "" -Type String -Force
                Write-Host "  [+] Disabled AppInit_DLLs at $path" -ForegroundColor Green
            }
            catch {
                Write-Host "  [!] Could not disable AppInit_DLLs: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    
    # --- Registry Audit Rules (SACLs) ---
    Write-Host "  [*] Applying registry audit rules..." -ForegroundColor Cyan
    
    function Set-RegistryAuditRule {
        param(
            [string]$Path,
            [System.Security.AccessControl.RegistryRights]$Rights,
            [string]$Description
        )
        
        try {
            if (-not (Test-Path $Path)) { return }
            
            $acl = Get-Acl -Path $Path
            $rule = New-Object System.Security.AccessControl.RegistryAuditRule(
                "Everyone", $Rights, "None", "None", "Success,Failure"
            )
            $acl.AddAuditRule($rule)
            Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
            Write-Host "      [+] $Description" -ForegroundColor Green
        }
        catch {
            # Silently skip failures for non-existent or protected keys
        }
    }
    
    # T1547.001 - Run Keys (Persistence)
    Set-RegistryAuditRule -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Rights "SetValue" -Description "HKLM Run Key"
    Set-RegistryAuditRule -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Rights "SetValue" -Description "HKLM RunOnce Key"
    Set-RegistryAuditRule -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Rights "SetValue" -Description "HKCU Run Key"
    Set-RegistryAuditRule -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Rights "SetValue" -Description "HKCU RunOnce Key"
    
    # T1543.003 - Service Creation
    Set-RegistryAuditRule -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Rights "CreateSubKey,SetValue" -Description "Services Creation"
    
    # T1053.005 - Scheduled Task Creation
    Set-RegistryAuditRule -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree" -Rights "CreateSubKey,SetValue" -Description "Scheduled Tasks"
    
    # T1547.005 - LSA Security Packages
    Set-RegistryAuditRule -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Rights "SetValue" -Description "LSA Security Packages"
    
    # T1003 - Credential Dumping Detection
    Set-RegistryAuditRule -Path "HKLM:\SAM" -Rights "WriteKey" -Description "SAM Hive Access"
    Set-RegistryAuditRule -Path "HKLM:\SYSTEM" -Rights "WriteKey" -Description "SYSTEM Hive Access"
    
    Write-Host ""
}
else {
    Write-Host "[SKIPPED] Registry Hardening" -ForegroundColor DarkGray
}
#endregion

#region ==================== SUMMARY ====================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  HARDENING COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host @"

Next Steps:
  1. Review Event Viewer -> Security for audit events
  2. Check PowerShell logs in Applications and Services -> Microsoft -> Windows -> PowerShell
  3. Use Autoruns.exe to manually review Run keys and Services
  4. Consider applying firewall rules (see firewall_script.ps1)

"@
#endregion
