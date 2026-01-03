# Coding Partner - Blue Team Registry Hardening Script
#
# IMPORTANT: This script makes significant changes to registry audit settings.
# It is designed for a competition environment. Test before using on a production system.
# Run this script with Administrator privileges.

Write-Host "Starting Blue Team registry hardening and auditing script..." -ForegroundColor Yellow

#------------------------------------------------------------------------------------
# Section 1: Set Specific Hardening Values
#------------------------------------------------------------------------------------
Write-Host "[+] Applying specific hardening values..."

try {
    # Disable AppInit_DLLs functionality entirely. This is a huge win for security.
    $appInitPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    if (Test-Path $appInitPath) {
        Set-ItemProperty -Path $appInitPath -Name "LoadAppInit_DLLs" -Value 0 -Type DWord -Force -ErrorAction Stop
        Set-ItemProperty -Path $appInitPath -Name "AppInit_DLLs" -Value "" -Type String -Force -ErrorAction Stop
        Write-Host "  [SUCCESS] AppInit_DLLs have been disabled."
    }

    # Also check the 32-bit path on 64-bit systems
    $appInitWow64Path = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
    if (Test-Path $appInitWow64Path) {
        Set-ItemProperty -Path $appInitWow64Path -Name "LoadAppInit_DLLs" -Value 0 -Type DWord -Force -ErrorAction Stop
        Set-ItemProperty -Path $appInitWow64Path -Name "AppInit_DLLs" -Value "" -Type String -Force -ErrorAction Stop
        Write-Host "  [SUCCESS] Wow6432Node AppInit_DLLs have been disabled."
    }
}
catch {
    Write-Host "  [FAILURE] Could not disable AppInit_DLLs. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# NOTE: The script does not automatically clear Run keys or Service lists,
# as legitimate software may be present. This requires manual review!
Write-Host "[!] Manual review required for Run keys and Services to find malicious entries." -ForegroundColor Cyan


#------------------------------------------------------------------------------------
# Section 2: Define and Apply Audit Rules (SACLs)
#------------------------------------------------------------------------------------
Write-Host "[+] Applying audit rules for detection..."

# Define a helper function to apply audit rules to a registry key
function Set-RegistryAuditRule {
    param(
        [string]$Path,
        [System.Security.AccessControl.RegistryRights]$Rights,
        [string]$Description
    )

    try {
        if (-not (Test-Path $Path)) {
            Write-Host "  [SKIPPED] Path does not exist: $Path" -ForegroundColor Gray
            return
        }

        # Get the current ACL and create a new audit rule
        $acl = Get-Acl -Path $Path
        # We audit for 'Everyone' to catch any user context attempting the action
        $rule = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone", $Rights, "None", "None", "Success,Failure")
        
        # Add the rule and set the new ACL
        $acl.AddAuditRule($rule)
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop

        Write-Host "  [SUCCESS] Applied '$Rights' audit rule to $Description"
    }
    catch {
        Write-Host "  [FAILURE] Could not apply audit rule to $Path. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# --- Apply Audits based on MITRE ATT&CK Techniques ---

# T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
Set-RegistryAuditRule -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Rights "SetValue" -Description "HKLM Run Key"
Set-RegistryAuditRule -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Rights "SetValue" -Description "HKLM RunOnce Key"
Set-RegistryAuditRule -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Rights "SetValue" -Description "HKCU Run Key"
Set-RegistryAuditRule -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Rights "SetValue" -Description "HKCU RunOnce Key"

# T1543.003 & T1053.005 - Service & Scheduled Task Creation
Set-RegistryAuditRule -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Rights "CreateSubKey,SetValue" -Description "Services Creation"
Set-RegistryAuditRule -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree" -Rights "CreateSubKey,SetValue" -Description "Scheduled Task Creation"

# T1547.005 - LSA Security Packages
Set-RegistryAuditRule -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Rights "SetValue" -Description "LSA Security Packages"

# T1003 - Credential Dumping
# Note: For RegSaveKey, the audit needs to be on the parent key. Auditing the 'WriteKey' right covers this.
Set-RegistryAuditRule -Path "HKLM:\SAM" -Rights "WriteKey" -Description "SAM Hive Dumping"
Set-RegistryAuditRule -Path "HKLM:\SYSTEM" -Rights "WriteKey" -Description "SYSTEM Hive Dumping"
Set-RegistryAuditRule -Path "HKLM:\Security\Policy\Secrets" -Rights "QueryValues,EnumerateSubKeys" -Description "LSA Secrets Access"

# T1218.005 - MSHTA Reconnaissance
Set-RegistryAuditRule -Path "HKCR:\PROTOCOLS\Handler\vbscript" -Rights "QueryValues" -Description "MSHTA VBScript Handler"
Set-RegistryAuditRule -Path "HKCR:\PROTOCOLS\Handler\javascript" -Rights "QueryValues" -Description "MSHTA JavaScript Handler"

# TA0043 - Reconnaissance
Set-RegistryAuditRule -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Rights "QueryValues" -Description "Audit Policy Recon"
Set-RegistryAuditRule -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" -Rights "QueryValues" -Description "Sysmon Config Recon"


Write-Host "`nScript finished. Please ensure your Security Event Log is configured to capture 'Audit Object Access' events." -ForegroundColor Green
Write-Host "You can enable this in Local Security Policy -> Advanced Audit Policy Configuration -> Object Access -> Audit Registry." -ForegroundColor Green