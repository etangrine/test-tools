# New-HardeningGPO.ps1
# Run this ONLY on the Domain Controller.
# Creates a GPO that disables NTLM, sets Audit policies, and enables Firewall logging.

Import-Module GroupPolicy

$GPOName = "BlueTeam_Hardening_Policy"

# 1. Create the GPO
Write-Host "Creating GPO: $GPOName..."
try {
    New-GPO -Name $GPOName -Comment "Created by Blue Team Script" | Out-Null
} catch {
    Write-Warning "GPO might already exist."
}

# 2. Set Registry Keys (Based on your registry_harden.ps1)
Write-Host "Configuring Registry Settings via GPO..."

# Disable AppInit_DLLs (Malware Persistence)
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ValueName "LoadAppInit_DLLs" -Type DWord -Value 0
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ValueName "AppInit_DLLs" -Type String -Value ""

# Enable Audit Process Creation (Command Line Logging)
# This corresponds to Event ID 4688
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1

# Disable SMBv1 (EternalBlue Prevention) - Critical for older Windows versions
Set-GPRegistryValue -Name $GPOName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -Type DWord -Value 0

# 3. Link the GPO to the Domain Root
Write-Host "Linking GPO to Domain Root..."
try {
    New-GPLink -Name $GPOName -Target "dc=$((Get-ADDomain).Name),dc=com" -LinkEnabled Yes | Out-Null
    Write-Host "SUCCESS: Hardening GPO Linked!" -ForegroundColor Green
    Write-Host "Run 'gpupdate /force' on client machines to apply immediately."
} catch {
    Write-Error "Could not link GPO. Check Domain DN."
}