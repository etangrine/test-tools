# Deploy-ContextAwareFirewall.ps1
# Run this ONCE on the Domain Controller
# ---------------------------------------------------------
Import-Module GroupPolicy
Import-Module ActiveDirectory

$GPOName = "BlueTeam_Smart_Firewall"
$Domain = (Get-ADDomain).DistinguishedName
$ScriptFileName = "SmartFirewall.ps1"

# 1. Create the 'Smart Firewall' Logic Content
# This is the code that will run on every machine
$SmartScriptContent = @'
# --- START OF LOCAL SCRIPT ---
$LogPath = "C:\Windows\Temp\FirewallLog.txt"
Start-Transcript -Path $LogPath -Append

Write-Host "Detecting Role and Applying Firewall Rules..."

# A. Nuke existing rules (Optional - risky but clean)
# Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
# Remove-NetFirewallRule -All

# B. Base Rules (Allow Management)
New-NetFirewallRule -DisplayName "Allow-RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
New-NetFirewallRule -DisplayName "Allow-ICMP" -Direction Inbound -Protocol ICMPv4 -Action Allow
# Allow WinRM for your management scripts
New-NetFirewallRule -DisplayName "Allow-WinRM" -Direction Inbound -Protocol TCP -LocalPort 5985,5986 -Action Allow

# C. Context Awareness: Am I a Domain Controller?
$IsDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4
if ($IsDC) {
    Write-Host "Role Detected: Domain Controller"
    New-NetFirewallRule -DisplayName "Allow-AD-TCP" -Direction Inbound -Protocol TCP -LocalPort 53,88,135,389,445,464,636,3268,3269 -Action Allow
    New-NetFirewallRule -DisplayName "Allow-AD-UDP" -Direction Inbound -Protocol UDP -LocalPort 53,88,123,389,464 -Action Allow
}

# D. Context Awareness: Am I a Web Server (IIS)?
if (Get-Service "W3SVC" -ErrorAction SilentlyContinue) {
    Write-Host "Role Detected: IIS Web Server"
    New-NetFirewallRule -DisplayName "Allow-HTTP-HTTPS" -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Allow
}

# E. Context Awareness: Am I a SQL Server?
if (Get-Service "MSSQLSERVER" -ErrorAction SilentlyContinue) {
    Write-Host "Role Detected: SQL Server"
    New-NetFirewallRule -DisplayName "Allow-SQL" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow
}

# F. Default Block (The "Lockdown")
# ONLY enable this if you are sure your allow rules are correct!
# Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block

Stop-Transcript
# --- END OF LOCAL SCRIPT ---
'@

# 2. Save the script to the SYSVOL (NETLOGON) so all computers can reach it
$SysVolPath = "\\$($env:USERDNSDOMAIN)\SYSVOL\$($env:USERDNSDOMAIN)\scripts"
if (-not (Test-Path $SysVolPath)) { New-Item -ItemType Directory -Path $SysVolPath -Force }
$ScriptPath = Join-Path $SysVolPath $ScriptFileName
Set-Content -Path $ScriptPath -Value $SmartScriptContent
Write-Host "Script saved to SYSVOL: $ScriptPath" -ForegroundColor Green

# 3. Create the GPO
New-GPO -Name $GPOName -Comment "Deploys Smart Firewall Script" -ErrorAction SilentlyContinue

# 4. Link GPO to the Domain Root
New-GPLink -Name $GPOName -Target $Domain -LinkEnabled Yes -ErrorAction SilentlyContinue

# 5. Set the GPO to run the script at Startup
# Note: Modifying GPO internals via PowerShell without 3rd party modules is complex.
# The most reliable way in a competition is to use the creation script above, 
# then perform this ONE manual step in GPMC.msc:
#
#   1. Edit "BlueTeam_Smart_Firewall"
#   2. Go to Computer Configuration -> Policies -> Windows Settings -> Scripts -> Startup
#   3. Add -> Browse -> Paste the path: \\yourdomain.com\sysvol\...\scripts\SmartFirewall.ps1
#
Write-Host "ACTION REQUIRED: Open Group Policy Management, edit '$GPOName', and add '$ScriptFileName' as a Computer Startup Script." -ForegroundColor Yellow