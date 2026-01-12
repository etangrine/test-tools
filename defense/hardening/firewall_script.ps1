# Panic-Firewall.ps1
# BLOCKS ALL TRAFFIC except Scoring, White Team, Out-of-Scope, and specific Services.
# Updated for ISTS Quals 2026 - Team 2

# --- CONFIGURATION (ISTS Quals 2026) ---
# Team-specific subnets
$TeamLAN = "10.2.1.0/24"             # Team 2 LAN
$TeamCloud = "192.168.2.0/24"        # Team 2 Cloud

# Out-of-Scope Subnets (DO NOT BLOCK per rules)
$OutOfScopeSubnets = @(
    "172.16.1.0/24",
    "172.20.1.0/24"
)

# Scoring Engine IPs (add when known from competition start)
$ScoringEngine = @()                 # Add scoring.ists.io IPs here

# Ports for scored services (all Windows boxes)
$RequiredPorts = @(
    3389,  # RDP (for cloud boxes remote access)
    53,    # DNS (Pyramids - AD/DNS)
    80,    # HTTP (Moon Landing - IIS)
    443,   # HTTPS (if needed)
    445,   # SMB (Wright Brothers)
    5985,  # WinRM HTTP (First Olympics)
    5986   # WinRM HTTPS (First Olympics)
)

Write-Host "Applying PANIC Firewall Rules..." -ForegroundColor Red

# 1. Reset Firewall
NetSh Advfirewall set allprofiles state on
NetSh Advfirewall set allprofiles firewallpolicy blockinbound, allowoutbound

# 2. Allow Out-of-Scope Subnets (REQUIRED - cannot block these per rules)
foreach ($Subnet in $OutOfScopeSubnets) {
    New-NetFirewallRule -Name "Allow-OutOfScope-$($Subnet -replace '[./]','-')" -DisplayName "Allow Out-of-Scope $Subnet" -Direction Inbound -RemoteAddress $Subnet -Action Allow
}
Write-Host "[+] Allowed out-of-scope subnets" -ForegroundColor Green

# 3. Allow Critical Management (RDP from Team LAN and Cloud)
New-NetFirewallRule -Name "Allow-Team-RDP-LAN" -DisplayName "Allow Team RDP LAN" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $TeamLAN -Action Allow
New-NetFirewallRule -Name "Allow-Team-RDP-Cloud" -DisplayName "Allow Team RDP Cloud" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $TeamCloud -Action Allow

# 4. Allow Scoring Engine (ALL PORTS from Scoring IP)
foreach ($IP in $ScoringEngine) {
    New-NetFirewallRule -Name "Allow-Scoring-$IP" -DisplayName "Allow Scoring $IP" -Direction Inbound -RemoteAddress $IP -Action Allow
}

# 5. Allow Required Services (Context Aware)
# If this machine runs IIS (Moon Landing), open HTTP/HTTPS
if (Get-Service "W3SVC" -ErrorAction SilentlyContinue) {
    New-NetFirewallRule -Name "Allow-HTTP" -DisplayName "Allow HTTP Web" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
    New-NetFirewallRule -Name "Allow-HTTPS" -DisplayName "Allow HTTPS Web" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
    Write-Host "[+] Allowed IIS ports (80, 443)" -ForegroundColor Green
}

# If WinRM is running (First Olympics), open WinRM ports
if (Get-Service "WinRM" -ErrorAction SilentlyContinue) {
    New-NetFirewallRule -Name "Allow-WinRM-HTTP" -DisplayName "Allow WinRM HTTP" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
    New-NetFirewallRule -Name "Allow-WinRM-HTTPS" -DisplayName "Allow WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
    Write-Host "[+] Allowed WinRM ports (5985, 5986)" -ForegroundColor Green
}

# If this machine is a Domain Controller (Pyramids), open AD Ports
if ((Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4) {
    New-NetFirewallRule -Name "Allow-AD" -DisplayName "Allow AD Services" -Direction Inbound -Protocol TCP -LocalPort 53, 88, 135, 389, 445, 464, 636, 3268, 3269 -Action Allow
    New-NetFirewallRule -Name "Allow-AD-UDP" -DisplayName "Allow AD UDP" -Direction Inbound -Protocol UDP -LocalPort 53, 88, 123, 389, 464 -Action Allow
    Write-Host "[+] Allowed AD/DNS ports" -ForegroundColor Green
}

# If SMB is running (Wright Brothers), ensure port 445 is open
if (Get-Service "LanmanServer" -ErrorAction SilentlyContinue) {
    New-NetFirewallRule -Name "Allow-SMB" -DisplayName "Allow SMB" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
    Write-Host "[+] Allowed SMB port (445)" -ForegroundColor Green
}

# 6. Allow ICMP (Silk Road is scored on ICMP)
New-NetFirewallRule -Name "Allow-ICMPv4-In" -DisplayName "Allow ICMPv4 Inbound" -Direction Inbound -Protocol ICMPv4 -Action Allow
Write-Host "[+] Allowed ICMP for scoring" -ForegroundColor Green

Write-Host "Firewall Lockdown Complete." -ForegroundColor Cyan