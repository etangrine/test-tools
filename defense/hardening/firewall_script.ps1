# Panic-Firewall.ps1
# BLOCKS ALL TRAFFIC except Scoring, White Team, and specific Services. Not sure if I will know the scoring ips
# should allow ports for other services like smb, winrm, and whatever is in the packet when I get it. 
# --- CONFIGURATION (UPDATE THESE FROM PACKET) ---
$WhiteTeamIPs = @("10.10.10.10")     # Example: Monitoring boxes
$ScoringEngine = @("172.16.1.50")    # Example: Scorify IP
$TeamSubnet = "10.0.1.0/24"          # Your team LAN
$RequiredPorts = @(
    3389, # RDP
    53,   # DNS (If you are the DNS server)
    80,   # HTTP (If you are the Web server)
    445   # SMB (If you are the File server)
)

Write-Host "Applying PANIC Firewall Rules..." -ForegroundColor Red

# 1. Reset Firewall
NetSh Advfirewall set allprofiles state on
NetSh Advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

# 2. Allow Critical Management (RDP from Team Only) TBH rdp should be disabled if its possible to detect if thisn't is a windows clould box
New-NetFirewallRule -Name "Allow-Team-RDP" -DisplayName "Allow Team RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress $TeamSubnet -Action Allow

# 3. Allow Scoring Engine (ALL PORTS from Scoring IP)
foreach ($IP in $ScoringEngine) {
    New-NetFirewallRule -Name "Allow-Scoring-$IP" -DisplayName "Allow Scoring $IP" -Direction Inbound -RemoteAddress $IP -Action Allow
}

# 4. Allow Required Services (Context Aware)
# If this machine runs IIS, open Port 80
if (Get-Service "W3SVC" -ErrorAction SilentlyContinue) {
    New-NetFirewallRule -Name "Allow-HTTP" -DisplayName "Allow HTTP Web" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
}

# If this machine is a Domain Controller, open AD Ports
if ((Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4) {
    New-NetFirewallRule -Name "Allow-AD" -DisplayName "Allow AD Services" -Direction Inbound -Protocol TCP -LocalPort 53,88,135,389,445,464,636,3268,3269 -Action Allow
    New-NetFirewallRule -Name "Allow-AD-UDP" -DisplayName "Allow AD UDP" -Direction Inbound -Protocol UDP -LocalPort 53,88,123,389,464 -Action Allow
}

Write-Host "Firewall Lockdown Complete."