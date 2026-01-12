# Competition Configuration for ISTS Quals 2026
# This file centralizes team-specific values for easy updates during competition.
# NOT CURRENTLY IN USE - Import this file when ready to centralize configuration.
#
# Usage: $Config = Import-PowerShellDataFile -Path ".\competition_config.psd1"
#        $TeamLAN = $Config.TeamLAN

@{
    # Team Identity
    TeamNumber        = 2
    TeamName          = "Team 2"  # Update with actual team name if known
    
    # Network Configuration
    TeamLAN           = "10.2.1.0/24"       # Team 2 LAN subnet
    TeamCloud         = "192.168.2.0/24"    # Team 2 Cloud subnet
    
    # Out-of-Scope Subnets (DO NOT BLOCK per rules)
    OutOfScopeSubnets = @(
        "172.16.1.0/24",
        "172.20.1.0/24"
    )
    
    # Scoring Engine (add IPs when known from competition start)
    ScoringEngineIPs  = @()           # Will be provided at competition start
    ScoringURL        = "scoring.ists.io"
    
    # Management Access
    CompsoleURL       = "compsole.ritsec.cloud"
    
    # DataDog Protection (Out-of-Scope per rules)
    DataDogPaths      = @(
        "C:\ProgramData\Datadog",
        "C:\Program Files\Datadog",
        "/etc/datadog-agent"
    )
    DataDogUsers      = @("datadog", "dd-dog", "dd-agent")
    
    # WhiteTeam User (Out-of-Scope per rules)
    WhiteTeamUser     = "whiteteam"
    
    # Machine Hostnames (from packet)
    Machines          = @{
        # LAN Machines
        "Pyramids"       = @{ IP = "10.2.1.1"; OS = "Win Server 2022"; Service = "AD/DNS"; Scored = $true }
        "FirstOlympics"  = @{ IP = "10.2.1.2"; OS = "Windows 10"; Service = "WinRM"; Scored = $true }
        "SilkRoad"       = @{ IP = "10.2.1.3"; OS = "Windows 10"; Service = "ICMP"; Scored = $true }
        "VikingRaids"    = @{ IP = "10.2.1.4"; OS = "Debian 12"; Service = "SSH"; Scored = $true }
        "Enlightenment"  = @{ IP = "10.2.1.5"; OS = "Ubuntu 22.04"; Service = "FTP"; Scored = $true }
        "Chernobyl"      = @{ IP = "10.2.1.6"; OS = "Rocky 9"; Service = "Docker/Apache"; Scored = $true }
        "TimeMachine"    = @{ IP = "10.2.1.254"; OS = "pfSense"; Service = "Router"; Scored = $false }
        
        # Cloud Machines
        "BigBang"        = @{ IP = "192.168.2.1"; OS = "Fedora 42"; Service = "MySQL"; Scored = $true }
        "DinoAsteroid"   = @{ IP = "192.168.2.2"; OS = "Ubuntu 24.04"; Service = "Wazuh"; Scored = $false }
        "WrightBrothers" = @{ IP = "192.168.2.3"; OS = "Win Server 2022"; Service = "SMB"; Scored = $true }
        "MoonLanding"    = @{ IP = "192.168.2.4"; OS = "Windows 10"; Service = "IIS"; Scored = $true }
    }
    
    # Domain Users (from packet)
    DomainAdmins      = @("fathertime", "chronos", "aion", "kairos")
    DomainUsers       = @("merlin", "terminator", "mrpeabody", "jamescole", "docbrown", "professorparadox")
    
    # Local Users (from packet)  
    LocalAdmins       = @("drwho", "martymcFly", "arthurdent", "sambeckett")
    LocalUsers        = @("loki", "riphunter", "theflash", "tonystark", "drstrange", "bartallen")
}
