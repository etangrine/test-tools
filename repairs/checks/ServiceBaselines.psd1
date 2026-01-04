# Service Baseline Configuration Data
# Update this file when you receive the competition packet with environment-specific values.
# Format: Each service key contains expected configuration values for validation.
#
# New in v2: PortCheckByPID flag
#   - Set to $true to check port ownership by service PID (strict)
#   - Set to $false to just check if port is listening system-wide (for shared svchost services)

@{
    # IIS World Wide Web Publishing Service
    W3SVC        = @{
        DisplayName          = "World Wide Web Publishing Service"
        ExpectedPorts        = @(80, 443)
        ExpectedImagePath    = '%SystemRoot%\System32\svchost.exe -k iissvcs'
        ExpectedLogOnAs      = 'LocalSystem'
        ExpectedDependencies = @('HTTP', 'WAS')
        PortCheckProtocol    = 'TCP'
        PortCheckByPID       = $false  # IIS uses HTTP.sys, not direct PID binding
        Notes                = "IIS web server - ports may vary by site configuration"
    }

    # DNS Server (runs on Domain Controllers)
    DNS          = @{
        DisplayName          = "DNS Server"
        ExpectedPorts        = @(53)
        ExpectedImagePath    = '%SystemRoot%\System32\dns.exe'
        ExpectedLogOnAs      = 'LocalSystem'  # On DCs, DNS runs as LocalSystem
        ExpectedDependencies = @('Tcpip', 'Afd', 'RpcSs')
        PortCheckProtocol    = 'TCP'
        PortCheckByPID       = $true   # DNS has its own process
        Notes                = "DNS uses both TCP and UDP port 53"
    }

    # SMB Server (LanmanServer) - Updated for Server 2016+
    LanmanServer = @{
        DisplayName          = "Server"
        ExpectedPorts        = @(445)
        ExpectedImagePath    = '%SystemRoot%\system32\svchost.exe -k smbsvcs'  # Server 2016+
        ExpectedLogOnAs      = 'LocalSystem'
        ExpectedDependencies = @('SamSS', 'Srv2')
        PortCheckProtocol    = 'TCP'
        PortCheckByPID       = $false  # SMB uses System process, not svchost PID
        Notes                = "SMB file sharing - ImagePath is -k smbsvcs on Server 2016+"
    }

    # Windows Remote Management (WinRM)
    WinRM        = @{
        DisplayName          = "Windows Remote Management (WS-Management)"
        ExpectedPorts        = @(5985, 5986)
        ExpectedImagePath    = '%SystemRoot%\System32\svchost.exe -k NetworkService'
        ExpectedLogOnAs      = 'NT AUTHORITY\NETWORK SERVICE'
        ExpectedDependencies = @('HTTP', 'RPCSS')
        PortCheckProtocol    = 'TCP'
        PortCheckByPID       = $false  # WinRM uses HTTP.sys
        Notes                = "5985=HTTP, 5986=HTTPS - uses HTTP.sys not direct socket"
    }

    # Active Directory Domain Services (NTDS)
    NTDS         = @{
        DisplayName          = "Active Directory Domain Services"
        ExpectedPorts        = @(389, 636, 3268, 3269)
        ExpectedImagePath    = '%SystemRoot%\System32\lsass.exe'
        ExpectedLogOnAs      = 'LocalSystem'
        ExpectedDependencies = @()  # NTDS has implicit deps, don't check strictly
        PortCheckProtocol    = 'TCP'
        PortCheckByPID       = $true   # LSASS has its own PID
        Notes                = "389=LDAP, 636=LDAPS, 3268/3269=Global Catalog. Dependencies are implicit."
    }

    # Active Directory Web Services
    ADWS         = @{
        DisplayName          = "Active Directory Web Services"
        ExpectedPorts        = @(9389)
        ExpectedImagePath    = '%SystemRoot%\ADWS\Microsoft.ActiveDirectory.WebServices.exe'
        ExpectedLogOnAs      = 'LocalSystem'
        ExpectedDependencies = @()
        PortCheckProtocol    = 'TCP'
        PortCheckByPID       = $true   # ADWS has its own process
        Notes                = "Required for PowerShell AD cmdlets"
    }

    # Remote Desktop Services (TermService) - Updated for Server 2016+
    TermService  = @{
        DisplayName          = "Remote Desktop Services"
        ExpectedPorts        = @(3389)
        ExpectedImagePath    = '%SystemRoot%\System32\svchost.exe -k termsvcs'  # Server 2016+
        ExpectedLogOnAs      = 'NT AUTHORITY\NETWORK SERVICE'
        ExpectedDependencies = @('RPCSS')  # TermDD may not exist on all versions
        PortCheckProtocol    = 'TCP'
        PortCheckByPID       = $false  # RDP uses tdtcp.sys driver
        Notes                = "RDP - ImagePath is -k termsvcs on Server 2016+"
    }

    # DHCP Server (the actual server role, not the client)
    DHCPServer   = @{
        DisplayName          = "DHCP Server"
        ExpectedPorts        = @(67)
        ExpectedImagePath    = '%SystemRoot%\System32\svchost.exe -k DHCPServer'
        ExpectedLogOnAs      = 'NT AUTHORITY\NETWORK SERVICE'
        ExpectedDependencies = @('Tcpip', 'Afd')
        PortCheckProtocol    = 'UDP'
        PortCheckByPID       = $true
        Notes                = "DHCP Server role - separate from Dhcp client service"
    }
}
