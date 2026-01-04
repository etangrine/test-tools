# Service Baseline Configuration Data
# Update this file when you receive the competition packet with environment-specific values.
# Format: Each service key contains expected configuration values for validation.

@{
    # IIS World Wide Web Publishing Service
    W3SVC        = @{
        DisplayName          = "World Wide Web Publishing Service"
        ExpectedPorts        = @(80, 443)
        ExpectedImagePath    = '%SystemRoot%\System32\svchost.exe -k iissvcs'
        ExpectedLogOnAs      = 'LocalSystem'
        ExpectedDependencies = @('HTTP', 'WAS')
        PortCheckProtocol    = 'TCP'
        Notes                = "IIS web server - ports may vary by site configuration"
    }

    # DNS Server
    DNS          = @{
        DisplayName          = "DNS Server"
        ExpectedPorts        = @(53)
        ExpectedImagePath    = '%SystemRoot%\System32\dns.exe'
        ExpectedLogOnAs      = 'NT AUTHORITY\NETWORK SERVICE'
        ExpectedDependencies = @('Tcpip', 'Afd', 'RpcSs')
        PortCheckProtocol    = 'TCP'  # Also UDP but we check TCP
        Notes                = "DNS uses both TCP and UDP port 53"
    }

    # SMB Server (LanmanServer)
    LanmanServer = @{
        DisplayName          = "Server"
        ExpectedPorts        = @(445)
        ExpectedImagePath    = '%SystemRoot%\system32\svchost.exe -k netsvcs -p'
        ExpectedLogOnAs      = 'LocalSystem'
        ExpectedDependencies = @('SamSS', 'Srv2')
        PortCheckProtocol    = 'TCP'
        Notes                = "SMB file sharing - port 445 is direct SMB over TCP"
    }

    # Windows Remote Management (WinRM)
    WinRM        = @{
        DisplayName          = "Windows Remote Management (WS-Management)"
        ExpectedPorts        = @(5985, 5986)
        ExpectedImagePath    = '%SystemRoot%\System32\svchost.exe -k NetworkService -p'
        ExpectedLogOnAs      = 'NT AUTHORITY\NETWORK SERVICE'
        ExpectedDependencies = @('HTTP', 'RPCSS')
        PortCheckProtocol    = 'TCP'
        Notes                = "5985=HTTP, 5986=HTTPS - may be disabled for hardening"
    }

    # Active Directory Domain Services (NTDS)
    NTDS         = @{
        DisplayName          = "Active Directory Domain Services"
        ExpectedPorts        = @(389, 636, 3268, 3269)
        ExpectedImagePath    = '%SystemRoot%\System32\lsass.exe'
        ExpectedLogOnAs      = 'LocalSystem'
        ExpectedDependencies = @('Netlogon', 'RPCSS', 'SamSS', 'LanmanServer', 'LanmanWorkstation', 'w32time', 'DNS')
        PortCheckProtocol    = 'TCP'
        Notes                = "389=LDAP, 636=LDAPS, 3268/3269=Global Catalog"
    }

    # Active Directory Web Services
    ADWS         = @{
        DisplayName          = "Active Directory Web Services"
        ExpectedPorts        = @(9389)
        ExpectedImagePath    = '%SystemRoot%\ADWS\Microsoft.ActiveDirectory.WebServices.exe'
        ExpectedLogOnAs      = 'LocalSystem'
        ExpectedDependencies = @()
        PortCheckProtocol    = 'TCP'
        Notes                = "Required for PowerShell AD cmdlets"
    }

    # Remote Desktop Services (TermService)
    TermService  = @{
        DisplayName          = "Remote Desktop Services"
        ExpectedPorts        = @(3389)
        ExpectedImagePath    = '%SystemRoot%\System32\svchost.exe -k NetworkService -p'
        ExpectedLogOnAs      = 'NT AUTHORITY\NETWORK SERVICE'
        ExpectedDependencies = @('RPCSS', 'TermDD')
        PortCheckProtocol    = 'TCP'
        Notes                = "RDP - important for cloud/remote boxes"
    }

    # DHCP Server
    Dhcp         = @{
        DisplayName          = "DHCP Server"
        ExpectedPorts        = @(67)
        ExpectedImagePath    = '%SystemRoot%\System32\svchost.exe -k DHCPServer'
        ExpectedLogOnAs      = 'NT AUTHORITY\NETWORK SERVICE'
        ExpectedDependencies = @('Tcpip', 'Afd', 'EventLog')
        PortCheckProtocol    = 'UDP'  # DHCP is UDP
        Notes                = "DHCP uses UDP ports 67 (server) and 68 (client)"
    }
}
