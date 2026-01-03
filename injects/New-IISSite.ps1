<#
.SYNOPSIS
    Automates creating a new Website in IIS.
.DESCRIPTION
    Creates a physical path, creates a default index.html, and binds the site to a port.
.PARAMETER Name
    Name of the website.
.PARAMETER Port
    Port to bind the website to. Default is 8080.
.PARAMETER Path
    Physical path for the website files. Default is C:\inetpub\wwwroot\<Name>.
.EXAMPLE
    .\New-IISSite.ps1 -Name "CorpSite" -Port 8080
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [int]$Port = 8080,

    [string]$Path
)

# default path logic
if (-not $Path) {
    if (Test-Path "C:\inetpub\wwwroot") {
        $Path = "C:\inetpub\wwwroot\$Name"
    }
    else {
        $Path = "C:\$Name"
    }
}

Write-Host "Creating IIS Site '$Name' on Port $Port..." -ForegroundColor Cyan

# Check for Web-Server module
if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
    Write-Host "[!] IIS Management tools not found. Attempting to import..." -ForegroundColor Yellow
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    if (-not (Get-Module -Name WebAdministration)) {
        Write-Host "[-] Failed to load WebAdministration module. Is IIS installed?" -ForegroundColor Red
        return
    }
}

# Create Directory
if (-not (Test-Path $Path)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
    Write-Host "[+] Created directory: $Path" -ForegroundColor Green
}

# Create index.html
$Content = "<html><body><h1>$Name</h1><p>Site created by IR Toolkit</p></body></html>"
$Content | Set-Content -Path "$Path\index.html"
Write-Host "[+] Created default index.html" -ForegroundColor Green

# Create Site
try {
    if (Test-Path "IIS:\Sites\$Name") {
        Write-Host "[!] Site '$Name' already exists. Skipping creation." -ForegroundColor Yellow
    }
    else {
        New-WebSite -Name $Name -Port $Port -PhysicalPath $Path -Force
        Write-Host "[+] IIS Site '$Name' created successfully on port $Port" -ForegroundColor Green
    }
    
    # Open Firewall Rule (Optional attempt)
    New-NetFirewallRule -DisplayName "IIS-$Name-$Port" -Direction Inbound -LocalPort $Port -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
    Write-Host "[+] Firewall rule created for port $Port" -ForegroundColor Green

}
catch {
    Write-Host "[-] Failed to create site: $($_.Exception.Message)" -ForegroundColor Red
}
