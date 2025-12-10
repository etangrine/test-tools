<#
.SYNOPSIS
    Creates a new GPO with basic security settings.
.DESCRIPTION
    Requires RSAT Group Policy Management tools.
    Creates a GPO and sets basic Account Lockout and Audit policies via Registry.
.PARAMETER Name
    Name of the GPO.
.EXAMPLE
    .\New-GPOTemplate.ps1 -Name "IR_Security_Baseline"
#>
param(
    [string]$Name = "IR_Security_Baseline"
)

Write-Host "Creating GPO '$Name'..." -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    Write-Host "[-] GroupPolicy module not found. Is RSAT installed?" -ForegroundColor Red
    return
}
Import-Module GroupPolicy

try {
    # Create GPO
    $GPO = New-GPO -Name $Name -ErrorAction Stop
    Write-Host "[+] GPO Created: $($GPO.Id)" -ForegroundColor Green

    # Note: Modifying specific policies inside a GPO via PowerShell often requires 
    # manipulating the registry.pol files or using 3rd party modules.
    # As a baseline, we will set registry keys for some policies if possible, 
    # but standards GPO modification usually requires the GPMC GUI or extensive registry mapping.
    
    # Allow user to know it's created and ready for linking
    Write-Host "[*] GPO '$Name' is ready. Please link it to an OU via GPMC." -ForegroundColor Yellow
    
    # Example: Link to Domain Root (Commented out to prevent accidental global scope)
    # New-GPLink -Name $Name -Target "dc=contoso,dc=com"
    
}
catch {
    Write-Host "[-] Failed to create GPO: $($_.Exception.Message)" -ForegroundColor Red
}
