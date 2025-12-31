# Universal-UserPasswordReset.ps1
# Detects if we are on a Domain Controller or a standard Server/Workstation
# and resets passwords accordingly for allowed users.

param(
    [string[]]$extraUsers = @(),
    [switch]$SaveToFile
)

# --- Context Detection (Robust) ---
function Test-IsDomainController {
    # Primary check: CIM (modern, preferred for PowerShell 3.0+)
    try {
        $ComputerInfo = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        return $ComputerInfo.DomainRole -ge 4
    }
    catch {
        # Fallback: WMI (legacy, widely available)
        try {
            $ComputerInfo = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
            return $ComputerInfo.DomainRole -ge 4
        }
        catch {
            # Final fallback: Check for NTDS service (only exists on DCs)
            try {
                $ntds = Get-Service -Name 'NTDS' -ErrorAction Stop
                return $ntds.Status -eq 'Running'
            }
            catch {
                # NTDS service doesn't exist = not a DC
                return $false
            }
        }
    }
}

$IsDC = Test-IsDomainController
Write-Host "Context Detected: $(if ($IsDC) {'Domain Controller'} else {'Workstation/Server'})" -ForegroundColor Cyan

# Load assembly for password generation
Add-Type -AssemblyName System.Web

# Ensure the output directory exists
$outDirectory = "$env:USERPROFILE\Desktop"
if (-not (Test-Path -Path $outDirectory)) {
    New-Item -ItemType Directory -Path $outDirectory -Force | Out-Null
}

# --- Password Reset Logic ---
if ($IsDC) {
    # This is a Domain Controller, reset domain user passwords.
    Write-Host "Starting Domain User Password Reset..." -ForegroundColor Yellow

    # Requires the ActiveDirectory module (should be on your DC)
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Error "ActiveDirectory module not available. Please install RSAT-AD-PowerShell."
        exit 1
    }

    # List of allowed domain users from the packet [cite: 151-162]
    $domainUsers = @(
        "fathertime",
        "chronos",
        "aion",
        "kairos",
        "merlin",
        "terminator",
        "mrpeabody",
        "jamescole",
        "docbrown",
        "professorparadox",
        "Administrator" # Always include the default admin
    )

    # Add any extra users specified via parameter
    $domainUsers += $extraUsers

    # Output file
    $outFile = "$outDirectory\Domain_Passwords.txt"
    $passwords = @()

    # Get all domain users and log the unallowed ones
    $allDomainUsers = Get-ADUser -Filter *
    $unallowedUsers = $allDomainUsers | Where-Object { $_.SamAccountName -notin $domainUsers } | Select-Object -ExpandProperty SamAccountName
    $unallowedLogFile = "$outDirectory\Unallowed_Domain_Users.txt"
    $unallowedUsers | Out-File -FilePath $unallowedLogFile
    Write-Host "List of non-allowed domain users saved to $unallowedLogFile" -ForegroundColor Gray

    Write-Host "Changing domain user passwords..." -ForegroundColor Yellow

    # Generate a single strong password
    $newPassword = [System.Web.Security.Membership]::GeneratePassword(8, 3)
    $passwords += "Password for all domain users: $newPassword"

    foreach ($user in $domainUsers) {
        try {
            # Check if user exists
            $adUser = Get-ADUser -Identity $user -ErrorAction Stop
            
            # Set the password
            $adUser | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) -Reset
            
            # Un-expire the password
            $adUser | Set-ADUser -PasswordNeverExpires $true
            
            Write-Host " - Successfully reset password for $user" -ForegroundColor Green
        }
        catch {
            Write-Warning " - Could not find or reset password for user $user. Error: $_"
        }
    }

    # Save passwords to file if requested
    if ($SaveToFile) {
        $passwords | Out-File -FilePath $outFile
        Write-Host "Password reset complete. Credentials saved to $outFile" -ForegroundColor Cyan
    }
    else {
        $passwords
    }

    Write-Host "Domain user password reset complete." -ForegroundColor Green

}
else {
    # This is a Workstation/Server, reset local user passwords.
    Write-Host "Starting Local User Password Reset..." -ForegroundColor Yellow
    
    # List of allowed local users from the packet [cite: 164-175]
    $localUsers = @(
        "drwho",
        "martymcFly",
        "arthurdent",
        "sambeckett",
        "loki",
        "riphunter",
        "theflash",
        "tonystark",
        "drstrange",
        "bartallen",
        "Administrator" # Always include the default admin
    )

    # Add any extra users specified via parameter
    $localUsers += $extraUsers

    # Output file
    $outFile = "$outDirectory\Local_Passwords_$(hostname).txt"
    $passwords = @()

    Write-Host "Changing local user passwords..." -ForegroundColor Yellow

    # Generate a single strong password
    $newPassword = [System.Web.Security.Membership]::GeneratePassword(8, 3)
    $passwords += "Password for all local users: $newPassword"

    foreach ($user in $localUsers) {
        try {
            # Check if user exists
            $localUser = Get-LocalUser -Name $user -ErrorAction Stop
            
            # Set the password
            $localUser | Set-LocalUser -Password (ConvertTo-SecureString $newPassword -AsPlainText -Force)
            
            Write-Host " - Successfully reset password for $user" -ForegroundColor Green
        }
        catch {
            Write-Warning " - Could not find or reset password for user $user. Error: $_"
        }
    }

    # Save passwords to file if requested
    if ($SaveToFile) {
        $passwords | Out-File -FilePath $outFile
        Write-Host "Password reset complete. Credentials saved to $outFile" -ForegroundColor Cyan
    }
    else {
        $passwords
    }

    Write-Host "Local user password reset complete." -ForegroundColor Green
}
