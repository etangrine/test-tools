# Requires the ActiveDirectory module (should be on your DC)
Import-Module ActiveDirectory

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

# Ensure the output directory exists
$outDirectory = "$env:USERPROFILE\Desktop"
if (-not (Test-Path -Path $outDirectory)) {
    New-Item -ItemType Directory -Path $outDirectory -Force | Out-Null
}

# Output file
$outFile = "$outDirectory\Domain_Passwords.txt"
$passwords = @()

# Get all domain users and log the unallowed ones
$allDomainUsers = Get-ADUser -Filter *
$unallowedUsers = $allDomainUsers | Where-Object { $_.SamAccountName -notin $domainUsers } | Select-Object -ExpandProperty SamAccountName
$unallowedLogFile = "$outDirectory\Unallowed_Domain_Users.txt"
$unallowedUsers | Out-File -FilePath $unallowedLogFile
Write-Host "List of non-allowed domain users saved to $unallowedLogFile"

# Load assembly for password generation
Add-Type -AssemblyName System.Web

Write-Host "Changing domain user passwords..."

# Generate a single strong password
$newPassword = [System.Web.Security.Membership]::GeneratePassword(12, 3)
$passwords += "Password for all domain users: $newPassword"

foreach ($user in $domainUsers) {
    try {
        # Check if user exists
        $adUser = Get-ADUser -Identity $user -ErrorAction Stop
        
        # Set the password
        $adUser | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) -Reset
        
        # Un-expire the password
        $adUser | Set-ADUser -PasswordNeverExpires $true
        
        #$passwords += "Successfully reset password for $user"
        Write-Host "Successfully reset password for $user"
    }
    catch {
        Write-Warning "Could not find or reset password for user $user. Error: $_"
    }
}

# Save passwords to file
# $passwords | Out-File -FilePath $outFile
$passwords
# Write-Host "Password reset complete. Credentials saved to $outFile"