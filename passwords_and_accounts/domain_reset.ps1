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

# Output file
$outFile = "C:\Users\Administrator\Desktop\Domain_Passwords.txt"
$passwords = @()

# Load assembly for password generation
Add-Type -AssemblyName System.Web

Write-Host "Changing domain user passwords..."

foreach ($user in $domainUsers) {
    try {
        # Check if user exists
        $adUser = Get-ADUser -Identity $user -ErrorAction Stop
        
        # Generate a strong password
        $newPassword = [System.Web.Security.Membership]::GeneratePassword(16, 3)
        
        # Set the password
        $adUser | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) -Reset
        
        # Un-expire the password
        $adUser | Set-ADUser -PasswordNeverExpires $true
        
        $passwords += "User: $user, Password: $newPassword"
        Write-Host "Successfully reset password for $user"
    }
    catch {
        Write-Warning "Could not find or reset password for user $user. Error: $_"
    }
}

# Save passwords to file
$passwords | Out-File -FilePath $outFile
Write-Host "Password reset complete. Credentials saved to $outFile"