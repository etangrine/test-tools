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

# Output file
$outFile = "C:\Users\Administrator\Desktop\Local_Passwords_$(hostname).txt"
$passwords = @()

# Load assembly for password generation
Add-Type -AssemblyName System.Web

Write-Host "Changing local user passwords..."

foreach ($user in $localUsers) {
    try {
        # Check if user exists
        $localUser = Get-LocalUser -Name $user -ErrorAction Stop
        
        # Generate a strong password
        $newPassword = [System.Web.Security.Membership]::GeneratePassword(16, 3)
        
        # Set the password
        $localUser | Set-LocalUser -Password (ConvertTo-SecureString $newPassword -AsPlainText -Force)
        
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