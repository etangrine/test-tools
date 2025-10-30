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

# Ensure the output directory exists
$outDirectory = "$env:USERPROFILE\Desktop"
if (-not (Test-Path -Path $outDirectory)) {
    New-Item -ItemType Directory -Path $outDirectory -Force | Out-Null
}

# Output file
$outFile = "$outDirectory\Local_Passwords_$(hostname).txt"
$passwords = @()

# Load assembly for password generation
Add-Type -AssemblyName System.Web

Write-Host "Changing local user passwords..."

# Generate a single strong password
$newPassword = [System.Web.Security.Membership]::GeneratePassword(12, 3)
$passwords += "Password for all local users: $newPassword"

foreach ($user in $localUsers) {
    try {
        # Check if user exists
        $localUser = Get-LocalUser -Name $user -ErrorAction Stop
        
        # Set the password
        $localUser | Set-LocalUser -Password (ConvertTo-SecureString $newPassword -AsPlainText -Force)
        
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