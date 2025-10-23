# List of allowed local users from the packet [cite: 164-175]
$allowedLocalUsers = @(
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
    # System accounts that should not be disabled
    "Administrator",
    "Guest",
    "DefaultAccount",
    "WDAGUtilityAccount",
    # Datadog users mentioned in rules [cite: 87]
    "datadog",
    "dd-dog",
    "dd-agent"
)

$groupName = "IRSeC_Allowed_Local_Users"

# Create the group if it doesn't exist
try {
    Get-LocalGroup $groupName -ErrorAction Stop | Out-Null
    Write-Host "Group $groupName already exists."
}
catch {
    New-LocalGroup -Name $groupName
    Write-Host "Created group $groupName."
}

# Add allowed users to the group
Write-Host "Adding users to $groupName..."
foreach ($user in $allowedLocalUsers) {
    try {
        Add-LocalGroupMember -Group $groupName -Member $user -ErrorAction Stop
        Write-Host " - Added $user"
    }
    catch {
        Write-Warning " - Could not find or add $user."
    }
}

# Disable all other users
Write-Host "Disabling all non-allowed local users..."
Get-LocalUser | ForEach-Object {                                                                         
    if ($_.Name -notin $allowedLocalUsers -and $_.Name -notlike '*datadog*' -and $_.Name -notlike '*dd-dog*') {                                                             
        try {                                                                                            
            Disable-LocalUser -Name $_.Name                                                              
            Write-Host " - Disabled user: $($_.Name)"                                                    
        }                                                                                                
        catch {                                                                                          
            Write-Warning " - Could not disable $($_.Name)."                                             
        }                                                                                                
    }                                                                                                    
}
Write-Host "User management complete."