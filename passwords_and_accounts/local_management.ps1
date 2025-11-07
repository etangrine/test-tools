param(
    [string[]]$extraExcludedUsers = @()
)

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
    "dd-agent",
    "whiteteam"
)

$allowedLocalUsers += $extraExcludedUsers

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
    $userName = $_.Name
    $normalizedUserName = $userName -replace '[^a-zA-Z0-9]', ''
    if (
        $userName -notin $allowedLocalUsers -and
        $normalizedUserName -notmatch '(?i)datadog' -and
        $normalizedUserName -notmatch '(?i)dddog' -and
        $normalizedUserName -notmatch '(?i)whiteteam' -and
        $normalizedUserName -notmatch '(?i)blackteam' -and
        $normalizedUserName -notmatch '(?i)grayteam'
    ) {
        Write-Host "Are you sure you want to disable $userName"
        $confirmation = Read-Host "Are you sure you want to disable $userName? (y/n)"
        if ($confirmation -eq 'y') {
            try {
                Disable-LocalUser -Name $userName
                Write-Host " - Disabled user: $userName"
            }
            catch {
                Write-Warning " - Could not disable $userName."
            }
        } else {
            Write-Host " - Skipped disabling user: $userName"
        }
    }
}
Write-Host "User management complete."