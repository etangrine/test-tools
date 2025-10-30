param(
    [string[]]$extraExcludedUsers = @()
)

# List of allowed domain users from the packet [cite: 151-162]
$allowedDomainUsers = @(
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
    # System accounts that should not be disabled
    "Administrator",
    "Guest",
    "krbtgt",
    "DefaultAccount"
)

$allowedDomainUsers += $extraExcludedUsers

$groupName = "IRSeC_Allowed_Users"

# Create the group if it doesn't exist
try {
    Get-ADGroup $groupName -ErrorAction Stop | Out-Null
    Write-Host "Group $groupName already exists."
}
catch {
    New-ADGroup -Name $groupName -GroupScope Global -PassThru
    Write-Host "Created group $groupName."
}

# Add allowed users to the group
Write-Host "Adding users to $groupName..."
foreach ($user in $allowedDomainUsers) {
    try {
        Add-ADGroupMember -Identity $groupName -Members (Get-ADUser -Identity $user) -ErrorAction Stop
        Write-Host " - Added $user"
    }
    catch {
        Write-Warning " - Could not find or add $user."
    }
}

# Disable all other users
Write-Host "Disabling all non-allowed domain users..."
Get-ADUser -Filter * | ForEach-Object {
    $userName = $_.SamAccountName
    $normalizedUserName = $userName -replace '[^a-zA-Z0-9]', ''
    if (
        $userName -notin $allowedDomainUsers -and
        $normalizedUserName -notmatch '(?i)datadog' -and
        $normalizedUserName -notmatch '(?i)dddog' -and
        $normalizedUserName -notmatch '(?i)whiteteam'
    ) {
        Write-Host "Are you sure you want to disable $userName"
        $confirmation = Read-Host "Are you sure you want to disable $userName? (y/n)"
        if ($confirmation -eq 'y') {
            try {
                Disable-ADAccount -Identity $userName
                Write-Host " - Disabled user: $userName"
            }
            catch {
                Write-Warning " - Could not disable $userName. It may be a protected system account."
            }
        } else {
            Write-Host " - Skipped disabling user: $userName"
        }
    }
}

Write-Host "User management complete."