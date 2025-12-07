# Improved: Universal-UserManagement.ps1
# Detects if we are on a Domain Controller or a standard Server/Workstation
# and manages users accordingly, disabling unauthorized accounts.

param(
    [string[]]$extraExcludedUsers = @()
)

# --- Context Detection ---
try {
    $ComputerInfo = Get-WmiObject Win32_ComputerSystem -ErrorAction Stop
    # DomainRole 4 or 5 means it is a Domain Controller
    $IsDC = $ComputerInfo.DomainRole -ge 4
    Write-Host "Context Detected: $(if ($IsDC) {'Domain Controller'} else {'Workstation/Server'})" -ForegroundColor Cyan
} catch {
    Write-Error "Could not determine computer role. Exiting."
    exit 1
}


# --- Management Logic ---
if ($IsDC) {
    # This is a Domain Controller, manage domain users.
    Write-Host "Starting Domain User Management..." -ForegroundColor Yellow

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
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw "ActiveDirectory module not found. Please install RSAT-AD-PowerShell."
        }
        Get-ADGroup $groupName -ErrorAction Stop | Out-Null
        Write-Host "Group $groupName already exists."
    }
    catch {
        Write-Host "Creating group $groupName..."
        try {
            New-ADGroup -Name $groupName -GroupScope Global -PassThru
            Write-Host "Created group $groupName."
        } catch {
            Write-Error "Failed to create AD group '$groupName'. Check permissions."
            # Continue without group creation
        }
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
            $normalizedUserName -notmatch '(?i)whiteteam' -and
            $normalizedUserName -notmatch '(?i)blackteam' -and
            $normalizedUserName -notmatch '(?i)grayteam'
        ) {
            $confirmation = Read-Host "Are you sure you want to disable domain user '$userName'? (y/n)"
            if ($confirmation -eq 'y') {
                try {
                    Disable-ADAccount -Identity $userName
                    Write-Host " - Disabled user: $userName" -ForegroundColor Green
                }
                catch {
                    Write-Warning " - Could not disable $userName. It may be a protected system account."
                }
            } else {
                Write-Host " - Skipped disabling user: $userName" -ForegroundColor Yellow
            }
        }
    }

    Write-Host "Domain user management complete." -ForegroundColor Green

} else {
    # This is a Workstation/Server, manage local users.
    Write-Host "Starting Local User Management..." -ForegroundColor Yellow
    
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
        Write-Host "Creating group $groupName..."
        try {
            New-LocalGroup -Name $groupName -ErrorAction Stop
            Write-Host "Created group $groupName."
        } catch {
             Write-Error "Failed to create local group '$groupName'. Check permissions."
             # Continue without group creation
        }
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
            $confirmation = Read-Host "Are you sure you want to disable local user '$userName'? (y/n)"
            if ($confirmation -eq 'y') {
                try {
                    Disable-LocalUser -Name $userName -ErrorAction Stop
                    Write-Host " - Disabled user: $userName" -ForegroundColor Green
                }
                catch {
                    Write-Warning " - Could not disable $userName."
                }
            } else {
                Write-Host " - Skipped disabling user: $userName" -ForegroundColor Yellow
            }
        }
    }
    Write-Host "Local user management complete." -ForegroundColor Green
}
