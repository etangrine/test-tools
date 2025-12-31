# Improved: Universal-UserAudit.ps1
# Detects if we are on a Domain Controller or a standard Server/Workstation
# and audits users accordingly.

# --- Configuration ---
$AuthorizedUsers = @("Administrator", "Guest", "krbtgt", "DefaultAccount") # Add your team users here

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

# --- Audit Logic ---
if ($IsDC) {
    Write-Host "Scanning Active Directory Users (Protected Groups)..." -ForegroundColor Yellow
    # Focus on Domain Admins and Enterprise Admins
    $AdminGroups = @("Domain Admins", "Enterprise Admins", "Administrators")
    
    foreach ($Group in $AdminGroups) {
        try {
            $Members = Get-ADGroupMember -Identity $Group -Recursive
            foreach ($Member in $Members) {
                if ($AuthorizedUsers -notcontains $Member.Name) {
                    Write-Host "[ALERT] Unknown Admin in $($Group): $($Member.Name) ($($Member.SamAccountName))" -ForegroundColor Red
                }
            }
        }
        catch {
            Write-Warning "Could not query group $Group"
        }
    }
}
else {
    Write-Host "Scanning Local Users..." -ForegroundColor Yellow
    $LocalUsers = Get-LocalUser
    foreach ($User in $LocalUsers) {
        if ($AuthorizedUsers -notcontains $User.Name) {
            Write-Host "[ALERT] Unknown Local User: $($User.Name) (Enabled: $($User.Enabled))" -ForegroundColor Red
            # Advanced: Check if they are in the local Administrators group
            $IsAdmin = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -like "*$($User.Name)" }
            if ($IsAdmin) {
                Write-Host "    -> WARNING: User has Local Admin Privileges!" -ForegroundColor Magenta
            }
        }
    }
}