<#
.SYNOPSIS
    Scans a system for users not on an approved list and investigates their associated activities.
.DESCRIPTION
    This script retrieves all local users on a system and compares them against a predefined list of approved usernames. 
    For any user not on the approved list, it logs their details and searches for any running processes or scheduled tasks associated with them.
    The findings are saved to a timestamped log file in the same directory where the script is run.
.NOTES
    Author: Gemini
    Date: 2025-10-14
    Version: 1.0

    IMPORTANT: This script must be run with administrative privileges to access all user, process, and task information.
    CUSTOMIZE: You MUST customize the $approvedUsers variable to include all known and authorized users in your environment.
#>

#----------------------------------------------------------------------------------------------------------------#
# --- CONFIGURATION ---
# Customize this list with the exact usernames of all approved users on the system.
# Common system/service accounts are included by default.
#----------------------------------------------------------------------------------------------------------------#
$approvedUsers = @(
    "Administrator",
    "DefaultAccount",
    "Guest",
    "WDAGUtilityAccount",
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    # --- ADD YOUR KNOWN USER ACCOUNTS BELOW ---
    "ericd" # Example: "jdoe", "admin_user", etc.
)

#----------------------------------------------------------------------------------------------------------------#
# --- SCRIPT INITIALIZATION ---
#----------------------------------------------------------------------------------------------------------------#
$logFileName = "user_scan_log_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
$logPath = Join-Path -Path $PSScriptRoot -ChildPath $logFileName
$logOutput = @()

Function Write-Log {
    param ([string]$Message)
    $logOutput += $Message
    Write-Host $Message
}

#----------------------------------------------------------------------------------------------------------------#
# --- MAIN SCRIPT LOGIC ---
#----------------------------------------------------------------------------------------------------------------#

Write-Log "=================================================="
Write-Log "Starting User and Activity Scan at $(Get-Date)"
Write-Log "=================================================="
Write-Log "Approved users list: $($approvedUsers -join ', ')"
$logOutput += "" # Add a newline for spacing in the log file

# --- 1. Identify Unapproved Users ---
try {
    $allLocalUsers = Get-LocalUser
}
catch {
    Write-Log "[ERROR] Failed to execute Get-LocalUser. Please ensure you are running PowerShell with administrative privileges."
    $logOutput | Out-File -FilePath $logPath -Encoding utf8
    Exit
}

$unapprovedUsers = $allLocalUsers | Where-Object { $_.Name -notin $approvedUsers }

if ($unapprovedUsers.Count -eq 0) {
    Write-Log "[INFO] No unapproved users found on the system."
} else {
    Write-Log "[ALERT] Found $($unapprovedUsers.Count) unapproved user(s). Investigating..."
    $logOutput += ""

    foreach ($user in $unapprovedUsers) {
        Write-Log "--------------------------------------------------"
        Write-Log "[FOUND] Unapproved User: $($user.Name)"
        Write-Log " - SID: $($user.SID.Value)"
        Write-Log " - Enabled: $($user.Enabled)"
        Write-Log " - LastLogon: $($user.LastLogon)"
        Write-Log " - Description: $($user.Description)"
        $logOutput += ""

        # --- 2. Investigate Associated Processes ---
        Write-Log "  [*] Checking for associated processes..."
        try {
            # Get all processes and their owners
            $processes = Get-CimInstance -ClassName Win32_Process | ForEach-Object {
                $ownerInfo = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
                if ($ownerInfo.User -eq $user.Name) {
                    [PSCustomObject]@{
                        ProcessName = $_.Name
                        ProcessId   = $_.ProcessId
                        Path        = $_.ExecutablePath
                        CommandLine = $_.CommandLine
                    }
                }
            }

            if ($processes) {
                foreach ($proc in $processes) {
                    Write-Log "    - [PROCESS] Name: $($proc.ProcessName), ID: $($proc.ProcessId)"
                    Write-Log "      Path: $($proc.Path)"
                    Write-Log "      CommandLine: $($proc.CommandLine)"
                }
            } else {
                Write-Log "    - No running processes found for user '$($user.Name)'."
            }
        } catch {
            Write-Log "    - [WARNING] Could not query processes for user '$($user.Name)'. Permissions might be insufficient."
        }
        $logOutput += ""

        # --- 3. Investigate Associated Scheduled Tasks ---
        Write-Log "  [*] Checking for associated scheduled tasks..."
        try {
            # Check for tasks where the principal is the user
            $tasks = Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq $user.Name -or $_.Principal.UserId -like "*\$($user.Name)" }
            
            if ($tasks) {
                foreach ($task in $tasks) {
                    Write-Log "    - [TASK] TaskName: $($task.TaskName)"
                    Write-Log "      State: $($task.State)"
                    Write-Log "      Actions: $($($task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join ', ')"
                }
            } else {
                Write-Log "    - No scheduled tasks found for user '$($user.Name)'."
            }
        } catch {
            Write-Log "    - [WARNING] Could not query scheduled tasks. Permissions might be insufficient."
        }
        $logOutput += ""

        # --- 4. Suggest Further Manual Investigation ---
        Write-Log "  [*] Recommended next steps for '$($user.Name)':"
        Write-Log "    - Investigate user's home directory: C:\Users\$($user.Name)"
        Write-Log "    - Check for services running as this user: Get-Service | Where-Object { $\\.UserName -eq '$($user.Name)' }"
        Write-Log "    - Review Windows Event Logs for logon events (Event ID 4624) and other activities related to this user."
    }
}

# --- 5. Finalize and Save Log ---
Write-Log "=================================================="
Write-Log "Scan finished at $(Get-Date)."
Write-Log "Log file saved to: $logPath"
Write-Log "=================================================="

$logOutput | Out-File -FilePath $logPath -Encoding utf8
