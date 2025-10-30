param (
    [string[]]$Keywords = @("mimikatz", "nc.exe", "ncat", "reverse", "shell", "malware", "psexec")
)

Write-Host "Searching for processes matching keywords: $($Keywords -join ', ')..."

# Get process details, including the command line
$processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath

$found = $false
foreach ($proc in $processes) {
    foreach ($keyword in $Keywords) {
        if ($proc.Name -like "*$keyword*" -or $proc.CommandLine -like "*$keyword*") {
            Write-Host "---"
            Write-Host "FOUND MATCH: $keyword" -ForegroundColor Red
            $proc | Format-List
            $found = $true
            break # Move to the next process
        }
    }
}

if (-not $found) {
    Write-Host "No suspicious processes found." -ForegroundColor Green
}