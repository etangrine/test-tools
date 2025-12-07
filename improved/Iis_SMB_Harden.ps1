# Harden-WindowsServices.ps1
# Detecting and hardening IIS and SMB automatically.

# --- SMB Hardening (Universal) ---
Write-Host "[-] Hardening SMB..."
# Disable SMBv1 (Wannacry/EternalBlue)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Type DWORD -Value 0 -Force
# Disable Null Session enumeration
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Type DWORD -Value 1 -Force

# --- IIS Hardening (Context Aware) ---
if (Get-Service "W3SVC" -ErrorAction SilentlyContinue) {
    Write-Host "[+] IIS Detected. Applying Web Hardening..." -ForegroundColor Green
    
    Import-Module WebAdministration

    # 1. Disable Directory Browsing (Prevents seeing file lists)
    Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value False -PSPath 'IIS:\'

    # 2. Add 'Hidden Segments' for sensitive folders (prevents accessing .git, .env, backups)
    $BadSegments = @("bin", "App_Code", ".git", ".env", "backup")
    foreach ($Segment in $BadSegments) {
        Add-WebConfigurationProperty -Filter /system.webServer/security/requestFiltering/hiddenSegments -Name "." -Value @{segment=$Segment} -PSPath 'IIS:\' -ErrorAction SilentlyContinue
    }

    # 3. Log all the things
    Set-ItemProperty -Path "IIS:\Sites\Default Web Site" -Name logFile.logExtFileFlags -Value "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,UserAgent,Cookie,Referer"
    
    Write-Host "    IIS Hardened."
} else {
    Write-Host "[-] IIS not found on this machine."
}