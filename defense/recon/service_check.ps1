# Get all running services, grab their file path, and check the digital signature
# Also checks ServiceDll for svchost-hosted services
Get-WmiObject Win32_Service | Where-Object { $_.State -eq 'Running' } | ForEach-Object {
    $rawPath = $_.PathName
    $serviceName = $_.Name
    
    # Skip if no path
    if ([string]::IsNullOrWhiteSpace($rawPath)) { return }
    
    # Extract the executable path - handle quoted paths with spaces
    if ($rawPath -match '^"([^"]+)"') {
        # Path is quoted: "C:\Program Files\app.exe" -args
        $path = $Matches[1]
    }
    elseif ($rawPath -match '^([^\s]+)') {
        # Path is not quoted: C:\Windows\system32\svchost.exe -k netsvcs
        $path = $Matches[1]
    }
    else {
        return
    }
    
    # Expand environment variables like %SystemRoot%
    $path = [System.Environment]::ExpandEnvironmentVariables($path)
    
    # Skip if path doesn't exist or is a directory
    if (-not (Test-Path $path -PathType Leaf)) { 
        Write-Warning "[$serviceName] EXE path not found: $path"
        return 
    }
    
    # Check the main executable signature
    try {
        $sig = Get-AuthenticodeSignature $path -ErrorAction Stop
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft') {
            [PSCustomObject]@{
                Name     = $serviceName
                Path     = $path
                SignedBy = $sig.SignerCertificate.Subject
                Status   = if ($sig.Status -ne 'Valid') { "INVALID SIG" } else { "NON-MS SIGNED" }
                Type     = "EXE"
            }
        }
    }
    catch [System.UnauthorizedAccessException] {
        Write-Warning "[$serviceName] Permission denied checking EXE signature: $path"
    }
    catch {
        Write-Warning "[$serviceName] Error checking EXE signature: $($_.Exception.Message)"
    }
    
    # Check if this is a svchost-hosted service (loads a DLL)
    $exeName = [System.IO.Path]::GetFileName($path).ToLower()
    if ($exeName -eq 'svchost.exe') {
        # Look up the ServiceDll in registry
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName\Parameters"
        
        try {
            $serviceDll = (Get-ItemProperty -Path $regPath -Name ServiceDll -ErrorAction Stop).ServiceDll
        }
        catch [System.Security.SecurityException] {
            Write-Warning "[$serviceName] Permission denied reading registry: $regPath"
            return
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            # No Parameters key or ServiceDll value - not all svchost services have this
            return
        }
        catch {
            Write-Warning "[$serviceName] Error reading registry: $($_.Exception.Message)"
            return
        }
        
        if ($serviceDll) {
            # Expand environment variables in the DLL path
            $serviceDll = [System.Environment]::ExpandEnvironmentVariables($serviceDll)
            
            if (Test-Path $serviceDll -PathType Leaf) {
                try {
                    $dllSig = Get-AuthenticodeSignature $serviceDll -ErrorAction Stop
                    
                    if ($dllSig.Status -ne 'Valid' -or $dllSig.SignerCertificate.Subject -notmatch 'Microsoft') {
                        [PSCustomObject]@{
                            Name     = $serviceName
                            Path     = $serviceDll
                            SignedBy = $dllSig.SignerCertificate.Subject
                            Status   = if ($dllSig.Status -ne 'Valid') { "INVALID SIG (DLL)" } else { "NON-MS SIGNED (DLL)" }
                            Type     = "ServiceDll"
                        }
                    }
                    
                    # Also check if DLL is in a suspicious location
                    if ($serviceDll -like "C:\Users\*" -or 
                        $serviceDll -like "C:\Temp\*" -or 
                        $serviceDll -like "*\AppData\*" -or
                        $serviceDll -like "C:\ProgramData\*") {
                        [PSCustomObject]@{
                            Name     = $serviceName
                            Path     = $serviceDll
                            SignedBy = if ($dllSig) { $dllSig.SignerCertificate.Subject } else { "UNKNOWN" }
                            Status   = "SUSPICIOUS DLL PATH"
                            Type     = "ServiceDll"
                        }
                    }
                }
                catch [System.UnauthorizedAccessException] {
                    Write-Warning "[$serviceName] Permission denied checking DLL signature: $serviceDll"
                }
                catch {
                    Write-Warning "[$serviceName] Error checking DLL signature: $($_.Exception.Message)"
                }
            }
            else {
                # DLL doesn't exist - very suspicious
                [PSCustomObject]@{
                    Name     = $serviceName
                    Path     = $serviceDll
                    SignedBy = "N/A"
                    Status   = "DLL NOT FOUND"
                    Type     = "ServiceDll"
                }
            }
        }
    }
}