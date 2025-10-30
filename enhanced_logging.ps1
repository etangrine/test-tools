Write-Host "Enabling enhanced logging..."

# --- Enable PowerShell Logging (via Registry) ---
$psLogKey = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"

# Script Block Logging
$sbLogKey = "$psLogKey\ScriptBlockLogging"
if (-not (Test-Path $sbLogKey)) { New-Item -Path $sbLogKey -Force }
Set-ItemProperty -Path $sbLogKey -Name "EnableScriptBlockLogging" -Value 1
Write-Host "Enabled PowerShell Script Block Logging."

# Module Logging
$modLogKey = "$psLogKey\ModuleLogging"
if (-not (Test-Path $modLogKey)) { New-Item -Path $modLogKey -Force }
Set-ItemProperty -Path $modLogKey -Name "EnableModuleLogging" -Value 1
Set-ItemProperty -Path $modLogKey -Name "ModuleNames" -Value "*" # Log all modules
Write-Host "Enabled PowerShell Module Logging."

# --- Enable Process Creation Auditing (Event ID 4688) ---
Write-Host "Enabling Process Creation auditing (Event ID 4688)..."
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# --- Increase Security Log Size ---
Write-Host "Increasing Security Event Log size to 1GB..."
Limit-EventLog -LogName Security -MaximumSize 1GB

Write-Host "Logging configuration complete."
Write-Host "Look for logs in Event Viewer -> Applications and Services -> Microsoft -> Windows -> PowerShell -> Operational"
Write-Host "Look for process logs in Event Viewer -> Windows Logs -> Security (Event ID 4688)"