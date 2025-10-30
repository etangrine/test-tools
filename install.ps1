# Installs Sysinternals and Wireshark using winget.

# Install Sysinternals
# winget install -e --id Microsoft.Sysinternals
# use this command instead to get sysinternals 
# Install-Module -Name SysInternals
# winget install -e --id Microsoft.Sysinternals.Suite
winget install sysinternals --accept-package-agreements
# Install Wireshark
winget install -e --id Wireshark.Wireshark