# Disable Windows updates
powershell -ExecutionPolicy Bypass -File .\Disable-Updates.ps1

# Install (add DNS/hosts/firewall rules + schedule daily refresh)
powershell -ExecutionPolicy Bypass -File .\DomainBlock-WindowsUpdate.ps1 -Install

# Refresh IP blocks on demand (DNS + hosts stay as-is)
powershell -ExecutionPolicy Bypass -File .\DomainBlock-WindowsUpdate.ps1 -RefreshIPs

# Disable Office365 updates 
.\Set-OfficeUpdates.ps1 -Disable -BlockNetwork
