<#  Disable-Updates.ps1
    Purpose: Aggressively disable Windows Update for lab VMs.
    Scope:   Windows 10/11 Home/Pro/Enterprise (tested on Win11 Pro).
    Run:     As Administrator. Reboot after completion.
#>

# --- Safety checks ---
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Error "This script must be run as Administrator. Exiting."
    exit 1
}

Write-Host "==> Disabling Windows Update (lab use only)..." -ForegroundColor Yellow

# Helper to ensure registry keys exist and values set
function Set-RegValue {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] $Value,
        [Microsoft.Win32.RegistryValueKind] $Type = [Microsoft.Win32.RegistryValueKind]::DWord
    )
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# --- Stop services that might hold file locks ---
$svcToStop = @('wuauserv','bits','dosvc','UsoSvc')
foreach ($svc in $svcToStop) {
    try { 
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Write-Host "Stopping service: $svc"
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

# --- Policy: Turn off automatic updates (works on Home/Pro via registry) ---
$wuPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$auPol = Join-Path $wuPol 'AU'

# NoAutoUpdate=1 => Disable automatic updates completely
Set-RegValue -Path $auPol -Name 'NoAutoUpdate' -Value 1
# AUOptions=1 => Never check (not strictly needed when NoAutoUpdate=1, but reinforces)
Set-RegValue -Path $auPol -Name 'AUOptions' -Value 1
# Exclude drivers from quality updates
Set-RegValue -Path $wuPol -Name 'ExcludeWUDriversInQualityUpdate' -Value 1
# Do not connect to Microsoft Update Internet locations
Set-RegValue -Path $wuPol -Name 'DoNotConnectToWindowsUpdateInternetLocations' -Value 1

# Trick: Force WSUS usage pointing to loopback so scans fail fast (blocks MU even if toggled back)
Set-RegValue -Path $auPol -Name 'UseWUServer' -Value 1
Set-RegValue -Path $wuPol -Name 'WUServer' -Value 'http://127.0.0.1' -Type String
Set-RegValue -Path $wuPol -Name 'WUStatusServer' -Value 'http://127.0.0.1' -Type String

# --- Delivery Optimization: Bypass ---
# 100 => Bypass (no peer caching / DO not used)
$doPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
Set-RegValue -Path $doPol -Name 'DODownloadMode' -Value 100

# --- Service startup types: Disabled (best effort) ---
$svcToDisable = @(
    'wuauserv',        # Windows Update
    'bits',            # Background Intelligent Transfer Service
    'dosvc',           # Delivery Optimization
    'UsoSvc'           # Update Orchestrator Service
    # 'WaaSMedicSvc'   # Windows Update Medic Service (system-protected; handled later)
)

foreach ($svc in $svcToDisable) {
    try {
        if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
            Write-Host "Disabling service startup: $svc"
            Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
        }
    } catch {}
}

# --- Best-effort: Disable Windows Update Medic Service (may be reverted by OS) ---
# This service is protected; switching via SCM often fails. We'll try via registry ACL + Start=4.
try {
    $medicKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
    if (Test-Path $medicKey) {
        $acl = Get-Acl $medicKey
        $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544') # Administrators
        $adm = $sid.Translate([System.Security.Principal.NTAccount])
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($adm, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.SetOwner($sid)
        $acl.ResetAccessRule($rule)
        Set-Acl -Path $medicKey -AclObject $acl
        # Set Start=4 (Disabled)
        New-ItemProperty -Path $medicKey -Name 'Start' -Value 4 -PropertyType DWord -Force | Out-Null
        Write-Host "Attempted to disable WaaSMedicSvc (may be reverted by OS after reboot)."
    }
} catch {
    Write-Warning "Could not modify WaaSMedicSvc (expected on some builds)."
}

# --- Disable update-related Scheduled Tasks ---
$taskRoots = @('\Microsoft\Windows\WindowsUpdate\','\Microsoft\Windows\UpdateOrchestrator\','\Microsoft\Windows\WindowsUpdate\AU\')
foreach ($root in $taskRoots) {
    try {
        Get-ScheduledTask | Where-Object { $_.TaskPath -eq $root } | ForEach-Object {
            Write-Host "Disabling scheduled task: $($_.TaskPath)$($_.TaskName)"
            Disable-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue | Out-Null
        }
    } catch {}
}

# --- Set all active network profiles as Metered (reduces background downloading) ---
try {
    $profiles = Get-NetConnectionProfile | Where-Object { $_.IPv4Connectivity -ne 'Disconnected' }
    foreach ($p in $profiles) {
        Write-Host "Setting metered connection on: $($p.InterfaceAlias)"
        Set-NetConnectionProfile -InterfaceAlias $p.InterfaceAlias -MeteredConnection Enabled -ErrorAction SilentlyContinue
    }
} catch {}

# --- Windows Firewall: block update services by service SID (clean and specific) ---
# Note: Service-specific rules avoid breaking other svchost-dependent networking.
function Ensure-FirewallRule {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Service
    )
    if (-not (Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $Name -Direction Outbound -Action Block -Service $Service -Enabled True | Out-Null
        Write-Host "Firewall rule added (block outbound): $Name for service $Service"
    } else {
        Write-Host "Firewall rule already exists: $Name"
    }
}
Ensure-FirewallRule -Name 'Block Windows Update (wuauserv)' -Service 'wuauserv'
Ensure-FirewallRule -Name 'Block Delivery Optimization (DoSvc)' -Service 'DoSvc'
Ensure-FirewallRule -Name 'Block Update Orchestrator (UsoSvc)' -Service 'UsoSvc'

# --- Clear pending update downloads ---
$dl = "$env:SystemRoot\SoftwareDistribution\Download"
try {
    if (Test-Path $dl) {
        Write-Host "Clearing pending update downloads..."
        Remove-Item -Path (Join-Path $dl '*') -Recurse -Force -ErrorAction SilentlyContinue
    }
} catch {}

# --- Flush DNS just in case there are cached endpoints ---
try { ipconfig /flushdns | Out-Null } catch {}

Write-Host "`nAll steps completed. A reboot is recommended." -ForegroundColor Green
Write-Host "Reminder: For a *reliable* vulnerable lab, prefer disconnecting the VM from the Internet." -ForegroundColor Yellow
