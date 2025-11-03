<#
.SYNOPSIS
  Disables or enables Microsoft 365/Office Click-to-Run updates (policy, service, tasks, and optional network blocks).

.PARAMETER Disable
  Apply settings to stop updates.

.PARAMETER Enable
  Revert settings to allow updates again.

.PARAMETER BlockNetwork
  (Optional when -Disable) Adds outbound firewall + hosts-file rules to block Office CDN update endpoints.

.PARAMETER RemoveNetworkBlocks
  (Optional when -Enable) Removes firewall + hosts-file rules previously created by this script.

.NOTES
  Run as Administrator. Tested on Windows 10/11 with Office 16.x Click-to-Run.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [switch]$Disable,
  [switch]$Enable,
  [switch]$BlockNetwork,
  [switch]$RemoveNetworkBlocks
)

function Assert-Admin {
  $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run as Administrator."
  }
}

function Set-Registry {
  param(
    [ValidateSet('Disable','Enable')][string]$Mode
  )
  # Office policy path (applies to Office 2016+/Microsoft 365 Apps)
  $baseKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate'
  if (-not (Test-Path $baseKey)) { New-Item -Path $baseKey -Force | Out-Null }
  if ($Mode -eq 'Disable') {
    New-ItemProperty -Path $baseKey -Name EnableAutomaticUpdates -PropertyType DWord -Value 0 -Force | Out-Null
  } else {
    # Remove the policy to restore default behavior
    if (Get-ItemProperty -Path $baseKey -Name EnableAutomaticUpdates -ErrorAction SilentlyContinue) {
      Remove-ItemProperty -Path $baseKey -Name EnableAutomaticUpdates -Force
    }
  }
}

function Set-ClickToRunService {
  param(
    [ValidateSet('Disable','Enable')][string]$Mode
  )
  $svc = 'ClickToRunSvc'  # Display name: Microsoft Office Click-to-Run Service
  if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
    if ($Mode -eq 'Disable') {
      try {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
      } catch {}
      Set-Service -Name $svc -StartupType Disabled
    } else {
      Set-Service -Name $svc -StartupType Automatic
      try { Start-Service -Name $svc -ErrorAction SilentlyContinue } catch {}
    }
  }
}

function Set-OfficeTasks {
  param(
    [ValidateSet('Disable','Enable')][string]$Mode
  )
  # Common Office update-related tasks (names can vary by build/tenant)
  $taskNames = @(
    '\Microsoft\Office\Office Automatic Updates 2.0',
    '\Microsoft\Office\Office Feature Updates',
    '\Microsoft\Office\Office Install Service Health Monitor'
  )
  foreach ($t in $taskNames) {
    try {
      $task = Get-ScheduledTask -TaskPath (Split-Path $t -Parent) -TaskName (Split-Path $t -Leaf) -ErrorAction Stop
      if ($Mode -eq 'Disable') {
        Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath | Out-Null
      } else {
        Enable-ScheduledTask  -TaskName $task.TaskName -TaskPath $task.TaskPath | Out-Null
      }
    } catch {
      # Task may not exist on all systems—ignore
    }
  }
}

function Set-NetworkBlocks {
  param(
    [ValidateSet('Add','Remove')][string]$Action
  )
  # Known update endpoints frequently contacted by Click-to-Run
  $domains = @(
    'officecdn.microsoft.com',
    'officeclient.microsoft.com'
  )

  # --- Firewall rules (Outbound) ---
  # Use RemoteFQDN when available (Win10 1709+). Fallback to blocking via hosts file if not supported.
  foreach ($d in $domains) {
    $ruleName = "Block Office Updates ($d)"
    if ($Action -eq 'Add') {
      # Remove an existing rule with same name to avoid duplicates
      if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
      }
      try {
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -Enabled True -Profile Any -RemoteFqdn $d -Program 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe' | Out-Null
      } catch {
        # Some builds don’t support -RemoteFQDN. Fall back to a broader program-based block without FQDN.
        try {
          New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -Enabled True -Profile Any -Program 'C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe' | Out-Null
        } catch {}
      }
    } else {
      if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
      }
    }
  }

  # --- Hosts file entries (optional, second layer) ---
  $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
  $beginMarker = '# BEGIN OfficeUpdateBlocks'
  $endMarker   = '# END OfficeUpdateBlocks'

  if ($Action -eq 'Add') {
    $blockLines = @()
    $blockLines += $beginMarker
    foreach ($d in $domains) { $blockLines += "0.0.0.0`t$d" }
    $blockLines += $endMarker

    $content = if (Test-Path $hosts) { Get-Content $hosts -ErrorAction Stop } else { @() }
    # Remove existing block (if any), then add cleanly
    if ($content -match [regex]::Escape($beginMarker)) {
      $start = ($content | Select-String -SimpleMatch $beginMarker).LineNumber - 1
      $stop  = ($content | Select-String -SimpleMatch $endMarker).LineNumber - 1
      if ($start -ge 0 -and $stop -ge $start) {
        $content = $content[0..($start-1)] + $content[($stop+1)..($content.Count-1)]
      }
    }
    $content += $blockLines
    # Take ownership/write (hosts is protected)
    $acl = Get-Acl $hosts
    $backup = "$hosts.bak.$((Get-Date).ToString('yyyyMMdd-HHmmss'))"
    Copy-Item $hosts $backup -Force
    Set-Content -Path $hosts -Value $content -Encoding ASCII -Force
  } else {
    if (Test-Path $hosts) {
      $content = Get-Content $hosts -ErrorAction SilentlyContinue
      if ($content -match [regex]::Escape($beginMarker)) {
        $start = ($content | Select-String -SimpleMatch $beginMarker).LineNumber - 1
        $stop  = ($content | Select-String -SimpleMatch $endMarker).LineNumber - 1
        if ($start -ge 0 -and $stop -ge $start) {
          $newContent = $content[0..($start-1)] + $content[($stop+1)..($content.Count-1)]
          Set-Content -Path $hosts -Value $newContent -Encoding ASCII -Force
        }
      }
    }
  }
}

function Show-Status {
  Write-Host "=== Office Update Status ===" -ForegroundColor Cyan
  $baseKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate'
  $policy = (Get-ItemProperty -Path $baseKey -ErrorAction SilentlyContinue).EnableAutomaticUpdates
  if ($null -eq $policy) { $policyText = "Not set (default/allowed)" } elseif ($policy -eq 0) { $policyText = "Disabled (0)" } else { $policyText = "Enabled ($policy)" }
  Write-Host ("Policy (EnableAutomaticUpdates): {0}" -f $policyText)

  $svc = Get-Service -Name ClickToRunSvc -ErrorAction SilentlyContinue
  if ($svc) { Write-Host ("ClickToRun Service: {0} / StartupType: {1}" -f $svc.Status,$svc.StartType) } else { Write-Host "ClickToRun Service: Not found" }

  $taskNames = @(
    '\Microsoft\Office\Office Automatic Updates 2.0',
    '\Microsoft\Office\Office Feature Updates',
    '\Microsoft\Office\Office Install Service Health Monitor'
  )
  foreach ($t in $taskNames) {
    try {
      $task = Get-ScheduledTask -TaskPath (Split-Path $t -Parent) -TaskName (Split-Path $t -Leaf) -ErrorAction Stop
      Write-Host ("Task {0}: {1}" -f $t, ($task.State))
    } catch {
      Write-Host ("Task {0}: Not found" -f $t)
    }
  }

  # Firewall rule visibility
  $rules = Get-NetFirewallRule -DisplayName 'Block Office Updates (*)' -ErrorAction SilentlyContinue
  if ($rules) {
    Write-Host "Firewall rules: Present"
  } else {
    Write-Host "Firewall rules: None"
  }
}

# ---------------- MAIN ----------------
try {
  Assert-Admin

  if (($Disable -and $Enable) -or (-not $Disable -and -not $Enable)) {
    throw "Specify either -Disable or -Enable."
  }

  if ($Disable) {
    Write-Host "[*] Disabling Office updates..." -ForegroundColor Yellow
    Set-Registry -Mode Disable
    Set-ClickToRunService -Mode Disable
    Set-OfficeTasks -Mode Disable
    if ($BlockNetwork) {
      Write-Host "[*] Applying network blocks for Office update CDNs..." -ForegroundColor Yellow
      Set-NetworkBlocks -Action Add
    }
  }

  if ($Enable) {
    Write-Host "[*] Re-enabling Office updates..." -ForegroundColor Yellow
    Set-Registry -Mode Enable
    Set-ClickToRunService -Mode Enable
    Set-OfficeTasks -Mode Enable
    if ($RemoveNetworkBlocks) {
      Write-Host "[*] Removing network blocks..." -ForegroundColor Yellow
      Set-NetworkBlocks -Action Remove
    }
  }

  Show-Status
  Write-Host "`nDone." -ForegroundColor Green
}
catch {
  Write-Error $_.Exception.Message
  exit 1
}
