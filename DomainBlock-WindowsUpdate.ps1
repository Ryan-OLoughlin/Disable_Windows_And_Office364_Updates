<#
    DomainBlock-WindowsUpdate.ps1 (FINAL)
    Purpose: Domain-level blocking for Windows Update on Windows 10/11.
    Layers:
      (1) NRPT wildcard DNS blocking -> 127.0.0.1  (strongest)
      (2) HOSTS overrides            -> 127.0.0.1  (belt-and-braces)
      (3) Firewall rules for resolved CDN IPs      (daily refresh task)
    Usage : -Install | -RefreshIPs | -Remove
    Notes : Run as Administrator. Reboot recommended after -Install/-Remove.
            Script is idempotent (safe to re-run).
#>

[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$RefreshIPs,
    [switch]$Remove
)

# ---------- Admin check ----------
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) { Write-Error "Run as Administrator."; exit 1 }

# ---------- Config ----------
$NrptNamespaces = @(
    '.windowsupdate.com',
    '.windowsupdate.microsoft.com',
    '.update.microsoft.com',
    '.download.windowsupdate.com',
    '.delivery.mp.microsoft.com',
    '.do.dsp.mp.microsoft.com'
)

$Hostnames = @(
    'windowsupdate.microsoft.com',
    'update.microsoft.com',
    'download.windowsupdate.com',
    'wustat.windows.com',
    'ntservicepack.microsoft.com',
    'fe2.update.microsoft.com',
    'fe3.update.microsoft.com',
    'sls.update.microsoft.com',
    'fe2cr.update.microsoft.com',
    'delivery.mp.microsoft.com',
    'dl.delivery.mp.microsoft.com',
    'tlu.dl.delivery.mp.microsoft.com',
    'geo-prod.do.dsp.mp.microsoft.com'
)

# Public resolvers (for resolving IPs even if local DNS is blocked)
$Resolvers = @('1.1.1.1','8.8.8.8','9.9.9.9','208.67.222.222')

$FwRulePrefix = 'Block WU Domains (Dynamic IPs)'
$TaskName     = 'WUBlock-RefreshIPs'
$scriptPath   = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
$ThisScript   = (Get-Item -LiteralPath $scriptPath).FullName

# ---------- NRPT helpers ----------
function Test-NrptExists {
    param([Parameter(Mandatory)] [string]$Namespace)
    $rules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue
    if (-not $rules) { return $false }
    foreach ($r in $rules) {
        if ($r.Namespace) {
            if ((@($r.Namespace) | ForEach-Object { $_.ToLowerInvariant() }) -contains $Namespace.ToLowerInvariant()) {
                return $true
            }
        }
    }
    return $false
}

# Returns an array of rule Name(s) matching a namespace suffix
function Get-NrptRuleNamesByNamespace {
    param([Parameter(Mandatory)] [string]$Namespace)
    $names = @()
    $rules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue
    foreach ($r in ($rules | Where-Object { $_.Namespace })) {
        $nsForRule = @($r.Namespace) | ForEach-Object { $_.ToLowerInvariant() }
        if ($nsForRule -contains $Namespace.ToLowerInvariant()) { $names += $r.Name }
    }
    return $names
}

function Add-NrptRule {
    param([Parameter(Mandatory)] [string]$Namespace)
    if (Test-NrptExists -Namespace $Namespace) {
        Write-Host ("NRPT exists: {0}" -f $Namespace)
        return
    }
    try {
        Add-DnsClientNrptRule -Namespace $Namespace -NameServers '127.0.0.1' -ErrorAction Stop | Out-Null
        Write-Host ("NRPT added: {0} -> 127.0.0.1" -f $Namespace)
    } catch {
        Write-Warning ("NRPT add failed for {0}: {1}" -f $Namespace, $_.Exception.Message)
    }
}

# Remove by rule -Name (supported by cmdlet)
function Remove-NrptRule {
    param([Parameter(Mandatory)] [string]$Namespace)
    try {
        $ruleNames = Get-NrptRuleNamesByNamespace -Namespace $Namespace
        if (-not $ruleNames -or $ruleNames.Count -eq 0) {
            Write-Host ("NRPT not present: {0}" -f $Namespace)
            return
        }
        foreach ($n in $ruleNames) {
            Remove-DnsClientNrptRule -Name $n -Force -ErrorAction Stop | Out-Null
            Write-Host ("NRPT removed: {0} (rule {1})" -f $Namespace, $n)
        }
    } catch {
        Write-Warning ("NRPT remove failed for {0}: {1}" -f $Namespace, $_.Exception.Message)
    }
}

# ---------- HOSTS ----------
function Update-HostsEntries {
    param([string[]]$Names, [switch]$Remove)
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $tag = '# WU-BLOCK'
    try { attrib -r $hostsPath 2>$null | Out-Null } catch {}

    $current = Get-Content -LiteralPath $hostsPath -ErrorAction Stop

    if ($Remove) {
        $new = $current | Where-Object { $_ -notmatch '\s+# WU-BLOCK$' }
        if ($new.Count -ne $current.Count) {
            Set-Content -LiteralPath $hostsPath -Value $new -Encoding ASCII
            Write-Host "Hosts entries removed."
        } else {
            Write-Host "No tagged hosts entries to remove."
        }
        return
    }

    $base = $current | Where-Object { $_ -notmatch '\s+# WU-BLOCK$' }
    $add  = foreach ($n in $Names | Sort-Object -Unique) { "127.0.0.1 $n $tag" }
    Set-Content -LiteralPath $hostsPath -Value @($base; $add) -Encoding ASCII
    Write-Host ("Hosts entries added for {0} names." -f $Names.Count)
}

# ---------- DNS resolution for firewall IPs ----------
function Resolve-NamesViaResolvers {
    param([string[]]$Names)
    $ips = New-Object System.Collections.Generic.HashSet[string]
    foreach ($name in $Names) {
        foreach ($srv in $Resolvers) {
            try {
                $records = Resolve-DnsName -Name $name -Server $srv -Type A,AAAA -DnsOnly -NoHostsFile -ErrorAction Stop |
                           Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress
                foreach ($ip in $records) { [void]$ips.Add($ip) }
                break # got answers for this name
            } catch {
                # try next resolver
            }
        }
    }
    return @($ips)  # plain array
}

# Try resolvers first; if nothing, temporarily lift NRPT, resolve, then restore
function Resolve-NamesWithFallback {
    param([string[]]$Names)

    $ips = Resolve-NamesViaResolvers -Names $Names
    if (@($ips).Count -gt 0) { return @($ips) }

    $hadAnyNrpt = $false
    foreach ($ns in $NrptNamespaces) { if (Test-NrptExists -Namespace $ns) { $hadAnyNrpt = $true; break } }

    if ($hadAnyNrpt) {
        Write-Verbose "Temporarily removing NRPT to resolve IPs..."
        foreach ($ns in $NrptNamespaces) { Remove-NrptRule -Namespace $ns }
        try   { $ips = Resolve-NamesViaResolvers -Names $Names }
        finally { foreach ($ns in $NrptNamespaces) { Add-NrptRule -Namespace $ns } }
    }
    return @($ips)
}

# ---------- Firewall ----------
function Remove-FirewallRules {
    Get-NetFirewallRule -DisplayName "$FwRulePrefix*" -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host "Firewall rules removed."
}

function Add-FirewallRulesForIPs {
    param([string[]]$IPs)
    if (-not $IPs -or @($IPs).Count -eq 0) {
        Write-Host "No IPs resolved to block (DNS/NRPT layer already blocks)."
        return
    }
    $count     = @($IPs).Count
    $chunkSize = 200
    for ($i=0; $i -lt $count; $i += $chunkSize) {
        $start = $i
        $end   = [Math]::Min($i + $chunkSize - 1, $count - 1)
        $chunk = @($IPs[$start..$end])
        $name  = if ($count -gt $chunkSize) { "{0} #{1}" -f $FwRulePrefix, (($i / $chunkSize) + 1) } else { $FwRulePrefix }

        New-NetFirewallRule -DisplayName $name `
            -Direction Outbound -Action Block -Enabled True `
            -RemoteAddress $chunk -Profile Any `
            -Description "Auto-generated by DomainBlock-WindowsUpdate.ps1" | Out-Null
    }
    Write-Host ("Firewall rules added for {0} IPs." -f $count)
}

# ---------- Scheduled task ----------
function Register-RefreshTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false | Out-Null
    }
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ThisScript`" -RefreshIPs"
    $trigger = New-ScheduledTaskTrigger -Daily -At 3:30am
    $settings= New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -AllowStartIfOnBatteries -Hidden
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description 'Refresh WU domain IP blocks' | Out-Null
    Write-Host ("Scheduled task registered: {0} (daily 03:30)." -f $TaskName)
}

function Unregister-RefreshTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false | Out-Null
        Write-Host ("Scheduled task removed: {0}." -f $TaskName)
    } else {
        Write-Host "No scheduled task to remove."
    }
}

# ---------- Workflows ----------
function Do-Install {
    Write-Host "==> Installing Windows Update domain blocking (DNS + hosts + firewall)..." -ForegroundColor Yellow

    # Resolve CDN IPs BEFORE enforcing NRPT (best chance to capture)
    $seedIPs = Resolve-NamesWithFallback -Names ($Hostnames | Sort-Object -Unique)

    # 1) NRPT rules
    foreach ($ns in $NrptNamespaces) { Add-NrptRule -Namespace $ns }

    # 2) HOSTS overrides
    Update-HostsEntries -Names $Hostnames

    # 3) Firewall from resolved IPs
    Remove-FirewallRules
    Add-FirewallRulesForIPs -IPs $seedIPs

    # 4) Daily refresh
    Register-RefreshTask

    Write-Host "`nInstall completed. Consider rebooting the VM." -ForegroundColor Green
}

function Do-RefreshIPs {
    Write-Host "==> Refreshing firewall IP blocks..." -ForegroundColor Yellow

    Remove-FirewallRules
    $ips = Resolve-NamesWithFallback -Names ($Hostnames | Sort-Object -Unique)
    Add-FirewallRulesForIPs -IPs $ips

    Write-Host "Refresh completed." -ForegroundColor Green
}

function Do-Remove {
    Write-Host "==> Removing all domain-blocking artifacts..." -ForegroundColor Yellow

    foreach ($ns in $NrptNamespaces) { Remove-NrptRule -Namespace $ns }
    Update-HostsEntries -Names $Hostnames -Remove
    Remove-FirewallRules
    Unregister-RefreshTask

    Write-Host "`nRemoval completed. Consider rebooting the VM." -ForegroundColor Green
}

switch ($true) {
    $Install    { Do-Install; break }
    $RefreshIPs { Do-RefreshIPs; break }
    $Remove     { Do-Remove; break }
    default     { Write-Host "Specify one of: -Install | -RefreshIPs | -Remove"; exit 1 }
}
