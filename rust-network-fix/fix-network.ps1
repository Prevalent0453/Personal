<#
    Fix for: internet drops ("DHCP server is not responding") as soon as
    you join a Rust server, and only disabling/enabling the adapter helps.

    What it does:
      1. Writes a diagnostic report to your Desktop (rust-net-report-*.txt).
      2. On the active network adapter turns off power saving, Energy Efficient
         Ethernet / Green Ethernet and Large Send Offload - the usual reasons a
         NIC driver hangs under the burst of UDP traffic a Rust join produces.
      3. Offers (asks first) to:
           - unbind known-bad "gaming network" filter drivers
             (cFosSpeed / ASUS GameFirst / MSI LAN Manager, Killer, SmartByte, NetLimiter);
           - lock 2.5 GbE adapters (Intel I225/I226, Realtek 8125) to 1 Gbps;
           - reset Winsock and the TCP/IP stack.

    Only driver settings are changed - nothing is flashed or uninstalled. Before
    any change the current settings are saved to rust-net-backup-*.json on the
    Desktop; to undo everything:  run-as-admin.bat -Restore "<path to that json>"

    Run:  run-as-admin.bat   (or: powershell -ExecutionPolicy Bypass -File fix-network.ps1)
    Only collect the report, change nothing:  run-as-admin.bat -ReportOnly
#>
param([switch]$ReportOnly, [string]$Restore)

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($ReportOnly) { $argList += '-ReportOnly' }
    if ($Restore) { $argList += @('-Restore', "`"$((Resolve-Path $Restore).Path)`"") }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

$powerSettings = 'AllowComputerToTurnOffDevice', 'SelectiveSuspend', 'DeviceSleepOnDisconnect'

# Registry key of the adapter under the Network class; holds PnPCapabilities.
function Get-NicClassKey([string]$Guid) {
    $classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    Get-ChildItem $classKey -ErrorAction SilentlyContinue | Where-Object {
        (Get-ItemProperty $_.PSPath -Name NetCfgInstanceId -ErrorAction SilentlyContinue).NetCfgInstanceId -eq $Guid
    } | Select-Object -First 1
}

if ($Restore) {
    $saved = Get-Content -Path $Restore -Raw | ConvertFrom-Json
    $name = $saved.Adapter
    Write-Host "Restoring settings of '$name' from $Restore"
    foreach ($p in $saved.Advanced) {
        $now = Get-NetAdapterAdvancedProperty -Name $name -RegistryKeyword $p.Keyword -ErrorAction SilentlyContinue
        if ($now -and ((@($now.RegistryValue) -join ',') -ne (@($p.Value) -join ','))) {
            Set-NetAdapterAdvancedProperty -Name $name -RegistryKeyword $p.Keyword -RegistryValue @($p.Value) -NoRestart
            Write-Host "  [restored] $($p.Keyword) = $(@($p.Value) -join ',')"
        }
    }
    foreach ($b in $saved.Bindings) {
        if ($b.Enabled) { Enable-NetAdapterBinding -Name $name -ComponentID $b.ComponentID -ErrorAction SilentlyContinue }
    }
    foreach ($p in $saved.Power.PSObject.Properties) {
        if ($p.Value -notin 'Enabled', 'Disabled') { continue }
        $params = @{ Name = $name; $p.Name = $p.Value; ErrorAction = 'SilentlyContinue' }
        Set-NetAdapterPowerManagement @params
    }
    if ($saved.NicKey) {
        if ($null -eq $saved.PnPCapabilities) {
            Remove-ItemProperty -Path $saved.NicKey -Name PnPCapabilities -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path $saved.NicKey -Name PnPCapabilities -Value ([int]$saved.PnPCapabilities) -Type DWord
        }
    }
    Restart-NetAdapter -Name $name -Confirm:$false
    Write-Host 'Done, previous settings are back.' -ForegroundColor Green
    Read-Host 'Press Enter to exit'
    exit
}

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function Write-Table($Data) {
    if ($Data) { $Data | Out-String -Width 300 | Write-Host } else { Write-Host '  (none)' }
}

# Accepts y/yes and also the Y key on a Russian layout (n / d for "da").
function Ask([string]$Question, [bool]$Default = $true) {
    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    $answer = Read-Host "$Question $suffix"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    $c = [char]::ToLowerInvariant($answer.Trim()[0])
    return ($c -eq 'y') -or ($c -eq [char]0x043D) -or ($c -eq [char]0x0434)
}

$desktop = [Environment]::GetFolderPath('Desktop')
$report = Join-Path $desktop ("rust-net-report-{0:yyyyMMdd-HHmmss}.txt" -f (Get-Date))
Start-Transcript -Path $report | Out-Null

# ---------------------------------------------------------------- adapter ---

$adapter = $null
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
if ($route) { $adapter = Get-NetAdapter -InterfaceIndex $route.ifIndex -ErrorAction SilentlyContinue }
if (-not $adapter -or -not $adapter.HardwareInterface) {
    # No default route (internet is down right now) or it goes through a VPN:
    # fall back to the first connected physical adapter, wired first.
    $adapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Sort-Object { $_.Status -ne 'Up' }, { $_.MediaType -ne '802.3' } |
        Select-Object -First 1
}
if (-not $adapter) {
    Write-Host 'No physical network adapter found.' -ForegroundColor Red
    Stop-Transcript | Out-Null
    Read-Host 'Press Enter to exit'
    exit 1
}
$name = $adapter.Name
$isWifi = $adapter.MediaType -match '802\.11'

# ------------------------------------------------------------ diagnostics ---

Write-Section 'System'
Write-Host ("  {0}  build {1}" -f (Get-CimInstance Win32_OperatingSystem).Caption, [Environment]::OSVersion.Version)
Write-Host "  Active adapter: $name  [$($adapter.InterfaceDescription)]"

Write-Section 'Physical adapters'
Write-Table (Get-NetAdapter -Physical | Format-Table Name, InterfaceDescription, Status, LinkSpeed, MediaType, DriverVersion, DriverDate, DriverProvider -AutoSize)

$driverDate = [datetime]::MinValue
if ([datetime]::TryParse([string]$adapter.DriverDate, [ref]$driverDate) -and $driverDate -lt (Get-Date).AddYears(-2)) {
    Write-Host "  [!] Driver is from $($driverDate.ToString('yyyy-MM-dd')). Install the latest one from the motherboard/laptop vendor or Intel/Realtek site." -ForegroundColor Yellow
}

Write-Section 'ipconfig /all'
ipconfig /all | Out-String | Write-Host

Write-Section "Third-party protocol/filter drivers bound to '$name'"
$bindings = Get-NetAdapterBinding -Name $name -AllBindings -ErrorAction SilentlyContinue
$thirdParty = $bindings | Where-Object { $_.Enabled -and $_.ComponentID -notmatch '^ms_' }
Write-Table ($thirdParty | Format-Table DisplayName, ComponentID -AutoSize)

$badPattern = 'cFos|Killer|Rivet|SmartByte|GameFirst|NetLimiter|Gaming ?LAN'
$badBindings = @($thirdParty | Where-Object { ($_.DisplayName + ' ' + $_.ComponentID) -match $badPattern })

Write-Section 'Network-shaping / VPN software services'
$services = Get-Service -ErrorAction SilentlyContinue |
    Where-Object { ($_.Name + ' ' + $_.DisplayName) -match "$badPattern|Hamachi|Radmin|ZeroTier|ExitLag|NoPing|WTFast" }
Write-Table ($services | Format-Table Name, DisplayName, Status, StartType -AutoSize)

Write-Section "Advanced properties of '$name'"
Write-Table (Get-NetAdapterAdvancedProperty -Name $name -ErrorAction SilentlyContinue |
    Format-Table DisplayName, DisplayValue, RegistryKeyword, RegistryValue -AutoSize)

Write-Section "Power management of '$name'"
Write-Table (Get-NetAdapterPowerManagement -Name $name -ErrorAction SilentlyContinue | Format-List)

Write-Section 'Network errors/warnings in the System log, last 3 days'
$providers = 'Dhcp|Tcpip|NDIS|Netwtw|Netwbw|Killer|e1[a-z]*express|e2f|rt640|rtcx|rt68|rt25|rtwlan'
$driverFile = [IO.Path]::GetFileNameWithoutExtension([string]$adapter.DriverFileName)
if ($driverFile) { $providers += '|' + [regex]::Escape($driverFile) }
$events = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = (Get-Date).AddDays(-3); Level = 1, 2, 3 } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match $providers } | Select-Object -First 60
Write-Table ($events | Format-Table TimeCreated, ProviderName, Id,
    @{ n = 'Message'; e = { ([string]$_.Message -split "`r?`n")[0] } } -AutoSize)

if ($ReportOnly) {
    Stop-Transcript | Out-Null
    Write-Host "`nReport saved: $report" -ForegroundColor Green
    Read-Host 'Press Enter to exit'
    exit
}

# ------------------------------------------------------------------ fixes ---

Write-Section 'Fixes'
Write-Host "  Changes are applied to '$name'. The adapter will reconnect once at the end (a few seconds offline)."
if (-not (Ask '  Apply the safe fixes (power saving, EEE/Green Ethernet, Large Send Offload)?')) {
    Stop-Transcript | Out-Null
    Write-Host "`nNothing changed. Report saved: $report" -ForegroundColor Green
    Read-Host 'Press Enter to exit'
    exit
}

$nicKey = Get-NicClassKey $adapter.InterfaceGuid
$pm = Get-NetAdapterPowerManagement -Name $name -ErrorAction SilentlyContinue
$power = [ordered]@{}
foreach ($setting in $powerSettings) { if ($pm) { $power[$setting] = [string]$pm.$setting } }
$backup = Join-Path $desktop ("rust-net-backup-{0:yyyyMMdd-HHmmss}.json" -f (Get-Date))
[pscustomobject]@{
    Adapter         = $name
    Advanced        = @(Get-NetAdapterAdvancedProperty -Name $name -ErrorAction SilentlyContinue |
        Where-Object RegistryKeyword |
        ForEach-Object { [pscustomobject]@{ Keyword = $_.RegistryKeyword; Value = @($_.RegistryValue) } })
    Bindings        = @($bindings | Select-Object ComponentID, Enabled)
    Power           = $power
    NicKey          = if ($nicKey) { $nicKey.PSPath } else { $null }
    PnPCapabilities = if ($nicKey) { (Get-ItemProperty $nicKey.PSPath -Name PnPCapabilities -ErrorAction SilentlyContinue).PnPCapabilities } else { $null }
} | ConvertTo-Json -Depth 4 | Set-Content -Path $backup -Encoding UTF8
Write-Host "  Current settings saved to $backup" -ForegroundColor Green
Write-Host "  To undo everything later: run-as-admin.bat -Restore `"$backup`""
Write-Host ''

$needRestart = $false

# "Allow the computer to turn off this device to save power" and friends.
$pmParams = (Get-Command Set-NetAdapterPowerManagement).Parameters
$turnOffDisabled = $false
foreach ($setting in $powerSettings) {
    if (-not $pmParams.ContainsKey($setting)) { continue }
    $params = @{ Name = $name; $setting = 'Disabled'; ErrorAction = 'Stop' }
    if ($pmParams.ContainsKey('NoRestart')) { $params.NoRestart = $true }
    try {
        Set-NetAdapterPowerManagement @params
        Write-Host "  [set] $setting = Disabled" -ForegroundColor Green
        if ($setting -eq 'AllowComputerToTurnOffDevice') { $turnOffDisabled = $true }
        $needRestart = $true
    } catch {
        Write-Host "  [skip] $setting not supported by this driver"
    }
}
if (-not $turnOffDisabled) {
    # Same checkbox via the registry (PnPCapabilities = 24), for older builds/drivers.
    if ($nicKey) {
        Set-ItemProperty -Path $nicKey.PSPath -Name PnPCapabilities -Value 24 -Type DWord
        Write-Host '  [set] Allow the computer to turn off this device = off (registry)' -ForegroundColor Green
        $needRestart = $true
    }
}

# Standard and vendor-specific keywords; 0 means "off" for every one of them.
$tweaks = [ordered]@{
    '*EEE'                     = 'Energy Efficient Ethernet'
    'EEELinkAdvertisement'     = 'Energy Efficient Ethernet (Intel)'
    'AdvancedEEE'              = 'Advanced EEE (Realtek)'
    'EnableGreenEthernet'      = 'Green Ethernet (Realtek)'
    'PowerSavingMode'          = 'Power Saving Mode (Realtek)'
    'GigaLite'                 = 'GigaLite (Realtek)'
    'ULPMode'                  = 'Ultra Low Power Mode (Intel)'
    'ReduceSpeedOnPowerDown'   = 'Reduce Speed On Power Down (Intel)'
    'SipsEnabled'              = 'System Idle Power Saver (Intel)'
    'AutoPowerSaveModeEnabled' = 'Auto Power Saver'
    '*LsoV2IPv4'               = 'Large Send Offload v2 (IPv4)'
    '*LsoV2IPv6'               = 'Large Send Offload v2 (IPv6)'
}
foreach ($keyword in $tweaks.Keys) {
    $prop = Get-NetAdapterAdvancedProperty -Name $name -RegistryKeyword $keyword -ErrorAction SilentlyContinue
    if (-not $prop) { continue }
    $label = $tweaks[$keyword]
    if ([string]@($prop.RegistryValue)[0] -eq '0') {
        Write-Host "  [ok]  $label already off"
        continue
    }
    if ($prop.ValidRegistryValues -and ($prop.ValidRegistryValues -notcontains '0')) {
        Write-Host "  [skip] $label - driver does not accept 0"
        continue
    }
    try {
        Set-NetAdapterAdvancedProperty -Name $name -RegistryKeyword $keyword -RegistryValue '0' -NoRestart -ErrorAction Stop
        Write-Host "  [set] $label = off" -ForegroundColor Green
        $needRestart = $true
    } catch {
        Write-Host "  [fail] $label : $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if ($isWifi) {
    # Power options > Wireless Adapter Settings > Power Saving Mode = Maximum Performance.
    $sub = '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1'
    $set = '12bbebe6-58d6-4636-95bb-3217ef867c1a'
    powercfg /setacvalueindex SCHEME_CURRENT $sub $set 0
    powercfg /setdcvalueindex SCHEME_CURRENT $sub $set 0
    powercfg /setactive SCHEME_CURRENT
    Write-Host '  [set] Wi-Fi power plan = Maximum Performance' -ForegroundColor Green
}

foreach ($b in $badBindings) {
    Write-Host ''
    Write-Host "  Found '$($b.DisplayName)' bound to the adapter. Such traffic shapers are a known cause" -ForegroundColor Yellow
    Write-Host '  of the connection dying when a game starts heavy UDP traffic.' -ForegroundColor Yellow
    if (Ask "  Unbind '$($b.DisplayName)' from '$name'?") {
        try {
            Disable-NetAdapterBinding -Name $name -ComponentID $b.ComponentID -ErrorAction Stop
            Write-Host '  [set] unbound (uninstall the program itself later for good)' -ForegroundColor Green
        } catch {
            Write-Host "  [fail] $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

if ($adapter.InterfaceDescription -match 'I225|I226|8125|2\.5\s*G') {
    $speed = Get-NetAdapterAdvancedProperty -Name $name -RegistryKeyword '*SpeedDuplex' -ErrorAction SilentlyContinue
    # Standardized *SpeedDuplex value 6 = 1 Gbps full duplex.
    if ($speed -and ($speed.ValidRegistryValues -contains '6') -and ([string]@($speed.RegistryValue)[0] -ne '6')) {
        Write-Host ''
        Write-Host '  This is a 2.5 GbE adapter; these are known to drop the link under load at 2.5 Gbps.' -ForegroundColor Yellow
        if (Ask '  Lock the link to 1 Gbps full duplex? (plenty for any home internet)') {
            Set-NetAdapterAdvancedProperty -Name $name -RegistryKeyword '*SpeedDuplex' -RegistryValue '6' -NoRestart
            Write-Host '  [set] Speed & Duplex = 1 Gbps Full Duplex' -ForegroundColor Green
            $needRestart = $true
        }
    }
}

$rebootNeeded = $false
Write-Host ''
if (Ask '  Also reset Winsock and TCP/IP? (needs a reboot; a manually set static IP/DNS would be cleared)' $false) {
    netsh winsock reset | Out-Host
    netsh int ip reset | Out-Host
    ipconfig /flushdns | Out-Host
    $rebootNeeded = $true
}

if ($needRestart) {
    Write-Host ''
    Write-Host "  Restarting '$name'..."
    Restart-NetAdapter -Name $name -Confirm:$false
    Start-Sleep -Seconds 8
    Write-Table (Get-NetIPConfiguration -InterfaceAlias $name -ErrorAction SilentlyContinue |
        Format-List InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer)
}

Stop-Transcript | Out-Null
Write-Host ''
Write-Host "Done. Report saved: $report" -ForegroundColor Green
if ($rebootNeeded) { Write-Host 'Reboot the PC to finish the TCP/IP reset.' -ForegroundColor Yellow }
Write-Host 'Also set Steam > Settings > In Game > "In-game server browser: Max pings / minute" to 500.'
Read-Host 'Press Enter to exit'
