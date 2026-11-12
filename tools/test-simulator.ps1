# WireScope - Live test of the impairment simulator from the GUI.
#
# CHANGES LIVE TRAFFIC for about 25 seconds, and only ICMP to one host: the simulator adds 100 ms
# (+/- 10 ms) and drops 10 % of the pings to 1.1.1.1 (or -Target) while the capture runs. Everything
# else passes untouched. Expected: round trips about 100 ms above normal and a few lost pings.
# Your saved simulator settings are put back afterwards.
#   .\tools\test-simulator.ps1 [-Target 1.1.1.1] [-Out <folder for screenshots>]
#Requires -Version 7
param(
    [string]$Target = '1.1.1.1',
    [string]$Out = (Join-Path $env:TEMP 'WireScope-screenshots')
)
Import-Module (Join-Path $PSScriptRoot 'WireScopeUi.psm1') -Force
New-Item -ItemType Directory -Force $Out | Out-Null

$baseline = (Test-Connection $Target -Count 4 | Where-Object Status -eq 'Success' | Measure-Object Latency -Average).Average
$saved = Backup-WireScopeSettings @('SimLatency', 'SimJitter', 'SimLoss', 'SimDirection', 'SimRate', 'SimOrder', 'SimMatch', 'Page')
$key = 'HKCU:\Software\WireScope'
Set-ItemProperty $key -Name SimLatency -Value 100 -Type DWord
Set-ItemProperty $key -Name SimJitter -Value 10 -Type DWord
Set-ItemProperty $key -Name SimLoss -Value 100 -Type DWord   # tenths of a percent: 10 %
Set-ItemProperty $key -Name SimDirection -Value 3 -Type DWord
Set-ItemProperty $key -Name SimRate -Value 0 -Type DWord
Set-ItemProperty $key -Name SimMatch -Value "icmp remote $Target"
$session = Start-WireScope
try {
    Send-WireScopeCommand $session 'CmdStart'      # capture
    Start-Sleep -Milliseconds 500
    Send-WireScopeCommand $session 'CmdSimToggle'  # simulator on
    Start-Sleep -Seconds 1
    $pings = Test-Connection $Target -Count 20 -TimeoutSeconds 2
    Send-WireScopeCommand $session 'CmdPageSimulator'
    Save-WindowShot $session.Window (Join-Path $Out 'simulator-live.png')
    Send-WireScopeCommand $session 'CmdPageCapture'
    Save-WindowShot $session.Window (Join-Path $Out 'simulator-capture.png')
} finally {
    Stop-WireScope $session
    Restore-WireScopeSettings $saved
}
$ok = @($pings | Where-Object Status -eq 'Success')
'baseline {0:N0} ms, impaired {1:N0} ms average, {2} of {3} pings lost' -f $baseline, ($ok | Measure-Object Latency -Average).Average,
    ($pings.Count - $ok.Count), $pings.Count
$after = (Test-Connection $Target -Count 2 | Where-Object Status -eq 'Success' | Measure-Object Latency -Average).Average
'after closing: {0:N0} ms' -f $after
