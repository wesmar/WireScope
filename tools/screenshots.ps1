# WireScope - Screenshots of every GUI page, for reviewing a change or the README.
# Changes no traffic: -Count turns on per-program counting, which reads copies of packets (listen mode).
# The window draws itself into the files, so other windows on the screen never end up in them.
#   .\tools\screenshots.ps1                      pages as they start, into %TEMP%\WireScope-screenshots
#   .\tools\screenshots.ps1 -Count -Out shots    with traffic counted on the Processes page
#Requires -Version 7
param(
    [string]$Out = (Join-Path $env:TEMP 'WireScope-screenshots'),
    [switch]$Count
)
Import-Module (Join-Path $PSScriptRoot 'WireScopeUi.psm1') -Force
New-Item -ItemType Directory -Force $Out | Out-Null

# The GUI saves the page and the counting switch; both are put back however the script ends.
$saved = Backup-WireScopeSettings @('ProcessMonitor', 'Page')
$session = Start-WireScope
try {
    if ($Count -and $saved['ProcessMonitor'] -ne 1) {
        Send-WireScopeCommand $session 'CmdPageProcesses'
        Send-WireScopeCommand $session 'CmdProcMonitor'
        Start-Sleep -Seconds 4  # a few samples for the rates
    }
    $pages = [ordered]@{ capture = 'CmdPageCapture'; processes = 'CmdPageProcesses'; firewall = 'CmdPageFirewall'; simulator = 'CmdPageSimulator' }
    $number = 1
    foreach ($page in $pages.Keys) {
        Send-WireScopeCommand $session $pages[$page]
        Save-WindowShot $session.Window (Join-Path $Out ('{0}-{1}.png' -f $number++, $page))
    }
} finally {
    Stop-WireScope $session
    Restore-WireScopeSettings $saved
}
