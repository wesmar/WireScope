# WireScope - Live test of the automatic undo of risky firewall changes.
#
# CHANGES LIVE TRAFFIC for about 20 seconds: the firewall is turned on with one rule that blocks only
# inbound Remote Desktop (TCP 3389). WireScope warns, applies it, and must undo it by itself after
# kRevertSeconds. The script then checks that the driver's filter table is empty again. Outbound
# traffic, DNS and web browsing are not affected. Your saved rules are put back afterwards.
#   .\tools\test-auto-undo.ps1 [-Out <folder for screenshots>]
#Requires -Version 7
param([string]$Out = (Join-Path $env:TEMP 'WireScope-screenshots'))
Import-Module (Join-Path $PSScriptRoot 'WireScopeUi.psm1') -Force
New-Item -ItemType Directory -Force $Out | Out-Null
$exe = Join-Path (Split-Path -Parent $PSScriptRoot) 'bin\WireScope.exe'

function Show-FilterTable {
    $p = Start-Process $exe -ArgumentList '--firewall-show' -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\wirescope-table.txt"
    Get-Content "$env:TEMP\wirescope-table.txt" | Select-Object -First 1
    Remove-Item "$env:TEMP\wirescope-table.txt" -ErrorAction SilentlyContinue
}

$saved = Backup-WireScopeSettings @('FirewallRules', 'FirewallPolicy', 'KernelOffload', 'Page')
Set-ItemProperty HKCU:\Software\WireScope -Name FirewallRules -Value "block in tcp dport 3389`n"
Set-ItemProperty HKCU:\Software\WireScope -Name FirewallPolicy -Value 0 -Type DWord
$session = Start-WireScope
try {
    Send-WireScopeCommand $session 'CmdPageFirewall'
    Start-Sleep -Milliseconds 600
    Save-WindowShot $session.Window (Join-Path $Out 'undo-1-before.png')
    Send-WireScopeCommand $session 'CmdFwToggle'
    $dialog = Find-WireScopeDialog $session
    if ($dialog -eq [IntPtr]::Zero) { throw 'No lockout warning appeared for a rule that blocks Remote Desktop.' }
    Save-WindowShot $dialog (Join-Path $Out 'undo-2-warning.png')
    Confirm-WireScopeDialog $dialog  # apply, with the automatic undo armed
    Start-Sleep -Milliseconds 1500
    Save-WindowShot $session.Window (Join-Path $Out 'undo-3-countdown.png')
    Start-Sleep -Seconds 22
    Save-WindowShot $session.Window (Join-Path $Out 'undo-4-reverted.png')
    "firewall switch enabled again: $(Test-WireScopeControl $session 'CmdFwToggle')"
} finally {
    Stop-WireScope $session
    Restore-WireScopeSettings $saved
    Show-FilterTable  # expected: no entries
}
