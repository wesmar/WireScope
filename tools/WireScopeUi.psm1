# WireScope - Drives the GUI from PowerShell for the scripts in tools\: starts bin\WireScope.exe, sends
# its commands, saves window screenshots, keeps the user's settings safe and closes it again.
# Command ids are read from src\gui\MainWindowDetail.h, so the scripts follow the enum when it changes.

$script:Root = Split-Path -Parent $PSScriptRoot
$script:SettingsKey = 'HKCU:\Software\WireScope'

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class WireScopeWin32 {
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
    [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr hwnd, int id);
    [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr hwnd);
    [DllImport("dwmapi.dll")] public static extern int DwmGetWindowAttribute(IntPtr hwnd, int attribute, out RECT rect, int size);
    delegate bool EnumProc(IntPtr hwnd, IntPtr param);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc callback, IntPtr param);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassNameW(IntPtr hwnd, StringBuilder name, int size);
    // Top-level window of a process by window class (dialogs are separate top-level windows).
    public static IntPtr Find(int pid, string windowClass) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((h, p) => {
            uint id; GetWindowThreadProcessId(h, out id);
            var name = new StringBuilder(64); GetClassNameW(h, name, 64);
            if (id == (uint)pid && name.ToString() == windowClass) { found = h; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
'@

$WM_COMMAND = 0x0111
$WM_CLOSE = 0x0010

function Get-WireScopeCommands {
    # Command name -> id, from the Command enum (sequential values, "Name = number" restarts the count).
    $text = Get-Content (Join-Path $script:Root 'src\gui\MainWindowDetail.h') -Raw
    $body = [regex]::Match($text, 'enum Command : UINT \{(.*?)\};', 'Singleline').Groups[1].Value
    $body = [regex]::Replace($body, '//[^\n]*', '')
    $ids = @{}
    $next = 0
    foreach ($item in $body -split ',') {
        $item = $item.Trim()
        if (-not $item) { continue }
        if ($item -match '^(\w+)\s*=\s*(\d+)$') { $item = $Matches[1]; $next = [int]$Matches[2] }
        $ids[$item] = $next
        $next++
    }
    $ids
}

function Start-WireScope {
    # Refuses to run beside another instance: that one would own the data plane and the test would
    # see disabled controls.
    if (Get-Process WireScope -ErrorAction SilentlyContinue) { throw 'Another WireScope instance is running. Close it first.' }
    $exe = Join-Path $script:Root 'bin\WireScope.exe'
    if (-not (Test-Path $exe)) { throw "$exe not found: run build.ps1 first." }
    $process = Start-Process $exe -PassThru
    $window = [IntPtr]::Zero
    for ($i = 0; $i -lt 50 -and $window -eq [IntPtr]::Zero; $i++) {
        Start-Sleep -Milliseconds 200
        $process.Refresh()
        $window = $process.MainWindowHandle
    }
    if ($window -eq [IntPtr]::Zero) { Stop-Process -Id $process.Id -Force; throw 'The WireScope window did not appear.' }
    Start-Sleep -Milliseconds 1500  # driver, adapters, first paint
    [pscustomobject]@{ Process = $process; Window = $window; Commands = Get-WireScopeCommands }
}

function Send-WireScopeCommand($Session, [string]$Name) {
    $id = $Session.Commands[$Name]
    if ($null -eq $id) { throw "Unknown command $Name" }
    [WireScopeWin32]::PostMessageW($Session.Window, $WM_COMMAND, [IntPtr]$id, [IntPtr]::Zero) | Out-Null
}

function Test-WireScopeControl($Session, [string]$Name) {
    # True when the button of that command is enabled.
    [WireScopeWin32]::IsWindowEnabled([WireScopeWin32]::GetDlgItem($Session.Window, $Session.Commands[$Name]))
}

function Find-WireScopeDialog($Session, [int]$TimeoutMs = 6000) {
    for ($waited = 0; $waited -lt $TimeoutMs; $waited += 200) {
        $dialog = [WireScopeWin32]::Find($Session.Process.Id, 'WireScope.Dialog')
        if ($dialog -ne [IntPtr]::Zero) { return $dialog }
        Start-Sleep -Milliseconds 200
    }
    [IntPtr]::Zero
}

function Confirm-WireScopeDialog([IntPtr]$Dialog) {
    [WireScopeWin32]::PostMessageW($Dialog, $WM_COMMAND, [IntPtr]1, [IntPtr]::Zero) | Out-Null  # IDOK
}

function Save-WindowShot([IntPtr]$Window, [string]$Path) {
    # The window draws itself into the bitmap (PrintWindow, PW_RENDERFULLCONTENT): nothing else on the
    # screen can end up in the file, and the window is not brought to the front while someone works.
    # The extended frame bounds (DWM attribute 9) cut off the invisible resize border.
    Start-Sleep -Milliseconds 900  # the last command repaints
    # Physical pixels for both rectangles: PowerShell is not DPI aware, and DWM always answers in pixels.
    $previous = [WireScopeWin32]::SetThreadDpiAwarenessContext([IntPtr](-4))  # PER_MONITOR_AWARE_V2
    $outer = New-Object WireScopeWin32+RECT
    $frame = New-Object WireScopeWin32+RECT
    [WireScopeWin32]::GetWindowRect($Window, [ref]$outer) | Out-Null
    [WireScopeWin32]::DwmGetWindowAttribute($Window, 9, [ref]$frame, 16) | Out-Null
    if ($previous -ne [IntPtr]::Zero) { [WireScopeWin32]::SetThreadDpiAwarenessContext($previous) | Out-Null }
    $full = New-Object System.Drawing.Bitmap ($outer.Right - $outer.Left), ($outer.Bottom - $outer.Top)
    $graphics = [System.Drawing.Graphics]::FromImage($full)
    $dc = $graphics.GetHdc()
    $printed = [WireScopeWin32]::PrintWindow($Window, $dc, 2)
    $graphics.ReleaseHdc($dc)
    $graphics.Dispose()
    try {
        if (-not $printed) { throw "PrintWindow failed for $Path" }
        $crop = [System.Drawing.Rectangle]::Intersect(
            (New-Object System.Drawing.Rectangle ($frame.Left - $outer.Left), ($frame.Top - $outer.Top), ($frame.Right - $frame.Left), ($frame.Bottom - $frame.Top)),
            (New-Object System.Drawing.Rectangle 0, 0, $full.Width, $full.Height))
        if ($crop.IsEmpty) { $crop = New-Object System.Drawing.Rectangle 0, 0, $full.Width, $full.Height }
        $shot = $full.Clone($crop, $full.PixelFormat)
        $shot.Save($Path, [System.Drawing.Imaging.ImageFormat]::Png)
        $shot.Dispose()
    } finally {
        $full.Dispose()
    }
    "saved $Path"
}

function Stop-WireScope($Session) {
    # WM_CLOSE: WireScope restores the adapter mode and the driver's filter table on the way out.
    [WireScopeWin32]::PostMessageW($Session.Window, $WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
    $Session.Process.WaitForExit(8000) | Out-Null
    if (-not $Session.Process.HasExited) {
        Stop-Process -Id $Session.Process.Id -Force
        Write-Warning 'WireScope did not close and was stopped; its next start repairs the driver state.'
    }
}

function Backup-WireScopeSettings([string[]]$Names) {
    # Values (or their absence) before a test writes its own settings.
    $saved = @{}
    $values = Get-ItemProperty $script:SettingsKey -ErrorAction SilentlyContinue
    foreach ($name in $Names) {
        $saved[$name] = if ($values -and $values.PSObject.Properties[$name]) { $values.$name } else { $null }
    }
    $saved
}

function Restore-WireScopeSettings([hashtable]$Saved) {
    if (-not (Test-Path $script:SettingsKey)) { New-Item $script:SettingsKey -Force | Out-Null }
    foreach ($name in $Saved.Keys) {
        if ($null -eq $Saved[$name]) {
            Remove-ItemProperty $script:SettingsKey -Name $name -ErrorAction SilentlyContinue
        } else {
            $type = if ($Saved[$name] -is [int]) { 'DWord' } else { 'String' }
            Set-ItemProperty $script:SettingsKey -Name $name -Value $Saved[$name] -Type $type
        }
    }
}

function Get-WireScopeSetting([string]$Name) {
    $values = Get-ItemProperty $script:SettingsKey -ErrorAction SilentlyContinue
    if ($values -and $values.PSObject.Properties[$Name]) { $values.$Name } else { $null }
}

Export-ModuleMember -Function * -Variable WM_COMMAND, WM_CLOSE
