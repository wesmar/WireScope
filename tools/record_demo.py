"""
WireScope - Automated video demonstration recorder (approx 30s)
Pure GUI showcase centered within standard 1920x1080 OBS canvas.
Zero cutoffs: window sits with comfortable margins on pure white studio backdrop.
"""

import os
import sys
import time
import glob
import ctypes
import subprocess
import threading
from ctypes import wintypes
import cv2

# DPI awareness (Per-Monitor V2)
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
user32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))

# Attach thread to interactive desktop
hdesk = user32.OpenDesktopW('Default', 0, False, 0x10000000)
if not hdesk:
    print('Failed to open Default desktop, error:', kernel32.GetLastError())
    sys.exit(1)
user32.SetThreadDesktop(hdesk)

# Constants
HWND_TOPMOST = ctypes.c_void_p(-1)
SWP_SHOWWINDOW = 0x0040
WM_COMMAND = 0x0111
WM_CLOSE = 0x0010

# Structures for Win32 API
class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb', wintypes.DWORD), ('lpReserved', wintypes.LPWSTR), ('lpDesktop', wintypes.LPWSTR),
        ('lpTitle', wintypes.LPWSTR), ('dwX', wintypes.DWORD), ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD), ('dwYSize', wintypes.DWORD), ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD), ('dwFillAttribute', wintypes.DWORD), ('dwFlags', wintypes.DWORD),
        ('wShowWindow', wintypes.WORD), ('cbReserved2', wintypes.WORD), ('lpReserved2', ctypes.c_void_p),
        ('hStdInput', wintypes.HANDLE), ('hStdOutput', wintypes.HANDLE), ('hStdError', wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', wintypes.HANDLE), ('hThread', wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD), ('dwThreadId', wintypes.DWORD),
    ]

class RECT(ctypes.Structure):
    _fields_ = [('left', ctypes.c_long), ('top', ctypes.c_long), ('right', ctypes.c_long), ('bottom', ctypes.c_long)]

# Mouse control helpers
def move_mouse_smooth(x_target, y_target, duration=0.35, steps=25):
    pt = wintypes.POINT()
    user32.GetCursorPos(ctypes.byref(pt))
    x0, y0 = pt.x, pt.y
    for i in range(1, steps + 1):
        t = i / float(steps)
        ease = t * t * (3.0 - 2.0 * t) # smoothstep
        x = int(x0 + (x_target - x0) * ease)
        y = int(y0 + (y_target - y0) * ease)
        user32.SetCursorPos(x, y)
        time.sleep(duration / float(steps))

def click_control(hwnd, ctrl_id, duration=0.3):
    hctrl = user32.GetDlgItem(hwnd, ctrl_id)
    if not hctrl:
        return
    r = RECT()
    user32.GetWindowRect(hctrl, ctypes.byref(r))
    cx, cy = (r.left + r.right) // 2, (r.top + r.bottom) // 2
    move_mouse_smooth(cx, cy, duration=duration)
    time.sleep(0.08)
    user32.mouse_event(0x0002, 0, 0, 0, 0) # LEFTDOWN
    user32.PostMessageW(hwnd, WM_COMMAND, ctrl_id, 0)
    time.sleep(0.08)
    user32.mouse_event(0x0004, 0, 0, 0, 0) # LEFTUP
    time.sleep(0.15)

def click_coords(x, y, duration=0.3):
    move_mouse_smooth(x, y, duration=duration)
    time.sleep(0.08)
    user32.mouse_event(0x0002, 0, 0, 0, 0)
    time.sleep(0.08)
    user32.mouse_event(0x0004, 0, 0, 0, 0)
    time.sleep(0.15)

def drag_slider_track(hwnd, slider_id, frac_start=0.08, frac_end=0.40, duration=0.45):
    hslider = user32.GetDlgItem(hwnd, slider_id)
    if not hslider:
        return
    r = RECT()
    user32.GetWindowRect(hslider, ctypes.byref(r))
    y_mid = (r.top + r.bottom) // 2
    w = r.right - r.left
    x1 = int(r.left + w * frac_start)
    x2 = int(r.left + w * frac_end)

    move_mouse_smooth(x1, y_mid, duration=0.25)
    time.sleep(0.08)
    user32.mouse_event(0x0002, 0, 0, 0, 0)
    time.sleep(0.08)
    for i in range(1, 26):
        x = int(x1 + (x2 - x1) * (i / 25.0))
        user32.SetCursorPos(x, y_mid)
        time.sleep(duration / 25.0)
    time.sleep(0.08)
    user32.mouse_event(0x0004, 0, 0, 0, 0)
    time.sleep(0.18)

def main():
    vid_dir = r'C:\Users\Administrator\Videos'
    os.makedirs(vid_dir, exist_ok=True)
    before_files = set(os.listdir(vid_dir))

    # 1. Bring Chrome about:blank to the foreground as backdrop
    print('Locating Chrome about:blank window...')
    chrome_hwnd = None
    def enum_chrome(hwnd, lparam):
        nonlocal chrome_hwnd
        if user32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, buf, 256)
            if 'about:blank' in buf.value or 'Google Chrome' in buf.value:
                chrome_hwnd = hwnd
                return False
        return True

    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows(WNDENUMPROC(enum_chrome), 0)

    if chrome_hwnd:
        print(f'Bringing Chrome (HWND {chrome_hwnd}) to front as maximized backdrop...')
        user32.ShowWindow(chrome_hwnd, 3) # SW_MAXIMIZE
        user32.SetForegroundWindow(chrome_hwnd)
        user32.SetWindowPos(chrome_hwnd, 0, 0, 0, 1920, 1200, SWP_SHOWWINDOW)
        time.sleep(0.5)

    obs_exe = r'C:\Program Files\obs-studio\bin\64bit\obs64.exe'
    obs_cwd = r'C:\Program Files\obs-studio\bin\64bit'

    print('Launching OBS Studio on WinSta0\\Default...')
    si_obs = STARTUPINFO()
    si_obs.cb = ctypes.sizeof(STARTUPINFO)
    si_obs.lpDesktop = 'WinSta0\\Default'
    pi_obs = PROCESS_INFORMATION()

    cmd_obs = f'"{obs_exe}" --startrecording --minimize-to-tray'
    res = kernel32.CreateProcessW(None, cmd_obs, None, None, False, 0, None, obs_cwd, ctypes.byref(si_obs), ctypes.byref(pi_obs))
    if not res:
        print('Failed to launch OBS, error:', kernel32.GetLastError())
        sys.exit(1)

    obs_pid = pi_obs.dwProcessId
    print(f'OBS PID: {obs_pid}')

    # Wait for OBS recording engine
    print('Waiting for OBS recording engine to start...')
    logs_dir = os.path.expanduser(r'~\AppData\Roaming\obs-studio\logs')
    recording_active = False
    start_wait = time.time()
    while time.time() - start_wait < 25:
        logs = sorted(glob.glob(os.path.join(logs_dir, '*.txt')), key=os.path.getmtime)
        if logs:
            try:
                with open(logs[-1], encoding='utf-8', errors='ignore') as f:
                    if '==== Recording Start ====' in f.read():
                        recording_active = True
                        break
            except Exception:
                pass
        time.sleep(0.5)

    if not recording_active:
        print('Warning: OBS Recording Start marker not detected, proceeding anyway...')
    else:
        print('OBS recording confirmed active!')

    # Launch WireScope GUI
    print('Launching WireScope GUI...')
    wirescope_exe = r'C:\Projekty\WireScope\bin\WireScope.exe'
    wirescope_dir = r'C:\Projekty\WireScope\bin'

    si_ws = STARTUPINFO()
    si_ws.cb = ctypes.sizeof(STARTUPINFO)
    si_ws.lpDesktop = 'WinSta0\\Default'
    pi_ws = PROCESS_INFORMATION()

    res_ws = kernel32.CreateProcessW(None, wirescope_exe, None, None, False, 0, None, wirescope_dir, ctypes.byref(si_ws), ctypes.byref(pi_ws))
    if not res_ws:
        print('Failed to launch WireScope GUI!')
        sys.exit(1)

    time.sleep(2.0)

    target_hwnd = None
    for _ in range(25):
        def enum_cb(hwnd, lparam):
            nonlocal target_hwnd
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value == pi_ws.dwProcessId:
                buf = ctypes.create_unicode_buffer(256)
                user32.GetWindowTextW(hwnd, buf, 256)
                if 'WireScope' in buf.value:
                    target_hwnd = hwnd
                    return False
            return True

        user32.EnumWindows(WNDENUMPROC(enum_cb), 0)
        if target_hwnd:
            break
        time.sleep(0.2)

    if not target_hwnd:
        print('Could not find WireScope window!')
        sys.exit(1)

    # Frame WireScope safely inside the 1920x1080 canvas:
    # x=220, y=50, w=1480, h=960 -> top margin 50px, bottom margin 70px (before 1080), left/right 220px!
    # Zero cutoff, 100% visible, centered over pure white backdrop!
    print(f'Setting WireScope (HWND {target_hwnd}) to (220, 50, 1480, 960) HWND_TOPMOST...')
    user32.SetWindowPos(target_hwnd, HWND_TOPMOST, 220, 50, 1480, 960, SWP_SHOWWINDOW)
    user32.SetForegroundWindow(target_hwnd)
    time.sleep(1.0)

    t_action_start = time.time()

    win_rect = RECT()
    user32.GetWindowRect(target_hwnd, ctypes.byref(win_rect))

    # Command IDs
    CMD_PAGE_CAPTURE = 1001
    CMD_PAGE_PROCESSES = 1002
    CMD_PAGE_FIREWALL = 1003
    CMD_PAGE_SIMULATOR = 1004
    CMD_ABOUT = 1007
    CMD_START = 1012
    CMD_STOP = 1013
    CMD_SIM_TOGGLE = 1025

    # 1. LIVE CAPTURE DEMONSTRATION
    print('--- Step 1: Live Capture ---')
    click_control(target_hwnd, CMD_START)
    print('Clicked Start capture')

    def send_pings():
        subprocess.run(['ping', '-n', '5', '1.1.1.1'], capture_output=True)

    thr = threading.Thread(target=send_pings, daemon=True)
    thr.start()

    # Move mouse around capture area while packets arrive
    time.sleep(1.0)
    move_mouse_smooth(win_rect.left + 500, win_rect.top + 320, duration=0.6)
    time.sleep(2.0)

    # Click on a packet row to show protocol tree & hex dump
    click_coords(win_rect.left + 500, win_rect.top + 260)
    print('Selected packet row (details & hex rendered)')
    time.sleep(1.8)

    # Click Stop capture
    click_control(target_hwnd, CMD_STOP)
    print('Clicked Stop capture')
    time.sleep(1.0)

    # 2. PROCESS MONITOR TAB DEMONSTRATION
    print('--- Step 2: Processes Tab ---')
    click_control(target_hwnd, CMD_PAGE_PROCESSES)
    print('Switched to Processes page')
    time.sleep(1.5)

    # Hover and click a process row
    move_mouse_smooth(win_rect.left + 450, win_rect.top + 260, duration=0.5)
    click_coords(win_rect.left + 450, win_rect.top + 260)
    time.sleep(1.8)

    # 3. FIREWALL TAB DEMONSTRATION
    print('--- Step 3: Firewall Rules ---')
    click_control(target_hwnd, CMD_PAGE_FIREWALL)
    print('Switched to Firewall page')
    time.sleep(1.5)

    # Hover and click a rule row
    click_coords(win_rect.left + 450, win_rect.top + 240, duration=0.5)
    time.sleep(1.8)

    # 4. SIMULATOR TAB DEMONSTRATION
    print('--- Step 4: Network Impairment Simulator ---')
    click_control(target_hwnd, CMD_PAGE_SIMULATOR)
    print('Switched to Simulator page')
    time.sleep(1.5)

    # Drag Latency slider (id 2004) to ~80 ms
    drag_slider_track(target_hwnd, 2004, frac_start=0.06, frac_end=0.35, duration=0.5)
    print('Adjusted Latency slider to ~80 ms')

    # Drag Loss slider (id 2006) to ~5%
    drag_slider_track(target_hwnd, 2006, frac_start=0.06, frac_end=0.22, duration=0.4)
    print('Adjusted Loss slider to ~5%')

    time.sleep(0.6)
    # Enable simulation via CmdSimToggle (id 1025)
    click_control(target_hwnd, CMD_SIM_TOGGLE)
    print('Enabled impairment simulation')
    time.sleep(2.0)
    click_control(target_hwnd, CMD_SIM_TOGGLE)
    print('Disabled impairment simulation')
    time.sleep(1.0)

    # 5. ABOUT DIALOG DEMONSTRATION
    print('--- Step 5: About Dialog ---')
    click_control(target_hwnd, CMD_ABOUT)
    print('Opened About dialog')

    # Ensure About dialog is TOPMOST and visible
    time.sleep(0.5)
    dialog_hwnd = [0]
    def enum_dlg(hwnd, lparam):
        cname = ctypes.create_unicode_buffer(64)
        user32.GetClassNameW(hwnd, cname, 64)
        if cname.value == 'WireScope.Dialog':
            dialog_hwnd[0] = hwnd
            return False
        return True
    user32.EnumWindows(WNDENUMPROC(enum_dlg), 0)

    if dialog_hwnd[0]:
        user32.SetWindowPos(dialog_hwnd[0], HWND_TOPMOST, 0, 0, 0, 0, 0x0001 | 0x0002 | SWP_SHOWWINDOW)

    time.sleep(3.0) # Viewer reads author, version, and GitHub repo

    # Dismiss About dialog
    if dialog_hwnd[0]:
        user32.PostMessageW(dialog_hwnd[0], WM_COMMAND, 1, 0) # IDOK
        print('Closed About dialog via IDOK')
    else:
        user32.keybd_event(0x0D, 0, 0, 0)
        time.sleep(0.05)
        user32.keybd_event(0x0D, 0, 2, 0)

    time.sleep(1.0)

    # Close WireScope GUI
    print('Closing WireScope GUI...')
    user32.PostMessageW(target_hwnd, WM_CLOSE, 0, 0)
    kernel32.WaitForSingleObject(pi_ws.hProcess, 4000)
    kernel32.CloseHandle(pi_ws.hThread)
    kernel32.CloseHandle(pi_ws.hProcess)
    time.sleep(1.0)

    t_action_end = time.time()
    total_demo_sec = t_action_end - t_action_start
    print(f'Total interactive sequence took {total_demo_sec:.1f} seconds.')

    # Stop OBS cleanly
    print('Stopping OBS Studio recording...')
    def enum_obs(hwnd, lparam):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == obs_pid:
            user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        return True

    user32.EnumWindows(WNDENUMPROC(enum_obs), 0)

    try:
        kernel32.WaitForSingleObject(pi_obs.hProcess, 8000)
    finally:
        kernel32.CloseHandle(pi_obs.hThread)
        kernel32.CloseHandle(pi_obs.hProcess)

    time.sleep(2.5)

    after_files = set(os.listdir(vid_dir))
    new_vids = [f for f in after_files - before_files if f.endswith('.mp4')]
    if not new_vids:
        all_vids = sorted(glob.glob(os.path.join(vid_dir, '*.mp4')), key=os.path.getmtime)
        if all_vids:
            raw_video = all_vids[-1]
        else:
            print('No recorded video found in', vid_dir)
            sys.exit(1)
    else:
        raw_video = os.path.join(vid_dir, new_vids[0])

    print(f'Raw OBS video recorded: {raw_video}')

    final_output = os.path.join(vid_dir, 'WireScope_demo_30s.mp4')

    cap = cv2.VideoCapture(raw_video)
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    fps = cap.get(cv2.CAP_PROP_FPS) or 60.0
    cap.release()

    raw_duration = total_frames / fps
    print(f'Raw video duration: {raw_duration:.2f}s ({total_frames} frames @ {fps} fps)')

    ffmpeg_exe = 'ffmpeg'
    ss_start = max(0.0, raw_duration - total_demo_sec - 0.5)
    t_length = min(34.0, total_demo_sec + 1.0)

    print(f'Trimming with FFmpeg: start={ss_start:.2f}s, length={t_length:.2f}s, no audio...')
    ffmpeg_cmd = [
        ffmpeg_exe, '-y',
        '-ss', f'{ss_start:.2f}',
        '-i', raw_video,
        '-t', f'{t_length:.2f}',
        '-c:v', 'copy',
        '-an',
        final_output
    ]

    ff_res = subprocess.run(ffmpeg_cmd, capture_output=True, text=True)
    if ff_res.returncode != 0:
        print('FFmpeg error, falling back to full strip without trim:', ff_res.stderr)
        subprocess.run([ffmpeg_exe, '-y', '-i', raw_video, '-c:v', 'copy', '-an', final_output], capture_output=True)

    if os.path.exists(final_output):
        fcap = cv2.VideoCapture(final_output)
        fcnt = int(fcap.get(cv2.CAP_PROP_FRAME_COUNT))
        ffps = fcap.get(cv2.CAP_PROP_FPS)
        fw = fcap.get(cv2.CAP_PROP_FRAME_WIDTH)
        fh = fcap.get(cv2.CAP_PROP_FRAME_HEIGHT)
        fdur = fcnt / ffps if ffps > 0 else 0
        fcap.release()
        print(f'SUCCESS! Final video created: {final_output}')
        print(f'Specs: {fw:.0f}x{fh:.0f}, {ffps:.1f} fps, {fdur:.2f}s ({fcnt} frames), size: {os.path.getsize(final_output):,} bytes')
    else:
        print('Failed to produce final output video!')

if __name__ == '__main__':
    main()
