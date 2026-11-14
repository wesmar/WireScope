// WireScope - Main window: creation, message loop and window procedure.
#include "gui/MainWindow.h"
#include "gui/MainWindowDetail.h"
#include "resources/resource.h"
#include "support/Language.h"
#include "support/Settings.h"
#include <CommCtrl.h>
#include <windowsx.h>
#include <algorithm>
#include <cmath>

#pragma comment(lib, "comctl32.lib")

namespace WS::Ui {
using namespace MainWindowDetail;

MainWindow::MainWindow(HINSTANCE instance)
    : m_instance(instance),
      m_bridge(std::make_shared<DriverBridge>()),
      m_ctl(std::make_unique<TrafficController>(m_bridge)) {
}

MainWindow::~MainWindow() {
    if (m_ctl) m_ctl->Shutdown();
}

bool MainWindow::Create(int showCommand) {
    Text::UseSaved();
    INITCOMMONCONTROLSEX icex{sizeof icex, ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icex);
    if (!Graphics::Get().Ready()) return false;

    WNDCLASSEXW wc{sizeof wc};
    wc.lpfnWndProc = Proc;
    wc.hInstance = m_instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));  // transparent on Mica
    wc.lpszClassName = kClassName;
    LoadIconWithScaleDown(m_instance, MAKEINTRESOURCEW(IDI_APP), GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), m_icon.put());
    LoadIconWithScaleDown(m_instance, MAKEINTRESOURCEW(IDI_APP), GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                          m_smallIcon.put());
    wc.hIcon = m_icon ? m_icon.get() : LoadIconW(nullptr, IDI_APPLICATION);
    wc.hIconSm = m_smallIcon.get();
    if (!RegisterClassExW(&wc)) return false;

    const std::wstring title = std::wstring(L"WireScope v ") + kAppVersion + L" - \u00A9 WESMAR Marek Weso\u0142owski - (2026)";
    m_hwnd = CreateWindowExW(0, kClassName, title.c_str(), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, 1280, 800,
                             nullptr, nullptr, m_instance, this);
    if (!m_hwnd) return false;
    RestorePlacement(showCommand);
    return true;
}

int MainWindow::Run() {
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (m_accel && TranslateAcceleratorW(m_hwnd, m_accel.get(), &msg)) continue;
        if (IsDialogMessageW(m_hwnd, &msg)) continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

LRESULT CALLBACK MainWindow::Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MainWindow* self = nullptr;
    if (msg == WM_NCCREATE) {
        self = static_cast<MainWindow*>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams);
        self->m_hwnd = hwnd;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<MainWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    if (msg == WM_NCDESTROY) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return self ? self->Handle(msg, wParam, lParam) : DefWindowProcW(hwnd, msg, wParam, lParam);
}

void MainWindow::BuildAccelerators() {
    ACCEL keys[] = {
        {FVIRTKEY, VK_F5, static_cast<WORD>(CmdToggleCapture)},
        {FVIRTKEY | FSHIFT, VK_F5, static_cast<WORD>(CmdStop)},
        {FVIRTKEY | FCONTROL, 'L', static_cast<WORD>(CmdClear)},
        {FVIRTKEY | FCONTROL, 'S', static_cast<WORD>(CmdSave)},
        {FVIRTKEY | FCONTROL, 'F', static_cast<WORD>(CmdFocusFilter)},
        {FVIRTKEY | FCONTROL, '1', static_cast<WORD>(CmdPageCapture)},
        {FVIRTKEY | FCONTROL, '2', static_cast<WORD>(CmdPageProcesses)},
        {FVIRTKEY | FCONTROL, '3', static_cast<WORD>(CmdPageFirewall)},
        {FVIRTKEY | FCONTROL, '4', static_cast<WORD>(CmdPageSimulator)},
        {FVIRTKEY | FCONTROL, '5', static_cast<WORD>(CmdPageDriver)},
        {FVIRTKEY | FCONTROL, 'N', static_cast<WORD>(CmdFwAdd)},
        {FVIRTKEY | FCONTROL | FSHIFT, 'K', static_cast<WORD>(CmdKill)},
    };
    m_accel.reset(CreateAcceleratorTableW(keys, static_cast<int>(std::size(keys))));
}

void MainWindow::CreateFieldResources() {
    const auto& g = Graphics::Get();
    m_fieldBrush.reset(CreateSolidBrush(g.GdiSurface(Color::Control)));
    m_cardFieldBrush.reset(CreateSolidBrush(g.GdiSurface(Color::FieldOnCard)));
    m_editFont.reset(CreateFontW(-static_cast<int>(m_fonts.F(13.0f) + 0.5f), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, m_fonts.UiFamily()));
    m_monoFont.reset(CreateFontW(-static_cast<int>(m_fonts.F(12.5f) + 0.5f), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, m_fonts.MonoFamily()));
    if (m_filterEdit) SendMessageW(m_filterEdit, WM_SETFONT, reinterpret_cast<WPARAM>(m_editFont.get()), TRUE);
    if (m_matchEdit) SendMessageW(m_matchEdit, WM_SETFONT, reinterpret_cast<WPARAM>(m_monoFont.get()), TRUE);
}

void MainWindow::OnCreate() {
    ApplyBackdrop(m_hwnd);
    m_fonts.Create(GetDpiForWindow(m_hwnd));
    BuildAccelerators();

    // Creation order is the Tab order.
    for (const ButtonSpec& b : kButtons) {
        CreateButton(m_hwnd, static_cast<int>(b.id), b.text ? Text::Get(b.text).c_str() : L"");
        m_looks[b.id] = b.look;
        if (b.id == CmdSave) {
            m_filterEdit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 10, 10, m_hwnd,
                                           reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdFilter)), m_instance, nullptr);
            SendMessageW(m_filterEdit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(Text::Get(IDS_FILTER_CUE).c_str()));
            m_list.Create(m_hwnd, kIdPackets);
            m_details.Create(m_hwnd, kIdDetails);
        } else if (b.id == CmdProcReset) {
            m_procList.Create(m_hwnd, kIdProcesses);
        } else if (b.id == CmdFwExport) {
            m_rules.Create(m_hwnd, kIdRules);
        } else if (b.id == CmdSimReset) {
            m_latency.Create(m_hwnd, kIdLatency, 0, 2000, 1, 2.0);
            m_jitter.Create(m_hwnd, kIdJitter, 0, 500, 1, 2.0);
            m_loss.Create(m_hwnd, kIdLoss, 0, 100, 0.1, 2.5);
            m_rate.Create(m_hwnd, kIdRate, 0, 1'000'000, 1, 3.0);  // kbit/s, 0 = unlimited
        } else if (b.id == CmdDirOut) {
            m_matchEdit = CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 10, 10, m_hwnd,
                                          reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdMatch)), m_instance, nullptr);
            SendMessageW(m_matchEdit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(Text::Get(IDS_MATCH_CUE).c_str()));
            SendMessageW(m_matchEdit, EM_SETLIMITTEXT, 512, 0);
        }
    }
    SendMessageW(m_filterEdit, EM_SETLIMITTEXT, 256, 0);
    CreateFieldResources();
    m_list.SetPlaceholder(Text::Get(IDS_LIST_EMPTY));
    m_procList.SetPlaceholder(Text::Get(IDS_PROC_EMPTY));

    LoadSettings();
    SyncSimulatorControls();
    ConnectDriver();
    RestoreMonitor();
    RefreshRuleRows();
    if (!m_driverOk) m_page = Page::Driver;
    ShowPage(m_page);
    UpdateControls();
    SetTimer(m_hwnd, kUiTimer, kUiTimerMs, nullptr);
}

LRESULT MainWindow::Handle(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        OnCreate();
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        Paint();
        return 0;
    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED) Layout();
        return 0;
    case WM_GETMINMAXINFO: {
        auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
        RECT r{0, 0, MinClientWidth(), MinClientHeight()};
        AdjustWindowRectExForDpi(&r, WS_OVERLAPPEDWINDOW, FALSE, 0, m_fonts.dpi());
        info->ptMinTrackSize = {r.right - r.left, r.bottom - r.top};
        return 0;
    }
    case WM_DPICHANGED: {
        m_fonts.Create(HIWORD(wParam));
        CreateFieldResources();
        m_list.Relayout();
        m_details.Relayout();
        m_rules.Relayout();
        m_procList.Relayout();
        const RECT* r = reinterpret_cast<const RECT*>(lParam);
        SetWindowPos(m_hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
        Layout();
        RedrawWindow(m_hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
        return 0;
    }
    case WM_SETTINGCHANGE:
    case WM_THEMECHANGED:
    case WM_DWMCOMPOSITIONCHANGED:
        ApplyBackdrop(m_hwnd);
        CreateFieldResources();
        RedrawWindow(m_hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
        return 0;
    case WM_MEASUREITEM: {
        auto& mis = *reinterpret_cast<MEASUREITEMSTRUCT*>(lParam);
        if (mis.CtlType == ODT_MENU) PopupMenu::Measure(mis);
        return TRUE;
    }
    case WM_DRAWITEM: {
        const auto& dis = *reinterpret_cast<const DRAWITEMSTRUCT*>(lParam);
        if (dis.CtlType == ODT_MENU) PopupMenu::Draw(dis);
        else if (auto it = m_looks.find(dis.CtlID); it != m_looks.end()) DrawButton(dis, m_fonts, it->second);
        return TRUE;
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        const bool onCard = reinterpret_cast<HWND>(lParam) == m_matchEdit;
        SetTextColor(dc, ToColorRef(Color::Text));
        SetBkColor(dc, Graphics::Get().GdiSurface(onCard ? Color::FieldOnCard : Color::Control));
        return reinterpret_cast<LRESULT>(onCard ? m_cardFieldBrush.get() : m_fieldBrush.get());
    }
    case WM_COMMAND:
        OnCommand(LOWORD(wParam), HIWORD(wParam), reinterpret_cast<HWND>(lParam));
        return 0;
    case WM_CONTEXTMENU: {
        HWND target = reinterpret_cast<HWND>(wParam);
        POINT p{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        if (p.x == -1 && p.y == -1) {  // keyboard: near the focused control
            RECT r{};
            GetWindowRect(target, &r);
            p = {r.left + m_fonts.S(40), r.top + m_fonts.S(40)};
        }
        ShowContextMenu(target, p);
        return 0;
    }
    case WM_TIMER:
        if (wParam == kUiTimer) OnTimer();
        return 0;
    case kDriverJobDone:
        OnDriverJobDone(lParam);
        return 0;
    case WM_SETCURSOR: {
        POINT p{};
        GetCursorPos(&p);
        ScreenToClient(m_hwnd, &p);
        const float x = static_cast<float>(p.x), y = static_cast<float>(p.y);
        if (m_page == Page::Capture && LOWORD(lParam) == HTCLIENT && x >= m_splitter.left && x < m_splitter.right && y >= m_splitter.top &&
            y < m_splitter.bottom) {
            SetCursor(LoadCursorW(nullptr, IDC_SIZENS));
            return TRUE;
        }
        break;
    }
    case WM_LBUTTONDOWN: {
        const float x = static_cast<float>(GET_X_LPARAM(lParam)), y = static_cast<float>(GET_Y_LPARAM(lParam));
        if (m_page == Page::Capture && x >= m_splitter.left && x < m_splitter.right && y >= m_splitter.top && y < m_splitter.bottom) {
            m_dragSplit = true;
            SetCapture(m_hwnd);
        }
        return 0;
    }
    case WM_MOUSEMOVE:
        if (m_dragSplit) {
            const float y = static_cast<float>(GET_Y_LPARAM(lParam));
            const float top = m_listCard.top, bottom = m_detailsCard.bottom;
            if (bottom - top > 1) m_split = std::clamp((y - top) / (bottom - top), 0.25f, 0.85f);
            Layout();
        }
        return 0;
    case WM_LBUTTONUP:
        if (m_dragSplit) {
            m_dragSplit = false;
            ReleaseCapture();
            Settings::WriteDword(L"Split", static_cast<DWORD>(std::lround(m_split * 1000)));
        }
        return 0;
    case WM_CAPTURECHANGED:
        m_dragSplit = false;
        return 0;
    case WM_CLOSE:
        if (m_drvDoing) {  // a driver change must not be cut in half
            SetStatus(Level::Warning, Text::Get(IDS_DRV_BUSY));
            return 0;
        }
        m_closing = true;
        SavePlacement();
        DestroyWindow(m_hwnd);
        return 0;
    case WM_DESTROY:
        KillTimer(m_hwnd, kUiTimer);
        if (m_ctl) m_ctl->Shutdown();  // restore the adapter mode and the driver table before exiting
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(m_hwnd, msg, wParam, lParam);
}

}  // namespace WS::Ui
