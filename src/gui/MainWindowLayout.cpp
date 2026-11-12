// WireScope - Main window: layout, window placement and painting.
#include "gui/MainWindow.h"
#include "gui/MainWindowDetail.h"
#include "support/Language.h"
#include "support/Settings.h"
#include "support/Text.h"
#include <algorithm>
#include <cmath>
#include <format>

namespace WS::Ui {
using namespace MainWindowDetail;

namespace {

void Place(HWND hwnd, const D2D1_RECT_F& r) {
    SetWindowPos(hwnd, nullptr, static_cast<int>(std::lround(r.left)), static_cast<int>(std::lround(r.top)),
                 static_cast<int>(std::lround(r.right - r.left)), static_cast<int>(std::lround(r.bottom - r.top)),
                 SWP_NOZORDER | SWP_NOACTIVATE);
}

}  // namespace

int MainWindow::MinClientWidth() const { return m_fonts.S(900); }
int MainWindow::MinClientHeight() const { return m_fonts.S(600); }

void MainWindow::Layout() {
    if (!m_list.hwnd()) return;
    RECT rc{};
    GetClientRect(m_hwnd, &rc);
    const auto& f = m_fonts;
    const float W = static_cast<float>(rc.right), H = static_cast<float>(rc.bottom);
    const float m = f.F(kMargin), gap = f.F(kGap), pad = f.F(kPad), cmdH = f.F(kCmdH);
    auto item = [&](UINT id) { return GetDlgItem(m_hwnd, static_cast<int>(id)); };

    // Frame: header, navigation rail, content, status strip.
    m_header = {0, 0, W, f.F(kHeaderH)};
    m_status = {0, H - f.F(kStatusH), W, H};
    m_nav = {f.F(8), m_header.bottom, f.F(8) + f.F(kNavW), m_status.top - f.F(8)};
    m_content = {m_nav.right + f.F(12), m_header.bottom, W - m, m_status.top - f.F(8)};
    const float comboW = std::clamp(W * 0.32f, f.F(240), f.F(400));
    Place(item(CmdAdapter), {W - m - comboW, (m_header.bottom - cmdH) / 2, W - m, (m_header.bottom + cmdH) / 2});

    float y = m_nav.top + f.F(4);
    for (UINT id : {CmdPageCapture, CmdPageProcesses, CmdPageFirewall, CmdPageSimulator, CmdPageDriver}) {
        Place(item(id), {m_nav.left, y, m_nav.right, y + f.F(kNavItemH)});
        y += f.F(kNavItemH) + f.F(2);
    }
    float by = m_nav.bottom - f.F(kNavItemH);
    Place(item(CmdAbout), {m_nav.left, by, m_nav.right, by + f.F(kNavItemH)});
    by -= f.F(kNavItemH) + f.F(2);
    Place(item(CmdLanguage), {m_nav.left, by, m_nav.right, by + f.F(kNavItemH)});
    by -= f.F(16) + f.F(44);
    Place(item(CmdKill), {m_nav.left + f.F(4), by, m_nav.right - f.F(4), by + f.F(44)});

    float top = m_content.top;
    const bool pending = m_revertAt != 0;
    if (m_ctl->KillSwitch() || pending) {
        m_banner = {m_content.left, top, m_content.right, top + f.F(44)};
        top = m_banner.bottom + gap;
    } else {
        m_banner = {};
    }
    // Keep / Undo sit on the banner while a change waits for confirmation.
    const float bh = f.F(30), bmid = (m_banner.top + m_banner.bottom) / 2;
    Place(item(CmdUndoChanges), {m_banner.right - f.F(12) - f.F(140), bmid - bh / 2, m_banner.right - f.F(12), bmid + bh / 2});
    Place(item(CmdKeepChanges), {m_banner.right - f.F(20) - f.F(260), bmid - bh / 2, m_banner.right - f.F(20) - f.F(140), bmid + bh / 2});
    for (UINT id : {CmdKeepChanges, CmdUndoChanges}) ShowWindow(item(id), pending ? SW_SHOWNA : SW_HIDE);
    const float L = m_content.left, R = m_content.right, B = m_content.bottom;
    const float cmdBottom = top + cmdH;
    const int lineH = f.S(19);
    auto row = [&](float x, std::initializer_list<std::pair<UINT, int>> buttons) {  // widths in DIP
        for (const auto& [id, width] : buttons) {
            const float w = f.F(static_cast<float>(width));
            Place(item(id), {x, top, x + w, cmdBottom});
            x += w + f.F(8);
        }
        return x;
    };
    auto placeEdit = [&](HWND edit, const D2D1_RECT_F& box) {
        const float mid = (box.top + box.bottom) / 2;
        Place(edit, {box.left + f.F(10), mid - static_cast<float>(lineH) / 2, box.right - f.F(10), mid + static_cast<float>(lineH) / 2});
    };

    // Capture: commands, filter, packet list, splitter, details.
    {
        const float x = row(L, {{CmdStart, 130}, {CmdStop, 110}, {CmdClear, 110}, {CmdSave, 130}});
        Place(item(CmdElevate), {L, top, L + f.F(250), cmdBottom});
        const float fx = std::max(x + f.F(22), R - f.F(400));
        m_filterBox = {fx, top, R, cmdBottom};
        placeEdit(m_filterEdit, m_filterBox);
        const float listTop = cmdBottom + gap;
        const float avail = std::max(f.F(160), B - listTop - gap);
        const float listH = std::round(avail * m_split);
        m_listCard = {L, listTop, R, listTop + listH};
        m_splitter = {L, m_listCard.bottom, R, m_listCard.bottom + gap};
        m_detailsCard = {L, m_splitter.bottom, R, B};
        Place(m_list.hwnd(), Inset(m_listCard, f.F(2), f.F(2)));
        Place(m_details.hwnd(), Inset(m_detailsCard, f.F(2), f.F(2)));
    }

    // Processes: counting switch and reset, the program list, details with the actions at the bottom.
    {
        const float x = row(L, {{CmdProcMonitor, 250}, {CmdProcReset, 160}});
        m_procSummary = {x + f.F(16), top, R, cmdBottom};
        const float below = B - cmdBottom - gap;
        const float detailsH = std::clamp(std::round(below * 0.4f), f.F(236), f.F(300));
        m_procCard = {L, cmdBottom + gap, R, B - detailsH - gap};
        m_procDetailsCard = {L, m_procCard.bottom + gap, R, B};
        Place(m_procList.hwnd(), {m_procCard.left + f.F(2), m_procCard.top + f.F(kCardHeaderH), m_procCard.right - f.F(2),
                                  m_procCard.bottom - f.F(2)});
        const float ay = m_procDetailsCard.bottom - pad - cmdH;
        float ax = m_procDetailsCard.left + pad;
        for (const auto& [id, width] : {std::pair{CmdProcBlock, 130.0f}, std::pair{CmdProcLimit, 170.0f}, std::pair{CmdProcImpair, 130.0f},
                                        std::pair{CmdProcPackets, 160.0f}, std::pair{CmdProcFolder, 150.0f}}) {
            Place(item(id), {ax, ay, ax + f.F(width), ay + cmdH});
            ax += f.F(width) + f.F(8);
        }
        m_procDetailsBody = {m_procDetailsCard.left + pad, m_procDetailsCard.top + f.F(14), m_procDetailsCard.right - pad, ay - f.F(12)};
    }

    // Network driver: actions on top, the report, start type, refresh and copy below.
    {
        row(L, {{CmdDrvInstall, 140}, {CmdDrvUninstall, 150}, {CmdDrvStart, 130}, {CmdDrvStop, 140}});
        const float bottomTop = B - cmdH;
        m_drvCard = {L, cmdBottom + gap, R, bottomTop - gap};
        float bx = L;
        for (const auto& [id, width] : {std::pair{CmdDrvStartType, 260.0f}, std::pair{CmdDrvRefresh, 130.0f}, std::pair{CmdDrvCopy, 160.0f}}) {
            Place(item(id), {bx, bottomTop, bx + f.F(width), B});
            bx += f.F(width) + f.F(8);
        }
    }

    // Firewall: switch and policy, rule card, rule commands and the offload switch.
    {
        row(L, {{CmdFwToggle, 140}, {CmdFwPolicy, 220}});
        float x = R;
        for (const auto& [id, width] : {std::pair{CmdFwExport, 120.0f}, std::pair{CmdFwImport, 120.0f}, std::pair{CmdFwAdd, 140.0f}}) {
            Place(item(id), {x - f.F(width), top, x, cmdBottom});
            x -= f.F(width) + f.F(8);
        }
        const float bottomTop = B - cmdH;
        m_rulesCard = {L, cmdBottom + gap, R, bottomTop - gap};
        Place(m_rules.hwnd(), {m_rulesCard.left + f.F(2), m_rulesCard.top + f.F(kCardHeaderH), m_rulesCard.right - f.F(2),
                               m_rulesCard.bottom - f.F(2)});
        float bx = L;
        for (const auto& [id, width] : {std::pair{CmdFwEdit, 110.0f}, std::pair{CmdFwRemove, 110.0f}, std::pair{CmdFwUp, 120.0f},
                                        std::pair{CmdFwDown, 130.0f}}) {
            Place(item(id), {bx, bottomTop, bx + f.F(width), B});
            bx += f.F(width) + f.F(8);
        }
        Place(item(CmdFwOffload), {std::max(bx + f.F(16), R - f.F(420)), bottomTop, R, B});
    }

    // Simulator: conditions card (sliders, direction, traffic match, order) and live card.
    {
        row(L, {{CmdSimToggle, 140}, {CmdSimPreset, 230}, {CmdSimReset, 110}});
        const float cardsTop = cmdBottom + gap;
        const bool wide = R - L >= f.F(880);
        const float rowH = f.F(kRowH);
        const float condH = f.F(kCardHeaderH) + rowH * 6 + f.F(22) + f.F(44) + pad;
        const float condW = wide ? std::round((R - L) * 0.54f) : R - L;
        m_condCard = {L, cardsTop, L + condW, wide ? std::max(B, cardsTop + condH) : cardsTop + condH};
        m_liveCard = wide ? D2D1_RECT_F{m_condCard.right + gap, cardsTop, R, B} : D2D1_RECT_F{L, m_condCard.bottom + gap, R, B};

        const float x0 = m_condCard.left + pad, x1 = m_condCard.right - pad;
        const float labelW = f.F(124), valueW = f.F(84);
        float ry = m_condCard.top + f.F(kCardHeaderH);
        Slider* sliders[] = {&m_latency, &m_jitter, &m_loss, &m_rate};
        for (size_t i = 0; i < std::size(sliders); ++i) {
            m_sliderRows[i] = {x0, ry, x1, ry + rowH};
            Place(sliders[i]->hwnd(), {x0 + labelW, ry + f.F(7), x1 - valueW, ry + rowH - f.F(7)});
            ry += rowH;
        }
        m_dirRow = {x0, ry, x1, ry + rowH};
        float sx = x0 + labelW;
        for (UINT id : {CmdDirBoth, CmdDirIn, CmdDirOut}) {
            const float w = std::min(f.F(128), (x1 - x0 - labelW - f.F(16)) / 3);
            Place(item(id), {sx, ry + f.F(7), sx + w, ry + rowH - f.F(7)});
            sx += w + f.F(8);
        }
        ry += rowH;
        m_matchRow = {x0, ry, x1, ry + rowH};
        m_matchBox = {x0 + labelW, ry + f.F(6), x1, ry + rowH - f.F(6)};
        placeEdit(m_matchEdit, m_matchBox);
        ry += rowH;
        m_matchHint = {x0 + labelW, ry - f.F(4), x1, ry + f.F(16)};
        ry += f.F(22);
        Place(item(CmdSimOrder), {x0, ry, x1, ry + f.F(36)});

        const D2D1_RECT_F& live = m_liveCard;
        const float tilesTop = live.top + f.F(kCardHeaderH);
        m_tiles = {live.left + pad, tilesTop, live.right - pad, tilesTop + f.F(64) * 2 + f.F(8)};
        const float chartsTop = m_tiles.bottom + f.F(16);
        const float chartH = std::max(f.F(50), (live.bottom - pad - chartsTop - f.F(16)) / 3);
        m_delayChart = {live.left + pad, chartsTop, live.right - pad, chartsTop + chartH};
        m_dropChart = {live.left + pad, m_delayChart.bottom + f.F(8), live.right - pad, m_delayChart.bottom + f.F(8) + chartH};
        m_throughputChart = {live.left + pad, m_dropChart.bottom + f.F(8), live.right - pad, m_dropChart.bottom + f.F(8) + chartH};
    }
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void MainWindow::ShowPage(Page page) {
    m_page = page;
    Settings::WriteDword(L"Page", static_cast<DWORD>(page));
    const bool capture = page == Page::Capture, firewall = page == Page::Firewall, simulator = page == Page::Simulator,
               processes = page == Page::Processes, driver = page == Page::Driver;
    const bool elevate = capture && !m_driverOk && !IsElevated();
    auto show = [&](HWND h, bool visible) {
        if (!h) return;
        if (!visible && GetFocus() == h) SetFocus(nullptr);
        ShowWindow(h, visible ? SW_SHOWNA : SW_HIDE);
    };
    auto item = [&](UINT id) { return GetDlgItem(m_hwnd, static_cast<int>(id)); };
    for (UINT id : {CmdStart, CmdStop}) show(item(id), capture && !elevate);
    show(item(CmdElevate), elevate);
    for (UINT id : {CmdClear, CmdSave}) show(item(id), capture);
    for (HWND h : {m_filterEdit, m_list.hwnd(), m_details.hwnd()}) show(h, capture);
    for (UINT id : {CmdProcMonitor, CmdProcReset, CmdProcBlock, CmdProcLimit, CmdProcImpair, CmdProcPackets, CmdProcFolder}) {
        show(item(id), processes);
    }
    show(m_procList.hwnd(), processes);
    for (UINT id : {CmdDrvInstall, CmdDrvUninstall, CmdDrvStart, CmdDrvStop, CmdDrvStartType, CmdDrvRefresh, CmdDrvCopy}) show(item(id), driver);
    for (UINT id : {CmdFwToggle, CmdFwPolicy, CmdFwAdd, CmdFwImport, CmdFwExport, CmdFwEdit, CmdFwRemove, CmdFwUp, CmdFwDown, CmdFwOffload}) {
        show(item(id), firewall);
    }
    show(m_rules.hwnd(), firewall);
    for (UINT id : {CmdSimToggle, CmdSimPreset, CmdSimReset, CmdDirBoth, CmdDirIn, CmdDirOut, CmdSimOrder}) show(item(id), simulator);
    for (HWND h : {m_latency.hwnd(), m_jitter.hwnd(), m_loss.hwnd(), m_rate.hwnd(), m_matchEdit}) show(h, simulator);

    m_looks[CmdPageCapture].checked = capture;
    m_looks[CmdPageProcesses].checked = processes;
    m_looks[CmdPageFirewall].checked = firewall;
    m_looks[CmdPageSimulator].checked = simulator;
    m_looks[CmdPageDriver].checked = driver;
    for (UINT id : {CmdPageCapture, CmdPageProcesses, CmdPageFirewall, CmdPageSimulator, CmdPageDriver}) InvalidateRect(item(id), nullptr, FALSE);
    Layout();
    if (processes) RefreshProcesses();  // at once, not on the next timer tick
    if (driver && !m_drvDoing) RefreshDriver();
}

void MainWindow::RestorePlacement(int showCommand) {
    const UINT dpi = GetDpiForWindow(m_hwnd);
    RECT desired{0, 0, MulDiv(1280, static_cast<int>(dpi), 96), MulDiv(800, static_cast<int>(dpi), 96)};
    AdjustWindowRectExForDpi(&desired, WS_OVERLAPPEDWINDOW, FALSE, 0, dpi);
    int w = desired.right - desired.left, h = desired.bottom - desired.top;
    MONITORINFO mi{sizeof mi};
    GetMonitorInfoW(MonitorFromWindow(m_hwnd, MONITOR_DEFAULTTOPRIMARY), &mi);
    w = std::min<int>(w, mi.rcWork.right - mi.rcWork.left);
    h = std::min<int>(h, mi.rcWork.bottom - mi.rcWork.top);
    int x = mi.rcWork.left + (mi.rcWork.right - mi.rcWork.left - w) / 2;
    int y = mi.rcWork.top + (mi.rcWork.bottom - mi.rcWork.top - h) / 2;

    // Saved position (physical pixels) when it is still on a monitor.
    int sx = 0, sy = 0, sw = 0, sh = 0;
    const std::wstring saved = Settings::Read(L"WindowRect");
    if (swscanf_s(saved.c_str(), L"%d %d %d %d", &sx, &sy, &sw, &sh) == 4 && sw > 400 && sh > 300) {
        const RECT r{sx, sy, sx + sw, sy + sh};
        if (MonitorFromRect(&r, MONITOR_DEFAULTTONULL)) {
            x = sx;
            y = sy;
            w = sw;
            h = sh;
        }
    }
    SetWindowPos(m_hwnd, nullptr, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
    const bool maximized = Settings::ReadDword(L"WindowMaximized", 0) != 0;
    ShowWindow(m_hwnd, showCommand == SW_SHOWMINIMIZED || showCommand == SW_MINIMIZE ? SW_SHOWNORMAL
                       : maximized && showCommand == SW_SHOWNORMAL                ? SW_SHOWMAXIMIZED
                                                                                  : showCommand);
    UpdateWindow(m_hwnd);
}

void MainWindow::SavePlacement() {
    WINDOWPLACEMENT wp{sizeof wp};
    if (!GetWindowPlacement(m_hwnd, &wp)) return;
    const RECT& r = wp.rcNormalPosition;
    Settings::Write(L"WindowRect", std::format(L"{} {} {} {}", r.left, r.top, r.right - r.left, r.bottom - r.top));
    Settings::WriteDword(L"WindowMaximized", wp.showCmd == SW_SHOWMAXIMIZED ? 1 : 0);
}

void MainWindow::InvalidateArea(const D2D1_RECT_F& r) {
    const RECT area = ToRect(Inset(r, -2, -2));
    InvalidateRect(m_hwnd, &area, FALSE);
}

// ---------------------------------------------------------------------------
// Painting
// ---------------------------------------------------------------------------
void MainWindow::Paint() {
    PaintScope ps(m_hwnd);
    RECT client{};
    GetClientRect(m_hwnd, &client);
    Ui::Paint(
        ps.dc(), client, m_fonts,
        [&](Canvas& c) {
            c.Clear(Graphics::Get().Base());
            PaintHeader(c);
            if (m_revertAt) {
                const auto& f = m_fonts;
                const uint64_t now = GetTickCount64();
                const uint64_t left = m_revertAt > now ? (m_revertAt - now + 999) / 1000 : 0;
                c.Fill(m_banner, WithAlpha(Color::Caution, 0.14f), f.F(6));
                c.Stroke(m_banner, WithAlpha(Color::Caution, 0.55f), f.F(6));
                c.Text(std::wstring(1, Icon::Warning), {m_banner.left + f.F(14), m_banner.top, m_banner.left + f.F(34), m_banner.bottom},
                       Font::Icon, Color::Caution, Align::Center);
                c.Text(Text::Format(IDS_REVERT_BANNER, left), {m_banner.left + f.F(44), m_banner.top, m_banner.right - f.F(290), m_banner.bottom},
                       Font::Strong, Color::Text);
            } else if (m_banner.bottom > m_banner.top) {
                const auto& f = m_fonts;
                c.Fill(m_banner, WithAlpha(Color::Danger, 0.85f), f.F(6));
                c.Text(std::wstring(1, Icon::Warning), {m_banner.left + f.F(14), m_banner.top, m_banner.left + f.F(34), m_banner.bottom},
                       Font::Icon, Color::Text, Align::Center);
                const std::wstring adapter = m_adapters.empty() ? std::wstring() : ToWide(m_adapters[m_adapterIndex].FriendlyName);
                c.Text(Text::Format(IDS_BANNER_KILL, adapter), {m_banner.left + f.F(44), m_banner.top, m_banner.right - f.F(14), m_banner.bottom},
                       Font::Strong, Color::Text);
            }
            switch (m_page) {
            case Page::Capture: PaintCapture(c); break;
            case Page::Firewall: PaintFirewall(c); break;
            case Page::Simulator: PaintSimulator(c); break;
            case Page::Processes: PaintProcesses(c); break;
            case Page::Driver: PaintDriver(c); break;
            }
            PaintStatus(c);
        },
        [&](HDC dc) { FillFieldsGdi(dc); });
}

void MainWindow::PaintHeader(Canvas& c) {
    const auto& f = m_fonts;
    const float mid = m_header.bottom / 2;
    const D2D1_RECT_F logo{f.F(20), mid - f.F(15), f.F(50), mid + f.F(15)};
    c.Fill(logo, Color::Accent, f.F(7));
    c.Text(std::wstring(1, Icon::Network), logo, Font::Icon, Color::Text, Align::Center);
    c.Text(L"WireScope", {logo.right + f.F(12), mid - f.F(19), logo.right + f.F(160), mid + f.F(5)}, Font::Title, Color::Text);
    c.Text(Text::Get(IDS_APP_TAGLINE), {logo.right + f.F(13), mid + f.F(3), m_header.right * 0.6f, mid + f.F(19)}, Font::Caption, Color::Text3);
}

void MainWindow::PaintCard(Canvas& c, const D2D1_RECT_F& card, const std::wstring& title, const std::wstring& note) {
    const auto& f = m_fonts;
    c.Fill(card, Color::Card, f.F(8));
    c.Stroke(card, Color::CardStroke, f.F(8));
    if (title.empty()) return;
    const D2D1_RECT_F head{card.left + f.F(kPad), card.top, card.right - f.F(kPad), card.top + f.F(kCardHeaderH)};
    const float tw = c.Width(title, Font::Strong) + 1;
    c.Text(title, {head.left, head.top, head.left + tw, head.bottom}, Font::Strong, Color::Text);
    if (!note.empty()) c.Text(note, {head.left + tw + f.F(16), head.top, head.right, head.bottom}, Font::Caption, Color::Text3, Align::Right);
}

void MainWindow::PaintField(Canvas& c, const D2D1_RECT_F& box, HWND edit, bool onCard, bool error) {
    const auto& f = m_fonts;
    c.Fill(box, onCard ? Color::FieldOnCard : Color::Control, f.F(4));
    c.Stroke(box, Color::ControlStroke, f.F(4));
    const bool focused = GetFocus() == edit;
    const D2D1_COLOR_F line = error ? Color::Critical : focused ? Color::AccentText : White(0.30f);
    c.Fill({box.left + f.F(1), box.bottom - f.F(focused || error ? 2.0f : 1.0f), box.right - f.F(1), box.bottom}, line);
}

void MainWindow::FillFieldsGdi(HDC dc) {
    // The EDIT controls paint with GDI; their surroundings in the field box are filled the same way,
    // so field and control read as one surface.
    const auto& f = m_fonts;
    auto fill = [&](const D2D1_RECT_F& box, HBRUSH brush) {
        const RECT r{static_cast<LONG>(box.left + f.F(3)), static_cast<LONG>(box.top + f.F(3)), static_cast<LONG>(box.right - f.F(3)),
                     static_cast<LONG>(box.bottom - f.F(3))};
        FillRect(dc, &r, brush);
    };
    if (m_page == Page::Capture) fill(m_filterBox, m_fieldBrush.get());
    if (m_page == Page::Simulator) fill(m_matchBox, m_cardFieldBrush.get());
}

void MainWindow::PaintCapture(Canvas& c) {
    const auto& f = m_fonts;
    c.Text(std::wstring(1, Icon::Search), {m_filterBox.left - f.F(22), m_filterBox.top, m_filterBox.left - f.F(8), m_filterBox.bottom},
           Font::Icon, m_filter.empty() ? Color::Text3 : Color::AccentText, Align::Center);
    PaintField(c, m_filterBox, m_filterEdit, false);
    PaintCard(c, m_listCard, {});
    PaintCard(c, m_detailsCard, {});
    // Splitter grip
    const float mid = (m_splitter.top + m_splitter.bottom) / 2, cx = (m_splitter.left + m_splitter.right) / 2;
    c.Fill({cx - f.F(18), mid - f.F(1.5f), cx + f.F(18), mid + f.F(1.5f)}, m_dragSplit ? Color::AccentText : White(0.18f), f.F(1.5f));
}

void MainWindow::PaintFirewall(Canvas& c) {
    const std::wstring note = Text::Get(m_offload ? IDS_CARD_RULES_KERNEL : IDS_CARD_RULES_ENGINE);
    PaintCard(c, m_rulesCard, std::format(L"{}  ·  {}", Text::Get(IDS_CARD_RULES), m_ruleSet.size()), note);
}

void MainWindow::PaintChart(Canvas& c, const D2D1_RECT_F& r, const std::wstring& title, const std::deque<double>& values,
                            const std::wstring& unit, bool bars, D2D1_COLOR_F color) {
    const auto& f = m_fonts;
    const double current = values.empty() ? 0.0 : values.back();
    double peak = 0;
    for (double v : values) peak = std::max(peak, v);
    c.Text(title, {r.left, r.top, r.right - f.F(90), r.top + f.F(18)}, Font::Caption, Color::Text3);
    c.Text(std::format(L"{:.1f} {}", current, unit), {r.right - f.F(120), r.top, r.right, r.top + f.F(18)}, Font::Strong, Color::Text, Align::Right);
    const D2D1_RECT_F plot{r.left, r.top + f.F(24), r.right, r.bottom};
    if (plot.bottom - plot.top < f.F(20)) return;
    // Scale: a round maximum above the peak, recessive grid at the maximum and the middle.
    double scale = 1;
    for (double step : {1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0, 10000.0, 20000.0}) {
        scale = step;
        if (peak <= step * 0.9) break;
    }
    const float h = plot.bottom - plot.top;
    c.Line({plot.left, plot.top + 0.5f}, {plot.right, plot.top + 0.5f}, Color::Grid);
    c.Line({plot.left, plot.top + h / 2}, {plot.right, plot.top + h / 2}, Color::Grid);
    c.Line({plot.left, plot.bottom - 0.5f}, {plot.right, plot.bottom - 0.5f}, Color::CardStroke);
    c.Text(std::format(L"{:g} {}", scale, unit), {plot.left + f.F(4), plot.top + f.F(1), plot.left + f.F(120), plot.top + f.F(15)}, Font::Caption,
           Color::Text3);
    constexpr size_t kSamples = 120;
    const float step = (plot.right - plot.left) / static_cast<float>(kSamples - 1);
    const size_t first = kSamples - std::min(values.size(), kSamples);
    auto yOf = [&](double v) { return plot.bottom - static_cast<float>(std::min(v / scale, 1.0)) * (h - f.F(2)); };
    if (bars) {
        const float bw = std::max(1.0f, step - f.F(1));
        for (size_t i = 0; i < values.size() && i < kSamples; ++i) {
            if (values[i] <= 0) continue;
            const float x = plot.left + static_cast<float>(first + i) * step;
            c.Fill({x - bw / 2, yOf(values[i]), x + bw / 2, plot.bottom - f.F(1)}, color, std::min(bw / 2, f.F(1.5f)));
        }
    } else if (values.size() >= 2) {
        std::vector<D2D1_POINT_2F> points;
        points.reserve(values.size());
        for (size_t i = 0; i < values.size() && i < kSamples; ++i) {
            points.push_back({plot.left + static_cast<float>(first + i) * step, yOf(values[i])});
        }
        c.Area(points.data(), points.size(), plot.bottom - f.F(1), WithAlpha(color, 0.14f));
        c.Polyline(points.data(), points.size(), color, f.F(2));
        c.Circle(points.back(), f.F(3.5f), color);
    }
}

void MainWindow::PaintSimulator(Canvas& c) {
    const auto& f = m_fonts;
    PaintCard(c, m_condCard, Text::Get(IDS_CARD_CONDITIONS));
    const UINT labels[] = {IDS_SIM_LATENCY, IDS_SIM_JITTER, IDS_SIM_LOSS, IDS_SIM_RATE};
    const std::wstring values[] = {Text::Format(IDS_VALUE_MS, m_profile.latencyMs), Text::Format(IDS_VALUE_JITTER, m_profile.jitterMs),
                                   Text::Format(IDS_VALUE_PERCENT, m_profile.lossPercent), RateText(m_profile.rateKbps)};
    const float labelW = f.F(124);
    for (size_t i = 0; i < std::size(labels); ++i) {
        const D2D1_RECT_F& r = m_sliderRows[i];
        c.Text(Text::Get(labels[i]), {r.left, r.top, r.left + labelW, r.bottom}, Font::Body, Color::Text2);
        c.Text(values[i], {r.right - f.F(80), r.top, r.right, r.bottom}, Font::Strong, Color::Text, Align::Right);
    }
    c.Text(Text::Get(IDS_SIM_DIRECTION), {m_dirRow.left, m_dirRow.top, m_dirRow.left + labelW, m_dirRow.bottom}, Font::Body, Color::Text2);
    c.Text(Text::Get(IDS_SIM_MATCH), {m_matchRow.left, m_matchRow.top, m_matchRow.left + labelW, m_matchRow.bottom}, Font::Body, Color::Text2);
    PaintField(c, m_matchBox, m_matchEdit, true, !m_matchError.empty());
    if (!m_matchError.empty()) c.Text(m_matchError, m_matchHint, Font::Caption, Color::Critical);
    else c.Text(Text::Get(IDS_SIM_MATCH_HINT), m_matchHint, Font::Caption, Color::Text3);

    // Live card: tiles and two small charts (one measure each, never a second axis).
    const bool on = m_profile.enabled && m_ctl->Impairment().enabled;
    std::wstring note = on ? std::wstring() : Text::Get(IDS_SIM_OFF_NOTE);
    if (on && !m_stats.HighResolutionTimer) note = Text::Get(IDS_SIM_TIMER_LOW);
    PaintCard(c, m_liveCard, Text::Get(IDS_CARD_LIVE), note);
    const uint64_t dropped = m_stats.SimDropped + m_stats.SimOverflow;
    const double lossRate = m_stats.SimSelected ? 100.0 * static_cast<double>(dropped) / static_cast<double>(m_stats.SimSelected) : 0.0;
    const double avgMs = m_stats.SimDelayed ? static_cast<double>(m_stats.SimDelaySumUs) / static_cast<double>(m_stats.SimDelayed) / 1000.0 : 0.0;
    struct Tile {
        UINT label;
        std::wstring value;
        bool critical;
    };
    const Tile tiles[] = {
        {IDS_TILE_MATCHED, FormatCount(m_stats.SimSelected), false},
        {IDS_TILE_DELAYED, FormatCount(m_stats.SimDelayed), false},
        {IDS_TILE_DROPPED, FormatCount(dropped), dropped > 0},
        {IDS_TILE_LOSS, std::format(L"{:.1f} %", lossRate), false},
        {IDS_TILE_INFLIGHT, FormatCount(m_stats.SimInFlight), false},
        {IDS_TILE_AVG, std::format(L"{:.1f} ms", avgMs), false},
    };
    const float tw = (m_tiles.right - m_tiles.left - f.F(16)) / 3, th = f.F(64);
    for (size_t i = 0; i < std::size(tiles); ++i) {
        const float x = m_tiles.left + static_cast<float>(i % 3) * (tw + f.F(8));
        const float y = m_tiles.top + static_cast<float>(i / 3) * (th + f.F(8));
        const D2D1_RECT_F t{x, y, x + tw, y + th};
        c.Fill(t, Color::Control, f.F(6));
        float lx = t.left + f.F(12);
        if (tiles[i].critical) {
            c.Circle({lx + f.F(3), t.top + f.F(17)}, f.F(3), Color::Critical);
            lx += f.F(12);
        }
        c.Text(Text::Get(tiles[i].label), {lx, t.top + f.F(8), t.right - f.F(8), t.top + f.F(26)}, Font::Caption, Color::Text3);
        c.Text(tiles[i].value, {t.left + f.F(12), t.top + f.F(26), t.right - f.F(8), t.bottom - f.F(6)}, Font::Hero, on ? Color::Text : Color::Text2);
    }
    PaintChart(c, m_delayChart, Text::Get(IDS_CHART_DELAY), m_delayHistory, L"ms", false, Color::AccentText);
    PaintChart(c, m_dropChart, Text::Get(IDS_CHART_DROPS), m_dropHistory, L"/s", true, Color::Critical);
    PaintChart(c, m_throughputChart, Text::Get(IDS_CHART_RATE), m_throughputHistory, L"kbit/s", false, Color::Success);
}

void MainWindow::PaintStatus(Canvas& c) {
    const auto& f = m_fonts;
    const D2D1_RECT_F& s = m_status;
    c.Line({s.left, s.top + 0.5f}, {s.right, s.top + 0.5f}, White(0.06f));
    float x = s.left + f.F(20);
    c.Circle({x, (s.top + s.bottom) / 2}, f.F(4), m_driverOk ? Color::Success : Color::Critical);
    x += f.F(12);
    std::wstring left = m_driverOk ? Text::Get(IDS_ST_DRIVER_OK) : Text::Get(IDS_ST_DRIVER_FAIL);
    if (!m_adapters.empty()) left += L"  ·  " + ToWide(m_adapters[m_adapterIndex].FriendlyName);
    const float lw = std::min(c.Width(left, Font::Caption) + 1, s.right * 0.34f);
    c.Text(left, {x, s.top, x + lw, s.bottom}, Font::Caption, Color::Text2);
    x += lw + f.F(24);

    // Chips on the right: what is active.
    float rx = s.right - f.F(16);
    auto chip = [&](UINT text, D2D1_COLOR_F color, bool solid) {
        const std::wstring label = Text::Get(text);
        const float w = c.Width(label, Font::Label) + f.F(16);
        const D2D1_RECT_F r{rx - w, s.top + f.F(8), rx, s.bottom - f.F(8)};
        c.Fill(r, solid ? color : WithAlpha(color, 0.16f), (r.bottom - r.top) / 2);
        c.Text(label, r, Font::Label, solid ? Color::Text : color, Align::Center);
        rx -= w + f.F(6);
    };
    if (m_ctl->KillSwitch()) chip(IDS_CHIP_KILL, Color::Danger, true);
    if (m_ctl->Impairment().enabled) chip(IDS_CHIP_SIMULATOR, Color::Caution, false);
    if (m_ctl->FirewallEnabled()) chip(IDS_CHIP_FIREWALL, Color::Success, false);
    if (m_ctl->Monitoring()) chip(IDS_CHIP_MONITOR, Color::AccentText, false);

    // Middle: a recent message, else the capture state and traffic.
    const D2D1_RECT_F middle{x, s.top, rx - f.F(12), s.bottom};
    if (!m_statusText.empty() && GetTickCount64() < m_statusUntil) {
        const D2D1_COLOR_F color = m_statusLevel == Level::Error     ? Color::Critical
                                   : m_statusLevel == Level::Warning ? Color::Caution
                                   : m_statusLevel == Level::Success ? Color::Success
                                                                     : Color::Text2;
        c.Text(m_statusText, middle, Font::Caption, color);
        return;
    }
    const bool capturing = m_ctl->Capturing();
    std::wstring text = Text::Get(capturing ? IDS_ST_CAPTURING : IDS_ST_IDLE);
    if (m_stats.TotalPackets) {
        text += L"  ·  " + Text::Format(IDS_ST_TRAFFIC, FormatCount(m_stats.TotalPackets), std::lround(m_stats.PacketsPerSec),
                                              FormatRate(m_stats.BytesPerSec));
        text += std::format(L"  ·  DNS {}  ·  TCP {}  ·  UDP {}  ·  ICMP {}", FormatCount(m_stats.DnsQueries),
                            FormatCount(m_stats.TcpPackets), FormatCount(m_stats.UdpPackets), FormatCount(m_stats.IcmpPackets));
    }
    c.Text(text, middle, Font::Caption, capturing ? Color::Text2 : Color::Text3);
}

}  // namespace WS::Ui
