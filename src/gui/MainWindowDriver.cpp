// WireScope - Main window: the Network driver page. Install, remove, start, stop and the start type of
// wsddntf, with an engineering report of its state (core/DriverSetup.h does the work). Every action
// runs on a worker thread; WireScope lets go of the driver first and opens it again afterwards.
#include "core/DriverSetup.h"
#include "gui/Dialogs.h"
#include "gui/MainWindow.h"
#include "gui/MainWindowDetail.h"
#include "support/Language.h"
#include "support/Settings.h"
#include "support/Text.h"
#include <format>

namespace WS::Ui {
using namespace MainWindowDetail;

namespace {

namespace DS = DriverSetup;

UINT ShortTypeName(DS::StartType type) {
    switch (type) {
    case DS::StartType::Boot: return IDS_DRV_SHORT_BOOT;
    case DS::StartType::System: return IDS_DRV_SHORT_SYSTEM;
    case DS::StartType::Automatic: return IDS_DRV_SHORT_AUTO;
    case DS::StartType::Manual: return IDS_DRV_SHORT_MANUAL;
    case DS::StartType::Disabled: return IDS_DRV_SHORT_DISABLED;
    }
    return IDS_DRV_SHORT_SYSTEM;
}

std::wstring RemoteNote() {
    return GetSystemMetrics(SM_REMOTESESSION) ? Text::Get(IDS_DLG_DRV_REMOTE) : std::wstring();
}

}  // namespace

// What the worker hands back to the window (WM_APP message, owned by the receiver).
struct MainWindow::DriverJobResult {
    std::wstring done;  // empty = only the state was read
    std::expected<DS::Outcome, std::wstring> outcome;
    DS::Status status;
};

void MainWindow::RefreshDriver() {
    RunDriverJob(IDS_DRV_STATE_READING, {}, nullptr, false);
}

void MainWindow::RunDriverJob(UINT doing, std::wstring done, std::function<std::expected<DS::Outcome, std::wstring>()> work, bool release) {
    if (m_drvDoing) {
        SetStatus(Level::Warning, Text::Get(IDS_DRV_BUSY));
        return;
    }
    if (release) ReleaseDriver();
    m_drvDoing = doing;
    if (work) SetStatus(Level::Info, Text::Get(doing));
    UpdateControls();
    InvalidateArea(m_drvCard);
    if (m_drvThread.joinable()) m_drvThread.join();
    const bool inUse = m_bridge->IsConnected();
    const HWND window = m_hwnd;
    m_drvThread = std::jthread([window, inUse, done = std::move(done), work = std::move(work)] {
        auto result = std::make_unique<DriverJobResult>();
        result->done = done;
        if (work) result->outcome = work();
        result->status = DS::Query(inUse);
        if (PostMessageW(window, kDriverJobDone, 0, reinterpret_cast<LPARAM>(result.get()))) result.release();
    });
}

void MainWindow::OnDriverJobDone(LPARAM lParam) {
    const std::unique_ptr<DriverJobResult> result(reinterpret_cast<DriverJobResult*>(lParam));
    if (m_drvThread.joinable()) m_drvThread.join();
    m_drvDoing = 0;
    m_drvStatus = std::move(result->status);
    m_drvKnown = true;
    if (!result->done.empty()) {
        if (!result->outcome) {
            SetStatus(Level::Error, result->outcome.error());
            Inform(m_hwnd, Text::Get(IDS_NAV_DRIVER), result->outcome.error(), true);
        } else {
            std::wstring text = result->done;
            for (const auto& note : result->outcome->notes) text += L"  ·  " + note;
            SetStatus(result->outcome->reboot ? Level::Warning : Level::Success, text);
            if (result->outcome->reboot) Inform(m_hwnd, Text::Get(IDS_NAV_DRIVER), Text::Get(IDS_DRV_REBOOT));
        }
        // Take the driver again if it answers, as at start-up.
        if (!m_bridge->IsConnected() && m_drvStatus.deviceOpens) {
            ConnectDriver();
            RestoreMonitor();
        }
    }
    UpdateControls();
    Layout();
}

void MainWindow::ReleaseDriver() {
    // Everything off first: the adapter mode and the filter table go back to how they were found.
    m_revertAt = 0;
    m_guarded = Guarded::None;
    m_undo = nullptr;
    m_ctl->Shutdown();
    m_bridge->Disconnect();
    m_driverOk = false;
    m_adapters.clear();
    m_adapterIndex = 0;
    m_driverText = Text::Get(IDS_DRV_BUSY);
    m_list.SetPlaceholder(m_driverText);
    Layout();
}

void MainWindow::RestoreMonitor() {
    // Counting per program only reads copies of packets, so the saved choice comes back by itself.
    if (!m_driverOk || m_adapters.empty() || !Settings::ReadDword(L"ProcessMonitor", 0)) return;
    if (auto r = m_ctl->SetMonitor(true); !r) SetStatus(Level::Warning, r.error());
}

void MainWindow::DriverAction(UINT command) {
    if (m_drvDoing) {
        SetStatus(Level::Warning, Text::Get(IDS_DRV_BUSY));
        return;
    }
    switch (command) {
    case CmdDrvInstall: {
        const auto inf = DS::FindPackage();
        if (!inf) {
            Inform(m_hwnd, Text::Get(IDS_NAV_DRIVER), Text::Get(IDS_DRV_NO_PACKAGE_FOLDER), true);
            return;
        }
        if (!Confirm(m_hwnd, Text::Get(IDS_DLG_DRV_INSTALL), Text::Format(IDS_DLG_DRV_INSTALL_MESSAGE, *inf) + RemoteNote(),
                     Text::Get(IDS_DRV_INSTALL))) {
            return;
        }
        RunDriverJob(IDS_DRV_DOING_INSTALL, Text::Get(IDS_DRV_DONE_INSTALL), [inf] { return DS::Install(*inf); }, true);
        return;
    }
    case CmdDrvUninstall:
        if (!Confirm(m_hwnd, Text::Get(IDS_DLG_DRV_UNINSTALL), Text::Get(IDS_DLG_DRV_UNINSTALL_MESSAGE) + RemoteNote(), Text::Get(IDS_DRV_UNINSTALL),
                     true)) {
            return;
        }
        RunDriverJob(IDS_DRV_DOING_UNINSTALL, Text::Get(IDS_DRV_DONE_UNINSTALL), [] { return DS::Uninstall(); }, true);
        return;
    case CmdDrvStart:
        if (!Confirm(m_hwnd, Text::Get(IDS_DLG_DRV_START), Text::Get(IDS_DLG_DRV_START_MESSAGE) + RemoteNote(), Text::Get(IDS_DRV_START))) return;
        RunDriverJob(IDS_DRV_DOING_START, Text::Get(IDS_DRV_DONE_START), [] { return DS::Start(); }, true);
        return;
    case CmdDrvStop:
        if (!Confirm(m_hwnd, Text::Get(IDS_DLG_DRV_CHANGE), Text::Get(IDS_DLG_DRV_STOP_MESSAGE) + RemoteNote(), Text::Get(IDS_DRV_STOP), true)) return;
        RunDriverJob(IDS_DRV_DOING_STOP, Text::Get(IDS_DRV_DONE_STOP), [] { return DS::Stop(); }, true);
        return;
    case CmdDrvRefresh:
        RefreshDriver();
        return;
    case CmdDrvCopy: {
        std::wstring text;
        for (const auto& [label, value] : DS::Report(m_drvStatus)) text += std::format(L"{:<14}{}\r\n", label, value);
        CopyToClipboard(m_hwnd, text);
        return;
    }
    default:
        break;
    }
    if (command >= CmdDrvTypeFirst && command <= CmdDrvTypeLast) {
        const auto type = static_cast<DS::StartType>(static_cast<DWORD>(DS::StartType::System) + (command - CmdDrvTypeFirst));
        const bool disabled = type == DS::StartType::Disabled;
        if (disabled && !Confirm(m_hwnd, Text::Get(IDS_DLG_DRV_DISABLE), Text::Get(IDS_DLG_DRV_DISABLED_MESSAGE) + RemoteNote(),
                                 Text::Get(IDS_DRV_SHORT_DISABLED), true)) {
            return;
        }
        RunDriverJob(IDS_DRV_DOING_TYPE, Text::Format(IDS_DRV_DONE_TYPE, Text::Get(ShortTypeName(type))), [type] { return DS::SetStartType(type); },
                     disabled);
    }
}

void MainWindow::ShowStartTypeMenu() {
    PopupMenu menu;
    menu.AddHeader(Text::Get(IDS_DRV_TYPE_HEADER));
    const UINT names[] = {IDS_DRV_TYPE_SYSTEM, IDS_DRV_TYPE_AUTO, IDS_DRV_TYPE_MANUAL, IDS_DRV_TYPE_DISABLED};
    for (UINT i = 0; i < std::size(names); ++i) {
        const auto type = static_cast<DS::StartType>(static_cast<DWORD>(DS::StartType::System) + i);
        menu.AddItem(CmdDrvTypeFirst + i, Text::Get(names[i]), {}, m_drvStatus.service && m_drvStatus.startType == type, true);
    }
    RECT r{};
    GetWindowRect(GetDlgItem(m_hwnd, CmdDrvStartType), &r);
    if (const UINT cmd = menu.Track(m_hwnd, m_fonts, {r.left, r.bottom + m_fonts.S(2)}, &r)) DriverAction(cmd);
}

void MainWindow::UpdateDriverControls() {
    const DS::Status& s = m_drvStatus;
    const bool idle = m_drvDoing == 0, known = m_drvKnown, admin = IsElevated();
    const bool can = idle && known && admin;
    auto enable = [&](UINT id, bool on) {
        HWND b = GetDlgItem(m_hwnd, static_cast<int>(id));
        if ((IsWindowEnabled(b) != FALSE) == on) return;
        if (!on && GetFocus() == b) SendMessageW(m_hwnd, WM_NEXTDLGCTL, 0, FALSE);
        EnableWindow(b, on);
    };
    enable(CmdDrvInstall, can && !s.installed && s.package.has_value());
    enable(CmdDrvUninstall, can && (s.installed || s.service || !s.staged.empty()));
    enable(CmdDrvStart, can && s.installed && s.startType != DS::StartType::Disabled && !(s.Running() && s.Attached() && s.deviceOpens));
    enable(CmdDrvStop, can && s.installed && (s.Running() || s.Attached()));
    enable(CmdDrvStartType, can && s.service);
    enable(CmdDrvRefresh, idle);
    enable(CmdDrvCopy, known);
    const std::wstring type = s.service ? Text::Format(IDS_DRV_START_TYPE, Text::Get(ShortTypeName(s.startType))) : Text::Format(IDS_DRV_START_TYPE, L"—");
    HWND combo = GetDlgItem(m_hwnd, CmdDrvStartType);
    wchar_t current[128]{};
    GetWindowTextW(combo, current, static_cast<int>(std::size(current)));
    if (type != current) SetWindowTextW(combo, type.c_str());
}

void MainWindow::PaintDriver(Canvas& c) {
    const auto& f = m_fonts;
    const DS::Status& s = m_drvStatus;
    const auto [state, dot] = [&]() -> std::pair<UINT, D2D1_COLOR_F> {
        if (m_drvDoing) return {m_drvDoing, Color::AccentText};
        if (!m_drvKnown) return {IDS_DRV_STATE_READING, Color::Text3};
        if (!s.installed) return {IDS_DRV_STATE_NONE, Color::Text3};
        if (!s.Running()) return s.Attached() ? std::pair{IDS_DRV_STATE_HOLDING, Color::Critical} : std::pair{IDS_DRV_STATE_STOPPED, Color::Text3};
        if (!s.Attached()) return {IDS_DRV_STATE_DETACHED, Color::Caution};
        if (!s.deviceOpens) return {IDS_DRV_STATE_SILENT, Color::Caution};
        return {IDS_DRV_STATE_OK, Color::Success};
    }();
    PaintCard(c, m_drvCard, Text::Get(IDS_CARD_DRIVER));
    const std::wstring note = Text::Get(state);
    const float noteW = c.Width(note, Font::Caption) + 1;
    const float headMid = m_drvCard.top + f.F(kCardHeaderH) / 2;
    const float noteRight = m_drvCard.right - f.F(kPad);
    c.Text(note, {noteRight - noteW, m_drvCard.top, noteRight, m_drvCard.top + f.F(kCardHeaderH)}, Font::Caption, Color::Text2, Align::Right);
    c.Circle({noteRight - noteW - f.F(10), headMid}, f.F(4), dot);
    if (!m_drvKnown) return;

    // The report in two columns; a section starts with an unindented label.
    const float x0 = m_drvCard.left + f.F(kPad), labelW = f.F(150), right = m_drvCard.right - f.F(kPad);
    const float lineH = f.F(23), bottom = m_drvCard.bottom - f.F(kPad);
    float y = m_drvCard.top + f.F(kCardHeaderH);
    bool first = true;
    for (const auto& [label, value] : DS::Report(s)) {
        const bool section = !label.starts_with(L" ");
        if (section && !first) y += f.F(6);
        first = false;
        if (y + lineH > bottom) break;
        const std::wstring_view name = section ? std::wstring_view(label) : std::wstring_view(label).substr(label.find_first_not_of(L' '));
        c.Text(name, {x0 + (section ? 0 : f.F(14)), y, x0 + labelW, y + lineH}, section ? Font::Strong : Font::Caption, section ? Color::Text : Color::Text3);
        c.Text(value, {x0 + labelW, y, right, y + lineH}, Font::Mono, section ? Color::Text : Color::Text2);
        y += lineH;
    }
}

}  // namespace WS::Ui
