// WireScope - Main window: drop-down and context menus, language switching, About.
#include "gui/Dialogs.h"
#include "gui/MainWindow.h"
#include "gui/MainWindowDetail.h"
#include "resources/resource.h"
#include "support/Language.h"
#include "support/Text.h"
#include <CommCtrl.h>
#include <format>

namespace WS::Ui {
using namespace MainWindowDetail;

namespace {

// Drops a menu below the button that opened it.
UINT TrackBelow(PopupMenu& menu, HWND owner, HWND button, const Fonts& fonts) {
    RECT r{};
    GetWindowRect(button, &r);
    return menu.Track(owner, fonts, {r.left, r.bottom + fonts.S(2)}, &r);
}

}  // namespace

void MainWindow::ShowAdapterMenu() {
    if (m_ctl->AdapterLocked()) {
        SetStatus(Level::Warning, Text::Get(IDS_DP_ADAPTER_BUSY));
        return;
    }
    PopupMenu menu;
    menu.AddHeader(Text::Get(IDS_CM_ADAPTERS));
    for (size_t i = 0; i < m_adapters.size() && CmdAdapterFirst + i <= CmdAdapterLast; ++i) {
        const auto& a = m_adapters[i];
        std::wstring detail = ToWide(a.MacAddress);
        if (a.HasGateway) detail = Text::Get(IDS_CM_DEFAULT_ROUTE) + L"  ·  " + detail;
        menu.AddItem(static_cast<UINT>(CmdAdapterFirst + i), ToWide(a.FriendlyName), detail, i == m_adapterIndex, true);
    }
    menu.AddSeparator();
    menu.AddItem(CmdRefreshAdapters, Text::Get(IDS_CM_REFRESH));
    if (const UINT cmd = TrackBelow(menu, m_hwnd, GetDlgItem(m_hwnd, CmdAdapter), m_fonts)) OnCommand(cmd, 0, nullptr);
}

void MainWindow::ShowPolicyMenu() {
    PopupMenu menu;
    menu.AddHeader(Text::Get(IDS_CM_POLICY_HEADER));
    menu.AddItem(CmdPolicyAllow, Text::Get(IDS_CM_POLICY_ALLOW), {}, m_policy == RuleAction::Allow, true);
    menu.AddItem(CmdPolicyBlock, Text::Get(IDS_CM_POLICY_BLOCK), {}, m_policy == RuleAction::Block, true);
    const UINT cmd = TrackBelow(menu, m_hwnd, GetDlgItem(m_hwnd, CmdFwPolicy), m_fonts);
    if (cmd == CmdPolicyAllow) SetPolicy(RuleAction::Allow);
    else if (cmd == CmdPolicyBlock) SetPolicy(RuleAction::Block);
}

void MainWindow::ShowPresetMenu() {
    PopupMenu menu;
    menu.AddHeader(Text::Get(IDS_PRESETS_HEADER));
    const auto presets = ImpairmentPresets();
    for (size_t i = 0; i < presets.size() && CmdPresetFirst + i <= CmdPresetLast; ++i) {
        const auto& p = presets[i];
        const bool current = p.latencyMs == m_profile.latencyMs && p.jitterMs == m_profile.jitterMs &&
                             p.lossPercent == m_profile.lossPercent && p.rateKbps == m_profile.rateKbps;
        menu.AddItem(static_cast<UINT>(CmdPresetFirst + i), Text::Get(p.name),
                     Text::Format(IDS_PRESET_DETAIL, p.latencyMs, p.jitterMs, p.lossPercent, RateText(p.rateKbps)), current, true);
    }
    if (const UINT cmd = TrackBelow(menu, m_hwnd, GetDlgItem(m_hwnd, CmdSimPreset), m_fonts)) OnCommand(cmd, 0, nullptr);
}

void MainWindow::ShowContextMenu(HWND target, POINT screen) {
    if (target == m_list.hwnd() || target == m_details.hwnd()) {
        const PacketRef p = target == m_list.hwnd() ? m_list.Selected() : m_details.Packet();
        if (!p) return;
        // The remote side of the conversation: destination of outbound, source of inbound packets.
        const std::string& remote = p->Dir == Direction::Outbound ? p->Destination : p->Source;
        const bool ip = p->Protocol != ProtocolType::Unknown && p->Protocol != ProtocolType::ARP;
        PopupMenu menu;
        const size_t marked = m_list.MarkedCount();
        menu.AddItem(CmdCopySummary, marked > 1 ? Text::Format(IDS_CM_COPY_SUMMARIES, marked) : Text::Get(IDS_CM_COPY_SUMMARY), L"Ctrl+C");
        menu.AddItem(CmdCopyDetails, Text::Get(IDS_CM_COPY_DETAILS));
        menu.AddItem(CmdCopyHex, Text::Get(IDS_CM_COPY_HEX));
        menu.AddSeparator();
        menu.AddItem(CmdSaveSelected, Text::Format(IDS_CM_SAVE_SELECTED, std::max<size_t>(marked, 1)));
        menu.AddItem(CmdSelectAll, Text::Get(IDS_CM_SELECT_ALL), L"Ctrl+A");
        menu.AddSeparator();
        menu.AddItem(CmdFilterSource, Text::Format(IDS_CM_ONLY_SOURCE, ToWide(p->Source)));
        menu.AddItem(CmdFilterDestination, Text::Format(IDS_CM_ONLY_DESTINATION, ToWide(p->Destination)));
        if (!p->DomainOrHost.empty()) menu.AddItem(CmdFilterHost, Text::Format(IDS_CM_ONLY, ToWide(p->DomainOrHost)));
        menu.AddItem(CmdFilterProtocol, Text::Format(IDS_CM_ONLY, ToWide(p->ProtocolName)));
        if (!m_filter.empty()) menu.AddItem(CmdClearFilter, Text::Get(IDS_CM_CLEAR_FILTER));
        if (ip) {
            menu.AddSeparator();
            menu.AddItem(CmdBlockRemote, Text::Format(IDS_CM_BLOCK_REMOTE, ToWide(remote)));
            menu.AddItem(CmdImpairRemote, Text::Format(IDS_CM_IMPAIR_REMOTE, ToWide(remote)));
        }
        auto filterBy = [&](const std::string& text) {
            SetWindowTextW(m_filterEdit, ToWide(text).c_str());  // EN_CHANGE rebuilds the view
        };
        switch (menu.Track(m_hwnd, m_fonts, screen)) {
        case CmdCopySummary: CopySummaries(); break;
        case CmdSaveSelected: SavePcap(true); break;
        case CmdSelectAll: m_list.SelectAll(); break;
        case CmdCopyDetails: m_details.SetPacket(p, m_baseTime); CopyToClipboard(m_hwnd, m_details.Text()); break;
        case CmdCopyHex: m_details.SetPacket(p, m_baseTime); CopyToClipboard(m_hwnd, m_details.HexText()); break;
        case CmdFilterSource: filterBy(p->Source); break;
        case CmdFilterDestination: filterBy(p->Destination); break;
        case CmdFilterHost: filterBy(p->DomainOrHost); break;
        case CmdFilterProtocol: filterBy(p->ProtocolName); break;
        case CmdClearFilter: filterBy({}); break;
        case CmdBlockRemote:
            ShowPage(Page::Firewall);
            AddRule(ToWide("block remote " + remote));
            break;
        case CmdImpairRemote:
            SetWindowTextW(m_matchEdit, ToWide("remote " + remote).c_str());
            ShowPage(Page::Simulator);
            break;
        default: break;
        }
        return;
    }
    if (target == m_procList.hwnd()) {
        const auto process = SelectedProcess();
        if (!process) return;
        const bool named = Actionable(process.get());
        PopupMenu menu;
        menu.AddItem(CmdProcBlock, Text::Get(IDS_PROC_BLOCK), {}, false, false, named);
        menu.AddItem(CmdProcLimit, Text::Get(IDS_PROC_LIMIT), {}, false, false, named && m_ctl->CanControl());
        menu.AddItem(CmdProcImpair, Text::Get(IDS_PROC_IMPAIR), {}, false, false, named);
        menu.AddSeparator();
        menu.AddItem(CmdProcPackets, Text::Get(IDS_PROC_PACKETS), L"Enter", false, false, named);
        menu.AddItem(CmdProcFolder, Text::Get(IDS_PROC_FOLDER), {}, false, false, !process->path.empty());
        menu.AddItem(CmdProcCopyPath, Text::Get(IDS_PROC_COPY_PATH), {}, false, false, !process->path.empty());
        if (const UINT cmd = menu.Track(m_hwnd, m_fonts, screen)) OnCommand(cmd, 0, nullptr);
        return;
    }
    if (target == m_rules.hwnd()) {
        const int index = m_rules.Selected();
        if (index < 0 || index >= static_cast<int>(m_ruleSet.size())) return;
        const bool enabled = m_ruleSet[static_cast<size_t>(index)].enabled;
        PopupMenu menu;
        menu.AddItem(CmdFwEdit, Text::Get(IDS_FW_EDIT), L"Enter");
        menu.AddItem(enabled ? CmdRuleDisable : CmdRuleEnable, Text::Get(enabled ? IDS_CM_DISABLE : IDS_CM_ENABLE), L"Space");
        menu.AddSeparator();
        menu.AddItem(CmdFwUp, Text::Get(IDS_FW_UP), L"Alt+↑", false, false, index > 0);
        menu.AddItem(CmdFwDown, Text::Get(IDS_FW_DOWN), L"Alt+↓", false, false, index + 1 < static_cast<int>(m_ruleSet.size()));
        menu.AddSeparator();
        menu.AddItem(CmdFwRemove, Text::Get(IDS_FW_REMOVE), L"Del");
        const UINT cmd = menu.Track(m_hwnd, m_fonts, screen);
        if (cmd == CmdRuleEnable || cmd == CmdRuleDisable) ToggleRule();
        else if (cmd) OnCommand(cmd, 0, nullptr);
    }
}

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------
void MainWindow::ShowLanguageMenu() {
    m_languages = Text::Available();
    PopupMenu menu;
    const bool automatic = Text::Automatic();
    std::wstring detected = Text::Detect();
    for (const auto& l : m_languages) {
        if (l.code == detected) detected = l.name;
    }
    menu.AddItem(CmdLanguageAuto, Text::Format(IDS_LANGUAGE_AUTO, detected), {}, automatic, true);
    menu.AddSeparator();
    for (size_t i = 0; i < m_languages.size() && CmdLanguageFirst + i <= CmdLanguageLast; ++i) {
        const auto& l = m_languages[i];
        menu.AddItem(static_cast<UINT>(CmdLanguageFirst + i), l.name, l.code == L"en" ? std::wstring() : std::format(L"{}%", l.Coverage()),
                     !automatic && l.code == Text::Current(), true);
    }
    RECT r{};
    GetWindowRect(GetDlgItem(m_hwnd, CmdLanguage), &r);
    if (const UINT cmd = menu.Track(m_hwnd, m_fonts, {r.right, r.top}, &r)) OnCommand(cmd, 0, nullptr);
}

void MainWindow::SetLanguage(UINT command) {
    if (command == CmdLanguageAuto) {
        Text::Use(L"auto", true);
    } else {
        const size_t index = command - CmdLanguageFirst;
        if (index >= m_languages.size()) return;
        Text::Use(m_languages[index].code, true);
    }
    ApplyLanguage();
}

void MainWindow::ApplyLanguage() {
    for (const ButtonSpec& b : kButtons) {
        if (b.text) SetWindowTextW(GetDlgItem(m_hwnd, static_cast<int>(b.id)), Text::Get(b.text).c_str());
    }
    SendMessageW(m_filterEdit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(Text::Get(IDS_FILTER_CUE).c_str()));
    SendMessageW(m_matchEdit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(Text::Get(IDS_MATCH_CUE).c_str()));
    m_list.SetPlaceholder(m_driverOk ? Text::Get(m_filter.empty() ? IDS_LIST_EMPTY : IDS_LIST_NO_MATCH) : m_driverText);
    m_procList.SetPlaceholder(Text::Get(IDS_PROC_EMPTY));
    const PacketRef selected = m_details.Packet();
    m_details.SetPacket(nullptr, 0);
    m_details.SetPacket(selected, m_baseTime);
    RefreshRuleRows();
    RefreshProcesses();
    if (!m_matchError.empty()) OnMatchChanged();
    UpdateControls();
    RedrawWindow(m_hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
}

void MainWindow::ShowAbout() {
    DialogSpec spec;
    spec.heading = Text::Format(IDS_ABOUT, kAppVersion);
    spec.message = Text::Format(IDS_ABOUT_MESSAGE, kCopyright, kGitHubRepo);
    spec.cancelButton = false;
    spec.ok = Text::Get(IDS_CLOSE);
    spec.width = 560;
    RunDialog(m_hwnd, spec);
}

}  // namespace WS::Ui
