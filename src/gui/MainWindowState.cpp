// WireScope - Main window: driver and adapters, the UI timer, what is possible right now, settings.
#include "gui/Dialogs.h"
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
constexpr size_t kHistory = 120;  // 60 s of 500 ms samples
}

void MainWindow::ConnectDriver() {
    if (auto r = m_bridge->Connect(); !r) {
        m_driverOk = false;
        m_driverText = IsElevated() ? Text::Format(IDS_MSG_DRIVER, r.error()) : Text::Get(IDS_MSG_ADMIN);
        m_list.SetPlaceholder(m_driverText);
        SetStatus(Level::Error, m_driverText);
        UpdateControls();
        return;
    }
    m_driverOk = true;
    if (const std::wstring notice = m_ctl->Attach(); !notice.empty()) SetStatus(m_ctl->CanControl() ? Level::Warning : Level::Info, notice);
    RefreshAdapters();
}

void MainWindow::RefreshAdapters() {
    auto list = m_bridge->QueryAdapters();
    if (!list || list->empty()) {
        m_adapters.clear();
        SetStatus(Level::Error, list ? Text::Get(IDS_MSG_NO_ADAPTERS) : list.error());
        UpdateControls();
        return;
    }
    // Keep the previous choice, else the saved one while its link is up, else the adapter with the
    // default route (the user may have moved from Ethernet to Wi-Fi since).
    const bool restart = m_adapters.empty();
    const std::string previous = restart ? ToUtf8(Settings::Read(L"Adapter")) : m_adapters[m_adapterIndex].SystemName;
    m_adapters = std::move(*list);
    size_t index = 0;
    bool found = false;
    for (size_t i = 0; i < m_adapters.size(); ++i) {
        if (!previous.empty() && m_adapters[i].SystemName == previous && (!restart || m_adapters[i].IsUp)) {
            index = i;
            found = true;
            break;
        }
    }
    if (!found) {
        for (size_t i = 0; i < m_adapters.size(); ++i) {
            if (m_adapters[i].HasGateway) {
                index = i;
                break;
            }
        }
    }
    SelectAdapter(index);
}

void MainWindow::UpdateControls() {
    const bool driver = m_driverOk && !m_adapters.empty();
    const bool control = driver && m_ctl->CanControl();
    const bool capturing = m_ctl->Capturing();
    const int rule = m_rules.Selected();
    const bool ruleSelected = rule >= 0 && rule < static_cast<int>(m_ruleSet.size());
    auto enable = [&](UINT id, bool on) {
        HWND b = GetDlgItem(m_hwnd, static_cast<int>(id));
        if ((IsWindowEnabled(b) != FALSE) == on) return;
        if (!on && GetFocus() == b) SendMessageW(m_hwnd, WM_NEXTDLGCTL, 0, FALSE);  // never disable the focused control
        EnableWindow(b, on);
    };
    enable(CmdAdapter, driver && !m_ctl->AdapterLocked());
    enable(CmdStart, driver && !capturing);
    enable(CmdStop, capturing);
    enable(CmdSave, m_list.Count() > 0);
    enable(CmdKill, control);
    enable(CmdFwToggle, control);
    enable(CmdFwOffload, control);
    enable(CmdFwEdit, ruleSelected);
    enable(CmdFwRemove, ruleSelected);
    enable(CmdFwUp, ruleSelected && rule > 0);
    enable(CmdFwDown, ruleSelected && rule + 1 < static_cast<int>(m_ruleSet.size()));
    enable(CmdFwExport, !m_ruleSet.empty());
    enable(CmdSimToggle, control && m_matchError.empty());
    const auto process = SelectedProcess();
    const bool named = Actionable(process.get());
    enable(CmdProcMonitor, driver);
    enable(CmdProcBlock, named);
    enable(CmdProcLimit, named && control && m_matchError.empty());
    enable(CmdProcImpair, named);
    enable(CmdProcPackets, named);
    enable(CmdProcFolder, process && !process->path.empty());

    auto check = [&](UINT id, bool on) {
        ButtonLook& look = m_looks[id];
        if (look.checked == on) return;
        look.checked = on;
        InvalidateRect(GetDlgItem(m_hwnd, static_cast<int>(id)), nullptr, FALSE);
    };
    check(CmdKill, m_ctl->KillSwitch());
    check(CmdFwToggle, m_ctl->FirewallEnabled());
    check(CmdFwOffload, m_offload);
    check(CmdSimToggle, m_ctl->Impairment().enabled);
    check(CmdProcMonitor, m_ctl->Monitoring());
    check(CmdSimOrder, m_profile.preserveOrder);
    check(CmdDirBoth, m_profile.dir == Dir::Both);
    check(CmdDirIn, m_profile.dir == Dir::In);
    check(CmdDirOut, m_profile.dir == Dir::Out);
    auto setText = [&](UINT id, const std::wstring& text) {  // only on change: every call repaints the button
        HWND b = GetDlgItem(m_hwnd, static_cast<int>(id));
        wchar_t current[256]{};
        GetWindowTextW(b, current, static_cast<int>(std::size(current)));
        if (text != current) SetWindowTextW(b, text.c_str());
    };
    setText(CmdKill, Text::Get(m_ctl->KillSwitch() ? IDS_KILL_ON : IDS_KILL));
    setText(CmdFwPolicy, Text::Format(IDS_FW_POLICY, Text::Get(m_policy == RuleAction::Allow ? IDS_ALLOW : IDS_BLOCK)));
    m_looks[CmdPageFirewall].badge = m_ctl->FirewallEnabled() ? std::to_wstring(m_ruleSet.size()) : std::wstring();
    m_looks[CmdPageSimulator].badge = m_ctl->Impairment().enabled ? std::wstring(L"●") : std::wstring();
    m_looks[CmdPageProcesses].badge = m_procAlerts > 0 ? std::to_wstring(m_procAlerts) : std::wstring();
    m_looks[CmdPageProcesses].alert = m_procAlerts > 0;
    for (UINT id : {CmdPageProcesses, CmdPageFirewall, CmdPageSimulator}) InvalidateRect(GetDlgItem(m_hwnd, static_cast<int>(id)), nullptr, FALSE);
    UpdateDriverControls();
    InvalidateArea(m_status);
}

void MainWindow::SetStatus(Level level, std::wstring text) {
    m_statusLevel = level;
    m_statusText = std::move(text);
    m_statusUntil = GetTickCount64() + (level == Level::Error ? 15000 : 6000);
    InvalidateArea(m_status);
}

bool MainWindow::Report(const std::expected<void, std::wstring>& result, const wchar_t* heading) {
    UpdateControls();
    if (result) return true;
    SetStatus(Level::Error, result.error());
    Inform(m_hwnd, heading, result.error(), true);
    return false;
}

// ---------------------------------------------------------------------------
// Timer: new packets, counters, history
// ---------------------------------------------------------------------------
void MainWindow::OnTimer() {
    if (!m_driverOk) return;
    if (m_revertAt) {
        if (GetTickCount64() >= m_revertAt) UndoChanges(true);
        else InvalidateArea(m_banner);  // the countdown
    }
    PullPackets();
    m_stats = m_ctl->Engine().GetStats();
    if (m_profileDirty) ApplyProfile();
    if (++m_tick % kSlowTicks == 0) {
        if (m_ctl->FirewallEnabled()) RefreshRuleRows();
        if (m_page == Page::Processes || m_ctl->Engine().Accounting()) RefreshProcesses();
        SampleSimulator();
        if (m_page == Page::Simulator) {
            InvalidateArea(m_liveCard);
            InvalidateArea(m_condCard);
        }
        UpdateControls();
    }
    InvalidateArea(m_status);
}

bool MainWindow::PassesFilter(const DecodedPacket& p) const {
    if (m_filter.empty()) return true;
    const std::string needle = ToUtf8(m_filter);
    if (ContainsIgnoreCase(p.ProtocolName, needle) || ContainsIgnoreCase(p.Source, needle) || ContainsIgnoreCase(p.Destination, needle) ||
        ContainsIgnoreCase(p.DomainOrHost, needle) || ContainsIgnoreCase(p.Info, needle) || ContainsIgnoreCase(p.Process, needle)) {
        return true;
    }
    const std::string ports = std::format("{} {}", p.SourcePort, p.DestPort);
    return p.SourcePort && ContainsIgnoreCase(ports, needle);
}

void MainWindow::PullPackets() {
    auto& engine = m_ctl->Engine();
    if (engine.ClearGeneration() != m_clearGeneration) {
        m_clearGeneration = engine.ClearGeneration();
        m_list.Clear();
    }
    std::vector<PacketRef> fresh;
    engine.CopyPacketsAfter(m_lastIndex, fresh);
    if (fresh.empty()) return;
    m_lastIndex = fresh.back()->Index;
    if (m_baseTime == 0) {
        m_baseTime = fresh.front()->TimestampUs;
        m_list.SetBaseTime(m_baseTime);
    }
    if (!m_filter.empty()) std::erase_if(fresh, [&](const PacketRef& p) { return !PassesFilter(*p); });
    const bool wasEmpty = m_list.Count() == 0;
    m_list.Append(fresh);
    if (wasEmpty && m_list.Count() > 0) UpdateControls();
}

void MainWindow::RebuildView() {
    auto all = m_ctl->Engine().GetRecentPackets();
    m_lastIndex = all.empty() ? m_lastIndex : all.back()->Index;
    if (!m_filter.empty()) std::erase_if(all, [&](const PacketRef& p) { return !PassesFilter(*p); });
    m_list.SetPlaceholder(Text::Get(m_filter.empty() ? IDS_LIST_EMPTY : IDS_LIST_NO_MATCH));
    m_list.SetRows(std::move(all));
    m_details.SetPacket(m_list.Selected(), m_baseTime);
    UpdateControls();
}

void MainWindow::RefreshRuleRows() {
    if (m_ctl->FirewallEnabled()) m_fw = m_ctl->PollFirewall();
    std::vector<RuleRow> rows;
    rows.reserve(m_ruleSet.size());
    for (const Rule& r : m_ruleSet) {
        RuleRow row;
        row.id = r.id;
        row.enabled = r.enabled;
        row.action = r.action;
        row.text = ToWide(r.text);
        row.summary = ToWide(Summarize(r.match));
        if (const auto it = m_fw.rules.find(r.id); it != m_fw.rules.end()) row.hits = it->second;
        rows.push_back(std::move(row));
    }
    m_rules.SetRows(std::move(rows));
    m_rules.SetPolicy(m_policy, m_fw.policy, m_ctl->FirewallEnabled());
}

void MainWindow::SampleSimulator() {
    const uint64_t now = MonotonicMicroseconds();
    const uint64_t dropped = m_stats.SimDropped + m_stats.SimOverflow;
    if (m_lastSampleUs) {
        const double seconds = std::max(0.001, static_cast<double>(now - m_lastSampleUs) / 1e6);
        const uint64_t bytes = m_stats.SimBytes - std::min(m_stats.SimBytes, m_lastSimBytes);
        const double kbps = (static_cast<double>(bytes) * 8.0) / seconds / 1000.0;
        m_throughputHistory.push_back(kbps);
        while (m_throughputHistory.size() > kHistory) m_throughputHistory.pop_front();

        if (m_ctl->Impairment().enabled) {
            const uint64_t delayed = m_stats.SimDelayed - std::min(m_stats.SimDelayed, m_lastDelayed);
            const uint64_t delaySum = m_stats.SimDelaySumUs - std::min(m_stats.SimDelaySumUs, m_lastDelaySum);
            // No packet delayed in the interval: keep the line at the configured latency instead of 0.
            const double avg = delayed ? static_cast<double>(delaySum) / static_cast<double>(delayed) / 1000.0
                                       : (m_delayHistory.empty() ? 0.0 : m_delayHistory.back());
            m_delayHistory.push_back(avg);
            m_dropHistory.push_back(static_cast<double>(dropped - std::min(dropped, m_lastDropped)) / seconds);
            while (m_delayHistory.size() > kHistory) m_delayHistory.pop_front();
            while (m_dropHistory.size() > kHistory) m_dropHistory.pop_front();
        }
    }
    m_lastSampleUs = now;
    m_lastDelayed = m_stats.SimDelayed;
    m_lastDelaySum = m_stats.SimDelaySumUs;
    m_lastDropped = dropped;
    m_lastSimBytes = m_stats.SimBytes;
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
void MainWindow::LoadSettings() {
    m_split = std::clamp(static_cast<float>(Settings::ReadDword(L"Split", 580)) / 1000.0f, 0.25f, 0.85f);
    if (auto parsed = ParseRulesText(ToUtf8(Settings::Read(L"FirewallRules")))) {
        m_ruleSet = std::move(*parsed);
        for (Rule& r : m_ruleSet) r.id = m_ctl->NewRuleId();
    }
    (void)m_ctl->SetRules(m_ruleSet);
    m_policy = Settings::ReadDword(L"FirewallPolicy", 0) ? RuleAction::Block : RuleAction::Allow;
    (void)m_ctl->SetPolicy(m_policy);
    m_offload = Settings::ReadDword(L"KernelOffload", 1) != 0;
    (void)m_ctl->SetKernelOffload(m_offload);

    m_profile.latencyMs = std::min<uint32_t>(Settings::ReadDword(L"SimLatency", 120), 2000);
    m_profile.jitterMs = std::min<uint32_t>(Settings::ReadDword(L"SimJitter", 20), 500);
    m_profile.lossPercent = std::min(100.0, Settings::ReadDword(L"SimLoss", 20) / 10.0);
    const DWORD dir = Settings::ReadDword(L"SimDirection", 3);
    m_profile.dir = dir == 1 ? Dir::In : dir == 2 ? Dir::Out : Dir::Both;
    m_profile.preserveOrder = Settings::ReadDword(L"SimOrder", 1) != 0;
    m_profile.rateKbps = std::min<uint32_t>(Settings::ReadDword(L"SimRate", 0), 1'000'000);
    m_profile.match = ToUtf8(Settings::Read(L"SimMatch"));
    m_profile.enabled = false;  // never impair the network unasked at start-up
    if (auto selector = ParseSelector(m_profile.match); !selector) m_profile.match.clear();
    m_page = static_cast<Page>(std::min<DWORD>(Settings::ReadDword(L"Page", 0), static_cast<DWORD>(Page::Driver)));
}

void MainWindow::SaveRules() {
    Settings::Write(L"FirewallRules", ToWide(FormatRulesText(m_ruleSet)));
    Settings::WriteDword(L"FirewallPolicy", m_policy == RuleAction::Block ? 1 : 0);
    Settings::WriteDword(L"KernelOffload", m_offload ? 1 : 0);
}

void MainWindow::SaveSimulator() {
    Settings::WriteDword(L"SimLatency", m_profile.latencyMs);
    Settings::WriteDword(L"SimJitter", m_profile.jitterMs);
    Settings::WriteDword(L"SimLoss", static_cast<DWORD>(std::lround(m_profile.lossPercent * 10)));
    Settings::WriteDword(L"SimDirection", static_cast<DWORD>(m_profile.dir));
    Settings::WriteDword(L"SimOrder", m_profile.preserveOrder ? 1 : 0);
    Settings::WriteDword(L"SimRate", m_profile.rateKbps);
    Settings::Write(L"SimMatch", ToWide(m_profile.match));
}

void MainWindow::SyncSimulatorControls() {
    m_latency.SetValue(m_profile.latencyMs);
    m_jitter.SetValue(m_profile.jitterMs);
    m_loss.SetValue(m_profile.lossPercent);
    m_rate.SetValue(m_profile.rateKbps);
    SetWindowTextW(m_matchEdit, ToWide(m_profile.match).c_str());
    m_matchError.clear();
    if (m_page == Page::Simulator) InvalidateArea(m_condCard);
}

}  // namespace WS::Ui
