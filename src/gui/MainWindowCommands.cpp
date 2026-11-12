// WireScope - Main window: commands of the capture, firewall and simulator pages and the kill switch.
#include "gui/Dialogs.h"
#include "gui/MainWindow.h"
#include "gui/MainWindowDetail.h"
#include "core/Safety.h"
#include "support/Language.h"
#include "support/Settings.h"
#include "support/Text.h"
#include <shellapi.h>
#include <algorithm>
#include <format>
#include <fstream>
#include <sstream>

namespace WS::Ui {
using namespace MainWindowDetail;

namespace {

std::wstring EditText(HWND edit) {
    const int n = GetWindowTextLengthW(edit);
    std::wstring text(static_cast<size_t>(n) + 1, L'\0');
    GetWindowTextW(edit, text.data(), n + 1);
    text.resize(static_cast<size_t>(n));
    return text;
}

}  // namespace

void MainWindow::OnCommand(UINT id, UINT code, HWND /*control*/) {
    switch (id) {
    case CmdPageCapture: ShowPage(Page::Capture); return;
    case CmdPageProcesses: ShowPage(Page::Processes); return;
    case CmdPageDriver: ShowPage(Page::Driver); return;
    case CmdDrvInstall:
    case CmdDrvUninstall:
    case CmdDrvStart:
    case CmdDrvStop:
    case CmdDrvRefresh:
    case CmdDrvCopy: DriverAction(id); return;
    case CmdDrvStartType: ShowStartTypeMenu(); return;
    case CmdPageFirewall: ShowPage(Page::Firewall); return;
    case CmdPageSimulator: ShowPage(Page::Simulator); return;
    case CmdAdapter: ShowAdapterMenu(); return;
    case CmdKill: ToggleKillSwitch(); return;
    case CmdLanguage: ShowLanguageMenu(); return;
    case CmdAbout: ShowAbout(); return;
    case CmdElevate: RestartElevated(); return;
    case CmdKeepChanges: KeepChanges(); return;
    case CmdUndoChanges: UndoChanges(false); return;

    case CmdStart: SetCapture(true); return;
    case CmdStop: SetCapture(false); return;
    case CmdToggleCapture: SetCapture(!m_ctl->Capturing()); return;
    case CmdClear: ClearCapture(); return;
    case CmdSave: SavePcap(false); return;
    case CmdSaveSelected: SavePcap(true); return;
    case CmdSelectAll: m_list.SelectAll(); return;
    case CmdFocusFilter:
        if (m_page != Page::Capture) ShowPage(Page::Capture);
        SetFocus(m_filterEdit);
        SendMessageW(m_filterEdit, EM_SETSEL, 0, -1);
        return;
    case kIdFilter:
        if (code == EN_CHANGE) {
            m_filter = EditText(m_filterEdit);
            RebuildView();
        }
        if (code == EN_SETFOCUS || code == EN_KILLFOCUS || code == EN_CHANGE) InvalidateArea(m_filterBox);
        return;
    case kIdPackets:
        if (code == LBN_SELCHANGE) m_details.SetPacket(m_list.Selected(), m_baseTime);
        else if (code == PacketListCopy) CopySummaries();
        return;

    case CmdProcMonitor: ToggleMonitor(); return;
    case CmdProcReset: ResetProcessCounters(); return;
    case CmdProcBlock: BlockProcess(); return;
    case CmdProcLimit: LimitProcess(); return;
    case CmdProcImpair: ImpairProcess(); return;
    case CmdProcPackets: ShowProcessPackets(); return;
    case CmdProcFolder: OpenProcessFolder(); return;
    case CmdProcCopyPath: CopyProcessPath(); return;
    case kIdProcesses:
        if (code == LBN_SELCHANGE) {
            UpdateControls();
            InvalidateArea(m_procDetailsCard);
        } else if (code == LBN_DBLCLK) {
            ShowProcessPackets();
        }
        return;

    case CmdFwToggle: ToggleFirewall(); return;
    case CmdFwPolicy: ShowPolicyMenu(); return;
    case CmdFwAdd:
        if (m_page != Page::Firewall) ShowPage(Page::Firewall);
        AddRule();
        return;
    case CmdFwImport: ImportRules(); return;
    case CmdFwExport: ExportRules(); return;
    case CmdFwEdit: EditRule(); return;
    case CmdFwRemove: RemoveRule(); return;
    case CmdFwUp: MoveRule(-1); return;
    case CmdFwDown: MoveRule(1); return;
    case CmdFwOffload: ToggleOffload(); return;
    case kIdRules:
        switch (code) {
        case LBN_SELCHANGE: UpdateControls(); break;
        case LBN_DBLCLK: EditRule(); break;
        case RuleListToggle: ToggleRule(); break;
        case RuleListDelete: RemoveRule(); break;
        case RuleListMoveUp: MoveRule(-1); break;
        case RuleListMoveDown: MoveRule(1); break;
        }
        return;

    case CmdSimToggle: ToggleSimulator(); return;
    case CmdSimPreset: ShowPresetMenu(); return;
    case CmdSimReset: ResetSimulator(); return;
    case CmdDirBoth: SetDirection(Dir::Both); return;
    case CmdDirIn: SetDirection(Dir::In); return;
    case CmdDirOut: SetDirection(Dir::Out); return;
    case CmdSimOrder:
        m_profile.preserveOrder = !m_profile.preserveOrder;
        m_profileDirty = true;
        UpdateControls();
        return;
    case kIdLatency:
    case kIdJitter:
    case kIdLoss:
    case kIdRate:
        if (code == SliderChanged) {
            m_profile.latencyMs = static_cast<uint32_t>(std::lround(m_latency.Value()));
            m_profile.jitterMs = static_cast<uint32_t>(std::lround(m_jitter.Value()));
            m_profile.lossPercent = std::round(m_loss.Value() * 10.0) / 10.0;
            m_profile.rateKbps = RoundRate(m_rate.Value());
            m_profileDirty = true;  // applied by the UI timer, so a drag does not reconfigure on every pixel
            InvalidateArea(m_condCard);
        }
        return;
    case kIdMatch:
        if (code == EN_CHANGE) OnMatchChanged();
        if (code == EN_SETFOCUS || code == EN_KILLFOCUS) InvalidateArea(m_matchBox);
        return;
    case CmdRefreshAdapters: RefreshAdapters(); return;
    }
    if (id >= CmdAdapterFirst && id <= CmdAdapterLast) SelectAdapter(id - CmdAdapterFirst);
    else if (id >= CmdPresetFirst && id <= CmdPresetLast) ApplyPreset(id - CmdPresetFirst);
    else if (id >= CmdLanguageAuto && id <= CmdLanguageLast) SetLanguage(id);
    else if (id >= CmdDrvTypeFirst && id <= CmdDrvTypeLast) DriverAction(id);
}

// ---------------------------------------------------------------------------
// Adapter, capture, kill switch
// ---------------------------------------------------------------------------
void MainWindow::SelectAdapter(size_t index) {
    if (index >= m_adapters.size()) return;
    if (auto r = m_ctl->SetAdapter(m_adapters[index].Handle); !r) {
        Report(r, Text::Get(IDS_ERR_ADAPTER).c_str());
        return;
    }
    m_adapterIndex = index;
    const auto& a = m_adapters[index];
    Settings::Write(L"Adapter", ToWide(a.SystemName));
    SetWindowTextW(GetDlgItem(m_hwnd, CmdAdapter), std::format(L"{}  ·  {}", ToWide(a.FriendlyName), ToWide(a.MacAddress)).c_str());
    UpdateControls();
    InvalidateArea(m_status);
}

void MainWindow::SetCapture(bool on) {
    if (on == m_ctl->Capturing()) return;
    if (!Report(m_ctl->SetCapture(on), Text::Get(IDS_ERR_CAPTURE).c_str())) return;
    if (on) {
        if (m_list.Count() == 0) m_baseTime = 0;
        SetStatus(Level::Success, Text::Format(IDS_MSG_CAPTURE_ON, ToWide(m_adapters[m_adapterIndex].FriendlyName)));
        SetFocus(m_list.hwnd());
    } else {
        SetStatus(Level::Info, Text::Get(IDS_MSG_CAPTURE_OFF));
    }
}

void MainWindow::ClearCapture() {
    m_ctl->Engine().ClearPackets();
    m_clearGeneration = m_ctl->Engine().ClearGeneration();
    m_list.Clear();
    m_details.SetPacket(nullptr, 0);
    m_baseTime = 0;
    UpdateControls();
}

void MainWindow::SavePcap(bool selected) {
    // Selected packets go out in capture order whatever the list shows: pcap readers expect time order.
    const auto packets = selected ? m_list.Marked() : m_ctl->Engine().GetRecentPackets();
    if (packets.empty()) {
        SetStatus(Level::Warning, Text::Get(IDS_MSG_NOTHING_TO_SAVE));
        return;
    }
    const auto path = PickFile(m_hwnd, true, {{Text::Get(IDS_FILE_PCAP), L"*.pcap"}, {Text::Get(IDS_FILE_ALL), L"*.*"}},
                               selected ? L"selection.pcap" : L"capture.pcap", L"pcap");
    if (!path) return;
    PcapWriter writer;
    bool ok = writer.Open(*path);
    for (const auto& p : packets) ok = ok && writer.WritePacket(p->RawData, p->TimestampUs);
    writer.Close();
    if (ok) SetStatus(Level::Success, Text::Format(IDS_MSG_SAVED, FormatCount(packets.size()), *path));
    else Inform(m_hwnd, Text::Format(IDS_MSG_SAVE_FAILED, *path), FormatError(), true);
}

void MainWindow::ToggleKillSwitch() {
    // An emergency control: no question first. It cuts every connection, a remote session included,
    // so it is undone by itself unless the user keeps it.
    const bool on = !m_ctl->KillSwitch();
    const std::wstring adapter = m_adapters.empty() ? std::wstring() : ToWide(m_adapters[m_adapterIndex].FriendlyName);
    if (!Report(m_ctl->SetKillSwitch(on), Text::Get(IDS_ERR_KILL).c_str())) return;
    SetStatus(on ? Level::Warning : Level::Success, on ? Text::Format(IDS_MSG_KILL_ON, adapter) : Text::Get(IDS_MSG_KILL_OFF));
    if (on) {
        ArmRevert(Guarded::KillSwitch, [this] { (void)m_ctl->SetKillSwitch(false); });
    } else if (m_guarded == Guarded::KillSwitch) {
        KeepChanges();
    }
    Layout();  // the banner
}

// ---------------------------------------------------------------------------
// Automatic undo
// ---------------------------------------------------------------------------
void MainWindow::ArmRevert(Guarded what, std::function<void()> undo) {
    m_guarded = what;
    m_undo = std::move(undo);
    m_revertAt = GetTickCount64() + kRevertSeconds * 1000ULL;
    Layout();
    SetFocus(GetDlgItem(m_hwnd, CmdKeepChanges));
}

void MainWindow::KeepChanges() {
    if (!m_revertAt) return;
    m_revertAt = 0;
    m_guarded = Guarded::None;
    m_undo = nullptr;
    SetStatus(Level::Success, Text::Get(IDS_MSG_KEPT));
    Layout();
}

void MainWindow::UndoChanges(bool automatic) {
    if (!m_revertAt) return;
    auto undo = std::move(m_undo);
    m_revertAt = 0;
    m_guarded = Guarded::None;
    m_undo = nullptr;
    if (undo) undo();
    if (automatic) SetStatus(Level::Warning, Text::Format(IDS_MSG_REVERTED, kRevertSeconds));
    RefreshRuleRows();
    UpdateControls();
    Layout();
}

bool MainWindow::ConfirmRisks(const std::vector<Rule>& rules, RuleAction policy) {
    const auto risks = LockoutRisks(rules, policy);
    if (risks.empty()) return true;
    return Confirm(m_hwnd, Text::Get(IDS_DLG_RISK), Text::Format(IDS_DLG_RISK_MESSAGE, DescribeRisks(risks), kRevertSeconds),
                   Text::Get(IDS_DLG_RISK_OK), true);
}

void MainWindow::RestartElevated() {
    std::wstring self(MAX_PATH, L'\0');
    self.resize(GetModuleFileNameW(nullptr, self.data(), static_cast<DWORD>(self.size())));
    SHELLEXECUTEINFOW info{sizeof info};
    info.lpVerb = L"runas";
    info.lpFile = self.c_str();
    info.nShow = SW_SHOWNORMAL;
    if (ShellExecuteExW(&info)) PostMessageW(m_hwnd, WM_CLOSE, 0, 0);
}

void MainWindow::CopySummaries() {
    // Every selected packet, one line each, in capture order; the focused one when nothing is marked.
    std::vector<PacketRef> packets = m_list.Marked();
    if (packets.empty() && m_list.Selected()) packets.push_back(m_list.Selected());
    std::wstring text;
    for (const PacketRef& p : packets) {
        if (!text.empty()) text += L"\r\n";
        text += std::format(L"#{}  {}  {}:{} -> {}:{}  {} B  {}", p->Index, ToWide(p->ProtocolName), ToWide(p->Source), p->SourcePort,
                            ToWide(p->Destination), p->DestPort, p->Length, ToWide(p->Info));
    }
    if (!text.empty()) CopyToClipboard(m_hwnd, text);
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------
bool MainWindow::PushRules(std::vector<Rule> rules) {
    // With the firewall on, a change that newly cuts DNS, HTTPS or Remote Desktop is confirmed and guarded.
    const bool guard = m_ctl->FirewallEnabled() && LockoutRisks(m_ruleSet, m_policy).empty() && !LockoutRisks(rules, m_policy).empty();
    if (guard && !ConfirmRisks(rules, m_policy)) return false;
    std::vector<Rule> previous = m_ruleSet;
    if (!Report(m_ctl->SetRules(std::move(rules)), Text::Get(IDS_ERR_FIREWALL).c_str())) return false;
    if (guard) {
        ArmRevert(Guarded::Firewall, [this, previous] {
            (void)m_ctl->SetRules(previous);
            m_ruleSet = m_ctl->Rules();
            SaveRules();
        });
    }
    m_ruleSet = m_ctl->Rules();  // with the ids the controller assigned
    SaveRules();
    RefreshRuleRows();
    UpdateControls();
    InvalidateArea(m_rulesCard);
    return true;
}

void MainWindow::ToggleFirewall() {
    const bool on = !m_ctl->FirewallEnabled();
    const bool risky = on && !LockoutRisks(m_ruleSet, m_policy).empty();
    if (risky && !ConfirmRisks(m_ruleSet, m_policy)) return;
    if (on && m_offload) {
        if (auto foreign = m_ctl->ForeignFilterCount(); foreign && *foreign > 0 &&
            !Confirm(m_hwnd, Text::Get(IDS_DLG_FOREIGN), Text::Format(IDS_DLG_FOREIGN_MESSAGE, *foreign), Text::Get(IDS_CONTINUE))) {
            return;
        }
    }
    if (!Report(m_ctl->SetFirewall(on), Text::Get(IDS_ERR_FIREWALL).c_str())) return;
    if (risky) ArmRevert(Guarded::Firewall, [this] { (void)m_ctl->SetFirewall(false); });
    else if (!on && m_guarded == Guarded::Firewall) KeepChanges();
    SetStatus(on ? Level::Success : Level::Info,
              on ? Text::Format(IDS_MSG_FW_ON, m_ruleSet.size(), Text::Get(m_policy == RuleAction::Allow ? IDS_ALLOW : IDS_BLOCK))
                 : Text::Get(IDS_MSG_FW_OFF));
    RefreshRuleRows();
}

void MainWindow::SetPolicy(RuleAction policy) {
    const RuleAction previous = m_policy;
    const bool guard = m_ctl->FirewallEnabled() && LockoutRisks(m_ruleSet, previous).empty() && !LockoutRisks(m_ruleSet, policy).empty();
    if (guard && !ConfirmRisks(m_ruleSet, policy)) return;
    if (!Report(m_ctl->SetPolicy(policy), Text::Get(IDS_ERR_FIREWALL).c_str())) return;
    if (guard) {
        ArmRevert(Guarded::Firewall, [this, previous] {
            (void)m_ctl->SetPolicy(previous);
            m_policy = previous;
            SaveRules();
        });
    }
    m_policy = policy;
    SaveRules();
    RefreshRuleRows();
    UpdateControls();
}

std::optional<std::wstring> MainWindow::RuleDialog(const std::wstring& heading, const std::wstring& text, const std::wstring& ok) {
    DialogSpec spec;
    spec.heading = heading;
    spec.message = Text::Get(IDS_DLG_RULE_MESSAGE);
    spec.monospace = Text::Get(IDS_RULE_HELP);
    spec.width = 640;
    spec.fields.push_back({Text::Get(IDS_DLG_RULE_FIELD), text, L"block out tcp dport 443", true});
    spec.ok = ok;
    spec.validate = [](const std::vector<std::wstring>& v) -> std::optional<std::wstring> {
        if (v.empty() || v[0].empty()) return std::wstring();  // nothing typed yet: no message, OK disabled
        auto rule = ParseRule(ToUtf8(v[0]));
        if (!rule) return ToWide(rule.error());
        return std::nullopt;
    };
    spec.preview = [](const std::vector<std::wstring>& v) {
        auto rule = ParseRule(ToUtf8(v.empty() ? std::wstring() : v[0]));
        if (!rule) return std::wstring();
        return Text::Get(rule->action == RuleAction::Allow ? IDS_PILL_ALLOW : IDS_PILL_BLOCK) + L"  ·  " + ToWide(Summarize(rule->match));
    };
    const DialogResult result = RunDialog(m_hwnd, spec);
    if (result.button != 1 || result.values.empty()) return std::nullopt;
    return result.values[0];
}

bool MainWindow::AddRule(std::wstring initial) {
    const auto text = RuleDialog(Text::Get(IDS_DLG_ADD_RULE), initial, Text::Get(IDS_DLG_ADD));
    if (!text) return false;
    auto rule = ParseRule(ToUtf8(*text));
    if (!rule) return false;
    std::vector<Rule> rules = m_ruleSet;
    rules.push_back(std::move(*rule));
    if (!PushRules(std::move(rules))) return false;
    m_rules.Select(static_cast<int>(m_ruleSet.size()) - 1);
    SetStatus(Level::Success, Text::Format(IDS_MSG_RULE_ADDED, ToWide(RuleText(m_ruleSet.back()))));
    return true;
}

void MainWindow::EditRule() {
    const int index = m_rules.Selected();
    if (index < 0 || index >= static_cast<int>(m_ruleSet.size())) return;
    const Rule& current = m_ruleSet[static_cast<size_t>(index)];
    const auto text = RuleDialog(Text::Get(IDS_DLG_EDIT_RULE), ToWide(RuleText(current)), Text::Get(IDS_DLG_SAVE));
    if (!text) return;
    auto rule = ParseRule(ToUtf8(*text));
    if (!rule) return;
    rule->id = current.id;
    rule->enabled = current.enabled;
    std::vector<Rule> rules = m_ruleSet;
    rules[static_cast<size_t>(index)] = std::move(*rule);
    PushRules(std::move(rules));
}

void MainWindow::RemoveRule() {
    const int index = m_rules.Selected();
    if (index < 0 || index >= static_cast<int>(m_ruleSet.size())) return;
    std::vector<Rule> rules = m_ruleSet;
    rules.erase(rules.begin() + index);
    if (PushRules(std::move(rules)) && !m_ruleSet.empty()) m_rules.Select(std::min(index, static_cast<int>(m_ruleSet.size()) - 1));
}

void MainWindow::MoveRule(int delta) {
    const int index = m_rules.Selected(), target = index + delta;
    if (index < 0 || target < 0 || target >= static_cast<int>(m_ruleSet.size())) return;
    std::vector<Rule> rules = m_ruleSet;
    std::swap(rules[static_cast<size_t>(index)], rules[static_cast<size_t>(target)]);
    if (PushRules(std::move(rules))) m_rules.Select(target);
}

void MainWindow::ToggleRule() {
    const int index = m_rules.Selected();
    if (index < 0 || index >= static_cast<int>(m_ruleSet.size())) return;
    std::vector<Rule> rules = m_ruleSet;
    rules[static_cast<size_t>(index)].enabled = !rules[static_cast<size_t>(index)].enabled;
    PushRules(std::move(rules));
}

void MainWindow::ImportRules() {
    const auto path = PickFile(m_hwnd, false, {{Text::Get(IDS_FILE_RULES), L"*.rules;*.txt"}, {Text::Get(IDS_FILE_ALL), L"*.*"}});
    if (!path) return;
    std::ifstream in(*path, std::ios::binary);
    std::stringstream buffer;
    buffer << in.rdbuf();
    std::string text = buffer.str();
    if (text.starts_with("\xEF\xBB\xBF")) text.erase(0, 3);
    auto parsed = ParseRulesText(text);
    if (!in || !parsed) {
        const std::wstring detail = parsed ? FormatError() : Text::Format(IDS_MSG_FILE_LINE, *path, parsed.error().line, ToWide(parsed.error().message));
        Inform(m_hwnd, Text::Get(IDS_ERR_RULES_FILE), detail, true);
        return;
    }
    std::vector<Rule> rules = std::move(*parsed);
    if (!m_ruleSet.empty()) {
        DialogSpec spec;
        spec.heading = Text::Get(IDS_DLG_IMPORT);
        spec.message = Text::Format(IDS_DLG_IMPORT_MESSAGE, *path, rules.size(), m_ruleSet.size());
        spec.ok = Text::Get(IDS_DLG_REPLACE);
        spec.extra = Text::Get(IDS_DLG_APPEND);
        const int button = RunDialog(m_hwnd, spec).button;
        if (button == 0) return;
        if (button == 2) {
            std::vector<Rule> merged = m_ruleSet;
            merged.insert(merged.end(), rules.begin(), rules.end());
            rules = std::move(merged);
        }
    }
    const size_t count = rules.size();
    if (PushRules(std::move(rules))) SetStatus(Level::Success, Text::Format(IDS_MSG_IMPORTED, count, *path));
}

void MainWindow::ExportRules() {
    const auto path = PickFile(m_hwnd, true, {{Text::Get(IDS_FILE_RULES), L"*.rules;*.txt"}}, L"wirescope.rules", L"rules");
    if (!path) return;
    std::ofstream out(*path, std::ios::binary | std::ios::trunc);
    out << FormatRulesText(m_ruleSet);
    if (out) SetStatus(Level::Success, Text::Format(IDS_MSG_EXPORTED, m_ruleSet.size(), *path));
    else Inform(m_hwnd, Text::Format(IDS_MSG_SAVE_FAILED, *path), FormatError(), true);
}

void MainWindow::ToggleOffload() {
    const bool on = !m_offload;
    if (!Report(m_ctl->SetKernelOffload(on), Text::Get(IDS_ERR_FIREWALL).c_str())) return;
    m_offload = on;
    SaveRules();
    UpdateControls();
    InvalidateArea(m_rulesCard);
}

// ---------------------------------------------------------------------------
// Simulator
// ---------------------------------------------------------------------------
void MainWindow::ApplyProfile() {
    m_profileDirty = false;
    SaveSimulator();
    if (auto r = m_ctl->SetImpairment(m_profile); !r) {
        m_profile.enabled = m_ctl->Impairment().enabled;
        Report(r, Text::Get(IDS_ERR_SIMULATOR).c_str());
    }
}

void MainWindow::ToggleSimulator() {
    m_profile.enabled = !m_ctl->Impairment().enabled;
    ApplyProfile();
    const bool on = m_ctl->Impairment().enabled;
    if (on == m_profile.enabled) {
        SetStatus(on ? Level::Success : Level::Info,
                  on ? Text::Format(IDS_MSG_SIM_ON, m_profile.latencyMs, m_profile.jitterMs, m_profile.lossPercent) : Text::Get(IDS_MSG_SIM_OFF));
    }
    m_delayHistory.clear();
    m_dropHistory.clear();
    m_lastSampleUs = 0;
    UpdateControls();
    InvalidateArea(m_liveCard);
}

void MainWindow::ApplyPreset(size_t index) {
    const auto presets = ImpairmentPresets();
    if (index >= presets.size()) return;
    const ImpairmentPreset& p = presets[index];
    m_profile.latencyMs = p.latencyMs;
    m_profile.jitterMs = p.jitterMs;
    m_profile.lossPercent = p.lossPercent;
    m_profile.rateKbps = p.rateKbps;
    SyncSimulatorControls();
    m_profileDirty = true;
    SetStatus(Level::Info, Text::Get(p.name));
}

void MainWindow::ResetSimulator() {
    m_profile.latencyMs = 0;
    m_profile.jitterMs = 0;
    m_profile.lossPercent = 0;
    m_profile.rateKbps = 0;
    m_profile.dir = Dir::Both;
    m_profile.preserveOrder = true;
    m_profile.match.clear();
    SyncSimulatorControls();
    m_profileDirty = true;
    UpdateControls();
}

void MainWindow::SetDirection(Dir dir) {
    m_profile.dir = dir;
    m_profileDirty = true;
    UpdateControls();
}

void MainWindow::OnMatchChanged() {
    const std::string text = ToUtf8(EditText(m_matchEdit));
    if (auto selector = ParseSelector(text); !selector) {
        m_matchError = ToWide(selector.error());
    } else {
        m_matchError.clear();
        if (text != m_profile.match) {
            m_profile.match = text;
            m_profileDirty = true;
        }
    }
    InvalidateArea(m_condCard);
    UpdateControls();
}

}  // namespace WS::Ui
