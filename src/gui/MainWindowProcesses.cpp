// WireScope - Main window: the Processes page. Traffic per program, its sockets and signature, and
// the actions that turn a program into a firewall rule, a bandwidth limit or a simulator target.
#include "core/ProcessTrust.h"
#include "core/Rules.h"
#include "gui/Dialogs.h"
#include "gui/MainWindow.h"
#include "gui/MainWindowDetail.h"
#include "support/Language.h"
#include "support/Settings.h"
#include "support/Text.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <ShlObj.h>
#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>
#include <format>

namespace WS::Ui {
using namespace MainWindowDetail;

namespace {

constexpr uint64_t kRecheckMs = 2000;  // how often a program without sockets is checked for having exited
constexpr double kSmoothing = 0.6;     // weight of the newest sample in the displayed rates

const std::wstring& WindowsFolder() {
    static const std::wstring folder = [] {
        std::wstring path(MAX_PATH, L'\0');
        path.resize(GetWindowsDirectoryW(path.data(), MAX_PATH));
        if (!path.empty() && path.back() != L'\\') path += L'\\';
        return FoldCase(path);
    }();
    return folder;
}

// Services of Windows share these processes: a rule for one of them reaches far beyond one program.
bool PartOfWindows(const ProcessInfo& p) {
    return p.pid == 4 || (!p.path.empty() && !WindowsFolder().empty() && FoldCase(p.path).starts_with(WindowsFolder()));
}

std::wstring StartedText(uint64_t filetime) {
    if (filetime == 0) return {};
    const FILETIME utc{static_cast<DWORD>(filetime), static_cast<DWORD>(filetime >> 32)};
    SYSTEMTIME system{}, local{};
    if (!FileTimeToSystemTime(&utc, &system) || !SystemTimeToTzSpecificLocalTime(nullptr, &system, &local)) return {};
    return std::format(L"{:04}-{:02}-{:02} {:02}:{:02}:{:02}", local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute,
                       local.wSecond);
}

// Established connections first, then other TCP states, listeners, UDP ports.
int Rank(const Endpoint& e) {
    if (e.protocol != 6) return 3;
    if (e.state == MIB_TCP_STATE_ESTAB) return 0;
    return e.state == MIB_TCP_STATE_LISTEN ? 2 : 1;
}

std::wstring Address(const Endpoint& e, const std::array<uint8_t, 16>& address, uint16_t port) {
    if (e.version == 4) {
        uint32_t v4 = 0;
        std::memcpy(&v4, address.data(), sizeof v4);
        return ToWide(std::format("{}:{}", FormatIpv4(v4), port));
    }
    return ToWide(std::format("[{}]:{}", FormatIpv6(std::span<const uint8_t, 16>(address)), port));
}

std::wstring EndpointText(const Endpoint& e) {
    std::wstring text = (e.protocol == 6 ? L"TCP  " : L"UDP  ") + Address(e, e.local, e.localPort);
    if (e.protocol != 6) return text;
    if (e.state == MIB_TCP_STATE_LISTEN) return text + L"  " + Text::Get(IDS_TCP_LISTEN);
    const UINT state = e.state == MIB_TCP_STATE_ESTAB                                         ? IDS_TCP_ESTABLISHED
                       : e.state == MIB_TCP_STATE_SYN_SENT || e.state == MIB_TCP_STATE_SYN_RCVD ? IDS_TCP_CONNECTING
                                                                                               : IDS_TCP_CLOSING;
    return text + L"  →  " + Address(e, e.remote, e.remotePort) + L"  " + Text::Get(state);
}

std::optional<uint32_t> ParseKbps(const std::vector<std::wstring>& values) {
    if (values.empty()) return std::nullopt;
    std::wstring_view text = values[0];
    while (!text.empty() && text.front() == L' ') text.remove_prefix(1);
    while (!text.empty() && text.back() == L' ') text.remove_suffix(1);
    const std::string digits = ToUtf8(text);
    uint32_t value = 0;
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), value);
    if (digits.empty() || ec != std::errc{} || end != digits.data() + digits.size() || value < 8 || value > 1'000'000) return std::nullopt;
    return value;
}

}  // namespace

// ---------------------------------------------------------------------------
// Data: socket tables, traffic totals, signatures
// ---------------------------------------------------------------------------
void MainWindow::RefreshProcesses() {
    auto& engine = m_ctl->Engine();
    m_procSnapshot = ProcessMapper::Instance().Current();
    const ProcessMapper::Snapshot& snapshot = *m_procSnapshot;
    const bool counting = engine.Accounting();
    const uint64_t nowUs = MonotonicMicroseconds(), nowMs = GetTickCount64();
    const double seconds = m_procSampleUs ? std::max(0.05, static_cast<double>(nowUs - m_procSampleUs) / 1e6) : 0.0;
    m_procSampleUs = nowUs;

    std::unordered_map<uint32_t, ProcessRow> rows;
    std::unordered_map<uint32_t, std::shared_ptr<const ProcessInfo>> infos;
    auto rowFor = [&](const std::shared_ptr<const ProcessInfo>& p) -> ProcessRow& {
        auto [it, inserted] = rows.try_emplace(p ? p->id : 0);
        ProcessRow& r = it->second;
        if (inserted) {
            r.counted = counting;
            if (p) {
                r.id = p->id;
                r.pid = p->pid;
                r.name = p->display.empty() ? Text::Format(IDS_PROC_UNNAMED, p->pid) : p->display;
                r.path = p->path;
                infos.emplace(p->id, p);
            }
        }
        return r;
    };

    // Programs with sockets right now.
    std::vector<uint32_t> sockets(snapshot.processes.size(), 0);
    for (const Endpoint& e : snapshot.endpoints) ++sockets[e.process];
    for (size_t i = 0; i < snapshot.processes.size(); ++i) {
        ProcessRow& r = rowFor(snapshot.processes[i]);
        r.sockets = sockets[i];
        m_procStates[r.id] = {true, nowMs};
    }

    // Traffic totals and rates (also of programs that have closed their sockets since).
    std::unordered_map<uint32_t, ProcessRate> rates;
    m_procIn = m_procOut = 0;
    for (const ProcessTraffic& t : engine.ProcessTotals()) {
        ProcessRow& r = rowFor(t.process);
        r.counted = true;
        r.bytesIn = t.total.bytesIn;
        r.bytesOut = t.total.bytesOut;
        r.packetsIn = t.total.packetsIn;
        r.packetsOut = t.total.packetsOut;
        ProcessRate rate{t.total.bytesIn, t.total.bytesOut, 0, 0};
        if (const auto previous = m_procRates.find(r.id); previous != m_procRates.end() && seconds > 0) {
            const ProcessRate& p = previous->second;
            const double in = static_cast<double>(t.total.bytesIn - std::min(t.total.bytesIn, p.bytesIn)) / seconds;
            const double out = static_cast<double>(t.total.bytesOut - std::min(t.total.bytesOut, p.bytesOut)) / seconds;
            rate.rateIn = p.rateIn + (in - p.rateIn) * kSmoothing;
            rate.rateOut = p.rateOut + (out - p.rateOut) * kSmoothing;
        }
        r.rateIn = rate.rateIn;
        r.rateOut = rate.rateOut;
        m_procIn += rate.rateIn;
        m_procOut += rate.rateOut;
        rates.emplace(r.id, rate);
    }
    m_procRates = std::move(rates);

    // Exited or not, and does it look like what it claims to be.
    m_procAlerts = 0;
    std::vector<ProcessRow> list;
    list.reserve(rows.size());
    for (auto& [id, r] : rows) {
        if (id != 0) {
            const ProcessInfo& info = *infos.at(id);
            ProcessState& state = m_procStates[id];
            if (r.sockets == 0 && state.running && nowMs - state.checkedAt >= kRecheckMs) {
                state.running = ProcessMapper::Running(info);
                state.checkedAt = nowMs;
            }
            r.running = state.running;
            if (!info.path.empty()) {
                const TrustReport trust = ProcessTrust::Instance().Check(info.path);
                r.signature = trust.signature;
                r.risk = trust.risk();
            }
            if (r.running && r.risk == Risk::High) ++m_procAlerts;
        }
        list.push_back(std::move(r));
    }
    std::erase_if(m_procStates, [&](const auto& entry) { return !infos.contains(entry.first); });
    m_procInfo = std::move(infos);
    m_procCount = m_procInfo.size();
    m_procList.SetRows(std::move(list));
    if (m_page == Page::Processes) {
        InvalidateArea(m_procSummary);
        InvalidateArea(m_procCard);
        InvalidateArea(m_procDetailsCard);
    }
    UpdateControls();
}

std::shared_ptr<const ProcessInfo> MainWindow::SelectedProcess() const {
    const ProcessRow* row = m_procList.Selected();
    if (!row || row->id == 0) return nullptr;
    const auto it = m_procInfo.find(row->id);
    return it == m_procInfo.end() ? nullptr : it->second;
}

bool MainWindow::Actionable(const ProcessInfo* process) {
    return process && process->pid != 4 && !process->name.empty();
}

std::string MainWindow::AppToken(const ProcessInfo& process) const {
    // The name is short and survives updates that move a program to a new folder. The path is used
    // when the name alone would also hit another program: an imitation of a Windows component, or
    // a second program of the same name in another folder.
    bool byPath = (ProcessTrust::Instance().Check(process.path).flags & TrustFlag::Imitation) != 0;
    for (const auto& [id, other] : m_procInfo) {
        if (other->name == process.name && !other->pathKey.empty() && other->pathKey != process.pathKey) byPath = true;
    }
    if (process.path.empty()) byPath = false;
    return "app " + QuoteToken(byPath ? ToUtf8(process.path) : process.name);
}

// ---------------------------------------------------------------------------
// Painting
// ---------------------------------------------------------------------------
void MainWindow::PaintProcesses(Canvas& c) {
    const bool counting = m_ctl->Engine().Accounting();
    const std::wstring summary = counting ? Text::Format(IDS_PROC_SUMMARY, m_procCount, FormatRate(m_procIn), FormatRate(m_procOut))
                                          : Text::Format(IDS_PROC_COUNT, m_procCount);
    c.Text(summary, m_procSummary, Font::Caption, Color::Text2, Align::Right);
    const std::wstring adapter = m_adapters.empty() ? std::wstring() : ToWide(m_adapters[m_adapterIndex].FriendlyName);
    PaintCard(c, m_procCard, Text::Get(IDS_CARD_PROCESSES), counting ? Text::Format(IDS_PROC_ON_NOTE, adapter) : Text::Get(IDS_PROC_OFF_NOTE));
    PaintCard(c, m_procDetailsCard, {});
    PaintProcessDetails(c);
}

void MainWindow::PaintProcessDetails(Canvas& c) {
    const auto& f = m_fonts;
    const D2D1_RECT_F& body = m_procDetailsBody;
    const ProcessRow* row = m_procList.Selected();
    if (!row) {
        c.Text(Text::Get(IDS_PROC_SELECT), body, Font::Body, Color::Text3, Align::Center);
        return;
    }
    const auto process = SelectedProcess();
    const float split = body.left + std::round((body.right - body.left) * 0.55f);
    const D2D1_RECT_F left{body.left, body.top, split - f.F(24), body.bottom};
    const D2D1_RECT_F right{split, body.top, body.right, body.bottom};
    const float lineH = f.F(24);

    // Heading: name, process id
    float x = left.left, y = left.top;
    if (row->risk == Risk::High) {
        c.Text(std::wstring(1, Icon::Warning), {x, y, x + f.F(22), y + f.F(28)}, Font::Icon, Color::Critical, Align::Center);
        x += f.F(30);
    }
    const std::wstring name = row->id == 0 ? Text::Get(IDS_PROC_NO_PROCESS) : row->name;
    const float nameW = std::min(c.Width(name, Font::Title) + 1, left.right - x);
    c.Text(name, {x, y, x + nameW, y + f.F(28)}, Font::Title, row->running ? Color::Text : Color::Text2);
    std::wstring tag = row->id == 0 ? std::wstring() : std::format(L"PID {}", row->pid);
    if (!row->running) tag += L"  ·  " + Text::Get(IDS_PROC_EXITED);
    c.Text(tag, {x + nameW + f.F(12), y, left.right, y + f.F(28)}, Font::Caption, Color::Text3);
    y += f.F(36);

    auto line = [&](const std::wstring& text, D2D1_COLOR_F color, wchar_t icon = 0, D2D1_COLOR_F iconColor = Color::Text3) {
        if (y + lineH > left.bottom + f.F(2)) return;
        float lx = left.left;
        if (icon) {
            c.Text(std::wstring(1, icon), {lx, y, lx + f.F(16), y + lineH}, Font::IconSmall, iconColor, Align::Center);
            lx += f.F(24);
        }
        c.Text(text, {lx, y, left.right, y + lineH}, Font::Caption, color);
        y += lineH;
    };

    if (process) {
        line(process->path.empty() ? Text::Get(IDS_SIG_NO_PATH) : process->path, Color::Text2, Icon::Folder);
        if (!process->path.empty()) {
            const TrustReport trust = ProcessTrust::Instance().Check(process->path);
            const bool high = trust.risk() == Risk::High;
            switch (trust.signature) {
            case Signature::Pending: line(Text::Get(IDS_SIG_PENDING), Color::Text3, Icon::Refresh); break;
            case Signature::Signed:
                line(trust.signer.empty() ? Text::Get(IDS_SIG_SIGNED_ANON) : Text::Format(IDS_SIG_SIGNED, trust.signer), Color::Text2, Icon::Check,
                     Color::Success);
                break;
            case Signature::Unsigned: line(Text::Get(IDS_SIG_UNSIGNED), high ? Color::Critical : Color::Caution, Icon::Warning, high ? Color::Critical : Color::Caution); break;
            case Signature::Invalid: line(Text::Get(IDS_SIG_INVALID), Color::Critical, Icon::Warning, Color::Critical); break;
            case Signature::Unknown: line(Text::Get(IDS_SIG_UNKNOWN), Color::Text3, Icon::Info); break;
            case Signature::Package:
                line(trust.signer.empty() ? Text::Get(IDS_SIG_PACKAGE_ANON) : Text::Format(IDS_SIG_PACKAGE, trust.signer), Color::Text2,
                     Icon::Check, Color::Success);
                break;
            }
            if (trust.risk() != Risk::None) {
                std::wstring reasons;
                for (const auto& [flag, text] : {std::pair{TrustFlag::Imitation, IDS_RISK_IMITATION}, std::pair{TrustFlag::Hidden, IDS_RISK_HIDDEN},
                                                 std::pair{TrustFlag::UserFolder, IDS_RISK_USER_FOLDER}}) {
                    if (!(trust.flags & flag)) continue;
                    if (!reasons.empty()) reasons += L"  ·  ";
                    reasons += Text::Get(text);
                }
                if (!reasons.empty()) line(reasons, high ? Color::Critical : Color::Caution, Icon::Info, high ? Color::Critical : Color::Caution);
            }
        }
        if (const std::wstring started = StartedText(process->started); !started.empty()) {
            line(Text::Format(IDS_PROC_STARTED, started), Color::Text3, Icon::Play);
        }
    } else {
        line(Text::Get(IDS_PROC_NO_PROCESS_NOTE), Color::Text2, Icon::Info);
    }
    if (row->counted) {
        line(Text::Format(IDS_PROC_TRAFFIC, FormatBytes(row->bytesIn), FormatCount(row->packetsIn), FormatBytes(row->bytesOut),
                          FormatCount(row->packetsOut)),
             Color::Text2, Icon::Speed);
    } else {
        line(Text::Get(IDS_PROC_NOT_COUNTED), Color::Text3, Icon::Speed);
    }

    // Sockets of this process, from the snapshot the list was built from.
    if (!process || !m_procSnapshot) return;
    std::vector<const Endpoint*> endpoints;
    for (size_t i = 0; i < m_procSnapshot->processes.size(); ++i) {
        if (m_procSnapshot->processes[i]->id != process->id) continue;
        for (const Endpoint& e : m_procSnapshot->endpoints) {
            if (e.process == i) endpoints.push_back(&e);
        }
    }
    std::ranges::stable_sort(endpoints, {}, [](const Endpoint* e) { return Rank(*e); });
    float ry = right.top + f.F(4);
    c.Text(std::format(L"{}  ·  {}", Text::Get(IDS_PROC_COL_SOCKETS), endpoints.size()), {right.left, ry, right.right, ry + f.F(20)}, Font::Label,
           Color::Text3);
    ry += f.F(28);
    if (endpoints.empty()) {
        c.Text(Text::Get(IDS_PROC_NO_SOCKETS), {right.left, ry, right.right, ry + f.F(20)}, Font::Caption, Color::Text3);
        return;
    }
    const float socketH = f.F(21);
    const size_t fit = static_cast<size_t>(std::max(1.0f, std::floor((right.bottom - ry) / socketH)));
    const size_t shown = endpoints.size() <= fit ? endpoints.size() : fit - 1;
    for (size_t i = 0; i < shown; ++i) {
        const Endpoint& e = *endpoints[i];
        const bool established = e.protocol == 6 && e.state == MIB_TCP_STATE_ESTAB;
        c.Text(EndpointText(e), {right.left, ry, right.right, ry + socketH}, Font::Mono, established ? Color::Text2 : Color::Text3);
        ry += socketH;
    }
    if (shown < endpoints.size()) {
        c.Text(Text::Format(IDS_PROC_MORE, endpoints.size() - shown), {right.left, ry, right.right, ry + socketH}, Font::Caption, Color::Text3);
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------
void MainWindow::ToggleMonitor() {
    const bool on = !m_ctl->Monitoring();
    if (!Report(m_ctl->SetMonitor(on), Text::Get(IDS_ERR_MONITOR).c_str())) return;
    Settings::WriteDword(L"ProcessMonitor", on ? 1 : 0);
    const std::wstring adapter = m_adapters.empty() ? std::wstring() : ToWide(m_adapters[m_adapterIndex].FriendlyName);
    SetStatus(on ? Level::Success : Level::Info, on ? Text::Format(IDS_MSG_MONITOR_ON, adapter) : Text::Get(IDS_MSG_MONITOR_OFF));
    m_procSampleUs = 0;  // rates start again from the next sample
    RefreshProcesses();
}

void MainWindow::ResetProcessCounters() {
    m_ctl->Engine().ResetProcessTotals();
    m_procRates.clear();
    m_procSampleUs = 0;
    RefreshProcesses();
}

void MainWindow::BlockProcess() {
    // A shared_ptr: the confirmation and the rule dialog run the message loop, and the timer may
    // rebuild the process list meanwhile.
    const auto process = SelectedProcess();
    if (!Actionable(process.get())) return;
    if (PartOfWindows(*process) && !Confirm(m_hwnd, Text::Get(IDS_DLG_PROC_SYSTEM), Text::Format(IDS_DLG_PROC_SYSTEM_MESSAGE, process->display),
                                            Text::Get(IDS_CONTINUE), true)) {
        return;
    }
    const std::wstring rule = ToWide("block " + AppToken(*process));
    ShowPage(Page::Firewall);
    if (AddRule(rule) && !m_ctl->FirewallEnabled()) SetStatus(Level::Warning, Text::Get(IDS_MSG_RULE_FW_OFF));
}

void MainWindow::LimitProcess() {
    const auto process = SelectedProcess();
    if (!Actionable(process.get())) return;
    DialogSpec spec;
    spec.heading = Text::Format(IDS_DLG_LIMIT, process->display);
    spec.message = Text::Get(IDS_DLG_LIMIT_MESSAGE);
    spec.fields.push_back({Text::Get(IDS_DLG_LIMIT_FIELD), std::to_wstring(m_profile.rateKbps ? m_profile.rateKbps : 1000), L"1000"});
    spec.ok = Text::Get(IDS_DLG_LIMIT_OK);
    spec.validate = [](const std::vector<std::wstring>& v) -> std::optional<std::wstring> {
        if (v.empty() || v[0].empty()) return std::wstring();  // nothing typed yet: no message, OK disabled
        if (!ParseKbps(v)) return Text::Get(IDS_DLG_LIMIT_BAD);
        return std::nullopt;
    };
    spec.preview = [](const std::vector<std::wstring>& v) {
        const auto kbps = ParseKbps(v);
        return kbps ? std::format(L"{}  ≈  {}", RateText(*kbps), FormatRate(*kbps * 125.0)) : std::wstring();
    };
    const DialogResult result = RunDialog(m_hwnd, spec);
    const auto kbps = result.button == 1 ? ParseKbps(result.values) : std::nullopt;
    if (!kbps) return;

    // A clean shaper for this program alone: no added delay or loss, both directions.
    m_profile.latencyMs = 0;
    m_profile.jitterMs = 0;
    m_profile.lossPercent = 0;
    m_profile.rateKbps = *kbps;
    m_profile.dir = Dir::Both;
    m_profile.preserveOrder = true;
    m_profile.match = AppToken(*process);
    m_profile.enabled = true;
    SyncSimulatorControls();
    ApplyProfile();
    m_delayHistory.clear();
    m_dropHistory.clear();
    m_lastSampleUs = 0;
    if (m_ctl->Impairment().enabled) SetStatus(Level::Success, Text::Format(IDS_MSG_PROC_LIMITED, process->display, RateText(*kbps)));
    UpdateControls();
}

void MainWindow::ImpairProcess() {
    const auto process = SelectedProcess();
    if (!Actionable(process.get())) return;
    SetWindowTextW(m_matchEdit, ToWide(AppToken(*process)).c_str());  // EN_CHANGE checks and applies it
    ShowPage(Page::Simulator);
}

void MainWindow::ShowProcessPackets() {
    const auto process = SelectedProcess();
    if (!Actionable(process.get())) return;
    SetWindowTextW(m_filterEdit, process->display.c_str());  // EN_CHANGE rebuilds the view
    ShowPage(Page::Capture);
}

void MainWindow::OpenProcessFolder() {
    const auto process = SelectedProcess();
    if (!process || process->path.empty()) return;
    if (PIDLIST_ABSOLUTE item = ILCreateFromPathW(process->path.c_str())) {
        SHOpenFolderAndSelectItems(item, 0, nullptr, 0);
        ILFree(item);
    }
}

void MainWindow::CopyProcessPath() {
    const auto process = SelectedProcess();
    if (!process || process->path.empty()) return;
    if (CopyToClipboard(m_hwnd, process->path)) SetStatus(Level::Info, Text::Get(IDS_PROC_COPIED));
}

}  // namespace WS::Ui
