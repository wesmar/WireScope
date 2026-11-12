#include "core/TrafficController.h"
#include "resources/resource.h"
#include "support/Common.h"
#include "support/Language.h"
#include "support/Settings.h"
#include "support/Text.h"
#include <cstring>
#include <format>

namespace WS {

namespace {

constexpr wchar_t kMutexName[] = L"Global\\WireScope.DataPlane";
constexpr wchar_t kLocalMutexName[] = L"Local\\WireScope.DataPlane";
constexpr wchar_t kRecoveryValue[] = L"DataPlaneRecovery";

constexpr int64_t kOwnerKill = -1;
constexpr int64_t kOwnerSelector = -2;
constexpr int64_t kOwnerForeign = -3;
constexpr int64_t kOwnerPolicy = -4;
constexpr int64_t kOwnerEngine = -5;  // from the first process rule on, the engine decides

#pragma pack(push, 1)
struct RecoveryRecord {
    uint32_t magic;       // 'WSDP'
    uint32_t version;
    uint64_t bootTime;    // the driver forgets everything on reboot
    uint64_t adapter;     // adapter whose mode WireScope changed, 0 = none
    uint32_t tableSet;    // WireScope's table is in the driver
    uint32_t foreignCount;
    // followed by foreignCount STATIC_FILTER entries
};
#pragma pack(pop)
constexpr uint32_t kRecoveryMagic = 0x50445357;

bool SameEntry(const STATIC_FILTER& a, const STATIC_FILTER& b) noexcept {
    return a.m_Adapter == b.m_Adapter && a.m_dwDirectionFlags == b.m_dwDirectionFlags && a.m_FilterAction == b.m_FilterAction &&
           a.m_ValidFields == b.m_ValidFields &&
           std::memcmp(&a.m_DataLinkFilter, &b.m_DataLinkFilter, sizeof(a.m_DataLinkFilter)) == 0 &&
           std::memcmp(&a.m_NetworkFilter, &b.m_NetworkFilter, sizeof(a.m_NetworkFilter)) == 0 &&
           std::memcmp(&a.m_TransportFilter, &b.m_TransportFilter, sizeof(a.m_TransportFilter)) == 0;
}

bool SameTable(const std::vector<STATIC_FILTER>& a, const std::vector<STATIC_FILTER>& b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (!SameEntry(a[i], b[i])) return false;
    }
    return true;
}

} // namespace

TrafficController::TrafficController(std::shared_ptr<DriverBridge> bridge)
    : m_bridge(std::move(bridge)), m_engine(std::make_unique<PacketEngine>(m_bridge)) {
}

TrafficController::~TrafficController() {
    Shutdown();
}

std::wstring TrafficController::Attach() {
    if (!m_mutex) m_mutex.reset(CreateMutexW(nullptr, FALSE, kMutexName));
    if (!m_mutex) m_mutex.reset(CreateMutexW(nullptr, FALSE, kLocalMutexName));
    if (m_mutex && !m_control) {
        const DWORD waited = WaitForSingleObject(m_mutex.get(), 0);
        m_control = waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED;  // abandoned: a session crashed
    }
    if (!m_control) {
        return Text::Get(IDS_DP_OTHER_INSTANCE);
    }
    return Recover();
}

std::expected<void, std::wstring> TrafficController::FilterSupport() {
    if (!m_bridge->IsConnected()) return std::unexpected(L"Driver not connected");
    if (!m_filterSupport) {
        auto count = m_bridge->GetStaticFilterCount();
        if (!count) {
            m_filterSupport = std::unexpected(count.error());
        } else if (*count > 0) {
            // A non-empty table lets us verify the entry layout before writing anything.
            auto table = m_bridge->ReadStaticFilters();
            m_filterSupport = table ? std::expected<void, std::wstring>() : std::unexpected(table.error());
        } else {
            m_filterSupport = std::expected<void, std::wstring>();
        }
    }
    return *m_filterSupport;
}

std::expected<size_t, std::wstring> TrafficController::ForeignFilterCount() {
    if (m_tableInstalled) return m_foreign.size();
    if (auto support = FilterSupport(); !support) return std::unexpected(support.error());
    auto table = m_bridge->ReadStaticFilters();
    if (!table) return std::unexpected(table.error());
    return table->size();
}

std::expected<void, std::wstring> TrafficController::SetAdapter(HANDLE adapter) {
    if (adapter == m_adapter) return {};
    if (AdapterLocked()) {
        return std::unexpected(Text::Get(IDS_DP_ADAPTER_BUSY));
    }
    const bool monitor = m_state.monitor;
    if (monitor) {
        if (auto r = SetMonitor(false); !r) return r;
    }
    m_adapter = adapter;
    if (monitor) return SetMonitor(true);
    return {};
}

bool TrafficController::Active() const noexcept {
    return AdapterLocked() || m_state.monitor;
}

bool TrafficController::AdapterLocked() const noexcept {
    return m_state.capture || m_state.kill || m_state.firewall || m_state.impairment.enabled;
}

std::expected<void, std::wstring> TrafficController::SetCapture(bool on) {
    if (on == m_state.capture) return {};
    State next = m_state;
    next.capture = on;
    return Transition(std::move(next));
}

std::expected<void, std::wstring> TrafficController::SetMonitor(bool on) {
    if (on == m_state.monitor) return {};
    State next = m_state;
    next.monitor = on;
    return Transition(std::move(next));
}

std::expected<void, std::wstring> TrafficController::SetKillSwitch(bool on) {
    if (on == m_state.kill) return {};
    State next = m_state;
    next.kill = on;
    return Transition(std::move(next));
}

std::expected<void, std::wstring> TrafficController::SetFirewall(bool on) {
    if (on == m_state.firewall) return {};
    State next = m_state;
    next.firewall = on;
    return Transition(std::move(next));
}

std::expected<void, std::wstring> TrafficController::SetRules(std::vector<Rule> rules) {
    for (Rule& r : rules) {
        if (r.id == 0) r.id = m_nextRuleId++;
        else if (r.id >= m_nextRuleId) m_nextRuleId = r.id + 1;
    }
    State next = m_state;
    next.rules = std::move(rules);
    if (!m_state.firewall) {
        m_state = std::move(next);
        return {};
    }
    return Transition(std::move(next));
}

std::expected<void, std::wstring> TrafficController::SetPolicy(RuleAction policy) {
    if (policy == m_state.policy) return {};
    State next = m_state;
    next.policy = policy;
    if (!m_state.firewall) {
        m_state = std::move(next);
        return {};
    }
    return Transition(std::move(next));
}

std::expected<void, std::wstring> TrafficController::SetKernelOffload(bool on) {
    if (on == m_state.kernelOffload) return {};
    State next = m_state;
    next.kernelOffload = on;
    if (!m_state.firewall && !m_state.kill) {
        m_state = std::move(next);
        return {};
    }
    return Transition(std::move(next));
}

std::expected<void, std::wstring> TrafficController::SetImpairment(const ImpairmentProfile& profile) {
    auto selector = ImpairmentSelector(profile);
    if (!selector) return std::unexpected(ToWide(selector.error()));
    State next = m_state;
    next.impairment = profile;
    next.impairmentMatch = *selector;
    if (!profile.enabled && !m_state.impairment.enabled) {
        m_state = std::move(next);
        return {};
    }
    return Transition(std::move(next));
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------
std::expected<void, std::wstring> TrafficController::Compose(const State& s, bool userAll, bool userSelected, bool withForeign,
                                                             std::vector<STATIC_FILTER>& table, std::vector<int64_t>& owners) const {
    auto append = [&](const std::vector<STATIC_FILTER>& entries, int64_t owner) {
        table.insert(table.end(), entries.begin(), entries.end());
        owners.insert(owners.end(), entries.size(), owner);
    };
    const bool offload = s.kernelOffload;
    const bool quiesce = !userAll && !userSelected && !withForeign;
    if (s.kill && (offload || quiesce)) append({CatchAll(FILTER_ACTION_DROP, m_adapter)}, kOwnerKill);
    if (s.firewall && offload) {
        for (size_t i = 0; i < s.rules.size(); ++i) {
            const Rule& rule = s.rules[i];
            if (!rule.enabled) continue;
            if (rule.match.app.set || rule.match.icmpTypeSet) {
                // The driver knows no processes and does not inspect ICMP type codes. First match wins,
                // so this rule and every rule after it must be judged by the engine: send the rest of
                // the traffic to user mode.
                append({CatchAll(FILTER_ACTION_REDIRECT, m_adapter)}, kOwnerEngine);
                break;
            }
            const DWORD action = rule.action == RuleAction::Block ? FILTER_ACTION_DROP
                                 : userAll                       ? FILTER_ACTION_REDIRECT
                                                                 : FILTER_ACTION_PASS;
            auto entries = Compile(rule.match, action, m_adapter);
            if (!entries) {
                return std::unexpected(Text::Format(IDS_DP_RULE, i + 1, ToWide(RuleText(rule)), ToWide(entries.error())));
            }
            append(*entries, static_cast<int64_t>(rule.id));
        }
    }
    if (userSelected) {
        auto entries = Compile(s.impairmentMatch, FILTER_ACTION_REDIRECT, m_adapter);
        if (!entries) return std::unexpected(Text::Format(IDS_DP_MATCH, ToWide(entries.error())));
        append(*entries, kOwnerSelector);
    }
    if (withForeign) append(m_foreign, kOwnerForeign);
    const DWORD policy = (s.firewall && offload && s.policy == RuleAction::Block) ? FILTER_ACTION_DROP
                         : userAll                                               ? FILTER_ACTION_REDIRECT
                                                                                 : FILTER_ACTION_PASS;
    append({CatchAll(policy, m_adapter)}, kOwnerPolicy);
    return {};
}

std::expected<TrafficController::Plan, std::wstring> TrafficController::MakePlan(const State& s) {
    const bool filters = FilterSupport().has_value();
    if (s.kernelOffload && (s.firewall || s.kill) && !filters) {
        return std::unexpected(Text::Format(IDS_DP_OFFLOAD, FilterSupport().error()));
    }
    if (filters && !m_tableInstalled) {
        // Fresh snapshot of what other applications have in the table, to keep and restore it.
        auto table = m_bridge->ReadStaticFilters();
        if (!table) return std::unexpected(table.error());
        m_foreign = std::move(*table);
    }

    const Selector& match = s.impairmentMatch;
    const bool selectsAll = match.dir == Dir::Both && match.MatchesAllFrames();
    const bool selectsApp = match.app.set || match.icmpTypeSet;  // the kernel cannot select by process or ICMP type
    const bool offload = s.kernelOffload && filters;

    size_t firstEngineRule = 0;
    bool needsEngineFirewall = false;
    for (const Rule& r : s.rules) {
        if (!r.enabled) continue;
        if (r.match.app.set || r.match.icmpTypeSet) {
            needsEngineFirewall = true;
            break;
        }
        if (offload) ++firstEngineRule;
    }
    const bool kernelEnforcesAll = offload && (!s.firewall || !needsEngineFirewall) && !s.impairment.enabled;

    // User mode sees everything while capturing or monitoring, while the engine enforces the firewall
    // or the kill switch, or when the simulator cannot leave the selection to the kernel.
    const bool userAll = s.capture || s.monitor || ((s.firewall || s.kill) && !kernelEnforcesAll) ||
                         (s.impairment.enabled && (selectsAll || selectsApp || s.firewall || !filters));
    const bool userSelected = s.impairment.enabled && !userAll;

    Plan p;
    // wsddntf evaluates static filters in both MODE_TUNNEL (0x03) and MODE_LISTEN (0x0C). When kernel
    // offload covers every active rule and the simulator is off, MODE_LISTEN lets the driver drop
    // blocked packets and pass allowed packets at DISPATCH_LEVEL without user-mode re-injection.
    const bool tunnel = s.impairment.enabled || ((s.kill || s.firewall) && !kernelEnforcesAll);
    const bool listen = s.capture || s.monitor || ((s.kill || s.firewall) && kernelEnforcesAll);
    p.engine = tunnel || listen;
    p.mode = tunnel ? MODE_TUNNEL : listen ? MODE_LISTEN : MODE_BYPASS;

    p.config.mode = p.mode;
    p.config.capture = s.capture;
    p.config.killSwitch = s.kill;
    p.config.firewall = s.firewall;
    p.config.policy = s.policy;
    for (const Rule& r : s.rules) {
        if (r.enabled) p.config.rules.push_back(r);
    }
    p.config.firstEngineRule = offload ? firstEngineRule : 0;
    p.config.policyInKernel = offload && !needsEngineFirewall;
    p.config.impairment = s.impairment;
    p.config.impairmentMatch = s.impairmentMatch;
    p.config.accounting = s.capture || s.monitor || (tunnel && userAll);  // partial traffic would give wrong totals

    p.ownTable = filters && ((offload && (s.kill || s.firewall)) || userSelected);
    if (p.ownTable) {
        if (auto r = Compose(s, userAll, userSelected, true, p.table, p.owners); !r) return std::unexpected(r.error());
    }
    if (filters) {
        if (auto r = Compose(s, false, false, false, p.quiesce, p.quiesceOwners); !r) return std::unexpected(r.error());
    }
    return p;
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------
std::expected<void, std::wstring> TrafficController::Transition(State next) {
    if (!m_bridge->IsConnected()) return std::unexpected(Text::Get(IDS_DP_NOT_CONNECTED));
    if (!m_adapter && (next.capture || next.monitor || next.kill || next.firewall || next.impairment.enabled)) {
        return std::unexpected(Text::Get(IDS_DP_NO_ADAPTER));
    }
    const bool control = next.kill || next.firewall || next.impairment.enabled;
    if (control && !m_control) {
        return std::unexpected(Text::Get(IDS_DP_OTHER_INSTANCE_CLOSE));
    }

    auto plan = MakePlan(next);
    if (!plan) return std::unexpected(plan.error());
    auto result = Execute(*plan);
    if (result) {
        m_state = std::move(next);
        WriteRecovery();
        return {};
    }

    // Put the previous state back; if even that fails, turn everything off so a half-applied
    // change can never leave the network closed.
    if (auto back = MakePlan(m_state); !back || !Execute(*back)) {
        State off;
        off.rules = m_state.rules;
        off.policy = m_state.policy;
        off.impairment = m_state.impairment;
        off.impairment.enabled = false;
        if (auto offPlan = MakePlan(off); offPlan) (void)Execute(*offPlan);
        m_state = std::move(off);
    }
    WriteRecovery();
    return result;
}

std::expected<void, std::wstring> TrafficController::Execute(const Plan& p) {
    const bool running = m_engine->IsRunning();
    auto quiesce = [&]() -> std::expected<void, std::wstring> {
        if (p.quiesce.empty()) return {};  // no filter support: the engine copes with the race
        return WriteTable(p.quiesce, p.quiesceOwners);
    };
    auto table = [&]() -> std::expected<void, std::wstring> {
        return p.ownTable ? WriteTable(p.table, p.owners) : RestoreForeign();
    };

    if (p.engine) {
        if (!running) {
            // The record exists before the adapter leaves bypass mode.
            m_modeAdapter = m_adapter;
            WriteRecovery();
            if (auto r = m_engine->Start(m_adapter, p.config); !r) {
                m_modeAdapter = nullptr;
                return r;
            }
        } else {
            if (p.mode != m_engine->Mode()) {
                if (auto r = quiesce(); !r) return r;
            }
            if (auto r = m_engine->Reconfigure(p.config); !r) return r;
        }
        return table();
    }

    if (running) {
        if (auto r = quiesce(); !r) return r;
        m_engine->Stop(MODE_BYPASS);  // drains and re-injects what is queued or held
        m_modeAdapter = nullptr;
    }
    return table();
}

std::expected<void, std::wstring> TrafficController::WriteTable(const std::vector<STATIC_FILTER>& table,
                                                                const std::vector<int64_t>& owners) {
    if (m_tableInstalled && SameTable(table, m_installed)) {
        m_owners = owners;
        return {};
    }
    HarvestCounters();
    if (!m_tableInstalled) {
        m_tableInstalled = true;  // the record must exist before the driver holds our table
        WriteRecovery();
    }
    if (auto r = m_bridge->WriteStaticFilters(table); !r) {
        // WriteStaticFilters cleared the table; put the other applications' filters back.
        (void)m_bridge->WriteStaticFilters(m_foreign);
        m_installed.clear();
        m_owners.clear();
        m_tableInstalled = false;
        WriteRecovery();
        m_filterSupport.reset();
        return std::unexpected(r.error());
    }
    m_installed = table;
    m_owners = owners;
    return {};
}

std::expected<void, std::wstring> TrafficController::RestoreForeign() {
    if (!m_tableInstalled) return {};
    HarvestCounters();
    if (auto r = m_bridge->WriteStaticFilters(m_foreign); !r) return r;
    m_tableInstalled = false;
    m_installed.clear();
    m_owners.clear();
    return {};
}

void TrafficController::HarvestCounters() {
    if (!m_tableInstalled || m_installed.empty()) return;
    auto table = m_bridge->ReadStaticFilters();
    if (!table || table->size() != m_owners.size()) return;
    for (size_t i = 0; i < table->size(); ++i) {
        const STATIC_FILTER& f = (*table)[i];
        m_totals[m_owners[i]] += HitCounter{f.m_PacketsIn + f.m_PacketsOut, f.m_BytesIn + f.m_BytesOut};
    }
}

FirewallStatus TrafficController::PollFirewall() {
    FirewallStatus status;
    status.installed = m_tableInstalled;
    status.foreignEntries = m_foreign.size();
    auto totals = m_totals;
    if (m_tableInstalled) {
        status.ownEntries = m_installed.size() >= m_foreign.size() ? m_installed.size() - m_foreign.size() : m_installed.size();
        if (auto table = m_bridge->ReadStaticFilters(); table && table->size() == m_owners.size()) {
            for (size_t i = 0; i < table->size(); ++i) {
                const STATIC_FILTER& f = (*table)[i];
                totals[m_owners[i]] += HitCounter{f.m_PacketsIn + f.m_PacketsOut, f.m_BytesIn + f.m_BytesOut};
            }
        }
    }
    for (const auto& [owner, hits] : totals) {
        if (hits.packets && owner != kOwnerForeign) status.kernelCounters = true;
    }
    // The engine's own counters: authoritative whenever it enforces the rules.
    const auto engine = m_engine->RuleHits();
    for (const Rule& r : m_state.rules) {
        HitCounter hits = totals[static_cast<int64_t>(r.id)];
        if (const auto it = engine.find(r.id); it != engine.end()) hits += it->second;
        status.rules[r.id] = hits;
    }
    status.policy = totals[kOwnerPolicy];
    if (const auto it = engine.find(0); it != engine.end()) status.policy += it->second;
    status.killSwitch = totals[kOwnerKill];
    return status;
}

void TrafficController::Shutdown() noexcept {
    try {
        if (m_bridge && m_bridge->IsConnected() && Active()) {
            State off;
            off.rules = m_state.rules;
            off.policy = m_state.policy;
            off.impairment = m_state.impairment;
            off.impairment.enabled = false;
            if (auto plan = MakePlan(off); plan) (void)Execute(*plan);
            m_state = std::move(off);
        }
        // Whatever the plan could not do, do directly.
        if (m_engine && m_engine->IsRunning()) m_engine->Stop(MODE_BYPASS);
        if (m_bridge && m_bridge->IsConnected()) {
            (void)RestoreForeign();
            if (m_modeAdapter) (void)m_bridge->SetAdapterMode(m_modeAdapter, MODE_BYPASS);
            m_modeAdapter = nullptr;
        }
        WriteRecovery();
    } catch (...) {
    }
    if (m_control && m_mutex) ReleaseMutex(m_mutex.get());
    m_control = false;
}

// ---------------------------------------------------------------------------
// Crash recovery
// ---------------------------------------------------------------------------
void TrafficController::WriteRecovery() {
    const bool modeChanged = m_modeAdapter != nullptr;
    if (!m_tableInstalled && !modeChanged) {
        Settings::Delete(kRecoveryValue);
        return;
    }
    std::vector<uint8_t> data(sizeof(RecoveryRecord) + m_foreign.size() * sizeof(STATIC_FILTER));
    RecoveryRecord record{};
    record.magic = kRecoveryMagic;
    record.version = 1;
    record.bootTime = BootTimeSeconds();
    record.adapter = modeChanged ? static_cast<uint64_t>(reinterpret_cast<uintptr_t>(m_modeAdapter)) : 0;
    record.tableSet = m_tableInstalled ? 1u : 0u;
    record.foreignCount = static_cast<uint32_t>(m_foreign.size());
    std::memcpy(data.data(), &record, sizeof(record));
    if (!m_foreign.empty()) std::memcpy(data.data() + sizeof(record), m_foreign.data(), m_foreign.size() * sizeof(STATIC_FILTER));
    Settings::WriteBinary(kRecoveryValue, data);
}

std::wstring TrafficController::Recover() {
    const auto data = Settings::ReadBinary(kRecoveryValue);
    if (!data) return {};
    Settings::Delete(kRecoveryValue);
    if (data->size() < sizeof(RecoveryRecord)) return {};
    RecoveryRecord record{};
    std::memcpy(&record, data->data(), sizeof(record));
    if (record.magic != kRecoveryMagic || data->size() != sizeof(record) + record.foreignCount * sizeof(STATIC_FILTER)) return {};
    // After a reboot the driver starts clean; the record is stale.
    const uint64_t boot = BootTimeSeconds();
    if ((boot > record.bootTime ? boot - record.bootTime : record.bootTime - boot) > 120) return {};

    bool mode = false, table = false;
    if (record.adapter) {
        mode = m_bridge->SetAdapterMode(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(record.adapter)), MODE_BYPASS).has_value();
    }
    if (record.tableSet) {
        std::vector<STATIC_FILTER> foreign(record.foreignCount);
        if (record.foreignCount) {
            std::memcpy(foreign.data(), data->data() + sizeof(record), record.foreignCount * sizeof(STATIC_FILTER));
        }
        table = m_bridge->WriteStaticFilters(foreign).has_value();
    }
    if (mode && table) return Text::Get(IDS_DP_RECOVERED_BOTH);
    if (mode) return Text::Get(IDS_DP_RECOVERED_MODE);
    if (table) return Text::Get(IDS_DP_RECOVERED_TABLE);
    return {};
}

} // namespace WS
