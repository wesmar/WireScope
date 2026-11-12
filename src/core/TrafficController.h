// WireScope - Data plane coordinator for one adapter.
//
// Capture, firewall, impairment simulator and kill switch all need the adapter mode and the
// driver's (single, global) static filter table. This class is their only owner: every change is a
// transition from one complete State to the next, computed as a Plan (adapter mode, engine config,
// filter table) and carried out in an order that never lets a packet slip through a half-applied
// state:
//
//   * The driver evaluates static filters in both tunnel mode and listen mode. When kernel offload
//     covers every active firewall rule and the simulator is off, listen mode lets wsddntf drop
//     blocked packets and pass allowed packets directly at DISPATCH_LEVEL; tunnelling is used only
//     when user mode must judge process rules, run the link simulator, or enforce without offload.
//   * Before the engine changes or leaves its mode, a "quiesce" table (the same rules without any
//     REDIRECT) stops new packets from entering the queue; the engine then drains it.
//   * Firewall "allow" rules become REDIRECT while user mode needs the traffic (capture, monitor,
//     simulator), PASS otherwise; the default policy is the last entry.
//
// Static filters of other applications are kept behind WireScope's entries and restored when it is
// done. A registry record (HKCU\Software\WireScope) lets the next start repair the driver state if a
// session ends without cleaning up, and a global mutex keeps two instances from fighting over it.
#pragma once
#include "core/DriverBridge.h"
#include "core/Impairment.h"
#include "core/PacketEngine.h"
#include "core/Rules.h"
#include "support/Handle.h"
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace WS {

struct FirewallStatus {
    std::unordered_map<uint64_t, HitCounter> rules;  // by Rule::id
    HitCounter policy;                               // packets that met the default policy
    HitCounter killSwitch;
    bool kernelCounters{false}; // the driver reported hits for WireScope's entries
    size_t ownEntries{0};      // driver entries WireScope installed
    size_t foreignEntries{0};  // entries of other applications kept in the table
    bool installed{false};
};

class TrafficController {
public:
    explicit TrafficController(std::shared_ptr<DriverBridge> bridge);
    ~TrafficController();

    TrafficController(const TrafficController&) = delete;
    TrafficController& operator=(const TrafficController&) = delete;

    // Call once the bridge is connected. Takes the data-plane lock and repairs what a session that
    // crashed left in the driver. Returns a message for the user, or an empty string.
    std::wstring Attach();

    [[nodiscard]] PacketEngine& Engine() noexcept { return *m_engine; }
    [[nodiscard]] bool CanControl() const noexcept { return m_control; }
    [[nodiscard]] std::expected<void, std::wstring> FilterSupport();
    [[nodiscard]] std::expected<size_t, std::wstring> ForeignFilterCount();

    [[nodiscard]] HANDLE Adapter() const noexcept { return m_adapter; }
    // The process monitor follows the new adapter; every other feature must be off first.
    [[nodiscard]] std::expected<void, std::wstring> SetAdapter(HANDLE adapter);
    [[nodiscard]] bool Active() const noexcept;         // anything uses the adapter
    [[nodiscard]] bool AdapterLocked() const noexcept;  // a feature that keeps the adapter from changing

    [[nodiscard]] bool Capturing() const noexcept { return m_state.capture; }
    [[nodiscard]] bool Monitoring() const noexcept { return m_state.monitor; }
    [[nodiscard]] bool KillSwitch() const noexcept { return m_state.kill; }
    [[nodiscard]] bool FirewallEnabled() const noexcept { return m_state.firewall; }
    [[nodiscard]] RuleAction Policy() const noexcept { return m_state.policy; }
    [[nodiscard]] const std::vector<Rule>& Rules() const noexcept { return m_state.rules; }
    [[nodiscard]] const ImpairmentProfile& Impairment() const noexcept { return m_state.impairment; }
    [[nodiscard]] bool KernelOffload() const noexcept { return m_state.kernelOffload; }

    [[nodiscard]] std::expected<void, std::wstring> SetCapture(bool on);
    // Counts traffic per process: listen mode (copies only, traffic is never changed) unless a feature
    // already brings every packet to user mode.
    [[nodiscard]] std::expected<void, std::wstring> SetMonitor(bool on);
    [[nodiscard]] std::expected<void, std::wstring> SetKillSwitch(bool on);
    [[nodiscard]] std::expected<void, std::wstring> SetFirewall(bool on);
    // Rules with id 0 get a fresh id; on failure the previous rules stay in force.
    [[nodiscard]] std::expected<void, std::wstring> SetRules(std::vector<Rule> rules);
    [[nodiscard]] std::expected<void, std::wstring> SetPolicy(RuleAction policy);
    [[nodiscard]] std::expected<void, std::wstring> SetImpairment(const ImpairmentProfile& profile);
    // Compiles L2/L3/L4 firewall rules into the driver's 181-byte STATIC_FILTER table for kernel-mode
    // enforcement at DISPATCH_LEVEL; process rules (app=) are redirected to the user-mode engine.
    [[nodiscard]] std::expected<void, std::wstring> SetKernelOffload(bool on);
    [[nodiscard]] uint64_t NewRuleId() noexcept { return m_nextRuleId++; }

    // Everything off; the driver table and the adapter mode are returned to how they were found.
    void Shutdown() noexcept;

    [[nodiscard]] FirewallStatus PollFirewall();

private:
    struct State {
        bool capture{false};
        bool monitor{false};
        bool kill{false};
        bool firewall{false};
        bool kernelOffload{true};
        RuleAction policy{RuleAction::Allow};
        std::vector<Rule> rules;
        ImpairmentProfile impairment;
        Selector impairmentMatch;
    };
    struct Plan {
        DWORD mode{MODE_BYPASS};
        bool engine{false};
        EngineConfig config;
        bool ownTable{false};
        std::vector<STATIC_FILTER> table;
        std::vector<int64_t> owners;
        std::vector<STATIC_FILTER> quiesce;
        std::vector<int64_t> quiesceOwners;
    };

    [[nodiscard]] std::expected<void, std::wstring> Transition(State next);
    [[nodiscard]] std::expected<Plan, std::wstring> MakePlan(const State& s);
    [[nodiscard]] std::expected<void, std::wstring> Compose(const State& s, bool userAll, bool userSelected, bool withForeign,
                                                            std::vector<STATIC_FILTER>& table, std::vector<int64_t>& owners) const;
    [[nodiscard]] std::expected<void, std::wstring> Execute(const Plan& plan);
    [[nodiscard]] std::expected<void, std::wstring> WriteTable(const std::vector<STATIC_FILTER>& table,
                                                               const std::vector<int64_t>& owners);
    [[nodiscard]] std::expected<void, std::wstring> RestoreForeign();
    void HarvestCounters();
    void WriteRecovery();
    std::wstring Recover();

    std::shared_ptr<DriverBridge> m_bridge;
    std::unique_ptr<PacketEngine> m_engine;
    HANDLE m_adapter{nullptr};
    State m_state;
    HANDLE m_modeAdapter{nullptr};  // adapter whose mode WireScope changed (for recovery)

    std::optional<std::expected<void, std::wstring>> m_filterSupport;
    bool m_tableInstalled{false};
    std::vector<STATIC_FILTER> m_installed;
    std::vector<int64_t> m_owners;
    std::vector<STATIC_FILTER> m_foreign;  // what the table held before WireScope wrote to it
    std::unordered_map<int64_t, HitCounter> m_totals;

    Handle m_mutex;
    bool m_control{false};
    uint64_t m_nextRuleId{1};
};

} // namespace WS
