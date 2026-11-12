// WireScope - Packet engine: the worker thread that owns one adapter's packet queue.
//
// Listen mode: the driver queues copies; the engine decodes them and never re-injects.
// Tunnel mode: the driver queues the originals; the engine must re-inject every packet it does not
// mean to drop. This is where the kill switch, the firewall rules and the impairment simulator act,
// in that order.
//
// Mode changes happen on the worker thread (Reconfigure), between two reads, so a packet is never
// re-injected twice or forgotten: the queue is drained with the old meaning, the delay line is
// flushed when tunnelling ends, then the new mode is set. TrafficController installs a "quiesce"
// filter table around the switch so that no packet enters the queue while its meaning changes.
#pragma once
#include "core/DriverBridge.h"
#include "core/Impairment.h"
#include "core/PacketParser.h"
#include "core/PcapWriter.h"
#include "core/ProcessTraffic.h"
#include "support/Handle.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <thread>
#include <unordered_map>

namespace WS {

struct EngineStats {
    uint64_t TotalPackets{0};   // every packet read from the driver
    uint64_t TotalBytes{0};
    double   PacketsPerSec{0.0};
    double   BytesPerSec{0.0};
    uint64_t DnsQueries{0};
    uint64_t TcpPackets{0};
    uint64_t UdpPackets{0};
    uint64_t IcmpPackets{0};
    uint64_t DroppedPackets{0};  // simulator + kill switch

    uint64_t Reinjected{0};
    uint64_t SendErrors{0};
    uint64_t KillDropped{0};
    uint64_t FirewallBlocked{0};
    uint64_t FirewallAllowed{0};

    uint64_t SimSelected{0};     // packets the simulator's match selected
    uint64_t SimDelayed{0};
    uint64_t SimDropped{0};
    uint64_t SimOverflow{0};     // dropped because the shaper queue or the delay line was full
    uint64_t SimBytes{0};        // bytes of selected packets let through (delayed or passed)
    uint64_t SimDelaySumUs{0};
    uint32_t SimInFlight{0};
    bool     HighResolutionTimer{false};
    DWORD    Mode{MODE_BYPASS};
};

struct EngineConfig {
    DWORD             mode{MODE_LISTEN};
    bool              capture{true};          // decode and keep packets for display / pcap
    bool              killSwitch{false};      // tunnel: drop everything that is read
    bool              firewall{false};        // tunnel: first matching rule decides, else the policy
    RuleAction        policy{RuleAction::Allow};
    std::vector<Rule> rules;                  // enabled rules, in order
    size_t            firstEngineRule{0};     // rules before this index are counted by the kernel table
    bool              policyInKernel{false};  // default policy is counted by the kernel table
    ImpairmentProfile impairment;             // tunnel: honoured when enabled
    Selector          impairmentMatch;
    bool              accounting{false};      // count traffic per process (user mode sees every packet)
};

using PacketCallback = std::function<void(const DecodedPacket&)>;
using PacketRef = std::shared_ptr<const DecodedPacket>;

class PacketEngine {
public:
    explicit PacketEngine(std::shared_ptr<DriverBridge> bridge);
    ~PacketEngine();

    PacketEngine(const PacketEngine&) = delete;
    PacketEngine& operator=(const PacketEngine&) = delete;

    [[nodiscard]] bool IsRunning() const noexcept;
    [[nodiscard]] bool IsRecordingPcap() const noexcept { return m_pcap.IsOpen(); }
    [[nodiscard]] DWORD Mode() const noexcept { return m_mode.load(); }

    // Returns once the worker has set the adapter mode (or failed to).
    [[nodiscard]] std::expected<void, std::wstring> Start(HANDLE hAdapter, const EngineConfig& config = {});
    // Applied by the worker; returns once it is in effect.
    [[nodiscard]] std::expected<void, std::wstring> Reconfigure(const EngineConfig& config);
    // Drains the queue, releases held packets and leaves the adapter in finalMode.
    void Stop(DWORD finalMode = MODE_BYPASS) noexcept;

    [[nodiscard]] bool StartPcap(const std::wstring& filePath);
    void StopPcap() noexcept;

    void SetPacketCallback(PacketCallback cb);
    [[nodiscard]] EngineStats GetStats() const;
    [[nodiscard]] std::vector<PacketRef> GetRecentPackets(size_t maxCount = SIZE_MAX) const;
    // Appends the kept packets whose Index is greater than afterIndex.
    void CopyPacketsAfter(uint64_t afterIndex, std::vector<PacketRef>& out) const;
    void ClearPackets() noexcept;
    [[nodiscard]] uint64_t ClearGeneration() const noexcept;  // changes on ClearPackets
    // Firewall hits by Rule::id since the engine was created; id 0 is the default policy.
    [[nodiscard]] std::unordered_map<uint64_t, HitCounter> RuleHits() const;
    // Traffic per process instance counted while accounting was on, since start or the last reset.
    [[nodiscard]] std::vector<ProcessTraffic> ProcessTotals() const;
    void ResetProcessTotals() noexcept;
    [[nodiscard]] bool Accounting() const noexcept { return m_accounting.load(); }

private:
    struct Worker;
    void WorkerMain(std::stop_token stopToken, HANDLE hAdapter, EngineConfig config);
    size_t Drain(Worker& w, size_t limit, DWORD semantics);
    void Process(Worker& w, std::unique_ptr<INTERMEDIATE_BUFFER>& buffer, DWORD semantics);
    void Send(Worker& w, INTERMEDIATE_BUFFER& buffer);
    void FlushDelayed(Worker& w, bool send);
    void ApplyPending(Worker& w);
    void CommitTraffic(Worker& w);
    void Shutdown(Worker& w, DWORD finalMode);
    void UpdateRates();

    std::shared_ptr<DriverBridge> m_bridge;
    std::jthread m_worker;
    Handle m_wake;
    std::atomic<DWORD> m_mode{MODE_BYPASS};
    std::atomic<bool> m_highResolution{false};
    std::atomic<bool> m_accounting{false};

    // Control handshake with the worker
    enum class Phase { Idle, Starting, Running, Stopped };
    mutable std::mutex m_ctlMutex;
    std::condition_variable m_ctlCv;
    Phase m_phase{Phase::Idle};
    std::optional<EngineConfig> m_pending;
    uint64_t m_requested{0};
    uint64_t m_applied{0};
    std::wstring m_ctlError;
    DWORD m_finalMode{MODE_BYPASS};

    // Captured packets
    mutable std::mutex m_mutex;
    PcapWriter m_pcap;
    PacketCallback m_callback;
    std::deque<PacketRef> m_recentPackets;
    size_t m_maxRecentPackets{20000};
    uint64_t m_clearGeneration{0};

    // Statistics
    std::atomic<uint64_t> m_totalPackets{0};
    std::atomic<uint64_t> m_totalBytes{0};
    std::atomic<uint64_t> m_dnsCount{0};
    std::atomic<uint64_t> m_tcpCount{0};
    std::atomic<uint64_t> m_udpCount{0};
    std::atomic<uint64_t> m_icmpCount{0};
    std::atomic<uint64_t> m_reinjected{0};
    std::atomic<uint64_t> m_sendErrors{0};
    std::atomic<uint64_t> m_killDropped{0};
    std::atomic<uint64_t> m_fwBlocked{0};
    std::atomic<uint64_t> m_fwAllowed{0};
    mutable std::mutex m_hitsMutex;
    std::unordered_map<uint64_t, HitCounter> m_ruleHits;
    std::atomic<uint64_t> m_simSelected{0};
    std::atomic<uint64_t> m_simDelayed{0};
    std::atomic<uint64_t> m_simDropped{0};
    std::atomic<uint64_t> m_simOverflow{0};
    std::atomic<uint64_t> m_simBytes{0};
    std::atomic<uint64_t> m_simDelaySumUs{0};
    std::atomic<uint32_t> m_simInFlight{0};
    mutable std::mutex m_trafficMutex;
    std::unordered_map<uint32_t, ProcessTraffic> m_traffic;  // by ProcessInfo::id, 0 = no process

    // Rate calculation (worker thread writes, m_mutex guards the published values)
    uint64_t m_lastCalcTimeUs{0};
    uint64_t m_lastPacketsSnapshot{0};
    uint64_t m_lastBytesSnapshot{0};
    double m_currentPps{0.0};
    double m_currentBps{0.0};
};

} // namespace WS
