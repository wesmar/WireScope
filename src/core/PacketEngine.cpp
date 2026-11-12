#include "core/PacketEngine.h"
#include "core/FrameView.h"
#include "core/ProcessMapper.h"
#include "resources/resource.h"
#include "support/Common.h"
#include "support/Language.h"
#include <algorithm>
#include <chrono>

namespace WS {

namespace {

constexpr size_t kBatch = 2048;       // packets per wake-up before the delay line is serviced
constexpr size_t kDrainAll = 65536;   // bound for "empty the queue" during a mode change
constexpr auto kStartTimeout = std::chrono::seconds(5);
constexpr auto kApplyTimeout = std::chrono::seconds(3);
constexpr size_t kMaxTracked = 4096;             // process instances kept in the traffic totals
constexpr uint64_t kForgetIdleUs = 600'000'000;  // beyond that, instances idle for 10 min are dropped

bool Tunnels(DWORD mode) noexcept {
    return (mode & MODE_TUNNEL) != 0;
}

bool NeedsApps(const EngineConfig& c) {
    if (c.capture || c.accounting) return true;  // the packet list shows the owner, the totals need it
    if (c.impairment.enabled && c.impairmentMatch.app.set) return true;
    if (c.firewall) {
        for (const Rule& r : c.rules) {
            if (r.match.app.set) return true;
        }
    }
    return false;
}

} // namespace

struct PacketEngine::Worker {
    HANDLE adapter{nullptr};
    DWORD mode{MODE_BYPASS};
    bool capture{true};
    bool kill{false};
    bool impair{false};
    bool firewall{false};
    RuleAction policy{RuleAction::Allow};
    std::vector<Rule> rules;
    size_t firstEngineRule{0};
    bool policyInKernel{false};
    bool needApps{false};  // a rule or the simulator matches processes, or the capture shows them
    bool account{false};
    std::shared_ptr<const ProcessMapper::Snapshot> apps;
    // Traffic of the current batch; the pointers live as long as `apps` (committed before it changes).
    std::unordered_map<const ProcessInfo*, TrafficCounters> traffic;
    Impairer impairer;
    DelayLine delay;
};

PacketEngine::PacketEngine(std::shared_ptr<DriverBridge> bridge)
    : m_bridge(std::move(bridge)), m_wake(CreateEventW(nullptr, FALSE, FALSE, nullptr)) {
}

PacketEngine::~PacketEngine() {
    Stop();
}

bool PacketEngine::IsRunning() const noexcept {
    std::lock_guard lock(m_ctlMutex);
    return m_phase == Phase::Running;
}

std::expected<void, std::wstring> PacketEngine::Start(HANDLE hAdapter, const EngineConfig& config) {
    if (!m_bridge || !m_bridge->IsConnected()) {
        return std::unexpected(L"Driver bridge is not connected");
    }
    if (!m_wake) return std::unexpected(L"Could not create the engine's wake-up event");

    Stop();
    {
        std::lock_guard lock(m_ctlMutex);
        m_phase = Phase::Starting;
        m_pending.reset();
        m_requested = m_applied = 0;
        m_ctlError.clear();
        m_finalMode = MODE_BYPASS;
    }
    m_worker = std::jthread([this, hAdapter, config](std::stop_token st) {
        WorkerMain(st, hAdapter, config);
    });

    std::wstring error;
    {
        std::unique_lock lock(m_ctlMutex);
        m_ctlCv.wait_for(lock, kStartTimeout, [this] { return m_phase != Phase::Starting; });
        if (m_phase == Phase::Running) return {};
        error = m_ctlError.empty() ? Text::Get(IDS_DP_ENGINE_START) : m_ctlError;
    }
    Stop();
    return std::unexpected(error);
}

std::expected<void, std::wstring> PacketEngine::Reconfigure(const EngineConfig& config) {
    std::unique_lock lock(m_ctlMutex);
    if (m_phase != Phase::Running) return std::unexpected(L"The packet engine is not running");
    m_pending = config;
    const uint64_t ticket = ++m_requested;
    SetEvent(m_wake.get());
    if (!m_ctlCv.wait_for(lock, kApplyTimeout, [&] { return m_applied >= ticket || m_phase != Phase::Running; })) {
        return std::unexpected(Text::Get(IDS_DP_ENGINE_APPLY));
    }
    if (m_phase != Phase::Running) {
        return std::unexpected(m_ctlError.empty() ? Text::Get(IDS_DP_ENGINE_STOPPED) : m_ctlError);
    }
    if (!m_ctlError.empty()) {
        std::wstring error = std::move(m_ctlError);
        m_ctlError.clear();
        return std::unexpected(std::move(error));
    }
    return {};
}

void PacketEngine::Stop(DWORD finalMode) noexcept {
    if (!m_worker.joinable()) return;
    {
        std::lock_guard lock(m_ctlMutex);
        m_finalMode = finalMode;
    }
    m_worker.request_stop();
    if (m_wake) SetEvent(m_wake.get());
    m_worker.join();
    m_worker = std::jthread();
    std::lock_guard lock(m_ctlMutex);
    m_phase = Phase::Idle;
}

bool PacketEngine::StartPcap(const std::wstring& filePath) {
    return m_pcap.Open(filePath);
}

void PacketEngine::StopPcap() noexcept {
    m_pcap.Close();
}

void PacketEngine::SetPacketCallback(PacketCallback cb) {
    std::lock_guard lock(m_mutex);
    m_callback = std::move(cb);
}

void PacketEngine::ClearPackets() noexcept {
    std::lock_guard lock(m_mutex);
    m_recentPackets.clear();
    ++m_clearGeneration;
}

uint64_t PacketEngine::ClearGeneration() const noexcept {
    std::lock_guard lock(m_mutex);
    return m_clearGeneration;
}

EngineStats PacketEngine::GetStats() const {
    EngineStats stats;
    stats.TotalPackets = m_totalPackets.load();
    stats.TotalBytes = m_totalBytes.load();
    stats.DnsQueries = m_dnsCount.load();
    stats.TcpPackets = m_tcpCount.load();
    stats.UdpPackets = m_udpCount.load();
    stats.IcmpPackets = m_icmpCount.load();
    stats.Reinjected = m_reinjected.load();
    stats.SendErrors = m_sendErrors.load();
    stats.KillDropped = m_killDropped.load();
    stats.FirewallBlocked = m_fwBlocked.load();
    stats.FirewallAllowed = m_fwAllowed.load();
    stats.SimSelected = m_simSelected.load();
    stats.SimDelayed = m_simDelayed.load();
    stats.SimDropped = m_simDropped.load();
    stats.SimOverflow = m_simOverflow.load();
    stats.SimBytes = m_simBytes.load();
    stats.SimDelaySumUs = m_simDelaySumUs.load();
    stats.SimInFlight = m_simInFlight.load();
    stats.DroppedPackets = stats.SimDropped + stats.SimOverflow + stats.KillDropped + stats.FirewallBlocked;
    stats.HighResolutionTimer = m_highResolution.load();
    stats.Mode = m_mode.load();

    std::lock_guard lock(m_mutex);
    stats.PacketsPerSec = m_currentPps;
    stats.BytesPerSec = m_currentBps;
    return stats;
}

std::unordered_map<uint64_t, HitCounter> PacketEngine::RuleHits() const {
    std::lock_guard lock(m_hitsMutex);
    return m_ruleHits;
}

std::vector<ProcessTraffic> PacketEngine::ProcessTotals() const {
    std::lock_guard lock(m_trafficMutex);
    std::vector<ProcessTraffic> out;
    out.reserve(m_traffic.size());
    for (const auto& [id, entry] : m_traffic) out.push_back(entry);
    return out;
}

void PacketEngine::ResetProcessTotals() noexcept {
    std::lock_guard lock(m_trafficMutex);
    m_traffic.clear();
}

std::vector<PacketRef> PacketEngine::GetRecentPackets(size_t maxCount) const {
    std::lock_guard lock(m_mutex);
    const size_t count = std::min(maxCount, m_recentPackets.size());
    return std::vector<PacketRef>(m_recentPackets.end() - static_cast<std::ptrdiff_t>(count), m_recentPackets.end());
}

void PacketEngine::CopyPacketsAfter(uint64_t afterIndex, std::vector<PacketRef>& out) const {
    std::lock_guard lock(m_mutex);
    const auto first = std::upper_bound(m_recentPackets.begin(), m_recentPackets.end(), afterIndex,
                                        [](uint64_t index, const PacketRef& p) { return index < p->Index; });
    out.insert(out.end(), first, m_recentPackets.end());
}

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------
void PacketEngine::WorkerMain(std::stop_token stopToken, HANDLE hAdapter, EngineConfig config) {
    auto fail = [this](std::wstring error) {
        {
            std::lock_guard lock(m_ctlMutex);
            m_ctlError = std::move(error);
            m_phase = Phase::Stopped;
        }
        m_ctlCv.notify_all();
    };

    Handle packetEvent(CreateEventW(nullptr, FALSE, FALSE, nullptr));
    // A high-resolution timer releases held packets with ~1 ms precision instead of the 15.6 ms tick.
    Handle timer(CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS));
    const bool highResolution = static_cast<bool>(timer);
    if (!timer) timer.reset(CreateWaitableTimerExW(nullptr, nullptr, 0, TIMER_ALL_ACCESS));
    if (!packetEvent || !timer) {
        fail(L"Could not create the engine's events: " + FormatError());
        return;
    }
    if (auto r = m_bridge->SetAdapterEvent(hAdapter, packetEvent.get()); !r) {
        fail(r.error());
        return;
    }
    if (auto r = m_bridge->SetAdapterMode(hAdapter, config.mode); !r) {
        (void)m_bridge->SetAdapterEvent(hAdapter, nullptr);
        fail(r.error());
        return;
    }

    auto w = std::make_unique<Worker>();
    w->adapter = hAdapter;
    w->mode = config.mode;
    w->capture = config.capture;
    w->kill = config.killSwitch;
    w->firewall = config.firewall;
    w->policy = config.policy;
    w->rules = config.rules;
    w->firstEngineRule = config.firstEngineRule;
    w->policyInKernel = config.policyInKernel;
    w->impair = config.impairment.enabled;
    w->needApps = NeedsApps(config);
    w->account = config.accounting;
    if (w->impair) w->impairer.Configure(config.impairment, config.impairmentMatch);
    m_mode = config.mode;
    m_accounting = w->account;
    m_highResolution = highResolution;
    m_lastCalcTimeUs = MonotonicMicroseconds();
    m_lastPacketsSnapshot = m_totalPackets.load();
    m_lastBytesSnapshot = m_totalBytes.load();
    {
        std::lock_guard lock(m_ctlMutex);
        m_phase = Phase::Running;
    }
    m_ctlCv.notify_all();

    const HANDLE waits[] = {packetEvent.get(), m_wake.get(), timer.get()};
    bool backlog = false;
    uint64_t armedFor = 0;
    while (!stopToken.stop_requested()) {
        const DWORD waited = WaitForMultipleObjects(static_cast<DWORD>(std::size(waits)), waits, FALSE, backlog ? 0 : 100);
        if (waited == WAIT_FAILED) break;

        ApplyPending(*w);
        CommitTraffic(*w);  // before the snapshot that owns its pointers is replaced
        if (w->needApps) w->apps = ProcessMapper::Instance().Current();  // one atomic load per batch
        backlog = Drain(*w, kBatch, w->mode) == kBatch;
        w->delay.Release(MonotonicMicroseconds(), [&](INTERMEDIATE_BUFFER& b) { Send(*w, b); });
        m_simInFlight = static_cast<uint32_t>(w->delay.Size());

        if (const auto next = w->delay.NextDue()) {
            const uint64_t now = MonotonicMicroseconds();
            if (*next <= now) {
                backlog = true;
            } else if (*next != armedFor) {
                LARGE_INTEGER due{};
                due.QuadPart = -static_cast<LONGLONG>((*next - now) * 10);  // relative, 100 ns units
                SetWaitableTimer(timer.get(), &due, 0, nullptr, nullptr, FALSE);
                armedFor = *next;
            }
        } else if (armedFor) {
            CancelWaitableTimer(timer.get());
            armedFor = 0;
        }
        UpdateRates();
    }

    DWORD finalMode = MODE_BYPASS;
    {
        std::lock_guard lock(m_ctlMutex);
        finalMode = m_finalMode;
    }
    Shutdown(*w, finalMode);
    CommitTraffic(*w);
    m_accounting = false;
    (void)m_bridge->SetAdapterEvent(hAdapter, nullptr);
    {
        std::lock_guard lock(m_ctlMutex);
        m_phase = Phase::Stopped;
    }
    m_ctlCv.notify_all();
}

size_t PacketEngine::Drain(Worker& w, size_t limit, DWORD semantics) {
    size_t count = 0;
    while (count < limit) {
        auto buffer = w.delay.Acquire();
        buffer->m_Length = 0;
        const auto read = m_bridge->ReadPacket(w.adapter, *buffer);
        if (!read || !*read) {
            w.delay.Recycle(std::move(buffer));
            break;
        }
        ++count;
        Process(w, buffer, semantics);
        if (buffer) w.delay.Recycle(std::move(buffer));
    }
    return count;
}

void PacketEngine::Process(Worker& w, std::unique_ptr<INTERMEDIATE_BUFFER>& buffer, DWORD semantics) {
    INTERMEDIATE_BUFFER& b = *buffer;
    b.m_Length = std::min<DWORD>(b.m_Length, static_cast<DWORD>(MAX_PACKET_SIZE));
    const bool outbound = (b.m_dwDeviceFlags & PACKET_FLAG_ON_SEND) != 0;  // m_Flags holds NDIS flags
    const Dir dir = outbound ? Dir::Out : Dir::In;
    // A packet is an original (ours to re-inject) when its direction is tunnelled.
    const bool original = (semantics & (outbound ? MODE_TUNNEL_SEND : MODE_TUNNEL_RECV)) != 0;
    const std::span<const uint8_t> frame(b.m_IBuffer, b.m_Length);
    FrameInfo info = InspectFrame(frame);
    if (w.needApps && w.apps && info.hasPorts) info.process = w.apps->Find(info.protocol, outbound ? info.srcPort : info.dstPort);
    if (w.account) w.traffic[info.process].Add(outbound, b.m_Length);

    const uint64_t index = ++m_totalPackets;
    m_totalBytes += b.m_Length;
    if (info.protocol == 6) {
        ++m_tcpCount;
    } else if (info.protocol == 17) {
        ++m_udpCount;
        if (info.hasPorts && (info.srcPort == 53 || info.dstPort == 53)) ++m_dnsCount;
    } else if (info.hasIcmp) {
        ++m_icmpCount;
    }

    std::shared_ptr<DecodedPacket> decoded;
    if (w.capture) {
        const uint64_t wallUs = GetCurrentTimestampMicroseconds();
        decoded = std::make_shared<DecodedPacket>(
            PacketParser::Parse(frame, outbound ? Direction::Outbound : Direction::Inbound, index, wallUs));
        if (info.process) decoded->Process = info.process->label;
        if (m_pcap.IsOpen()) m_pcap.WritePacket(frame, wallUs);
    }

    PacketFate fate = (original || w.firewall) ? PacketFate::Passed : PacketFate::Observed;
    uint32_t delayUs = 0;
    bool blocked = false;
    if (original && !w.kill && w.firewall) {
        const Rule* hit = nullptr;
        size_t hitIndex = w.rules.size();
        for (size_t i = 0; i < w.rules.size(); ++i) {
            if (Matches(w.rules[i].match, info, dir)) {
                hit = &w.rules[i];
                hitIndex = i;
                break;
            }
        }
        const bool countedInKernel = hit ? (hitIndex < w.firstEngineRule) : w.policyInKernel;
        if (!countedInKernel) {
            std::lock_guard lock(m_hitsMutex);
            m_ruleHits[hit ? hit->id : 0] += HitCounter{1, b.m_Length};
        }
        blocked = (hit ? hit->action : w.policy) == RuleAction::Block;
        ++(blocked ? m_fwBlocked : m_fwAllowed);
    }

    if (original) {
        if (w.kill) {
            fate = PacketFate::Killed;
            ++m_killDropped;
        } else if (blocked) {
            fate = PacketFate::Blocked;
        } else if (w.impair && w.impairer.Selects(info, dir)) {
            ++m_simSelected;
            const auto decision = w.impairer.Decide(dir, b.m_Length, MonotonicMicroseconds());
            switch (decision.verdict) {
            case Impairer::Verdict::Drop:
                fate = PacketFate::Dropped;
                ++m_simDropped;
                break;
            case Impairer::Verdict::Overflow:
                fate = PacketFate::Dropped;
                ++m_simOverflow;
                break;
            case Impairer::Verdict::Delay:
                if (w.delay.Push(decision.dueUs, buffer)) {  // takes the buffer
                    m_simBytes += b.m_Length;
                    fate = PacketFate::Delayed;
                    delayUs = decision.delayUs;
                    ++m_simDelayed;
                    m_simDelaySumUs += decision.delayUs;
                } else {
                    fate = PacketFate::Dropped;
                    ++m_simOverflow;
                }
                break;
            case Impairer::Verdict::Pass:
                m_simBytes += b.m_Length;
                Send(w, b);
                break;
            }
        } else {
            Send(w, b);
        }
    }

    if (decoded) {
        decoded->Fate = fate;
        decoded->DelayUs = delayUs;
        PacketCallback callback;
        {
            std::lock_guard lock(m_mutex);
            if (m_recentPackets.size() >= m_maxRecentPackets) m_recentPackets.pop_front();
            m_recentPackets.push_back(decoded);
            callback = m_callback;
        }
        if (callback) callback(*decoded);
    }
}

void PacketEngine::Send(Worker& w, INTERMEDIATE_BUFFER& buffer) {
    if (m_bridge->Reinject(w.adapter, buffer)) {
        ++m_reinjected;
    } else {
        ++m_sendErrors;
    }
}

void PacketEngine::FlushDelayed(Worker& w, bool send) {
    if (send) {
        w.delay.Release(UINT64_MAX, [&](INTERMEDIATE_BUFFER& b) { Send(w, b); });
    } else {
        m_killDropped += w.delay.Size();
        w.delay.Clear();
    }
    w.impairer.ResetOrdering();
    m_simInFlight = 0;
}

void PacketEngine::ApplyPending(Worker& w) {
    std::optional<EngineConfig> config;
    uint64_t ticket = 0;
    {
        std::lock_guard lock(m_ctlMutex);
        if (!m_pending) return;
        config = std::move(m_pending);
        m_pending.reset();
        ticket = m_requested;
    }

    std::wstring error;
    if (config->mode != w.mode) {
        // Empty the queue under the old meaning, then switch. Stragglers that slipped in during the
        // switch are re-injected if either mode tunnelled them (a duplicate beats a lost packet).
        Drain(w, kDrainAll, w.mode);
        if (Tunnels(w.mode) && !Tunnels(config->mode)) FlushDelayed(w, !w.kill);
        if (auto r = m_bridge->SetAdapterMode(w.adapter, config->mode); !r) {
            error = r.error();
        } else {
            const DWORD old = w.mode;
            w.mode = config->mode;
            m_mode = w.mode;
            Drain(w, kDrainAll, old | w.mode);
        }
    }
    if (config->killSwitch && !w.kill) FlushDelayed(w, false);  // held packets die with the kill switch
    if (!config->impairment.enabled && w.impair) FlushDelayed(w, !config->killSwitch);
    w.kill = config->killSwitch;
    w.capture = config->capture;
    w.firewall = config->firewall;
    w.policy = config->policy;
    w.rules = std::move(config->rules);
    w.firstEngineRule = config->firstEngineRule;
    w.policyInKernel = config->policyInKernel;
    w.impair = config->impairment.enabled;
    w.needApps = NeedsApps(*config);
    w.account = config->accounting;
    m_accounting = w.account;
    if (w.impair) w.impairer.Configure(config->impairment, config->impairmentMatch);

    {
        std::lock_guard lock(m_ctlMutex);
        m_applied = ticket;
        if (!error.empty()) m_ctlError = std::move(error);
    }
    m_ctlCv.notify_all();
}

void PacketEngine::CommitTraffic(Worker& w) {
    if (w.traffic.empty()) return;
    const uint64_t now = MonotonicMicroseconds();
    std::lock_guard lock(m_trafficMutex);
    for (const auto& [process, counters] : w.traffic) {
        auto [it, inserted] = m_traffic.try_emplace(process ? process->id : 0);
        if (inserted && process) it->second.process = process->shared_from_this();
        it->second.total += counters;
        it->second.lastPacketUs = now;
    }
    w.traffic.clear();
    if (m_traffic.size() > kMaxTracked) {
        std::erase_if(m_traffic, [&](const auto& entry) { return entry.first != 0 && now - entry.second.lastPacketUs > kForgetIdleUs; });
    }
}

void PacketEngine::Shutdown(Worker& w, DWORD finalMode) {
    Drain(w, kDrainAll, w.mode);
    FlushDelayed(w, !w.kill);
    if (finalMode != w.mode) {
        const DWORD old = w.mode;
        (void)m_bridge->SetAdapterMode(w.adapter, finalMode);
        w.mode = finalMode;
        Drain(w, kDrainAll, old | finalMode);
    }
    m_mode = finalMode;
}

void PacketEngine::UpdateRates() {
    const uint64_t now = MonotonicMicroseconds();
    const uint64_t elapsedUs = now - m_lastCalcTimeUs;
    if (elapsedUs < 500'000ULL) return;
    const double sec = static_cast<double>(elapsedUs) / 1'000'000.0;
    const uint64_t packets = m_totalPackets.load();
    const uint64_t bytes = m_totalBytes.load();
    {
        std::lock_guard lock(m_mutex);
        m_currentPps = static_cast<double>(packets - m_lastPacketsSnapshot) / sec;
        m_currentBps = static_cast<double>(bytes - m_lastBytesSnapshot) / sec;
    }
    m_lastCalcTimeUs = now;
    m_lastPacketsSnapshot = packets;
    m_lastBytesSnapshot = bytes;
}

} // namespace WS
