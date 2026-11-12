// WireScope - Which process owns a packet: local (protocol, port) -> process.
//
// The driver works below TCP/IP and knows nothing about processes, so the owner is looked up in the
// socket tables (GetExtendedTcpTable / GetExtendedUdpTable, IPv4 and IPv6). Building those tables
// takes milliseconds, far too long for the data path, so a background thread rebuilds an immutable
// Snapshot every 250 ms while someone uses it; readers take the current snapshot (one atomic load) and
// look ports up without locks or allocation.
//
// The key is the local port: an outbound packet's source port, an inbound packet's destination port.
// A port bound by several processes on different local addresses resolves to one of them.
//
// Every process instance is described once (ProcessInfo) and shared by the snapshots, the packets
// and the per-process traffic totals. A pid that Windows hands to a new process gets a new
// ProcessInfo: the creation time tells the two apart.
#pragma once
#include <Windows.h>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace WS {

struct ProcessInfo : std::enable_shared_from_this<ProcessInfo> {
    uint32_t     id{0};       // unique per process instance in this WireScope session
    DWORD        pid{0};
    uint64_t     started{0};  // creation time (FILETIME), 0 when Windows does not tell
    std::string  name;        // folded image name, "discord.exe"; "system" for pid 4; empty = unknown
    std::string  pathKey;     // folded full path, UTF-8: what an "app" rule with a path compares
    std::wstring path;        // full image path as reported; empty for protected or vanished processes
    std::wstring display;     // image name as written on disk, "Discord.exe"
    std::string  label;       // the same in UTF-8 for packet lists, or "pid 1234" when the name is unknown
};

// One socket from the tables: a TCP connection or listener, or a bound UDP port.
struct Endpoint {
    uint32_t process{0};    // index into Snapshot::processes
    uint8_t  protocol{0};   // 6 or 17
    uint8_t  version{4};    // 4 or 6
    uint8_t  state{0};      // MIB_TCP_STATE for TCP, 0 for UDP
    uint16_t localPort{0};  // host byte order
    uint16_t remotePort{0};
    std::array<uint8_t, 16> local{};   // IPv4 in the first four bytes, network order
    std::array<uint8_t, 16> remote{};
};

class ProcessMapper {
public:
    struct Snapshot {
        std::unordered_map<uint32_t, uint32_t> ports;  // (protocol << 16 | port) -> index into processes
        std::vector<std::shared_ptr<const ProcessInfo>> processes;
        std::vector<Endpoint> endpoints;
        // nullptr when the port has no owner (closed, or in TIME_WAIT); valid while the snapshot lives.
        [[nodiscard]] const ProcessInfo* Find(uint8_t protocol, uint16_t localPort) const noexcept;
    };

    static ProcessMapper& Instance();
    ~ProcessMapper();

    ProcessMapper(const ProcessMapper&) = delete;
    ProcessMapper& operator=(const ProcessMapper&) = delete;

    // The newest snapshot; starts the refresher on first use. Never empty.
    [[nodiscard]] std::shared_ptr<const Snapshot> Current();

    // False once the process has exited (a reused pid is a different process).
    [[nodiscard]] static bool Running(const ProcessInfo& process) noexcept;

private:
    struct Known {
        std::shared_ptr<const ProcessInfo> info;
        uint64_t lastSeen{0};  // GetTickCount64 of the last build that found a socket of this pid
    };

    ProcessMapper() = default;
    void Run(std::stop_token stop);
    std::shared_ptr<const Snapshot> Build();
    std::shared_ptr<const ProcessInfo> Describe(DWORD pid);

    std::atomic<std::shared_ptr<const Snapshot>> m_current{std::make_shared<const Snapshot>()};
    std::atomic<uint64_t> m_lastUse{0};  // GetTickCount64 of the last Current(): idle refresher sleeps
    std::once_flag m_started;
    std::mutex m_wakeMutex;
    std::condition_variable_any m_wake;
    // Refresher thread only:
    std::unordered_map<DWORD, Known> m_known;
    uint64_t m_lastBuild{0};
    uint32_t m_nextId{0};
    std::jthread m_thread;  // last member: joined before the rest is destroyed
};

} // namespace WS
