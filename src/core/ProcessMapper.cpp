#include "core/ProcessMapper.h"
#include "support/Handle.h"
#include "support/Text.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <chrono>
#include <cstring>

#pragma comment(lib, "iphlpapi.lib")

namespace WS {

namespace {

constexpr auto kRefresh = std::chrono::milliseconds(250);
constexpr uint64_t kIdleMs = 3000;      // no reader for this long: stop rebuilding the tables
constexpr uint64_t kForgetMs = 30'000;  // a pid without sockets for this long is forgotten

constexpr uint32_t Key(uint8_t protocol, uint16_t port) noexcept {
    return (static_cast<uint32_t>(protocol) << 16) | port;
}

uint64_t CreationTime(HANDLE process) noexcept {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
    return (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

// True when `pid` still names the process that was created at `started` (0 = cannot tell: assume so).
bool SameProcess(DWORD pid, uint64_t started) noexcept {
    if (started == 0) return true;
    const Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    return !process || CreationTime(process.get()) == started;
}

// Calls add(row) for every row of one socket table.
template <class Table, class Query, class Add>
void ReadTable(Query query, Add add) {
    ULONG size = 0;
    if (query(nullptr, &size) != ERROR_INSUFFICIENT_BUFFER || size == 0) return;
    std::vector<BYTE> buffer(size + 4096);  // room for sockets opened meanwhile
    size = static_cast<ULONG>(buffer.size());
    if (query(buffer.data(), &size) != NO_ERROR) return;
    const auto* table = reinterpret_cast<const Table*>(buffer.data());
    for (DWORD i = 0; i < table->dwNumEntries; ++i) add(table->table[i]);
}

uint16_t Port(DWORD networkOrder) noexcept {
    return ntohs(static_cast<u_short>(networkOrder));
}

std::array<uint8_t, 16> V4(DWORD address) noexcept {
    std::array<uint8_t, 16> bytes{};
    std::memcpy(bytes.data(), &address, sizeof address);
    return bytes;
}

std::array<uint8_t, 16> V6(const UCHAR (&address)[16]) noexcept {
    std::array<uint8_t, 16> bytes{};
    std::memcpy(bytes.data(), address, bytes.size());
    return bytes;
}

} // namespace

const ProcessInfo* ProcessMapper::Snapshot::Find(uint8_t protocol, uint16_t localPort) const noexcept {
    const auto it = ports.find(Key(protocol, localPort));
    return it == ports.end() ? nullptr : processes[it->second].get();
}

ProcessMapper& ProcessMapper::Instance() {
    static ProcessMapper instance;
    return instance;
}

ProcessMapper::~ProcessMapper() {
    if (m_thread.joinable()) {
        m_thread.request_stop();
        m_wake.notify_all();
        m_thread.join();
    }
}

std::shared_ptr<const ProcessMapper::Snapshot> ProcessMapper::Current() {
    m_lastUse = GetTickCount64();
    std::call_once(m_started, [this] {
        m_current = Build();  // the first caller gets real data at once
        m_thread = std::jthread([this](std::stop_token stop) { Run(stop); });
    });
    return m_current.load();
}

bool ProcessMapper::Running(const ProcessInfo& process) noexcept {
    if (process.pid == 4) return true;
    const Handle handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.pid));
    if (!handle) return false;  // gone (a process we may not query at all never had a path either)
    DWORD code = 0;
    if (!GetExitCodeProcess(handle.get(), &code) || code != STILL_ACTIVE) return false;
    return process.started == 0 || CreationTime(handle.get()) == process.started;
}

void ProcessMapper::Run(std::stop_token stop) {
    std::unique_lock lock(m_wakeMutex);
    while (!stop.stop_requested()) {
        m_wake.wait_for(lock, stop, kRefresh, [] { return false; });
        if (stop.stop_requested()) break;
        if (GetTickCount64() - m_lastUse.load() > kIdleMs) continue;  // nobody is looking
        lock.unlock();
        m_current = Build();
        lock.lock();
    }
}

std::shared_ptr<const ProcessInfo> ProcessMapper::Describe(DWORD pid) {
    auto info = std::make_shared<ProcessInfo>();
    info->id = ++m_nextId;
    info->pid = pid;
    if (pid == 4) {
        info->name = "system";
        info->display = L"System";
        info->label = "System";
        return info;
    }
    if (const Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)); process) {
        info->started = CreationTime(process.get());
        std::wstring path(32768, L'\0');  // long paths: the image name is not limited to MAX_PATH
        DWORD size = static_cast<DWORD>(path.size());
        if (QueryFullProcessImageNameW(process.get(), 0, path.data(), &size)) {
            path.resize(size);
            info->path = std::move(path);
        }
    }
    info->display = info->path.substr(info->path.find_last_of(L'\\') + 1);
    info->name = ToUtf8(FoldCase(info->display));
    info->pathKey = ToUtf8(FoldCase(info->path));
    info->label = info->display.empty() ? "pid " + std::to_string(pid) : ToUtf8(info->display);
    return info;
}

std::shared_ptr<const ProcessMapper::Snapshot> ProcessMapper::Build() {
    auto snapshot = std::make_shared<Snapshot>();
    const uint64_t now = GetTickCount64();
    // A pid missing from the previous build (or after a pause) may have been handed to a new process.
    const bool continuous = m_lastBuild != 0 && now - m_lastBuild < 2000;
    std::unordered_map<DWORD, uint32_t> indexOf;  // pid -> index into snapshot->processes

    auto owner = [&](DWORD pid) -> uint32_t {
        if (const auto it = indexOf.find(pid); it != indexOf.end()) return it->second;
        Known& known = m_known[pid];
        const bool fresh = continuous && known.lastSeen == m_lastBuild;
        if (!known.info || (!fresh && !SameProcess(pid, known.info->started))) known.info = Describe(pid);
        known.lastSeen = now;
        const auto index = static_cast<uint32_t>(snapshot->processes.size());
        snapshot->processes.push_back(known.info);
        indexOf.emplace(pid, index);
        return index;
    };
    auto add = [&](uint8_t protocol, DWORD pid, Endpoint e) {
        if (pid == 0) return;  // TIME_WAIT and closed sockets belong to no process
        e.process = owner(pid);
        e.protocol = protocol;
        snapshot->ports[Key(protocol, e.localPort)] = e.process;
        snapshot->endpoints.push_back(e);
    };

    ReadTable<MIB_TCPTABLE_OWNER_PID>(
        [](void* b, ULONG* s) { return GetExtendedTcpTable(b, s, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0); },
        [&](const MIB_TCPROW_OWNER_PID& r) {
            add(6, r.dwOwningPid, {.version = 4, .state = static_cast<uint8_t>(r.dwState), .localPort = Port(r.dwLocalPort),
                                   .remotePort = Port(r.dwRemotePort), .local = V4(r.dwLocalAddr), .remote = V4(r.dwRemoteAddr)});
        });
    ReadTable<MIB_TCP6TABLE_OWNER_PID>(
        [](void* b, ULONG* s) { return GetExtendedTcpTable(b, s, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0); },
        [&](const MIB_TCP6ROW_OWNER_PID& r) {
            add(6, r.dwOwningPid, {.version = 6, .state = static_cast<uint8_t>(r.dwState), .localPort = Port(r.dwLocalPort),
                                   .remotePort = Port(r.dwRemotePort), .local = V6(r.ucLocalAddr), .remote = V6(r.ucRemoteAddr)});
        });
    ReadTable<MIB_UDPTABLE_OWNER_PID>(
        [](void* b, ULONG* s) { return GetExtendedUdpTable(b, s, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0); },
        [&](const MIB_UDPROW_OWNER_PID& r) {
            add(17, r.dwOwningPid, {.version = 4, .localPort = Port(r.dwLocalPort), .local = V4(r.dwLocalAddr)});
        });
    ReadTable<MIB_UDP6TABLE_OWNER_PID>(
        [](void* b, ULONG* s) { return GetExtendedUdpTable(b, s, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0); },
        [&](const MIB_UDP6ROW_OWNER_PID& r) {
            add(17, r.dwOwningPid, {.version = 6, .localPort = Port(r.dwLocalPort), .local = V6(r.ucLocalAddr)});
        });

    std::erase_if(m_known, [&](const auto& entry) { return now - entry.second.lastSeen > kForgetMs; });
    m_lastBuild = now;
    return snapshot;
}

} // namespace WS
