// WireScope - Kernel Driver Bridge (WinpkFilter / wsddntf.sys communication)
#pragma once
#include "core/FilterAbi.h"
#include "core/PacketTypes.h"
#include "support/Handle.h"
#include <vector>
#include <span>
#include <string>
#include <expected>
#include <mutex>
#include <unordered_set>
#include <utility>

namespace WS {

class DriverBridge {
public:
    DriverBridge();
    ~DriverBridge();

    DriverBridge(const DriverBridge&) = delete;
    DriverBridge& operator=(const DriverBridge&) = delete;
    DriverBridge(DriverBridge&&) noexcept = default;
    DriverBridge& operator=(DriverBridge&&) noexcept = default;

    [[nodiscard]] bool IsConnected() const noexcept { return static_cast<bool>(m_device); }
    [[nodiscard]] const std::wstring& DevicePath() const noexcept { return m_activeDevicePath; }

    [[nodiscard]] std::expected<void, std::wstring> Connect();
    void Disconnect() noexcept;

    [[nodiscard]] std::expected<DWORD, std::wstring> GetVersion();
    [[nodiscard]] std::expected<std::vector<AdapterDescription>, std::wstring> QueryAdapters();

    [[nodiscard]] std::expected<void, std::wstring> SetAdapterMode(HANDLE hAdapter, DWORD mode);
    [[nodiscard]] std::expected<DWORD, std::wstring> GetAdapterMode(HANDLE hAdapter);

    [[nodiscard]] std::expected<void, std::wstring> SetAdapterEvent(HANDLE hAdapter, HANDLE hEvent);
    [[nodiscard]] std::expected<void, std::wstring> SetPacketEvent(HANDLE hEvent);

    [[nodiscard]] std::expected<bool, std::wstring> ReadPacket(HANDLE hAdapter, INTERMEDIATE_BUFFER& buffer);
    [[nodiscard]] std::expected<void, std::wstring> SendPacketToAdapter(HANDLE hAdapter, const uint8_t* data, size_t length);
    [[nodiscard]] std::expected<void, std::wstring> SendPacketToMstcp(HANDLE hAdapter, const uint8_t* data, size_t length);
    // Re-inject a buffer exactly as it was read (keeps the driver's metadata, e.g. 802.1Q).
    [[nodiscard]] std::expected<void, std::wstring> Reinject(HANDLE hAdapter, INTERMEDIATE_BUFFER& buffer);

    [[nodiscard]] std::expected<void, std::wstring> FlushQueue(HANDLE hAdapter);
    [[nodiscard]] std::expected<DWORD, std::wstring> GetQueueSize(HANDLE hAdapter);

    // Static filter table (global to the driver, shared with every application that uses it).
    [[nodiscard]] std::expected<DWORD, std::wstring> GetStaticFilterCount();
    [[nodiscard]] std::expected<std::vector<STATIC_FILTER>, std::wstring> ReadStaticFilters();
    // Replaces the whole table and reads it back to prove the driver parsed it with our layout.
    // An empty span resets the table.
    [[nodiscard]] std::expected<void, std::wstring> WriteStaticFilters(std::span<const STATIC_FILTER> filters);
    [[nodiscard]] std::expected<void, std::wstring> ResetStaticFilters();
    // Diagnostics for --firewall-selftest: raw bytes sent and the raw table read back. Resets the table.
    [[nodiscard]] std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, std::wstring>
    StaticFilterRoundTrip(std::span<const STATIC_FILTER> filters);

private:
    void ResetAllActiveModes() noexcept;

    FileHandle m_device;
    std::wstring m_activeDevicePath;
    mutable std::mutex m_mutex;
    std::unordered_set<HANDLE> m_activeAdapters;
};

} // namespace WS
