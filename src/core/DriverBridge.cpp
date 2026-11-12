#include "core/DriverBridge.h"
#include "resources/resource.h"
#include "support/Common.h"
#include "support/Language.h"
#include "support/Text.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <format>
#include <algorithm>
#include <cstring>
#include <unordered_map>

#pragma comment(lib, "iphlpapi.lib")

namespace WS {

namespace {

struct AdapterInfo {
    std::string FriendlyName;
    bool IsUp{false};
    bool HasGateway{false};
};

std::unordered_map<std::string, AdapterInfo> GetAdapterFriendlyNames() {
    std::unordered_map<std::string, AdapterInfo> map;
    ULONG outBufLen = 15000;
    std::vector<BYTE> buffer(outBufLen);

    DWORD bestIf = 0;
    const IPAddr destAddr = 0x08080808; // 8.8.8.8 in network byte order
    (void)GetBestInterface(destAddr, &bestIf);

    DWORD ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_GATEWAYS, nullptr,
                                    reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &outBufLen);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(outBufLen);
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_GATEWAYS, nullptr,
                                   reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &outBufLen);
    }

    if (ret == NO_ERROR) {
        for (auto curr = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()); curr != nullptr; curr = curr->Next) {
            if (curr->AdapterName) {
                std::string guid = curr->AdapterName;
                AdapterInfo info;
                if (curr->FriendlyName) {
                    info.FriendlyName = ToUtf8(curr->FriendlyName);
                }
                info.IsUp = (curr->OperStatus == IfOperStatusUp);
                if (bestIf != 0) {
                    info.HasGateway = (curr->IfIndex == bestIf);
                } else {
                    info.HasGateway = (curr->FirstGatewayAddress != nullptr);
                }
                map[guid] = std::move(info);
            }
        }
    }
    return map;
}

} // namespace

DriverBridge::DriverBridge() = default;

DriverBridge::~DriverBridge() {
    Disconnect();
}

void DriverBridge::ResetAllActiveModes() noexcept {
    if (!m_device) return;
    for (HANDLE hAdapter : m_activeAdapters) {
        ADAPTER_MODE modeReq{ hAdapter, MODE_BYPASS };
        DWORD returned = 0;
        DeviceIoControl(m_device.get(), IOCTL_SET_ADAPTER_MODE,
                        &modeReq, sizeof(modeReq), nullptr, 0, &returned, nullptr);
    }
    m_activeAdapters.clear();
}

std::expected<void, std::wstring> DriverBridge::Connect() {
    std::lock_guard lock(m_mutex);
    if (m_device) {
        return {};
    }

    // Try primary target: wsddntf (Topaz OFD / WinpkFilter OEM)
    const wchar_t* candidatePaths[] = {
        L"\\\\.\\wsddntf",
        L"\\\\.\\NDISRD"
    };

    for (const wchar_t* path : candidatePaths) {
        FileHandle dev(CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        ));

        if (dev) {
            m_device = std::move(dev);
            m_activeDevicePath = path;
            return {};
        }
    }

    const DWORD err = GetLastError();
    if (err == ERROR_ACCESS_DENIED) {
        return std::unexpected(Text::Get(IDS_DP_ACCESS_DENIED));
    }
    return std::unexpected(Text::Format(IDS_DP_OPEN_FAILED, FormatError(err)));
}

void DriverBridge::Disconnect() noexcept {
    std::lock_guard lock(m_mutex);
    if (m_device) {
        ResetAllActiveModes();
        m_device.reset();
        m_activeDevicePath.clear();
    }
}

std::expected<DWORD, std::wstring> DriverBridge::GetVersion() {
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    DWORD version = 0;
    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_GET_VERSION, nullptr, 0,
                         &version, sizeof(version), &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_GET_VERSION failed: {}", FormatError()));
    }
    return version;
}

std::expected<std::vector<AdapterDescription>, std::wstring> DriverBridge::QueryAdapters() {
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    TCP_ADAPTER_LIST rawList{};
    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_GET_TCPIP_INTERFACES, nullptr, 0,
                         &rawList, sizeof(rawList), &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_GET_TCPIP_INTERFACES failed: {}", FormatError()));
    }

    const auto friendlyMap = GetAdapterFriendlyNames();
    std::vector<AdapterDescription> result;
    const uint32_t count = std::min(rawList.m_nAdapterCount, static_cast<DWORD>(MAX_ADAPTER_COUNT));
    result.reserve(count);

    for (uint32_t i = 0; i < count; ++i) {
        AdapterDescription desc;
        desc.Index = i;
        desc.Handle = rawList.m_nAdapterHandle[i];
        desc.SystemName = rawList.m_szAdapterNameList[i];
        desc.MTU = rawList.m_usMTU[i];
        desc.Medium = rawList.m_nAdapterMediumList[i];

        std::span<const uint8_t, 6> macSpan(rawList.m_czCurrentAddress[i], 6);
        desc.MacAddress = FormatMac(macSpan);

        // Try extracting GUID from \\DEVICE\\{...}
        std::string friendly = desc.SystemName;
        const size_t braceStart = desc.SystemName.find('{');
        const size_t braceEnd = desc.SystemName.find('}');
        if (braceStart != std::string::npos && braceEnd != std::string::npos && braceEnd > braceStart) {
            const std::string guid = desc.SystemName.substr(braceStart, braceEnd - braceStart + 1);
            if (auto it = friendlyMap.find(guid); it != friendlyMap.end()) {
                friendly = it->second.FriendlyName;
                desc.IsUp = it->second.IsUp;
                desc.HasGateway = it->second.HasGateway;
            }
        }
        desc.FriendlyName = std::move(friendly);
        result.push_back(std::move(desc));
    }

    return result;
}

std::expected<void, std::wstring> DriverBridge::SetAdapterMode(HANDLE hAdapter, DWORD mode) {
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    ADAPTER_MODE req{ hAdapter, mode };
    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_SET_ADAPTER_MODE,
                         &req, sizeof(req), nullptr, 0, &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_SET_ADAPTER_MODE failed: {}", FormatError()));
    }

    if (mode == MODE_BYPASS) {
        m_activeAdapters.erase(hAdapter);
    } else {
        m_activeAdapters.insert(hAdapter);
    }
    return {};
}

std::expected<DWORD, std::wstring> DriverBridge::GetAdapterMode(HANDLE hAdapter) {
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    ADAPTER_MODE req{ hAdapter, 0 };
    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_GET_ADAPTER_MODE,
                         &hAdapter, sizeof(hAdapter), &req, sizeof(req), &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_GET_ADAPTER_MODE failed: {}", FormatError()));
    }
    return req.dwFlags;
}

std::expected<void, std::wstring> DriverBridge::SetAdapterEvent(HANDLE hAdapter, HANDLE hEvent) {
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    struct {
        HANDLE hAdapter;
        HANDLE hEvent;
    } req{ hAdapter, hEvent };

    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_SET_ADAPTER_EVENT,
                         &req, sizeof(req), nullptr, 0, &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_SET_ADAPTER_EVENT failed: {}", FormatError()));
    }
    return {};
}

std::expected<void, std::wstring> DriverBridge::SetPacketEvent(HANDLE hEvent) {
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_SET_PACKET_EVENT,
                         &hEvent, sizeof(hEvent), nullptr, 0, &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_SET_PACKET_EVENT failed: {}", FormatError()));
    }
    return {};
}

std::expected<bool, std::wstring> DriverBridge::ReadPacket(HANDLE hAdapter, INTERMEDIATE_BUFFER& buffer) {
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    ETH_REQUEST req{ hAdapter, &buffer };
    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_READ_PACKET,
                         &req, sizeof(req), nullptr, 0, &returned, nullptr)) {
        const DWORD err = GetLastError();
        if (err == ERROR_NO_MORE_ITEMS || err == ERROR_EMPTY || returned == 0) {
            return false; // Queue empty
        }
        return std::unexpected(std::format(L"IOCTL_READ_PACKET failed: {}", FormatError(err)));
    }
    return (buffer.m_Length > 0);
}

std::expected<void, std::wstring> DriverBridge::SendPacketToAdapter(HANDLE hAdapter, const uint8_t* data, size_t length) {
    if (!data || length == 0 || length > MAX_PACKET_SIZE) {
        return std::unexpected(L"Invalid packet data or length");
    }

    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    INTERMEDIATE_BUFFER buf{};
    buf.m_Length = static_cast<DWORD>(length);
    buf.m_dwDeviceFlags = PACKET_FLAG_ON_SEND;
    memcpy(buf.m_IBuffer, data, length);

    ETH_REQUEST req{ hAdapter, &buf };
    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_SEND_PACKET_TO_ADAPTER,
                         &req, sizeof(req), nullptr, 0, &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_SEND_PACKET_TO_ADAPTER failed: {}", FormatError()));
    }
    return {};
}

std::expected<void, std::wstring> DriverBridge::SendPacketToMstcp(HANDLE hAdapter, const uint8_t* data, size_t length) {
    if (!data || length == 0 || length > MAX_PACKET_SIZE) {
        return std::unexpected(L"Invalid packet data or length");
    }

    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    INTERMEDIATE_BUFFER buf{};
    buf.m_Length = static_cast<DWORD>(length);
    buf.m_dwDeviceFlags = PACKET_FLAG_ON_RECEIVE;
    memcpy(buf.m_IBuffer, data, length);

    ETH_REQUEST req{ hAdapter, &buf };
    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_SEND_PACKET_TO_MSTCP,
                         &req, sizeof(req), nullptr, 0, &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_SEND_PACKET_TO_MSTCP failed: {}", FormatError()));
    }
    return {};
}

std::expected<void, std::wstring> DriverBridge::Reinject(HANDLE hAdapter, INTERMEDIATE_BUFFER& buffer) {
    if (buffer.m_Length == 0 || buffer.m_Length > MAX_PACKET_SIZE) {
        return std::unexpected(L"Invalid packet length");
    }
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    const bool outbound = (buffer.m_dwDeviceFlags & PACKET_FLAG_ON_SEND) != 0;
    ETH_REQUEST req{ hAdapter, &buffer };
    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), outbound ? IOCTL_SEND_PACKET_TO_ADAPTER : IOCTL_SEND_PACKET_TO_MSTCP,
                         &req, sizeof(req), nullptr, 0, &returned, nullptr)) {
        return std::unexpected(std::format(L"Re-injecting a packet failed: {}", FormatError()));
    }
    return {};
}

std::expected<DWORD, std::wstring> DriverBridge::GetStaticFilterCount() {
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    DWORD count = 0;
    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_GET_PACKET_FILTERS_TABLE_SIZE,
                         nullptr, 0, &count, sizeof(count), &returned, nullptr)) {
        return std::unexpected(std::format(L"The driver has no static filter support (IOCTL_GET_PACKET_FILTERS_TABLE_SIZE: {})", FormatError()));
    }
    return count;
}

std::expected<std::vector<STATIC_FILTER>, std::wstring> DriverBridge::ReadStaticFilters() {
    auto count = GetStaticFilterCount();
    if (!count) return std::unexpected(count.error());

    // Room for a few entries more than reported, in case another application grows the table meanwhile.
    const size_t capacity = static_cast<size_t>(*count) + 16;
    std::vector<uint8_t> buffer(sizeof(STATIC_FILTER_TABLE_HEADER) + capacity * sizeof(STATIC_FILTER));
    auto* header = reinterpret_cast<STATIC_FILTER_TABLE_HEADER*>(buffer.data());
    header->m_TableSize = static_cast<DWORD>(capacity);

    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");
    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_GET_PACKET_FILTERS_TABLE, nullptr, 0,
                         buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_GET_PACKET_FILTERS failed: {}", FormatError()));
    }
    // wsddntf reports the whole output buffer as returned, so the entry count comes from the header.
    // The entry layout itself is proven by WriteStaticFilters' read-back.
    if (returned < sizeof(STATIC_FILTER_TABLE_HEADER)) {
        if (*count == 0) return std::vector<STATIC_FILTER>{};
        return std::unexpected(std::format(L"The driver returned {} bytes for a table of {} filters", returned, *count));
    }
    const size_t entries = header->m_TableSize;
    const size_t needed = sizeof(STATIC_FILTER_TABLE_HEADER) + entries * sizeof(STATIC_FILTER);
    if (entries > capacity || returned < needed) {
        return std::unexpected(std::format(
            L"Static filter table not understood: the driver reports {} entries in {} bytes (buffer for {}, {} bytes per entry)",
            entries, returned, capacity, sizeof(STATIC_FILTER)));
    }
    std::vector<STATIC_FILTER> filters(entries);
    if (entries) {
        std::memcpy(filters.data(), buffer.data() + sizeof(STATIC_FILTER_TABLE_HEADER), entries * sizeof(STATIC_FILTER));
    }
    return filters;
}

std::expected<void, std::wstring> DriverBridge::WriteStaticFilters(std::span<const STATIC_FILTER> filters) {
    if (filters.empty()) return ResetStaticFilters();

    std::vector<uint8_t> buffer(sizeof(STATIC_FILTER_TABLE_HEADER) + filters.size() * sizeof(STATIC_FILTER));
    auto* header = reinterpret_cast<STATIC_FILTER_TABLE_HEADER*>(buffer.data());
    header->m_TableSize = static_cast<DWORD>(filters.size());
    std::memcpy(buffer.data() + sizeof(STATIC_FILTER_TABLE_HEADER), filters.data(), filters.size() * sizeof(STATIC_FILTER));
    {
        std::lock_guard lock(m_mutex);
        if (!m_device) return std::unexpected(L"Driver not connected");
        DWORD returned = 0;
        if (!DeviceIoControl(m_device.get(), IOCTL_SET_PACKET_FILTERS, buffer.data(), static_cast<DWORD>(buffer.size()),
                             nullptr, 0, &returned, nullptr)) {
            return std::unexpected(std::format(L"IOCTL_SET_PACKET_FILTERS failed: {}", FormatError()));
        }
    }

    // Read the table back: a driver with a different structure layout would report other sizes or
    // other values, and a table it misread must not stay active.
    auto readBack = ReadStaticFilters();
    auto mismatch = [&]() -> std::wstring {
        if (!readBack) return readBack.error();
        if (readBack->size() != filters.size()) {
            return std::format(L"the driver holds {} filters after {} were written", readBack->size(), filters.size());
        }
        for (size_t i = 0; i < filters.size(); ++i) {
            const STATIC_FILTER& a = filters[i];
            const STATIC_FILTER& b = (*readBack)[i];
            if (a.m_Adapter != b.m_Adapter || a.m_dwDirectionFlags != b.m_dwDirectionFlags || a.m_FilterAction != b.m_FilterAction ||
                a.m_ValidFields != b.m_ValidFields ||
                std::memcmp(&a.m_DataLinkFilter, &b.m_DataLinkFilter, sizeof(a.m_DataLinkFilter)) != 0 ||
                std::memcmp(&a.m_NetworkFilter, &b.m_NetworkFilter, sizeof(a.m_NetworkFilter)) != 0 ||
                std::memcmp(&a.m_TransportFilter, &b.m_TransportFilter, sizeof(a.m_TransportFilter)) != 0) {
                return std::format(L"filter {} reads back differently", i);
            }
        }
        return {};
    }();
    if (!mismatch.empty()) {
        (void)ResetStaticFilters();
        return std::unexpected(L"The driver did not accept the filter table as written (" + mismatch +
                               L"). The table was cleared to keep the network safe.");
    }
    return {};
}

std::expected<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>, std::wstring>
DriverBridge::StaticFilterRoundTrip(std::span<const STATIC_FILTER> filters) {
    std::vector<uint8_t> sent(sizeof(STATIC_FILTER_TABLE_HEADER) + filters.size() * sizeof(STATIC_FILTER));
    reinterpret_cast<STATIC_FILTER_TABLE_HEADER*>(sent.data())->m_TableSize = static_cast<DWORD>(filters.size());
    if (!filters.empty()) std::memcpy(sent.data() + sizeof(STATIC_FILTER_TABLE_HEADER), filters.data(), filters.size() * sizeof(STATIC_FILTER));
    std::vector<uint8_t> back(sent.size() + 16 * sizeof(STATIC_FILTER));
    reinterpret_cast<STATIC_FILTER_TABLE_HEADER*>(back.data())->m_TableSize = static_cast<DWORD>(filters.size() + 16);
    std::wstring error;
    {
        std::lock_guard lock(m_mutex);
        if (!m_device) return std::unexpected(L"Driver not connected");
        DWORD returned = 0;
        if (!DeviceIoControl(m_device.get(), IOCTL_SET_PACKET_FILTERS, sent.data(), static_cast<DWORD>(sent.size()), nullptr, 0, &returned, nullptr)) {
            return std::unexpected(std::format(L"IOCTL_SET_PACKET_FILTERS failed: {}", FormatError()));
        }
        if (!DeviceIoControl(m_device.get(), IOCTL_GET_PACKET_FILTERS_TABLE, nullptr, 0, back.data(), static_cast<DWORD>(back.size()), &returned, nullptr)) {
            error = std::format(L"IOCTL_GET_PACKET_FILTERS failed: {}", FormatError());
        }
    }
    (void)ResetStaticFilters();
    if (!error.empty()) return std::unexpected(error);
    return std::pair{std::move(sent), std::move(back)};
}

std::expected<void, std::wstring> DriverBridge::FlushQueue(HANDLE hAdapter) {
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_FLUSH_ADAPTER_PACKET_QUEUE,
                         &hAdapter, sizeof(hAdapter), nullptr, 0, &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_FLUSH_ADAPTER_PACKET_QUEUE failed: {}", FormatError()));
    }
    return {};
}

std::expected<DWORD, std::wstring> DriverBridge::GetQueueSize(HANDLE hAdapter) {
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    DWORD size = 0;
    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_GET_ADAPTER_PACKET_QUEUE_SIZE,
                         &hAdapter, sizeof(hAdapter), &size, sizeof(size), &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_GET_ADAPTER_PACKET_QUEUE_SIZE failed: {}", FormatError()));
    }
    return size;
}

std::expected<void, std::wstring> DriverBridge::ResetStaticFilters() {
    std::lock_guard lock(m_mutex);
    if (!m_device) return std::unexpected(L"Driver not connected");

    DWORD returned = 0;
    if (!DeviceIoControl(m_device.get(), IOCTL_RESET_PACKET_FILTERS,
                         nullptr, 0, nullptr, 0, &returned, nullptr)) {
        return std::unexpected(std::format(L"IOCTL_RESET_PACKET_FILTERS failed: {}", FormatError()));
    }
    return {};
}

} // namespace WS
