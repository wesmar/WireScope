#include "core/PcapWriter.h"

namespace WS {

namespace {

#pragma pack(push, 1)
struct PcapGlobalHeader {
    uint32_t magic_number{0xa1b2c3d4}; // microsecond timestamp format
    uint16_t version_major{2};
    uint16_t version_minor{4};
    int32_t  thiszone{0};
    uint32_t sigfigs{0};
    uint32_t snaplen{65535};
    uint32_t network{1};               // LINKTYPE_ETHERNET = 1
};
static_assert(sizeof(PcapGlobalHeader) == 24, "PcapGlobalHeader must be 24 bytes");

struct PcapPacketHeader {
    uint32_t ts_sec{0};
    uint32_t ts_usec{0};
    uint32_t incl_len{0};
    uint32_t orig_len{0};
};
static_assert(sizeof(PcapPacketHeader) == 16, "PcapPacketHeader must be 16 bytes");
#pragma pack(pop)

} // namespace

PcapWriter::PcapWriter() = default;

PcapWriter::~PcapWriter() {
    Close();
}

bool PcapWriter::Open(const std::wstring& filePath) {
    std::lock_guard lock(m_mutex);
    Close();

    m_file.open(filePath, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!m_file.is_open()) {
        return false;
    }

    PcapGlobalHeader header{};
    m_file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    if (!m_file.good()) {
        m_file.close();
        return false;
    }

    m_packetsWritten = 0;
    m_bytesWritten = sizeof(header);
    return true;
}

void PcapWriter::Close() noexcept {
    if (m_file.is_open()) {
        m_file.flush();
        m_file.close();
    }
}

bool PcapWriter::WritePacket(std::span<const uint8_t> frame, uint64_t timestampUs) {
    std::lock_guard lock(m_mutex);
    if (!m_file.is_open() || frame.empty()) {
        return false;
    }

    PcapPacketHeader pHeader{};
    pHeader.ts_sec = static_cast<uint32_t>(timestampUs / 1'000'000ULL);
    pHeader.ts_usec = static_cast<uint32_t>(timestampUs % 1'000'000ULL);
    pHeader.incl_len = static_cast<uint32_t>(frame.size());
    pHeader.orig_len = static_cast<uint32_t>(frame.size());

    m_file.write(reinterpret_cast<const char*>(&pHeader), sizeof(pHeader));
    m_file.write(reinterpret_cast<const char*>(frame.data()), frame.size());

    if (!m_file.good()) {
        return false;
    }

    m_packetsWritten++;
    m_bytesWritten += sizeof(pHeader) + frame.size();
    return true;
}

} // namespace WS
