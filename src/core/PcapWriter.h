// WireScope - PCAP (Wireshark compatible) File Writer
#pragma once
#include <string>
#include <vector>
#include <span>
#include <fstream>
#include <mutex>
#include <cstdint>

namespace WS {

class PcapWriter {
public:
    PcapWriter();
    ~PcapWriter();

    PcapWriter(const PcapWriter&) = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;

    [[nodiscard]] bool Open(const std::wstring& filePath);
    void Close() noexcept;
    [[nodiscard]] bool IsOpen() const noexcept { return m_file.is_open(); }

    bool WritePacket(std::span<const uint8_t> frame, uint64_t timestampUs);
    [[nodiscard]] uint64_t PacketsWritten() const noexcept { return m_packetsWritten; }
    [[nodiscard]] uint64_t BytesWritten() const noexcept { return m_bytesWritten; }

private:
    std::ofstream m_file;
    std::mutex m_mutex;
    uint64_t m_packetsWritten{0};
    uint64_t m_bytesWritten{0};
};

} // namespace WS
