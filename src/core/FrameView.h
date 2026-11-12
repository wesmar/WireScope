// WireScope - Minimal, allocation-free view of the fields rules match on (L2 -> L4).
// Used on the data path (impairment selector), so it never throws and never allocates.
#pragma once
#include <array>
#include <cstdint>
#include <span>

namespace WS {

struct ProcessInfo;

struct FrameInfo {
    bool     ip{false};
    uint8_t  version{0};     // 4 or 6
    uint8_t  protocol{0};    // IP protocol / IPv6 upper-layer header
    bool     fragment{false};  // non-first fragment: no L4 header
    uint32_t src4{0};        // host byte order
    uint32_t dst4{0};
    std::array<uint8_t, 16> src6{};
    std::array<uint8_t, 16> dst6{};
    bool     hasPorts{false};
    uint16_t srcPort{0};
    uint16_t dstPort{0};
    bool     hasIcmp{false};
    uint8_t  icmpType{0};
    uint8_t  icmpCode{0};
    // Owning process, set by the packet engine from a ProcessMapper snapshot (nullptr = unknown).
    const ProcessInfo* process{nullptr};
};

[[nodiscard]] FrameInfo InspectFrame(std::span<const uint8_t> frame) noexcept;

} // namespace WS
