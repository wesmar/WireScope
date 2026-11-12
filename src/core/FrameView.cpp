#include "core/FrameView.h"
#include <algorithm>

namespace WS {

namespace {

uint16_t Be16(std::span<const uint8_t> s, size_t at) noexcept {
    return static_cast<uint16_t>((s[at] << 8) | s[at + 1]);
}

uint32_t Be32(std::span<const uint8_t> s, size_t at) noexcept {
    return (static_cast<uint32_t>(s[at]) << 24) | (static_cast<uint32_t>(s[at + 1]) << 16) |
           (static_cast<uint32_t>(s[at + 2]) << 8) | s[at + 3];
}

void InspectTransport(std::span<const uint8_t> l4, FrameInfo& out) noexcept {
    if (out.fragment) return;
    switch (out.protocol) {
    case 6:   // TCP
    case 17:  // UDP
        if (l4.size() >= 4) {
            out.hasPorts = true;
            out.srcPort = Be16(l4, 0);
            out.dstPort = Be16(l4, 2);
        }
        break;
    case 1:   // ICMP
    case 58:  // ICMPv6
        if (l4.size() >= 2) {
            out.hasIcmp = true;
            out.icmpType = l4[0];
            out.icmpCode = l4[1];
        }
        break;
    default:
        break;
    }
}

} // namespace

FrameInfo InspectFrame(std::span<const uint8_t> frame) noexcept {
    FrameInfo out;
    if (frame.size() < 14) return out;
    size_t offset = 12;
    uint16_t etherType = Be16(frame, offset);
    offset += 2;
    // 802.1Q / 802.1ad tags (the driver normally strips them, but tolerate one or two)
    for (int tags = 0; tags < 2 && (etherType == 0x8100 || etherType == 0x88A8); ++tags) {
        if (frame.size() < offset + 4) return out;
        etherType = Be16(frame, offset + 2);
        offset += 4;
    }
    const auto l3 = frame.subspan(offset);

    if (etherType == 0x0800) {
        if (l3.size() < 20 || (l3[0] >> 4) != 4) return out;
        const size_t ihl = static_cast<size_t>(l3[0] & 0x0F) * 4;
        if (ihl < 20 || l3.size() < ihl) return out;
        out.ip = true;
        out.version = 4;
        out.protocol = l3[9];
        out.fragment = (Be16(l3, 6) & 0x1FFF) != 0;
        out.src4 = Be32(l3, 12);
        out.dst4 = Be32(l3, 16);
        InspectTransport(l3.subspan(ihl), out);
    } else if (etherType == 0x86DD) {
        if (l3.size() < 40 || (l3[0] >> 4) != 6) return out;
        out.ip = true;
        out.version = 6;
        std::copy_n(l3.begin() + 8, 16, out.src6.begin());
        std::copy_n(l3.begin() + 24, 16, out.dst6.begin());
        uint8_t next = l3[6];
        size_t at = 40;
        // Walk the common extension headers to the upper-layer protocol.
        for (int hops = 0; hops < 8; ++hops) {
            if (next == 0 || next == 43 || next == 60) {  // hop-by-hop, routing, destination options
                if (l3.size() < at + 8) return out;
                const uint8_t following = l3[at];
                at += (static_cast<size_t>(l3[at + 1]) + 1) * 8;
                next = following;
            } else if (next == 44) {  // fragment
                if (l3.size() < at + 8) return out;
                out.fragment = (Be16(l3, at + 2) & 0xFFF8) != 0;
                next = l3[at];
                at += 8;
            } else {
                break;
            }
        }
        out.protocol = next;
        if (at <= l3.size()) InspectTransport(l3.subspan(at), out);
    }
    return out;
}

} // namespace WS
