// WireScope - Packet Parser (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS, TLS SNI)
#pragma once
#include "core/PacketTypes.h"
#include <span>
#include <string>
#include <vector>

namespace WS {

// One decoded header field for the details view ("IPv4", "TTL", "64").
struct HeaderField {
    std::string layer;
    std::string name;
    std::string value;
};

class PacketParser {
public:
    [[nodiscard]] static DecodedPacket Parse(std::span<const uint8_t> frame, Direction dir, uint64_t index, uint64_t timestampUs);
    // Field-by-field view of the L2-L4 headers.
    [[nodiscard]] static std::vector<HeaderField> Breakdown(std::span<const uint8_t> frame);

private:
    static void ParseArp(std::span<const uint8_t> payload, DecodedPacket& out);
    static void ParseIpv4(std::span<const uint8_t> payload, DecodedPacket& out);
    static void ParseIpv6(std::span<const uint8_t> payload, DecodedPacket& out);
    static void ParseTcp(std::span<const uint8_t> payload, DecodedPacket& out);
    static void ParseUdp(std::span<const uint8_t> payload, DecodedPacket& out);
    static void ParseIcmp(std::span<const uint8_t> payload, DecodedPacket& out);

    // Layer 7 payload parsers
    static void TryParseDns(std::span<const uint8_t> udpPayload, DecodedPacket& out);
    static void TryParseTlsSni(std::span<const uint8_t> tcpPayload, DecodedPacket& out);
    static void TryParseHttp(std::span<const uint8_t> tcpPayload, DecodedPacket& out);
};

} // namespace WS
