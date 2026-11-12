#include "core/PacketParser.h"
#include "support/Text.h"
#include <format>
#include <winsock2.h>

namespace WS {

DecodedPacket PacketParser::Parse(std::span<const uint8_t> frame, Direction dir, uint64_t index, uint64_t timestampUs) {
    DecodedPacket out;
    out.Index = index;
    out.TimestampUs = timestampUs;
    out.Dir = dir;
    out.Length = static_cast<uint32_t>(frame.size());
    out.RawData.assign(frame.begin(), frame.end());

    if (frame.size() < sizeof(ETH_HEADER)) {
        out.Protocol = ProtocolType::Unknown;
        out.ProtocolName = "MALFORMED";
        out.Info = std::format("Truncated frame ({} bytes)", frame.size());
        return out;
    }

    const auto* eth = reinterpret_cast<const ETH_HEADER*>(frame.data());
    std::span<const uint8_t, 6> srcMac(eth->SrcMac, 6);
    std::span<const uint8_t, 6> dstMac(eth->DestMac, 6);
    out.Source = FormatMac(srcMac);
    out.Destination = FormatMac(dstMac);

    const uint16_t etherType = ntohs(eth->EtherType);
    auto payload = frame.subspan(sizeof(ETH_HEADER));

    switch (etherType) {
    case 0x0800: // IPv4
        ParseIpv4(payload, out);
        break;
    case 0x86DD: // IPv6
        ParseIpv6(payload, out);
        break;
    case 0x0806: // ARP
        ParseArp(payload, out);
        break;
    default:
        out.Protocol = ProtocolType::Unknown;
        out.ProtocolName = std::format("0x{:04X}", etherType);
        out.Info = std::format("Ethernet payload ({} bytes)", payload.size());
        break;
    }

    return out;
}

void PacketParser::ParseArp(std::span<const uint8_t> payload, DecodedPacket& out) {
    out.Protocol = ProtocolType::ARP;
    out.ProtocolName = "ARP";

    if (payload.size() < sizeof(ARP_HEADER)) {
        out.Info = "Truncated ARP packet";
        return;
    }

    const auto* arp = reinterpret_cast<const ARP_HEADER*>(payload.data());
    const uint16_t opcode = ntohs(arp->Opcode);

    const uint32_t srcIp = *reinterpret_cast<const uint32_t*>(arp->SenderIp);
    const uint32_t dstIp = *reinterpret_cast<const uint32_t*>(arp->TargetIp);
    out.Source = FormatIpv4(srcIp);
    out.Destination = FormatIpv4(dstIp);

    if (opcode == 1) {
        out.Info = std::format("Who has {}? Tell {}", FormatIpv4(dstIp), FormatIpv4(srcIp));
    } else if (opcode == 2) {
        std::span<const uint8_t, 6> senderMac(arp->SenderMac, 6);
        out.Info = std::format("{} is at {}", FormatIpv4(srcIp), FormatMac(senderMac));
    } else {
        out.Info = std::format("ARP Opcode {}", opcode);
    }
}

void PacketParser::ParseIpv4(std::span<const uint8_t> payload, DecodedPacket& out) {
    out.Protocol = ProtocolType::IPv4;
    out.ProtocolName = "IPv4";

    if (payload.size() < sizeof(IPV4_HEADER)) {
        out.Info = "Truncated IPv4 packet";
        return;
    }

    const auto* ip = reinterpret_cast<const IPV4_HEADER*>(payload.data());
    const uint8_t ihl = (ip->VersionAndIhl & 0x0F) * 4;
    if (ihl < sizeof(IPV4_HEADER) || payload.size() < ihl) {
        out.Info = "Malformed IPv4 header length";
        return;
    }

    out.Source = FormatIpv4(ip->SrcIp);
    out.Destination = FormatIpv4(ip->DestIp);
    auto l4Payload = payload.subspan(ihl);

    switch (ip->Protocol) {
    case 6: // TCP
        ParseTcp(l4Payload, out);
        break;
    case 17: // UDP
        ParseUdp(l4Payload, out);
        break;
    case 1: // ICMP
        ParseIcmp(l4Payload, out);
        break;
    default:
        out.ProtocolName = std::format("IP (0x{:02X})", ip->Protocol);
        out.Info = std::format("TTL={} Protocol={}", ip->Ttl, ip->Protocol);
        break;
    }
}

void PacketParser::ParseIpv6(std::span<const uint8_t> payload, DecodedPacket& out) {
    out.Protocol = ProtocolType::IPv6;
    out.ProtocolName = "IPv6";

    if (payload.size() < sizeof(IPV6_HEADER)) {
        out.Info = "Truncated IPv6 packet";
        return;
    }

    const auto* ip = reinterpret_cast<const IPV6_HEADER*>(payload.data());
    std::span<const uint8_t, 16> srcSpan(ip->SrcIp, 16);
    std::span<const uint8_t, 16> dstSpan(ip->DestIp, 16);
    out.Source = FormatIpv6(srcSpan);
    out.Destination = FormatIpv6(dstSpan);

    auto l4Payload = payload.subspan(sizeof(IPV6_HEADER));
    switch (ip->NextHeader) {
    case 6:
        ParseTcp(l4Payload, out);
        break;
    case 17:
        ParseUdp(l4Payload, out);
        break;
    case 58: // ICMPv6
        out.ProtocolName = "ICMPv6";
        out.Info = std::format("ICMPv6 packet ({} bytes)", l4Payload.size());
        break;
    default:
        out.ProtocolName = std::format("IPv6 ({})", ip->NextHeader);
        out.Info = std::format("NextHeader={}", ip->NextHeader);
        break;
    }
}

void PacketParser::ParseTcp(std::span<const uint8_t> payload, DecodedPacket& out) {
    out.Protocol = ProtocolType::TCP;
    out.ProtocolName = "TCP";

    if (payload.size() < sizeof(TCP_HEADER)) {
        out.Info = "Truncated TCP segment";
        return;
    }

    const auto* tcp = reinterpret_cast<const TCP_HEADER*>(payload.data());
    out.SourcePort = ntohs(tcp->SrcPort);
    out.DestPort = ntohs(tcp->DestPort);

    const uint8_t offset = ((tcp->DataOffset >> 4) & 0x0F) * 4;
    std::string flags;
    if (tcp->Flags & 0x02) flags += "SYN ";
    if (tcp->Flags & 0x10) flags += "ACK ";
    if (tcp->Flags & 0x01) flags += "FIN ";
    if (tcp->Flags & 0x04) flags += "RST ";
    if (tcp->Flags & 0x08) flags += "PSH ";
    if (!flags.empty()) flags.pop_back();

    out.Info = std::format("{} -> {} [{}] Len={}", out.SourcePort, out.DestPort, flags, payload.size());

    if (offset >= sizeof(TCP_HEADER) && payload.size() > offset) {
        auto appPayload = payload.subspan(offset);
        if (out.DestPort == 443 || out.SourcePort == 443) {
            TryParseTlsSni(appPayload, out);
        } else if (out.DestPort == 80 || out.SourcePort == 80 || out.DestPort == 8080 || out.SourcePort == 8080) {
            TryParseHttp(appPayload, out);
        }
    }
}

void PacketParser::ParseUdp(std::span<const uint8_t> payload, DecodedPacket& out) {
    out.Protocol = ProtocolType::UDP;
    out.ProtocolName = "UDP";

    if (payload.size() < sizeof(UDP_HEADER)) {
        out.Info = "Truncated UDP datagram";
        return;
    }

    const auto* udp = reinterpret_cast<const UDP_HEADER*>(payload.data());
    out.SourcePort = ntohs(udp->SrcPort);
    out.DestPort = ntohs(udp->DestPort);
    const uint16_t length = ntohs(udp->Length);

    out.Info = std::format("{} -> {} Len={}", out.SourcePort, out.DestPort, length);

    if (payload.size() > sizeof(UDP_HEADER)) {
        auto appPayload = payload.subspan(sizeof(UDP_HEADER));
        if (out.DestPort == 53 || out.SourcePort == 53) {
            TryParseDns(appPayload, out);
        } else if (out.DestPort == 67 || out.DestPort == 68 || out.SourcePort == 67 || out.SourcePort == 68) {
            out.ProtocolName = "DHCP";
            out.Info = std::format("DHCP message ({} bytes)", appPayload.size());
        } else if (out.DestPort == 123 || out.SourcePort == 123) {
            out.ProtocolName = "NTP";
            out.Info = "Network Time Protocol";
        }
    }
}

void PacketParser::ParseIcmp(std::span<const uint8_t> payload, DecodedPacket& out) {
    out.Protocol = ProtocolType::ICMP;
    out.ProtocolName = "ICMP";

    if (payload.size() < sizeof(ICMP_HEADER)) {
        out.Info = "Truncated ICMP packet";
        return;
    }

    const auto* icmp = reinterpret_cast<const ICMP_HEADER*>(payload.data());
    const uint16_t seq = ntohs(icmp->Sequence);
    const uint16_t id = ntohs(icmp->Id);

    switch (icmp->Type) {
    case 8:
        out.Info = std::format("Echo Request (Ping) id=0x{:04X} seq={}", id, seq);
        break;
    case 0:
        out.Info = std::format("Echo Reply (Pong) id=0x{:04X} seq={}", id, seq);
        break;
    case 3:
        out.Info = std::format("Destination Unreachable (code {})", icmp->Code);
        break;
    case 11:
        out.Info = "Time to Live Exceeded (TTL expired in transit)";
        break;
    default:
        out.Info = std::format("ICMP Type {} Code {}", icmp->Type, icmp->Code);
        break;
    }
}

void PacketParser::TryParseDns(std::span<const uint8_t> udpPayload, DecodedPacket& out) {
    if (udpPayload.size() < 12) return;

    const uint16_t flags = ntohs(*reinterpret_cast<const uint16_t*>(udpPayload.data() + 2));
    const uint16_t qdCount = ntohs(*reinterpret_cast<const uint16_t*>(udpPayload.data() + 4));
    const bool isResponse = (flags & 0x8000) != 0;

    out.Protocol = ProtocolType::DNS;
    out.ProtocolName = "DNS";

    if (qdCount == 0) return;

    // Parse first Question QNAME
    size_t pos = 12;
    std::string qname;
    size_t jumps = 0;

    while (pos < udpPayload.size() && jumps < 20) {
        const uint8_t len = udpPayload[pos];
        if (len == 0) break;

        if ((len & 0xC0) == 0xC0) { // Pointer compression
            if (pos + 1 >= udpPayload.size()) break;
            const size_t ptr = ((len & 0x3F) << 8) | udpPayload[pos + 1];
            pos = ptr;
            jumps++;
            continue;
        }

        pos++;
        if (pos + len > udpPayload.size()) break;

        if (!qname.empty()) qname += '.';
        qname.append(reinterpret_cast<const char*>(udpPayload.data() + pos), len);
        pos += len;
    }

    if (!qname.empty()) {
        out.DomainOrHost = qname;
        if (isResponse) {
            out.Info = std::format("DNS Response for {}", qname);
        } else {
            out.Info = std::format("DNS Standard Query: {}", qname);
        }
    }
}

void PacketParser::TryParseTlsSni(std::span<const uint8_t> tcpPayload, DecodedPacket& out) {
    // Check for TLS Handshake (0x16), Version (0x03 0x01..0x03), Type ClientHello (0x01)
    if (tcpPayload.size() < 44) return;
    if (tcpPayload[0] != 0x16) return; // ContentType: Handshake
    if (tcpPayload[1] != 0x03) return; // Major version 3

    if (tcpPayload[5] != 0x01) return; // HandshakeType: ClientHello

    size_t pos = 43; // Skip past header + client random (32B)
    if (pos >= tcpPayload.size()) return;

    // Session ID length
    const uint8_t sessionLen = tcpPayload[pos];
    pos += 1 + sessionLen;
    if (pos + 2 >= tcpPayload.size()) return;

    // Cipher suites length
    const uint16_t cipherLen = static_cast<uint16_t>((tcpPayload[pos] << 8) | tcpPayload[pos + 1]);
    pos += 2 + cipherLen;
    if (pos + 1 >= tcpPayload.size()) return;

    // Compression methods length
    const uint8_t compLen = tcpPayload[pos];
    pos += 1 + compLen;
    if (pos + 2 >= tcpPayload.size()) return;

    // Extensions length
    const uint16_t extTotalLen = static_cast<uint16_t>((tcpPayload[pos] << 8) | tcpPayload[pos + 1]);
    pos += 2;

    const size_t extEnd = std::min(pos + extTotalLen, tcpPayload.size());
    while (pos + 4 <= extEnd) {
        const uint16_t extType = static_cast<uint16_t>((tcpPayload[pos] << 8) | tcpPayload[pos + 1]);
        const uint16_t extLen = static_cast<uint16_t>((tcpPayload[pos + 2] << 8) | tcpPayload[pos + 3]);
        pos += 4;

        if (pos + extLen > extEnd) break;

        if (extType == 0x0000) { // Server Name Indication (SNI)
            if (extLen >= 5) {
                // Skip server_name_list length (2 bytes) + name_type (1 byte)
                const uint16_t nameLen = static_cast<uint16_t>((tcpPayload[pos + 3] << 8) | tcpPayload[pos + 4]);
                if (pos + 5 + nameLen <= extEnd) {
                    std::string sni(reinterpret_cast<const char*>(tcpPayload.data() + pos + 5), nameLen);
                    out.DomainOrHost = sni;
                    out.Protocol = ProtocolType::TLS;
                    out.ProtocolName = "TLS";
                    out.Info = std::format("TLS ClientHello (SNI: {})", sni);
                    return;
                }
            }
        }
        pos += extLen;
    }
}

void PacketParser::TryParseHttp(std::span<const uint8_t> tcpPayload, DecodedPacket& out) {
    if (tcpPayload.size() < 10) return;
    std::string_view text(reinterpret_cast<const char*>(tcpPayload.data()), tcpPayload.size());

    if (text.starts_with("GET ") || text.starts_with("POST ") || text.starts_with("HEAD ") ||
        text.starts_with("PUT ") || text.starts_with("DELETE ") || text.starts_with("HTTP/1.")) {

        out.ProtocolName = "HTTP";
        // Find end of first line
        const size_t lineEnd = text.find("\r\n");
        if (lineEnd != std::string::npos) {
            out.Info = std::string(text.substr(0, lineEnd));
        }

        // Try to extract Host header
        const size_t hostPos = text.find("\r\nHost: ");
        if (hostPos != std::string::npos) {
            const size_t hostValStart = hostPos + 8;
            const size_t hostValEnd = text.find("\r\n", hostValStart);
            if (hostValEnd != std::string::npos) {
                out.DomainOrHost = std::string(text.substr(hostValStart, hostValEnd - hostValStart));
            }
        }
    }
}

} // namespace WS

namespace WS {

namespace {

uint16_t Get16(std::span<const uint8_t> s, size_t at) { return static_cast<uint16_t>((s[at] << 8) | s[at + 1]); }
uint32_t Get32(std::span<const uint8_t> s, size_t at) {
    return (static_cast<uint32_t>(s[at]) << 24) | (static_cast<uint32_t>(s[at + 1]) << 16) | (static_cast<uint32_t>(s[at + 2]) << 8) | s[at + 3];
}

const char* EtherTypeName(uint16_t type) {
    switch (type) {
    case 0x0800: return "IPv4";
    case 0x86DD: return "IPv6";
    case 0x0806: return "ARP";
    case 0x8100: return "802.1Q VLAN";
    case 0x88CC: return "LLDP";
    case 0x888E: return "802.1X EAPOL";
    default: return "unknown";
    }
}

const char* ProtocolName(uint8_t p) {
    switch (p) {
    case 1: return "ICMP";
    case 2: return "IGMP";
    case 6: return "TCP";
    case 17: return "UDP";
    case 41: return "IPv6-in-IPv4";
    case 47: return "GRE";
    case 50: return "ESP";
    case 58: return "ICMPv6";
    default: return "other";
    }
}

std::string TcpFlags(uint8_t f) {
    std::string out;
    struct Named {
        uint8_t bit;
        const char* name;
    };
    static constexpr Named names[] = {{0x80, "CWR"}, {0x40, "ECE"}, {0x20, "URG"}, {0x10, "ACK"},
                                      {0x08, "PSH"}, {0x04, "RST"}, {0x02, "SYN"}, {0x01, "FIN"}};
    for (const auto& [bit, name] : names) {
        if (f & bit) {
            if (!out.empty()) out += ' ';
            out += name;
        }
    }
    return std::format("0x{:02X}  {}", f, out.empty() ? std::string("none") : out);
}

void BreakdownTransport(uint8_t protocol, std::span<const uint8_t> l4, std::vector<HeaderField>& out) {
    if (protocol == 6 && l4.size() >= 20) {
        const size_t offset = static_cast<size_t>(l4[12] >> 4) * 4;
        out.push_back({"TCP", "Ports", std::format("{} → {}", Get16(l4, 0), Get16(l4, 2))});
        out.push_back({"TCP", "Sequence", std::to_string(Get32(l4, 4))});
        out.push_back({"TCP", "Acknowledgment", std::to_string(Get32(l4, 8))});
        out.push_back({"TCP", "Flags", TcpFlags(l4[13])});
        out.push_back({"TCP", "Window", std::to_string(Get16(l4, 14))});
        out.push_back({"TCP", "Header / payload", std::format("{} B / {} B", offset, l4.size() > offset ? l4.size() - offset : 0)});
    } else if (protocol == 17 && l4.size() >= 8) {
        out.push_back({"UDP", "Ports", std::format("{} → {}", Get16(l4, 0), Get16(l4, 2))});
        out.push_back({"UDP", "Length", std::format("{} B", Get16(l4, 4))});
        out.push_back({"UDP", "Checksum", std::format("0x{:04X}", Get16(l4, 6))});
    } else if ((protocol == 1 || protocol == 58) && l4.size() >= 4) {
        const char* layer = protocol == 1 ? "ICMP" : "ICMPv6";
        out.push_back({layer, "Type / code", std::format("{} / {}", l4[0], l4[1])});
        if (l4.size() >= 8 && (l4[0] == 0 || l4[0] == 8 || l4[0] == 128 || l4[0] == 129)) {
            out.push_back({layer, "Identifier / sequence", std::format("0x{:04X} / {}", Get16(l4, 4), Get16(l4, 6))});
        }
    }
}

} // namespace

std::vector<HeaderField> PacketParser::Breakdown(std::span<const uint8_t> frame) {
    std::vector<HeaderField> out;
    if (frame.size() < 14) return out;
    out.push_back({"Ethernet", "Destination", FormatMac(std::span<const uint8_t, 6>(frame.data(), 6))});
    out.push_back({"Ethernet", "Source", FormatMac(std::span<const uint8_t, 6>(frame.data() + 6, 6))});
    uint16_t type = Get16(frame, 12);
    size_t offset = 14;
    if (type == 0x8100 && frame.size() >= 18) {
        out.push_back({"Ethernet", "VLAN", std::format("{} (priority {})", Get16(frame, 14) & 0x0FFF, Get16(frame, 14) >> 13)});
        type = Get16(frame, 16);
        offset = 18;
    }
    out.push_back({"Ethernet", "Type", std::format("0x{:04X}  {}", type, EtherTypeName(type))});
    const auto l3 = frame.subspan(offset);

    if (type == 0x0800 && l3.size() >= 20) {
        const size_t ihl = static_cast<size_t>(l3[0] & 0x0F) * 4;
        const uint16_t flags = Get16(l3, 6);
        out.push_back({"IPv4", "Source", FormatIpv4(*reinterpret_cast<const uint32_t*>(l3.data() + 12))});
        out.push_back({"IPv4", "Destination", FormatIpv4(*reinterpret_cast<const uint32_t*>(l3.data() + 16))});
        out.push_back({"IPv4", "Protocol", std::format("{}  {}", l3[9], ProtocolName(l3[9]))});
        out.push_back({"IPv4", "TTL", std::to_string(l3[8])});
        out.push_back({"IPv4", "Total length", std::format("{} B (header {} B)", Get16(l3, 2), ihl)});
        out.push_back({"IPv4", "Identification", std::format("0x{:04X}", Get16(l3, 4))});
        out.push_back({"IPv4", "Flags / offset", std::format("{}{}/ {}", (flags & 0x4000) ? "DF " : "", (flags & 0x2000) ? "MF " : "",
                                                           (flags & 0x1FFF) * 8)});
        out.push_back({"IPv4", "DSCP / ECN", std::format("{} / {}", l3[1] >> 2, l3[1] & 3)});
        if (ihl >= 20 && l3.size() >= ihl && (flags & 0x1FFF) == 0) BreakdownTransport(l3[9], l3.subspan(ihl), out);
    } else if (type == 0x86DD && l3.size() >= 40) {
        out.push_back({"IPv6", "Source", FormatIpv6(std::span<const uint8_t, 16>(l3.data() + 8, 16))});
        out.push_back({"IPv6", "Destination", FormatIpv6(std::span<const uint8_t, 16>(l3.data() + 24, 16))});
        out.push_back({"IPv6", "Next header", std::format("{}  {}", l3[6], ProtocolName(l3[6]))});
        out.push_back({"IPv6", "Hop limit", std::to_string(l3[7])});
        out.push_back({"IPv6", "Payload length", std::format("{} B", Get16(l3, 4))});
        out.push_back({"IPv6", "Flow label", std::format("0x{:05X}", Get32(l3, 0) & 0xFFFFF)});
        BreakdownTransport(l3[6], l3.subspan(40), out);
    } else if (type == 0x0806 && l3.size() >= 28) {
        const uint16_t op = Get16(l3, 6);
        out.push_back({"ARP", "Operation", op == 1 ? "1  request" : op == 2 ? "2  reply" : std::to_string(op)});
        out.push_back({"ARP", "Sender", std::format("{}  {}", FormatIpv4(*reinterpret_cast<const uint32_t*>(l3.data() + 14)),
                                                   FormatMac(std::span<const uint8_t, 6>(l3.data() + 8, 6)))});
        out.push_back({"ARP", "Target", std::format("{}  {}", FormatIpv4(*reinterpret_cast<const uint32_t*>(l3.data() + 24)),
                                                   FormatMac(std::span<const uint8_t, 6>(l3.data() + 18, 6)))});
    }
    return out;
}

} // namespace WS
