// WireScope - Rule compiler: selectors to WinpkFilter STATIC_FILTER entries, and their description.
#include "core/PacketTypes.h"
#include "core/Rules.h"
#include "core/RulesDetail.h"
#include "resources/resource.h"
#include <algorithm>
#include <bit>
#include <cstring>
#include <format>
#include <optional>
#include <utility>

namespace WS {

using namespace RulesDetail;

namespace {

int PrefixOfMask(uint32_t mask) {
    const int ones = std::popcount(mask);
    const uint32_t expected = ones == 0 ? 0 : 0xFFFFFFFFu << (32 - ones);
    return mask == expected ? ones : -1;
}

struct Block4 {
    uint32_t net;
    uint32_t mask;
};

std::vector<Block4> RangeToCidrs(uint32_t lo, uint32_t hi) {
    std::vector<Block4> out;
    uint64_t cur = lo;
    const uint64_t end = static_cast<uint64_t>(hi) + 1;
    while (cur < end) {
        int bits = cur == 0 ? 32 : std::countr_zero(static_cast<uint32_t>(cur));
        while (bits > 0 && cur + (1ULL << bits) > end) --bits;
        const uint32_t mask = bits >= 32 ? 0u : (0xFFFFFFFFu << bits);
        out.push_back({static_cast<uint32_t>(cur), mask});
        cur += 1ULL << bits;
    }
    return out;
}

STATIC_FILTER BaseEntry(DWORD action, HANDLE adapter, DWORD directionFlags) {
    STATIC_FILTER f{};
    f.m_Adapter = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(adapter));
    f.m_dwDirectionFlags = directionFlags;
    f.m_FilterAction = action;
    return f;
}

void SetSubnetV4(IP_ADDRESS_V4& a, uint32_t net, uint32_t mask) {
    a.m_AddressType = IP_SUBNET_TYPE;
    a.m_IpSubnet.m_Ip = std::byteswap(net);  // network order in memory
    a.m_IpSubnet.m_IpMask = std::byteswap(mask);
}

void SetSubnetV6(IP_ADDRESS_V6& a, const AddressMatch& m) {
    a.m_AddressType = IP_SUBNET_TYPE;
    std::memcpy(a.m_IpSubnet.m_Ip, m.net6.data(), 16);
    const auto mask = MaskBytes(m.prefix6);
    std::memcpy(a.m_IpSubnet.m_IpMask, mask.data(), 16);
}

const char* ActionName(DWORD action) {
    switch (action) {
    case FILTER_ACTION_PASS: return "PASS";
    case FILTER_ACTION_DROP: return "DROP";
    case FILTER_ACTION_REDIRECT: return "REDIRECT";
    case 4: return "PASS+RDR";
    case 5: return "DROP+RDR";
    default: return "?";
    }
}

} // namespace

STATIC_FILTER CatchAll(DWORD action, HANDLE adapter) {
    return BaseEntry(action, adapter, PACKET_FLAG_ON_SEND | PACKET_FLAG_ON_RECEIVE);
}

std::expected<std::vector<STATIC_FILTER>, std::string> Compile(const Selector& s, DWORD action, HANDLE adapter) {
    std::vector<STATIC_FILTER> out;
    if (s.dir == Dir::None) return out;
    if (s.app.set) {
        return std::unexpected(Msg(IDS_RULE_APP_KERNEL));  // the driver knows no processes
    }

    // Relative keywords resolve differently per direction, so each direction becomes its own pass.
    const bool relative = s.remote.set || s.local.set || s.rport.set || s.lport.set;
    std::vector<Dir> passes;
    if (relative) {
        if (Has(s.dir, Dir::Out)) passes.push_back(Dir::Out);
        if (Has(s.dir, Dir::In)) passes.push_back(Dir::In);
    } else {
        passes.push_back(s.dir);
    }

    for (const Dir pass : passes) {
        const DWORD flags = (Has(pass, Dir::Out) ? PACKET_FLAG_ON_SEND : 0) | (Has(pass, Dir::In) ? PACKET_FLAG_ON_RECEIVE : 0);
        if (s.MatchesAllFrames()) {
            out.push_back(BaseEntry(action, adapter, flags));
            continue;
        }
        const bool outbound = pass == Dir::Out;
        const AddressMatch src = s.src.set ? s.src : relative ? (outbound ? s.local : s.remote) : AddressMatch{};
        const AddressMatch dst = s.dst.set ? s.dst : relative ? (outbound ? s.remote : s.local) : AddressMatch{};
        const PortMatch sp = s.sport.set ? s.sport : relative ? (outbound ? s.lport : s.rport) : PortMatch{};
        const PortMatch dp = s.dport.set ? s.dport : relative ? (outbound ? s.rport : s.lport) : PortMatch{};

        std::vector<std::pair<PortMatch, PortMatch>> portVariants;
        if (s.port.set) portVariants = {{s.port, PortMatch{}}, {PortMatch{}, s.port}};
        else portVariants = {{sp, dp}};
        const bool anyPorts = s.port.set || sp.set || dp.set;

        std::vector<Family> families;
        if (s.family == Family::Any) families = {Family::V4, Family::V6};
        else families = {s.family};

        for (const Family family : families) {
            std::vector<int> protocols;
            switch (s.proto) {
            case Proto::Any: protocols = anyPorts ? std::vector<int>{6, 17} : std::vector<int>{-1}; break;
            case Proto::Tcp: protocols = {6}; break;
            case Proto::Udp: protocols = {17}; break;
            case Proto::TcpUdp: protocols = {6, 17}; break;
            case Proto::Icmp: protocols = {family == Family::V4 ? 1 : 58}; break;
            case Proto::Number: protocols = {s.protoNumber}; break;
            }

            std::vector<std::optional<Block4>> srcBlocks{std::nullopt}, dstBlocks{std::nullopt};
            if (family == Family::V4) {
                if (src.set) {
                    srcBlocks.clear();
                    for (const auto& b : RangeToCidrs(src.lo4, src.hi4)) srcBlocks.emplace_back(b);
                }
                if (dst.set) {
                    dstBlocks.clear();
                    for (const auto& b : RangeToCidrs(dst.lo4, dst.hi4)) dstBlocks.emplace_back(b);
                }
            }

            for (const int protocol : protocols) {
                for (const auto& sb : srcBlocks) {
                    for (const auto& db : dstBlocks) {
                        for (const auto& [ps, pd] : portVariants) {
                            STATIC_FILTER e = BaseEntry(action, adapter, flags);
                            e.m_ValidFields = NETWORK_LAYER_VALID;
                            if (family == Family::V4) {
                                e.m_NetworkFilter.m_dwUnionSelector = FILTER_NET_IPV4;
                                IP_V4_FILTER& ip = e.m_NetworkFilter.m_IPv4;
                                if (sb) {
                                    ip.m_ValidFields |= IP_FILTER_SRC_ADDRESS;
                                    SetSubnetV4(ip.m_SrcAddress, sb->net, sb->mask);
                                }
                                if (db) {
                                    ip.m_ValidFields |= IP_FILTER_DEST_ADDRESS;
                                    SetSubnetV4(ip.m_DestAddress, db->net, db->mask);
                                }
                                if (protocol >= 0) {
                                    ip.m_ValidFields |= IP_FILTER_PROTOCOL;
                                    ip.m_Protocol = static_cast<BYTE>(protocol);
                                }
                            } else {
                                e.m_NetworkFilter.m_dwUnionSelector = FILTER_NET_IPV6;
                                IP_V6_FILTER& ip = e.m_NetworkFilter.m_IPv6;
                                if (src.set) {
                                    ip.m_ValidFields |= IP_FILTER_SRC_ADDRESS;
                                    SetSubnetV6(ip.m_SrcAddress, src);
                                }
                                if (dst.set) {
                                    ip.m_ValidFields |= IP_FILTER_DEST_ADDRESS;
                                    SetSubnetV6(ip.m_DestAddress, dst);
                                }
                                if (protocol >= 0) {
                                    ip.m_ValidFields |= IP_FILTER_PROTOCOL;
                                    ip.m_Protocol = static_cast<BYTE>(protocol);
                                }
                            }
                            if (ps.set || pd.set) {
                                e.m_ValidFields |= TRANSPORT_LAYER_VALID;
                                e.m_TransportFilter.m_dwUnionSelector = FILTER_TRANSPORT_TCPUDP;
                                TCPUDP_FILTER& t = e.m_TransportFilter.m_TcpUdp;
                                if (ps.set) {
                                    t.m_ValidFields |= TCPUDP_SRC_PORT;
                                    t.m_SourcePort = {ps.lo, ps.hi};
                                }
                                if (pd.set) {
                                    t.m_ValidFields |= TCPUDP_DEST_PORT;
                                    t.m_DestPort = {pd.lo, pd.hi};
                                }
                            } else if (s.icmpTypeSet) {
                                e.m_ValidFields |= TRANSPORT_LAYER_VALID;
                                e.m_TransportFilter.m_dwUnionSelector = FILTER_TRANSPORT_ICMP;
                                e.m_TransportFilter.m_Icmp.m_ValidFields = ICMP_FILTER_TYPE;
                                e.m_TransportFilter.m_Icmp.m_TypeRange = {s.icmpType, s.icmpType};
                            }
                            out.push_back(e);
                            if (out.size() > kMaxEntriesPerSelector) {
                                return std::unexpected(Msg(IDS_RULE_TOO_WIDE, kMaxEntriesPerSelector));
                            }
                        }
                    }
                }
            }
        }
    }
    return out;
}

std::string DescribeFilter(const STATIC_FILTER& f) {
    const bool send = f.m_dwDirectionFlags & PACKET_FLAG_ON_SEND, recv = f.m_dwDirectionFlags & PACKET_FLAG_ON_RECEIVE;
    std::string text = std::format("{:<8} {:<4} ", ActionName(f.m_FilterAction), send && recv ? "both" : send ? "out" : recv ? "in" : "none");
    text += f.m_Adapter ? std::format("adapter 0x{:X}  ", f.m_Adapter) : std::string("all adapters  ");

    if (f.m_ValidFields & DATA_LINK_LAYER_VALID) text += "eth ";
    if (!(f.m_ValidFields & NETWORK_LAYER_VALID)) {
        text += "every frame";
    } else if (f.m_NetworkFilter.m_dwUnionSelector == FILTER_NET_IPV4) {
        const IP_V4_FILTER& ip = f.m_NetworkFilter.m_IPv4;
        text += "ip4";
        if (ip.m_ValidFields & IP_FILTER_PROTOCOL) text += std::format(" proto {}", ip.m_Protocol);
        auto address = [](const IP_ADDRESS_V4& a) {
            if (a.m_AddressType == IP_RANGE_TYPE) {
                return FormatIpv4Host(std::byteswap(a.m_IpRange.m_StartIp)) + "-" + FormatIpv4Host(std::byteswap(a.m_IpRange.m_EndIp));
            }
            const uint32_t mask = std::byteswap(a.m_IpSubnet.m_IpMask);
            const int prefix = PrefixOfMask(mask);
            const std::string ip4 = FormatIpv4Host(std::byteswap(a.m_IpSubnet.m_Ip));
            return prefix == 32 ? ip4 : prefix >= 0 ? std::format("{}/{}", ip4, prefix) : ip4 + " mask " + FormatIpv4Host(mask);
        };
        if (ip.m_ValidFields & IP_FILTER_SRC_ADDRESS) text += " src " + address(ip.m_SrcAddress);
        if (ip.m_ValidFields & IP_FILTER_DEST_ADDRESS) text += " dst " + address(ip.m_DestAddress);
    } else if (f.m_NetworkFilter.m_dwUnionSelector == FILTER_NET_IPV6) {
        const IP_V6_FILTER& ip = f.m_NetworkFilter.m_IPv6;
        text += "ip6";
        if (ip.m_ValidFields & IP_FILTER_PROTOCOL) text += std::format(" proto {}", ip.m_Protocol);
        auto address = [](const IP_ADDRESS_V6& a) {
            if (a.m_AddressType == IP_RANGE_TYPE) return FormatIpv6Bytes(a.m_IpRange.m_StartIp) + "-" + FormatIpv6Bytes(a.m_IpRange.m_EndIp);
            int prefix = 0;
            for (const BYTE b : a.m_IpSubnet.m_IpMask) prefix += std::popcount(static_cast<unsigned>(b));
            return FormatIpv6Bytes(a.m_IpSubnet.m_Ip) + (prefix < 128 ? std::format("/{}", prefix) : std::string());
        };
        if (ip.m_ValidFields & IP_FILTER_SRC_ADDRESS) text += " src " + address(ip.m_SrcAddress);
        if (ip.m_ValidFields & IP_FILTER_DEST_ADDRESS) text += " dst " + address(ip.m_DestAddress);
    } else {
        text += std::format("network selector {}", f.m_NetworkFilter.m_dwUnionSelector);
    }
    if (f.m_ValidFields & TRANSPORT_LAYER_VALID) {
        if (f.m_TransportFilter.m_dwUnionSelector == FILTER_TRANSPORT_TCPUDP) {
            const TCPUDP_FILTER& t = f.m_TransportFilter.m_TcpUdp;
            auto range = [](const PORT_RANGE& r) {
                return r.m_StartRange == r.m_EndRange ? std::to_string(r.m_StartRange) : std::format("{}-{}", r.m_StartRange, r.m_EndRange);
            };
            if (t.m_ValidFields & TCPUDP_SRC_PORT) text += " sport " + range(t.m_SourcePort);
            if (t.m_ValidFields & TCPUDP_DEST_PORT) text += " dport " + range(t.m_DestPort);
            if (t.m_ValidFields & TCPUDP_TCP_FLAGS) text += std::format(" flags 0x{:02X}", t.m_TCPFlags);
        } else if (f.m_TransportFilter.m_dwUnionSelector == FILTER_TRANSPORT_ICMP) {
            const ICMP_TYPE_FILTER& i = f.m_TransportFilter.m_Icmp;
            if (i.m_ValidFields & ICMP_FILTER_TYPE) text += std::format(" type {}-{}", i.m_TypeRange.m_StartRange, i.m_TypeRange.m_EndRange);
            if (i.m_ValidFields & ICMP_FILTER_CODE) text += std::format(" code {}-{}", i.m_CodeRange.m_StartRange, i.m_CodeRange.m_EndRange);
        }
    }
    text += std::format("   [in {} pkt / {} B, out {} pkt / {} B]", f.m_PacketsIn, f.m_BytesIn, f.m_PacketsOut, f.m_BytesOut);
    return text;
}

} // namespace WS
