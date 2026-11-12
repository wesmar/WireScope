#include "core/Safety.h"
#include "resources/resource.h"
#include "support/Language.h"
#include <winsock2.h>
#include <ws2ipdef.h>
#include <winternl.h>  // NTSTATUS for ip2string.h
#include <ip2string.h>
#include <iphlpapi.h>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ntdll.lib")

namespace WS {

namespace {

// The IPv4 DNS servers Windows uses (host byte order); a public resolver when none is configured.
std::vector<uint32_t> DnsServers() {
    std::vector<uint32_t> servers;
    ULONG size = 0;
    if (GetNetworkParams(nullptr, &size) == ERROR_BUFFER_OVERFLOW && size) {
        std::vector<uint8_t> buffer(size);
        auto* info = reinterpret_cast<FIXED_INFO*>(buffer.data());
        if (GetNetworkParams(info, &size) == NO_ERROR) {
            for (const IP_ADDR_STRING* a = &info->DnsServerList; a; a = a->Next) {
                in_addr address{};
                PCSTR end = nullptr;
                if (RtlIpv4StringToAddressA(a->IpAddress.String, TRUE, &end, &address) == 0 && end && *end == '\0' &&
                    address.s_addr != 0) {
                    servers.push_back(ntohl(address.s_addr));
                }
            }
        }
    }
    if (servers.empty()) servers.push_back(0x08080808);  // 8.8.8.8
    return servers;
}

FrameInfo Flow(uint8_t protocol, uint32_t src, uint16_t sport, uint32_t dst, uint16_t dport) {
    FrameInfo f;
    f.ip = true;
    f.version = 4;
    f.protocol = protocol;
    f.src4 = src;
    f.dst4 = dst;
    f.hasPorts = true;
    f.srcPort = sport;
    f.dstPort = dport;
    return f;
}

// The rule that decides the flow, or nullptr when the default policy does. `blocked` reports the verdict.
const Rule* Decide(std::span<const Rule> rules, RuleAction policy, const FrameInfo& f, Dir dir, bool& blocked) {
    for (const Rule& r : rules) {
        if (r.enabled && Matches(r.match, f, dir)) {
            blocked = r.action == RuleAction::Block;
            return &r;
        }
    }
    blocked = policy == RuleAction::Block;
    return nullptr;
}

} // namespace

std::vector<LockoutRisk> LockoutRisks(std::span<const Rule> rules, RuleAction policy) {
    constexpr uint32_t kLocal = 0xC0A80064;   // 192.168.0.100, a typical LAN address of this machine
    constexpr uint32_t kPeer = 0x0A000002;    // 10.0.0.2, a remote desktop client
    constexpr uint32_t kWeb = 0x01010101;     // 1.1.1.1, any web server
    std::vector<LockoutRisk> risks;
    auto check = [&](UINT name, const FrameInfo& f, Dir dir) {
        bool blocked = false;
        const Rule* rule = Decide(rules, policy, f, dir, blocked);
        if (blocked) risks.push_back({name, rule});
        return blocked;
    };
    for (uint32_t dns : DnsServers()) {
        if (check(IDS_RISK_DNS, Flow(17, kLocal, 50353, dns, 53), Dir::Out)) break;
    }
    check(IDS_RISK_WEB, Flow(6, kLocal, 50443, kWeb, 443), Dir::Out);
    check(IDS_RISK_RDP, Flow(6, kPeer, 50389, kLocal, 3389), Dir::In);
    return risks;
}

std::wstring DescribeRisks(std::span<const LockoutRisk> risks) {
    std::wstring out;
    for (const LockoutRisk& r : risks) {
        if (!out.empty()) out += L", ";
        out += Text::Get(r.name);
    }
    return out;
}

} // namespace WS
