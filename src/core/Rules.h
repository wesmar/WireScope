// WireScope - Traffic selectors and firewall rules.
//
// One small language serves the firewall ("block out tcp dport 443"), the impairment simulator's
// traffic match ("udp rport 27015-27030") and the rules files. A selector is matched in user mode
// against FrameInfo, and compiled into WinpkFilter STATIC_FILTER entries for the kernel.
//
//   rule      := action selector
//   action    := allow | pass | permit | block | drop | deny
//   selector  := { direction | family | protocol | address | port | "type" N | "all" }
//   direction := in | out | both
//   family    := ip4 | ip6
//   protocol  := tcp | udp | icmp | "proto" N
//   address   := (from | to | remote | local | host) ADDR      ADDR: a.b.c.d[/n] | a.b.c.d-e.f.g.h | v6[/n]
//   port      := (sport | dport | rport | lport | port) P       P: n | n-m
//   app       := "app" NAME | "app" PATH                         a value with spaces goes in "quotes"
//
// "remote"/"local" (and rport/lport) are relative to the packet direction: for outbound traffic the
// remote side is the destination, for inbound traffic it is the source.
#pragma once
#include "core/FilterAbi.h"
#include "core/FrameView.h"
#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace WS {

enum class Dir : uint8_t { None = 0, In = 1, Out = 2, Both = 3 };
[[nodiscard]] constexpr bool Has(Dir set, Dir d) noexcept {
    return (static_cast<uint8_t>(set) & static_cast<uint8_t>(d)) != 0;
}

enum class Family : uint8_t { Any, V4, V6 };
enum class Proto : uint8_t { Any, Tcp, Udp, TcpUdp, Icmp, Number };

struct AddressMatch {
    bool     set{false};
    Family   family{Family::Any};
    uint32_t lo4{0}, hi4{0};          // IPv4, host order, inclusive range
    std::array<uint8_t, 16> net6{};   // IPv6 network (masked)
    uint8_t  prefix6{128};

    [[nodiscard]] bool Contains4(uint32_t ip) const noexcept { return ip >= lo4 && ip <= hi4; }
    [[nodiscard]] bool Contains6(const std::array<uint8_t, 16>& ip) const noexcept;
};

struct PortMatch {
    bool     set{false};
    uint16_t lo{0}, hi{65535};
    [[nodiscard]] bool Contains(uint16_t p) const noexcept { return p >= lo && p <= hi; }
};

struct AppMatch {
    bool        set{false};
    bool        path{false};  // `name` is a full image path (a program in one folder only)
    std::string name;         // folded process name ("discord.exe") or path ("c:\tools\nc.exe")
};

struct Selector {
    Dir      dir{Dir::Both};
    Family   family{Family::Any};
    Proto    proto{Proto::Any};
    uint8_t  protoNumber{0};
    AddressMatch src, dst, remote, local;
    PortMatch    sport, dport, rport, lport, port;
    AppMatch     app;
    bool     icmpTypeSet{false};
    uint8_t  icmpType{0};

    // True when only the direction restricts the selector (it matches every frame, ARP included).
    [[nodiscard]] bool MatchesAllFrames() const noexcept;
};

enum class RuleAction : uint8_t { Allow, Block };

struct HitCounter {
    uint64_t packets{0};
    uint64_t bytes{0};
    HitCounter& operator+=(const HitCounter& o) noexcept {
        packets += o.packets;
        bytes += o.bytes;
        return *this;
    }
};

struct Rule {
    uint64_t   id{0};          // assigned by the owner; stable while the rule lives
    bool       enabled{true};
    RuleAction action{RuleAction::Block};
    Selector   match;
    std::string text;          // normalised selector text, without the action word
};

[[nodiscard]] std::expected<Selector, std::string> ParseSelector(std::string_view text);
[[nodiscard]] std::expected<Rule, std::string> ParseRule(std::string_view text);
[[nodiscard]] std::string RuleText(const Rule& rule);          // "block out tcp dport 443"
[[nodiscard]] std::string Summarize(const Selector& selector);  // "Outbound · TCP · remote port 443"
// One value as the rule language writes it: in quotes when it holds a space or a comma.
[[nodiscard]] std::string QuoteToken(std::string_view value);

// User-mode match (data path: noexcept, no allocation).
[[nodiscard]] bool Matches(const Selector& selector, const FrameInfo& frame, Dir packetDir) noexcept;

// Driver entries equivalent to the selector, each with `action` (FILTER_ACTION_*).
[[nodiscard]] std::expected<std::vector<STATIC_FILTER>, std::string> Compile(const Selector& selector, DWORD action,
                                                                             HANDLE adapter);
[[nodiscard]] STATIC_FILTER CatchAll(DWORD action, HANDLE adapter);  // matches every frame, both directions
[[nodiscard]] std::string DescribeFilter(const STATIC_FILTER& filter);  // one line for --firewall-show

// Rules files and the stored rule list: one rule per line, '#' starts a comment and
// "# off: <rule>" keeps a disabled rule.
struct RulesTextError {
    size_t line{0};
    std::string message;
};
[[nodiscard]] std::expected<std::vector<Rule>, RulesTextError> ParseRulesText(std::string_view text);
[[nodiscard]] std::string FormatRulesText(std::span<const Rule> rules);

[[nodiscard]] std::string RulesHelp();  // from the string table

} // namespace WS
