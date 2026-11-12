#include "core/Rules.h"
#include "core/ProcessMapper.h"
#include "core/RulesDetail.h"
#include "resources/resource.h"
#include "support/Language.h"
#include "support/Text.h"
#include <winsock2.h>
#include <ws2ipdef.h>
#include <winternl.h>  // NTSTATUS for ip2string.h
#include <ip2string.h>
#include <algorithm>
#include <bit>
#include <cctype>
#include <charconv>
#include <cstring>
#include <format>
#include <optional>
#include <type_traits>
#include <utility>

#pragma comment(lib, "ntdll.lib")

namespace WS {

using namespace RulesDetail;

namespace {

std::string Lower(std::string_view s) {
    std::string out(s);
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

std::string_view Trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
}

bool Separator(char c) noexcept {
    return std::isspace(static_cast<unsigned char>(c)) || c == ',';
}

// Words separated by blanks or commas; "a quoted value" is one token (without the quotes), so
// program names and paths may contain spaces. Windows names never contain a quote.
std::vector<std::string_view> Tokenize(std::string_view text) {
    std::vector<std::string_view> tokens;
    size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && Separator(text[i])) ++i;
        if (i < text.size() && text[i] == '"') {
            const size_t start = ++i;
            while (i < text.size() && text[i] != '"') ++i;
            tokens.push_back(text.substr(start, i - start));
            if (i < text.size()) ++i;  // closing quote
            continue;
        }
        const size_t start = i;
        while (i < text.size() && !Separator(text[i])) ++i;
        if (i > start) tokens.push_back(text.substr(start, i - start));
    }
    return tokens;
}

std::optional<uint32_t> ParseNumber(std::string_view s, uint32_t max) {
    uint32_t value = 0;
    if (s.empty()) return std::nullopt;
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    if (ec != std::errc{} || end != s.data() + s.size() || value > max) return std::nullopt;
    return value;
}

std::optional<uint32_t> ParseIpv4(std::string_view s) {
    uint32_t value = 0;
    for (int part = 0; part < 4; ++part) {
        const size_t dot = s.find('.');
        const std::string_view piece = part < 3 ? s.substr(0, dot) : s;
        if (part < 3 && dot == std::string_view::npos) return std::nullopt;
        if (piece.empty() || piece.size() > 3) return std::nullopt;
        const auto octet = ParseNumber(piece, 255);
        if (!octet) return std::nullopt;
        value = (value << 8) | *octet;
        if (part < 3) s.remove_prefix(dot + 1);
    }
    return value;
}

bool ParseIpv6(std::string_view s, std::array<uint8_t, 16>& out) {
    if (s.empty() || s.size() > 63 || s.find(':') == std::string_view::npos) return false;
    const std::string z(s);
    in6_addr address{};
    PCSTR terminator = nullptr;
    if (RtlIpv6StringToAddressA(z.c_str(), &terminator, &address) != 0 || !terminator || *terminator != '\0') return false;
    std::memcpy(out.data(), address.u.Byte, 16);
    return true;
}

std::expected<AddressMatch, std::string> ParseAddress(std::string_view token) {
    AddressMatch m;
    const std::string lower = Lower(token);
    if (lower == "any" || lower == "*") return m;
    m.set = true;

    if (const size_t dash = token.find('-'); dash != std::string_view::npos && token.find(':') == std::string_view::npos) {
        const auto lo = ParseIpv4(token.substr(0, dash));
        const auto hi = ParseIpv4(token.substr(dash + 1));
        if (!lo || !hi) return std::unexpected(Msg(IDS_RULE_BAD_RANGE, token));
        if (*lo > *hi) return std::unexpected(Msg(IDS_RULE_RANGE_ORDER, token));
        m.family = Family::V4;
        m.lo4 = *lo;
        m.hi4 = *hi;
        return m;
    }

    std::string_view address = token;
    std::optional<uint32_t> prefix;
    if (const size_t slash = token.find('/'); slash != std::string_view::npos) {
        prefix = ParseNumber(token.substr(slash + 1), 128);
        if (!prefix) return std::unexpected(Msg(IDS_RULE_BAD_PREFIX, token));
        address = token.substr(0, slash);
    }
    if (const auto v4 = ParseIpv4(address)) {
        if (prefix && *prefix > 32) return std::unexpected(Msg(IDS_RULE_PREFIX_V4, token));
        const uint32_t bits = prefix.value_or(32);
        const uint32_t mask = bits == 0 ? 0 : 0xFFFFFFFFu << (32 - bits);
        m.family = Family::V4;
        m.lo4 = *v4 & mask;
        m.hi4 = m.lo4 | ~mask;
        return m;
    }
    std::array<uint8_t, 16> v6{};
    if (ParseIpv6(address, v6)) {
        const uint32_t bits = prefix.value_or(128);
        MaskV6(v6, bits);
        m.family = Family::V6;
        m.net6 = v6;
        m.prefix6 = static_cast<uint8_t>(bits);
        return m;
    }
    return std::unexpected(Msg(IDS_RULE_BAD_ADDRESS, token));
}

std::expected<PortMatch, std::string> ParsePorts(std::string_view token) {
    PortMatch p;
    const std::string lower = Lower(token);
    if (lower == "any" || lower == "*") return p;
    const size_t dash = token.find('-');
    const auto lo = ParseNumber(token.substr(0, dash), 65535);
    const auto hi = dash == std::string_view::npos ? lo : ParseNumber(token.substr(dash + 1), 65535);
    if (!lo || !hi) return std::unexpected(Msg(IDS_RULE_BAD_PORT, token));
    if (*lo > *hi) return std::unexpected(Msg(IDS_RULE_PORT_ORDER, token));
    p.set = true;
    p.lo = static_cast<uint16_t>(*lo);
    p.hi = static_cast<uint16_t>(*hi);
    return p;
}

std::optional<uint8_t> ParseProtocolName(std::string_view token) {
    const std::string t = Lower(token);
    struct Named {
        std::string_view name;
        uint8_t number;
    };
    static constexpr Named kNames[] = {
        {"tcp", 6}, {"udp", 17}, {"icmp", 1}, {"igmp", 2}, {"gre", 47},
        {"esp", 50}, {"ah", 51}, {"icmp6", 58}, {"icmpv6", 58}, {"sctp", 132},
    };
    for (const auto& [name, number] : kNames) {
        if (t == name) return number;
    }
    if (const auto n = ParseNumber(token, 255)) return static_cast<uint8_t>(*n);
    return std::nullopt;
}

std::string FormatAddress(const AddressMatch& a) {
    if (a.family == Family::V6) {
        std::string text = FormatIpv6Bytes(a.net6.data());
        if (a.prefix6 < 128) text += std::format("/{}", a.prefix6);
        return text;
    }
    if (a.lo4 == a.hi4) return FormatIpv4Host(a.lo4);
    const uint64_t size = static_cast<uint64_t>(a.hi4) - a.lo4 + 1;
    if (std::has_single_bit(size) && (a.lo4 & (size - 1)) == 0) {
        return std::format("{}/{}", FormatIpv4Host(a.lo4), 32 - std::countr_zero(size));
    }
    return FormatIpv4Host(a.lo4) + "-" + FormatIpv4Host(a.hi4);
}

std::string FormatPorts(const PortMatch& p) {
    return p.lo == p.hi ? std::to_string(p.lo) : std::format("{}-{}", p.lo, p.hi);
}

bool UsesPorts(const Selector& s) {
    return s.sport.set || s.dport.set || s.rport.set || s.lport.set || s.port.set;
}

} // namespace

namespace RulesDetail {

std::string FormatIpv4Host(uint32_t ip) {
    return std::format("{}.{}.{}.{}", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

std::string FormatIpv6Bytes(const uint8_t* bytes) {
    in6_addr address{};
    std::memcpy(address.u.Byte, bytes, 16);
    char text[64]{};
    RtlIpv6AddressToStringA(&address, text);
    return text;
}

void MaskV6(std::array<uint8_t, 16>& bytes, uint32_t prefix) {
    for (uint32_t i = 0; i < 16; ++i) {
        const uint32_t bits = prefix > i * 8 ? std::min<uint32_t>(prefix - i * 8, 8) : 0;
        const uint8_t mask = bits == 0 ? 0 : static_cast<uint8_t>(0xFFu << (8 - bits));
        bytes[i] &= mask;
    }
}

std::array<uint8_t, 16> MaskBytes(uint32_t prefix) {
    std::array<uint8_t, 16> mask;
    mask.fill(0xFF);
    MaskV6(mask, prefix);
    return mask;
}

} // namespace RulesDetail

bool AddressMatch::Contains6(const std::array<uint8_t, 16>& ip) const noexcept {
    uint32_t bits = prefix6;
    for (size_t i = 0; i < 16 && bits > 0; ++i) {
        const uint32_t take = std::min<uint32_t>(bits, 8);
        const uint8_t mask = static_cast<uint8_t>(0xFFu << (8 - take));
        if ((ip[i] & mask) != (net6[i] & mask)) return false;
        bits -= take;
    }
    return true;
}

bool Selector::MatchesAllFrames() const noexcept {
    return family == Family::Any && proto == Proto::Any && !src.set && !dst.set && !remote.set && !local.set &&
           !sport.set && !dport.set && !rport.set && !lport.set && !port.set && !icmpTypeSet && !app.set;
}

std::expected<Selector, std::string> ParseSelector(std::string_view text) {
    const auto tokens = Tokenize(text);
    Selector s;
    bool dirSet = false, familySet = false, protoSet = false;

    auto value = [&](size_t& i, const std::string& keyword) -> std::expected<std::string_view, std::string> {
        if (i + 1 >= tokens.size()) return std::unexpected(Msg(IDS_RULE_NEEDS_VALUE, keyword));
        return tokens[++i];
    };
    auto setDir = [&](Dir d) -> std::optional<std::string> {
        if (dirSet && s.dir != d) return Msg(IDS_RULE_DIRECTIONS);
        s.dir = d;
        dirSet = true;
        return std::nullopt;
    };
    auto setFamily = [&](Family f) -> std::optional<std::string> {
        if (familySet && s.family != f) return Msg(IDS_RULE_FAMILIES);
        s.family = f;
        familySet = true;
        return std::nullopt;
    };
    auto setProto = [&](Proto p, uint8_t number) -> std::optional<std::string> {
        if (protoSet) {
            const bool tcpUdp = (s.proto == Proto::Tcp && p == Proto::Udp) || (s.proto == Proto::Udp && p == Proto::Tcp);
            if (tcpUdp) {
                s.proto = Proto::TcpUdp;
                return std::nullopt;
            }
            if (s.proto != p || s.protoNumber != number) return Msg(IDS_RULE_PROTOCOLS);
        }
        s.proto = p;
        s.protoNumber = number;
        protoSet = true;
        return std::nullopt;
    };

    for (size_t i = 0; i < tokens.size(); ++i) {
        const std::string t = Lower(tokens[i]);
        std::optional<std::string> error;
        AddressMatch* address = nullptr;
        PortMatch* ports = nullptr;

        if (t == "in" || t == "inbound" || t == "incoming") error = setDir(Dir::In);
        else if (t == "out" || t == "outbound" || t == "outgoing") error = setDir(Dir::Out);
        else if (t == "both" || t == "inout") error = setDir(Dir::Both);
        else if (t == "ip4" || t == "ipv4") error = setFamily(Family::V4);
        else if (t == "ip6" || t == "ipv6") error = setFamily(Family::V6);
        else if (t == "ip" || t == "all" || t == "any" || t == "*") continue;
        else if (t == "tcp") error = setProto(Proto::Tcp, 6);
        else if (t == "udp") error = setProto(Proto::Udp, 17);
        else if (t == "icmp") error = setProto(Proto::Icmp, 0);
        else if (t == "icmp6" || t == "icmpv6") {
            error = setProto(Proto::Icmp, 0);
            if (!error) error = setFamily(Family::V6);
        } else if (t == "proto" || t == "protocol") {
            auto v = value(i, t);
            if (!v) return std::unexpected(v.error());
            const auto number = ParseProtocolName(*v);
            if (!number) return std::unexpected(Msg(IDS_RULE_BAD_PROTOCOL, *v));
            if (*number == 6) error = setProto(Proto::Tcp, 6);
            else if (*number == 17) error = setProto(Proto::Udp, 17);
            else if (*number == 1 || *number == 58) error = setProto(Proto::Icmp, 0);
            else error = setProto(Proto::Number, *number);
        } else if (t == "from" || t == "src") address = &s.src;
        else if (t == "to" || t == "dst") address = &s.dst;
        else if (t == "remote" || t == "host" || t == "peer") address = &s.remote;
        else if (t == "local") address = &s.local;
        else if (t == "sport" || t == "srcport") ports = &s.sport;
        else if (t == "dport" || t == "dstport") ports = &s.dport;
        else if (t == "rport") ports = &s.rport;
        else if (t == "lport") ports = &s.lport;
        else if (t == "port") ports = &s.port;
        else if (t == "app" || t.starts_with("app:")) {
            std::string name;
            if (t.starts_with("app:")) {
                name = std::string(tokens[i].substr(4));
            } else {
                auto v = value(i, t);
                if (!v) return std::unexpected(v.error());
                name = std::string(*v);
            }
            if (s.app.set) return std::unexpected(Msg(IDS_RULE_TWICE, "app"));
            if (name.empty()) return std::unexpected(Msg(IDS_RULE_NEEDS_VALUE, "app"));
            s.app.set = true;
            s.app.name = FoldCase(name);  // also folds letters beyond ASCII, as ProcessMapper does
            s.app.path = s.app.name.find_first_of("\\/:") != std::string::npos;
            if (s.app.path) std::replace(s.app.name.begin(), s.app.name.end(), '/', '\\');
            else if (s.app.name.find('.') == std::string::npos) s.app.name += ".exe";  // "app discord" = discord.exe
        } else if (t == "type") {
            auto v = value(i, t);
            if (!v) return std::unexpected(v.error());
            const auto type = ParseNumber(*v, 255);
            if (!type) return std::unexpected(Msg(IDS_RULE_BAD_TYPE, *v));
            if (s.icmpTypeSet) return std::unexpected(Msg(IDS_RULE_TWICE, "type"));
            s.icmpTypeSet = true;
            s.icmpType = static_cast<uint8_t>(*type);
        } else {
            // A bare address means "this host", whichever side of the conversation it is on.
            const auto bare = ParseAddress(tokens[i]);
            if (!bare || !bare->set) return std::unexpected(Msg(IDS_RULE_UNEXPECTED, tokens[i]));
            if (s.remote.set) return std::unexpected(Msg(IDS_RULE_REMOTES));
            s.remote = *bare;
            continue;
        }

        if (error) return std::unexpected(*error);
        if (address) {
            auto v = value(i, t);
            if (!v) return std::unexpected(v.error());
            if (address->set) return std::unexpected(Msg(IDS_RULE_TWICE, t));
            auto parsed = ParseAddress(*v);
            if (!parsed) return std::unexpected(parsed.error());
            *address = *parsed;
        } else if (ports) {
            auto v = value(i, t);
            if (!v) return std::unexpected(v.error());
            if (ports->set) return std::unexpected(Msg(IDS_RULE_TWICE, t));
            auto parsed = ParsePorts(*v);
            if (!parsed) return std::unexpected(parsed.error());
            *ports = *parsed;
        }
    }

    // Consistency
    if ((s.src.set || s.dst.set) && (s.remote.set || s.local.set)) {
        return std::unexpected(Msg(IDS_RULE_MIX_ADDRESS));
    }
    if ((s.sport.set || s.dport.set) && (s.rport.set || s.lport.set)) {
        return std::unexpected(Msg(IDS_RULE_MIX_PORTS));
    }
    if (s.port.set && (s.sport.set || s.dport.set || s.rport.set || s.lport.set)) {
        return std::unexpected(Msg(IDS_RULE_PORT_EITHER));
    }
    if (UsesPorts(s) && (s.proto == Proto::Icmp || s.proto == Proto::Number)) {
        return std::unexpected(Msg(IDS_RULE_PORT_PROTO));
    }
    if (s.icmpTypeSet) {
        if (s.proto == Proto::Any) s.proto = Proto::Icmp;
        else if (s.proto != Proto::Icmp) return std::unexpected(Msg(IDS_RULE_TYPE_PROTO));
    }
    Family addressFamily = Family::Any;
    for (const AddressMatch* a : {&s.src, &s.dst, &s.remote, &s.local}) {
        if (!a->set) continue;
        if (addressFamily != Family::Any && addressFamily != a->family) {
            return std::unexpected(Msg(IDS_RULE_MIX_FAMILY));
        }
        addressFamily = a->family;
    }
    if (addressFamily != Family::Any) {
        if (familySet && s.family != addressFamily) return std::unexpected(Msg(IDS_RULE_FAMILY_CONFLICT));
        s.family = addressFamily;
    }
    return s;
}

std::expected<Rule, std::string> ParseRule(std::string_view text) {
    const auto tokens = Tokenize(text);
    if (tokens.empty()) return std::unexpected(Msg(IDS_RULE_EMPTY));
    Rule rule;
    const std::string action = Lower(tokens.front());
    if (action == "allow" || action == "pass" || action == "permit" || action == "accept") rule.action = RuleAction::Allow;
    else if (action == "block" || action == "drop" || action == "deny" || action == "reject") rule.action = RuleAction::Block;
    else return std::unexpected(Msg(IDS_RULE_ACTION, tokens.front()));

    std::string selectorText;
    for (size_t i = 1; i < tokens.size(); ++i) {
        if (!selectorText.empty()) selectorText += ' ';
        selectorText += QuoteToken(Lower(tokens[i]));
    }
    auto selector = ParseSelector(selectorText);
    if (!selector) return std::unexpected(selector.error());
    rule.match = *selector;
    rule.text = selectorText.empty() ? std::string("all") : selectorText;
    return rule;
}

std::string QuoteToken(std::string_view value) {
    if (!value.empty() && std::ranges::none_of(value, Separator)) return std::string(value);
    return '"' + std::string(value) + '"';
}

std::string RuleText(const Rule& rule) {
    return std::string(rule.action == RuleAction::Allow ? "allow " : "block ") + (rule.text.empty() ? "all" : rule.text);
}

std::string Summarize(const Selector& s) {
    std::vector<std::string> parts;
    parts.push_back(Msg(s.dir == Dir::In ? IDS_DIR_IN : s.dir == Dir::Out ? IDS_DIR_OUT : IDS_SUM_BOTH));
    if (s.family == Family::V4) parts.emplace_back("IPv4");
    else if (s.family == Family::V6) parts.emplace_back("IPv6");
    switch (s.proto) {
    case Proto::Tcp: parts.emplace_back("TCP"); break;
    case Proto::Udp: parts.emplace_back("UDP"); break;
    case Proto::TcpUdp: parts.emplace_back("TCP+UDP"); break;
    case Proto::Icmp: parts.push_back(s.icmpTypeSet ? Msg(IDS_SUM_ICMP_TYPE, s.icmpType) : std::string("ICMP")); break;
    case Proto::Number: parts.push_back(Msg(IDS_SUM_PROTO, s.protoNumber)); break;
    case Proto::Any: if (s.MatchesAllFrames()) parts.push_back(Msg(IDS_SUM_ALL)); break;
    }
    if (s.src.set) parts.push_back(Msg(IDS_SUM_FROM, FormatAddress(s.src)));
    if (s.dst.set) parts.push_back(Msg(IDS_SUM_TO, FormatAddress(s.dst)));
    if (s.remote.set) parts.push_back(Msg(IDS_SUM_REMOTE, FormatAddress(s.remote)));
    if (s.local.set) parts.push_back(Msg(IDS_SUM_LOCAL, FormatAddress(s.local)));
    if (s.sport.set) parts.push_back(Msg(IDS_SUM_SPORT, FormatPorts(s.sport)));
    if (s.dport.set) parts.push_back(Msg(IDS_SUM_DPORT, FormatPorts(s.dport)));
    if (s.rport.set) parts.push_back(Msg(IDS_SUM_RPORT, FormatPorts(s.rport)));
    if (s.lport.set) parts.push_back(Msg(IDS_SUM_LPORT, FormatPorts(s.lport)));
    if (s.port.set) parts.push_back(Msg(IDS_SUM_PORT, FormatPorts(s.port)));
    if (s.app.set) parts.push_back(Msg(IDS_SUM_APP, s.app.name));
    std::string out;
    for (const auto& p : parts) {
        if (!out.empty()) out += " · ";
        out += p;
    }
    return out;
}

bool Matches(const Selector& s, const FrameInfo& f, Dir d) noexcept {
    if (!Has(s.dir, d)) return false;
    if (s.MatchesAllFrames()) return true;
    if (!f.ip) return false;
    if ((s.family == Family::V4 && f.version != 4) || (s.family == Family::V6 && f.version != 6)) return false;

    const bool ports = UsesPorts(s);
    switch (s.proto) {
    case Proto::Any:
        if (ports && f.protocol != 6 && f.protocol != 17) return false;
        break;
    case Proto::Tcp: if (f.protocol != 6) return false; break;
    case Proto::Udp: if (f.protocol != 17) return false; break;
    case Proto::TcpUdp: if (f.protocol != 6 && f.protocol != 17) return false; break;
    case Proto::Icmp: if (f.protocol != (f.version == 4 ? 1 : 58)) return false; break;
    case Proto::Number: if (f.protocol != s.protoNumber) return false; break;
    }

    const bool outbound = d == Dir::Out;
    const AddressMatch& srcA = s.src.set ? s.src : (outbound ? s.local : s.remote);
    const AddressMatch& dstA = s.dst.set ? s.dst : (outbound ? s.remote : s.local);
    auto addressOk = [&](const AddressMatch& a, bool source) {
        if (!a.set) return true;
        if (a.family == Family::V4) return f.version == 4 && a.Contains4(source ? f.src4 : f.dst4);
        return f.version == 6 && a.Contains6(source ? f.src6 : f.dst6);
    };
    if (!addressOk(srcA, true) || !addressOk(dstA, false)) return false;

    if (ports) {
        if (!f.hasPorts) return false;
        const PortMatch& sp = s.sport.set ? s.sport : (outbound ? s.lport : s.rport);
        const PortMatch& dp = s.dport.set ? s.dport : (outbound ? s.rport : s.lport);
        if (sp.set && !sp.Contains(f.srcPort)) return false;
        if (dp.set && !dp.Contains(f.dstPort)) return false;
        if (s.port.set && !s.port.Contains(f.srcPort) && !s.port.Contains(f.dstPort)) return false;
    }
    if (s.app.set) {  // the owner is resolved once per packet by the engine
        if (!f.process || (s.app.path ? f.process->pathKey : f.process->name) != s.app.name) return false;
    }
    if (s.icmpTypeSet && (!f.hasIcmp || f.icmpType != s.icmpType)) return false;
    return true;
}

std::expected<std::vector<Rule>, RulesTextError> ParseRulesText(std::string_view text) {
    std::vector<Rule> rules;
    size_t lineNumber = 0;
    while (!text.empty()) {
        ++lineNumber;
        const size_t end = text.find('\n');
        std::string_view line = Trim(text.substr(0, end));
        text = end == std::string_view::npos ? std::string_view() : text.substr(end + 1);
        if (line.empty()) continue;
        bool enabled = true;
        if (line.front() == '#') {
            const std::string lower = Lower(line.substr(0, std::min<size_t>(line.size(), 8)));
            if (!lower.starts_with("# off:") && !lower.starts_with("#off:")) continue;  // comment
            line = Trim(line.substr(line.find(':') + 1));
            enabled = false;
        }
        auto rule = ParseRule(line);
        if (!rule) return std::unexpected(RulesTextError{lineNumber, rule.error()});
        rule->enabled = enabled;
        rules.push_back(std::move(*rule));
    }
    return rules;
}

std::string FormatRulesText(std::span<const Rule> rules) {
    std::string out = "# WireScope firewall rules: first match wins. \"# off:\" keeps a disabled rule.\n";
    for (const Rule& r : rules) {
        if (!r.enabled) out += "# off: ";
        out += RuleText(r);
        out += '\n';
    }
    return out;
}

std::string RulesHelp() {
    return ToUtf8(Text::Get(IDS_RULE_HELP));
}

} // namespace WS
