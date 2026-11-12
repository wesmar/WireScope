// WireScope - Command line: option parsing and rule files.
#include "app/CliDetail.h"
#include "support/Text.h"
#include <charconv>
#include <format>
#include <fstream>
#include <sstream>

namespace WS::Cli {

namespace {

template <class T>
std::optional<T> Number(std::wstring_view text) {
    const std::string s = ToUtf8(text);
    T value{};
    const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
    if (ec != std::errc{} || end != s.data() + s.size()) return std::nullopt;
    return value;
}

} // namespace

std::expected<Options, std::string> ParseOptions(int argc, wchar_t* argv[]) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        auto value = [&]() -> std::expected<std::wstring, std::string> {
            if (i + 1 >= argc) return std::unexpected(std::format("{} needs a value", ToUtf8(arg)));
            return std::wstring(argv[++i]);
        };
        auto number = [&]<class T>(T max) -> std::expected<T, std::string> {
            auto v = value();
            if (!v) return std::unexpected(v.error());
            const auto n = Number<T>(*v);
            if (!n || *n > max) return std::unexpected(std::format("{}: '{}' is not a valid number", ToUtf8(arg), ToUtf8(*v)));
            return *n;
        };
        auto fail = [](const std::string& e) { return std::unexpected(e); };

        if (arg == L"-h" || arg == L"--help" || arg == L"/?") o.help = true;
        else if (arg == L"--rules-help") o.rulesHelp = true;
        else if (arg == L"--check") o.check = true;
        else if (arg == L"--processes") o.processes = true;
        else if (arg == L"--driver") {
            auto v = value();
            if (!v) return fail(v.error());
            o.driverAction = *v;
            if (i + 1 < argc && argv[i + 1][0] != L'-') o.driverValue = argv[++i];
        }
        else if (arg == L"--trust") {
            auto v = value();
            if (!v) return fail(v.error());
            o.trustFile = *v;
        }
        else if (arg == L"--lng-export") {
            auto v = value();
            if (!v) return fail(v.error());
            o.lngExport = *v;
        } else if (arg == L"--lng-check") {
            o.lngCheck = true;
            if (i + 1 < argc && argv[i + 1][0] != L'-') o.lngFile = argv[++i];
        }
        else if (arg == L"-i" || arg == L"--info") o.info = true;
        else if (arg == L"-l" || arg == L"--list" || arg == L"--adapters") o.adapters = true;
        else if (arg == L"--firewall-show") o.firewallShow = true;
        else if (arg == L"--firewall-reset") o.firewallReset = true;
        else if (arg == L"--firewall-selftest") o.firewallSelfTest = true;
        else if (arg == L"--force") o.force = true;
        else if (arg == L"--kernel-filters") {
            o.kernelFilters = true;
            o.firewall = true;
        }
        else if (arg == L"-s" || arg == L"--sniff") {
            o.sniff = true;
            // Phase 1 syntax: --sniff [index]
            if (i + 1 < argc && argv[i + 1][0] != L'-') {
                if (const auto n = Number<uint32_t>(argv[i + 1])) {
                    o.adapter = *n;
                    ++i;
                }
            }
        } else if (arg == L"-F" || arg == L"--firewall") o.firewall = true;
        else if (arg == L"-S" || arg == L"--impair" || arg == L"--simulate") o.impair = true;
        else if (arg == L"-a" || arg == L"--adapter") {
            auto n = number(UINT32_MAX);
            if (!n) return fail(n.error());
            o.adapter = static_cast<uint32_t>(*n);
        } else if (arg == L"-c" || arg == L"--count") {
            auto n = number(UINT64_MAX);
            if (!n) return fail(n.error());
            o.count = *n;
        } else if (arg == L"-t" || arg == L"--duration") {
            auto n = number(86400u * 7);
            if (!n) return fail(n.error());
            o.duration = *n;
        } else if (arg == L"-w" || arg == L"--pcap") {
            auto v = value();
            if (!v) return fail(v.error());
            o.pcap = *v;
        } else if (arg == L"-f" || arg == L"--filter") {
            auto v = value();
            if (!v) return fail(v.error());
            o.filter = *v;
        } else if (arg == L"-r" || arg == L"--rule") {
            auto v = value();
            if (!v) return fail(v.error());
            o.rules.push_back(*v);
            o.firewall = true;
        } else if (arg == L"-R" || arg == L"--rules") {
            auto v = value();
            if (!v) return fail(v.error());
            o.ruleFiles.push_back(*v);
            o.firewall = true;
        } else if (arg == L"--policy") {
            auto v = value();
            if (!v) return fail(v.error());
            if (*v == L"allow" || *v == L"pass") o.policy = RuleAction::Allow;
            else if (*v == L"block" || *v == L"drop" || *v == L"deny") o.policy = RuleAction::Block;
            else return fail("--policy takes allow or block");
            o.firewall = true;
        } else if (arg == L"--latency") {
            auto n = number(kMaxLatencyMs);
            if (!n) return fail(n.error());
            o.impairment.latencyMs = *n;
            o.impair = true;
        } else if (arg == L"--jitter") {
            auto n = number(kMaxJitterMs);
            if (!n) return fail(n.error());
            o.impairment.jitterMs = *n;
            o.impair = true;
        } else if (arg == L"--loss") {
            auto v = value();
            if (!v) return fail(v.error());
            std::wstring text = *v;
            if (!text.empty() && text.back() == L'%') text.pop_back();
            const auto n = Number<double>(text);
            if (!n || *n < 0.0 || *n > 100.0) return fail("--loss takes a percentage between 0 and 100");
            o.impairment.lossPercent = *n;
            o.impair = true;
        } else if (arg == L"--rate") {
            auto n = number(10'000'000); // kbps
            if (!n) return fail(n.error());
            o.impairment.rateKbps = *n;
            o.impair = true;
        } else if (arg == L"--dir") {
            auto v = value();
            if (!v) return fail(v.error());
            if (*v == L"in" || *v == L"inbound") o.impairment.dir = Dir::In;
            else if (*v == L"out" || *v == L"outbound") o.impairment.dir = Dir::Out;
            else if (*v == L"both") o.impairment.dir = Dir::Both;
            else return fail("--dir takes in, out or both");
            o.impair = true;
        } else if (arg == L"--match") {
            auto v = value();
            if (!v) return fail(v.error());
            o.impairment.match = ToUtf8(*v);
            o.impair = true;
        } else if (arg == L"--reorder") {
            o.impairment.preserveOrder = false;
            o.impair = true;
        } else {
            return fail(std::format("Unknown option: {}. Run with --help for options.", ToUtf8(arg)));
        }
    }
    o.impairment.enabled = o.impair;
    return o;
}

std::expected<std::vector<Rule>, std::string> LoadRules(const Options& o) {
    std::vector<Rule> rules;
    for (const auto& file : o.ruleFiles) {
        std::ifstream in(file, std::ios::binary);
        if (!in) return std::unexpected(std::format("Cannot open rules file {}", ToUtf8(file)));
        std::stringstream buffer;
        buffer << in.rdbuf();
        std::string text = buffer.str();
        if (text.starts_with("\xEF\xBB\xBF")) text.erase(0, 3);
        auto parsed = ParseRulesText(text);
        if (!parsed) return std::unexpected(std::format("{}:{}: {}", ToUtf8(file), parsed.error().line, parsed.error().message));
        for (auto& r : *parsed) {
            if (r.enabled) rules.push_back(std::move(r));
        }
    }
    for (const auto& text : o.rules) {
        auto rule = ParseRule(ToUtf8(text));
        if (!rule) return std::unexpected(std::format("Rule \"{}\": {}", ToUtf8(text), rule.error()));
        rules.push_back(std::move(*rule));
    }
    return rules;
}

} // namespace WS::Cli
