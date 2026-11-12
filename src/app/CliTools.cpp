// WireScope - Command line: information, driver diagnostics and the translator tools.
#include "app/CliDetail.h"
#include "core/FilterAbi.h"
#include "core/Safety.h"
#include "support/Common.h"
#include "support/Language.h"
#include "support/Text.h"
#include <format>

namespace WS::Cli {

int ShowInfo(const Console& con, DriverBridge& bridge) {
    auto verRes = bridge.GetVersion();
    con.WriteLine(std::format("{}[+] Successfully connected to driver: {}{}", con.Green(), ToUtf8(bridge.DevicePath()), con.Reset()));
    if (verRes) {
        const DWORD v = verRes.value();
        con.WriteLine(std::format("    Engine version: {}.{}.{} (0x{:08X})", (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF, v));
    }
    if (auto filters = bridge.GetStaticFilterCount()) {
        con.WriteLine(std::format("    Static filters: supported, {} entries in the table", *filters));
    } else {
        con.WriteLine(std::format("    Static filters: {}", ToUtf8(filters.error())));
    }
    return 0;
}

int ListAdapters(const Console& con, DriverBridge& bridge) {
    auto adaptersRes = bridge.QueryAdapters();
    if (!adaptersRes) {
        con.WriteLine(std::format("{}[-] Failed to query adapters: {}{}", con.Red(), ToUtf8(adaptersRes.error()), con.Reset()));
        return 3;
    }

    const auto& adapters = adaptersRes.value();
    con.WriteLine(std::format("{}{}[+] Discovered {} Network Adapters:{}{}", con.Green(), con.Bold(), adapters.size(), con.Reset(), con.Reset()));
    con.WriteLine();

    for (const auto& a : adapters) {
        std::string statusTag;
        if (a.HasGateway) {
            statusTag = std::format(" {}{}[ACTIVE - Default Gateway]{}", con.Green(), con.Bold(), con.Reset());
        } else if (a.IsUp) {
            statusTag = std::format(" {}{}[LINK UP]{}", con.Cyan(), con.Dim(), con.Reset());
        }

        con.WriteLine(std::format("  [{}] {}{}{}{}", a.Index, con.Bold(), a.FriendlyName, con.Reset(), statusTag));
        con.WriteLine(std::format("      MAC Address:  {}", a.MacAddress));
        con.WriteLine(std::format("      MTU:          {}", a.MTU));
        con.WriteLine(std::format("      Kernel Handle: 0x{:X}", reinterpret_cast<uintptr_t>(a.Handle)));
        con.WriteLine(std::format("      System Name:  {}{}{}", con.Dim(), a.SystemName, con.Reset()));
        con.WriteLine();
    }
    return 0;
}

int ResetFilters(const Console& con, DriverBridge& bridge, bool force) {
    auto count = bridge.GetStaticFilterCount();
    if (!count) {
        con.WriteLine(std::format("{}[-] {}{}", con.Red(), ToUtf8(count.error()), con.Reset()));
        return 7;
    }
    if (*count > 0 && !force) {
        con.WriteLine(std::format("{}[!] The driver holds {} static filters, possibly from other applications.{}", con.Yellow(), *count, con.Reset()));
        con.WriteLine("    Add --force to remove them all.");
        return 8;
    }
    if (auto r = bridge.ResetStaticFilters(); !r) {
        con.WriteLine(std::format("{}[-] {}{}", con.Red(), ToUtf8(r.error()), con.Reset()));
        return 7;
    }
    con.WriteLine(std::format("{}[+] Static filter table cleared ({} entries removed).{}", con.Green(), *count, con.Reset()));
    return 0;
}

int ShowFilterTable(const Console& con, DriverBridge& bridge) {
    auto count = bridge.GetStaticFilterCount();
    if (!count) {
        con.WriteLine(std::format("{}[-] {}{}", con.Red(), ToUtf8(count.error()), con.Reset()));
        return 7;
    }
    con.WriteLine(std::format("{}[+] Driver static filter table: {} entries{}", con.Green(), *count, con.Reset()));
    auto table = bridge.ReadStaticFilters();
    if (!table) {
        con.WriteLine(std::format("{}[-] {}{}", con.Red(), ToUtf8(table.error()), con.Reset()));
        return 7;
    }
    for (size_t i = 0; i < table->size(); ++i) {
        con.WriteLine(std::format("  {:3}  {}", i + 1, DescribeFilter((*table)[i])));
    }
    return 0;
}

// Proves the STATIC_FILTER layout against the driver: writes PASS entries for documentation-only
// address ranges (RFC 5737 / RFC 3849, never routed), reads them back field by field, then puts the
// previous table back. PASS only skips user-mode processing, so the test cannot block anything.
int FilterSelfTest(const Console& con, DriverBridge& bridge, bool force) {
    auto before = bridge.ReadStaticFilters();
    if (!before) {
        con.WriteLine(std::format("{}[-] {}{}", con.Red(), ToUtf8(before.error()), con.Reset()));
        return 7;
    }
    if (!before->empty() && !force) {
        con.WriteLine(std::format("{}[!] The driver holds {} static filters; the self-test would replace them for a moment.{}",
                                  con.Yellow(), before->size(), con.Reset()));
        con.WriteLine("    Add --force to run it anyway (the table is restored afterwards).");
        return 8;
    }
    std::vector<STATIC_FILTER> probe;
    for (const char* text : {"ip4 udp to 203.0.113.0/24 dport 9", "out ip6 tcp to 2001:db8::/32 sport 7-9",
                             "in icmp type 8 from 198.51.100.7", "out ip4 from 192.0.2.10-192.0.2.13"}) {
        auto selector = ParseSelector(text);
        auto entries = selector ? Compile(*selector, FILTER_ACTION_PASS, nullptr)
                                : std::expected<std::vector<STATIC_FILTER>, std::string>(std::unexpected(selector.error()));
        if (!entries) {
            con.WriteLine(std::format("{}[-] Self-test selector \"{}\": {}{}", con.Red(), text, entries.error(), con.Reset()));
            return 1;
        }
        probe.insert(probe.end(), entries->begin(), entries->end());
    }
    const auto written = bridge.WriteStaticFilters(probe);
    const auto restored = bridge.WriteStaticFilters(*before);
    if (!written) {
        con.WriteLine(std::format("{}[-] Self-test failed: {}{}", con.Red(), ToUtf8(written.error()), con.Reset()));
        // Show where the driver's layout differs, for diagnosing other driver builds.
        if (auto raw = bridge.StaticFilterRoundTrip(std::span(probe).first(1)); raw) {
            const auto& [sent, back] = *raw;
            con.WriteLine("    offset  sent                                              read back");
            for (size_t at = 0; at < sent.size(); at += 16) {
                std::string a, b;
                bool differs = false;
                for (size_t i = at; i < at + 16 && i < sent.size(); ++i) {
                    a += std::format("{:02X} ", sent[i]);
                    b += std::format("{:02X} ", back[i]);
                    differs |= sent[i] != back[i];
                }
                con.WriteLine(std::format("    {}{:04X}    {:<48}  {}{}", differs ? con.Yellow() : "", at, a, b, differs ? con.Reset() : ""));
            }
        }
        (void)bridge.WriteStaticFilters(*before);
        return 7;
    }
    con.WriteLine(std::format("{}[+] Static filter layout verified: {} entries written and read back identically{}", con.Green(),
                              probe.size(), con.Reset()));
    con.WriteLine(std::format("    ({}-byte table header, {} bytes per STATIC_FILTER)", sizeof(STATIC_FILTER_TABLE_HEADER),
                              sizeof(STATIC_FILTER)));
    if (!restored) {
        con.WriteLine(std::format("{}[!] Restoring the previous table failed: {}{}", con.Yellow(), ToUtf8(restored.error()), con.Reset()));
        return 7;
    }
    con.WriteLine(std::format("    Previous table restored ({} entries).", before->size()));
    return 0;
}

void WarnLockout(const Console& con, const std::vector<Rule>& rules, RuleAction policy) {
    const auto risks = LockoutRisks(rules, policy);
    if (risks.empty()) return;
    con.WriteLine(std::format("{}[!] These rules block {}.{}", con.Yellow(), ToUtf8(DescribeRisks(risks)), con.Reset()));
    for (const auto& r : risks) {
        if (r.rule) con.WriteLine(std::format("    {}: {}", ToUtf8(Text::Get(r.name)), RuleText(*r.rule)));
        else con.WriteLine(std::format("    {}: the default policy (block)", ToUtf8(Text::Get(r.name))));
    }
}

int CheckRules(const Console& con, const Options& o, const std::vector<Rule>& rules) {
    con.WriteLine(std::format("{}[+] Nothing was applied: --check only explains the configuration.{}", con.Green(), con.Reset()));
    if (o.firewall) {
        con.WriteLine(std::format("Firewall: {} rules, default policy {}", rules.size(), o.policy == RuleAction::Allow ? "allow" : "block"));
        // Mirrors TrafficController::Compose: the driver knows no processes, so from the first app rule
        // on everything is redirected to the engine (first match wins).
        size_t total = 0;
        size_t firstApp = 0;
        for (size_t i = 0; i < rules.size(); ++i) {
            const Rule& r = rules[i];
            auto entries = Compile(r.match, r.action == RuleAction::Block ? FILTER_ACTION_DROP : FILTER_ACTION_PASS, nullptr);
            const size_t n = entries ? entries->size() : 0;
            if (r.match.app.set && !firstApp) firstApp = i + 1;
            if (!firstApp) total += n;
            const std::string where = r.match.app.set ? std::string("engine only") : std::format("{} driver entries", n);
            con.WriteLine(std::format("  {:2}. {}{:<5}{} {:<36} {}  [{}]", i + 1, r.action == RuleAction::Block ? con.Red() : con.Green(),
                                      r.action == RuleAction::Block ? "block" : "allow", con.Reset(), r.text, Summarize(r.match), where));
        }
        if (firstApp) {
            con.WriteLine(std::format("  Kernel offload would write {} entries, then redirect everything from rule {} on to the engine.", total,
                                      firstApp));
        } else {
            con.WriteLine(std::format("  Kernel offload would write {} entries plus the default policy.", total));
        }
        WarnLockout(con, rules, o.policy);
    }
    if (o.impair) {
        auto selector = ImpairmentSelector(o.impairment);
        const auto& p = o.impairment;
        std::string rateStr;
        if (p.rateKbps > 0) rateStr = std::format(", rate {} kbps", p.rateKbps);
        con.WriteLine(std::format("Simulator: latency {} ms, jitter \u00B1{} ms, loss {:.1f} %{}, traffic: {}", p.latencyMs, p.jitterMs, p.lossPercent, rateStr,
                                  selector ? Summarize(*selector) : selector.error()));
    }
    if (!o.firewall && !o.impair) con.WriteLine("Nothing to check: give --rule, --rules or simulator options.");
    return 0;
}

int ExportLanguage(const Console& con, const std::wstring& path) {
    if (!Text::ExportTemplate(path)) {
        con.WriteLine(std::format("{}[-] Cannot write {}{}", con.Red(), ToUtf8(path), con.Reset()));
        return 1;
    }
    con.WriteLine(std::format("{}[+] English template written to {}{}", con.Green(), ToUtf8(path), con.Reset()));
    con.WriteLine("    Translate the text after '=', save it as language\\<code>.lng next to WireScope.exe.");
    return 0;
}

int CheckLanguages(const Console& con, const std::wstring& file) {
    const auto reports = Text::Check(file);
    if (reports.empty()) {
        con.WriteLine(std::format("{}[-] No language file found{}", con.Red(), con.Reset()));
        return 1;
    }
    int problems = 0;
    for (const auto& r : reports) {
        const bool clean = r.missing.empty() && r.unknown.empty() && r.placeholders.empty();
        con.WriteLine(std::format("{}{} ({}){}  {} of {} strings, {} %  {}", clean ? con.Green() : con.Yellow(), ToUtf8(r.language.name),
                                  ToUtf8(r.language.code), con.Reset(), r.language.translated, r.language.total, r.language.Coverage(),
                                  ToUtf8(r.file)));
        auto list = [&](const char* what, const std::vector<UINT>& ids) {
            if (ids.empty()) return;
            std::string line;
            for (UINT id : ids) line += std::format(" {}", id);
            con.WriteLine(std::format("    {}:{}", what, line));
        };
        list("missing", r.missing);
        list("unknown ids", r.unknown);
        list("placeholders differ from English (falls back to English)", r.placeholders);
        if (!clean) ++problems;
    }
    return problems ? 11 : 0;
}

} // namespace WS::Cli
