// WireScope - Command line: help and dispatch to the commands (CliTools.cpp, CliSession.cpp).
#include "app/Cli.h"
#include "app/CliDetail.h"
#include "support/Common.h"
#include "support/Text.h"
#include <format>
#include <memory>

namespace WS::Cli {

void PrintHelp(const Console& con) {
    con.WriteLine(std::format("{}{}WireScope - Modern C++23 network analyzer, firewall and impairment simulator{}", con.Cyan(), con.Bold(), con.Reset()));
    con.WriteLine(std::format("{}Powered by the WinpkFilter kernel driver (wsddntf.sys){}", con.Dim(), con.Reset()));
    con.WriteLine();
    con.WriteLine("Usage: WireScope.exe [options]");
    con.WriteLine("   (Running with no arguments launches the graphical user interface)");
    con.WriteLine();
    con.WriteLine("Information:");
    con.WriteLine("  -i, --info                    Show kernel driver connection state and version");
    con.WriteLine("  -l, --list, --adapters        List all network adapters, GUIDs, MACs and MTU");
    con.WriteLine("      --firewall-show           Print the driver's static filter table");
    con.WriteLine("      --firewall-reset          Remove every static filter from the driver (needs --force)");
    con.WriteLine("      --firewall-selftest       Verify the static filter layout with harmless test entries");
    con.WriteLine("      --rules-help              Explain the rule and traffic match syntax");
    con.WriteLine("      --lng-export <file>       Write the English texts as a template for language\\<code>.lng");
    con.WriteLine("      --lng-check [<file>]      Check language\\*.lng (or one file): coverage, unknown ids, placeholders");
    con.WriteLine("      --trust <file>            Check a program's signature and folder, as the Processes page does");
    con.WriteLine("                                (exit 0 no concern, 13 worth a look, 14 suspicious; nothing is run)");
    con.WriteLine();
    con.WriteLine("      --check                   Validate and explain --rule / --rules / simulator options; apply nothing");
    con.WriteLine();
    con.WriteLine("Network driver (wsddntf, through the Windows APIs; a change needs --force and restarts the adapters):");
    con.WriteLine("      --driver status           Component, bindings, service, driver store, device and package");
    con.WriteLine("      --driver install [<inf>]  From rsc\\wsddntf.inf (or the given INF); rolled back if it does not answer");
    con.WriteLine("      --driver uninstall        Remove the filter and every copy of the package from the driver store");
    con.WriteLine("      --driver start | stop     Start and attach / detach and stop (exit 15 or 16 from status: not working)");
    con.WriteLine("      --driver attach | detach  Only the filter's bindings to the adapters");
    con.WriteLine("      --driver start-type <t>   system | automatic | manual | disabled (disabled stops it first)");
    con.WriteLine();
    con.WriteLine("Session (any combination; ends with Ctrl+C, --duration or --count):");
    con.WriteLine("  -s, --sniff [index]           Live packet capture");
    con.WriteLine("  -F, --firewall                Static firewall in the driver (implied by --rule / --rules)");
    con.WriteLine("  -S, --impair                  Network impairment simulator (implied by its options)");
    con.WriteLine("      --processes               Programs using the network; in a session (or with --duration) also");
    con.WriteLine("                                their traffic, counted from copies of the packets (listen mode)");
    con.WriteLine("  -a, --adapter <index>         Adapter to use (default: the one with the default route)");
    con.WriteLine("  -t, --duration <seconds>      Stop after this many seconds");
    con.WriteLine();
    con.WriteLine("Capture:");
    con.WriteLine("  -c, --count <N>               Stop after N packets");
    con.WriteLine("  -w, --pcap <file.pcap>        Save captured traffic to a Wireshark .pcap file");
    con.WriteLine("  -f, --filter <keyword>        Only display packets matching keyword (DNS, 443, etc.)");
    con.WriteLine();
    con.WriteLine("Firewall:");
    con.WriteLine("  -r, --rule \"<rule>\"           Add a rule, e.g. \"block out tcp dport 443\" (repeatable)");
    con.WriteLine("  -R, --rules <file>            Load rules from a text file, one per line");
    con.WriteLine("      --policy allow|block      What happens to packets no rule matches (default: allow)");
    con.WriteLine("      --kernel-filters          Also write the rules into the driver's static filter table");
    con.WriteLine();
    con.WriteLine("Impairment simulator:");
    con.WriteLine("      --latency <ms>            Added one-way delay");
    con.WriteLine("      --jitter <ms>             Random variation of the delay (+/-, uniform)");
    con.WriteLine("      --loss <percent>          Random packet loss, e.g. 5 or 15");
    con.WriteLine("      --rate <kbps>             Bandwidth limit (token bucket, drop-tail queue)");
    con.WriteLine("      --dir in|out|both         Direction to impair (default: both)");
    con.WriteLine("      --match \"<selector>\"      Only impair matching traffic, e.g. \"udp rport 27015\"");
    con.WriteLine("      --reorder                 Let jitter reorder packets (default: keep order)");
    con.WriteLine();
    con.WriteLine("Examples:");
    con.WriteLine("  WireScope.exe --adapters");
    con.WriteLine("  WireScope.exe --sniff 0 --filter DNS");
    con.WriteLine("  WireScope.exe --sniff --pcap capture.pcap --count 500");
    con.WriteLine("  WireScope.exe --rule \"block out tcp dport 443\" --rule \"block udp rport 27015-27030\" --duration 60");
    con.WriteLine("  WireScope.exe --latency 120 --jitter 30 --loss 5 --match \"udp rport 27015\"");
    con.WriteLine("  WireScope.exe --sniff --loss 15 --dir in --filter ICMP");
    con.WriteLine("  WireScope.exe --processes --duration 30");
}

void PrintHelp() {
    Console con;
    PrintHelp(con);
}

int Run(int argc, wchar_t* argv[]) {
    Console con;

    auto parsed = ParseOptions(argc, argv);
    if (!parsed) {
        con.WriteLine(std::format("{}[-] {}{}", con.Red(), parsed.error(), con.Reset()));
        return 1;
    }
    Options& o = *parsed;
    if (o.help || argc <= 1) {
        PrintHelp(con);
        return 0;
    }
    if (o.rulesHelp) {
        con.WriteLine(RulesHelp());
        return 0;
    }
    if (!o.lngExport.empty()) return ExportLanguage(con, o.lngExport);
    if (o.lngCheck) return CheckLanguages(con, o.lngFile);
    if (!o.trustFile.empty()) return TrustFile(con, o.trustFile);
    if (o.processes && !o.duration && !o.sniff && !o.firewall && !o.impair) return ListProcesses(con);

    // Rules are checked before touching the driver, so a typo never half-starts a session.
    auto rules = LoadRules(o);
    if (!rules) {
        con.WriteLine(std::format("{}[-] {}{}", con.Red(), rules.error(), con.Reset()));
        return 1;
    }
    if (o.impair) {
        if (auto selector = ImpairmentSelector(o.impairment); !selector) {
            con.WriteLine(std::format("{}[-] Simulator: {}{}", con.Red(), selector.error(), con.Reset()));
            return 1;
        }
    }
    if (o.check) return CheckRules(con, o, *rules);
    // A session that changes traffic must be stoppable: with output redirected nobody can press
    // Ctrl+C, so it needs an end of its own.
    if ((o.firewall || o.impair) && !o.duration && !con.IsInteractive()) {
        con.WriteLine(std::format("{}[-] A firewall or simulator session needs --duration when its output is not a console.{}", con.Red(), con.Reset()));
        con.WriteLine("    To only validate rules, use --check.");
        return 12;
    }

    if (!IsElevated()) {
        con.WriteLine(std::format("{}[!] WireScope requires Administrator privileges to access the network driver.{}\r\n"
                                  "    Please run from an elevated terminal.", con.Red(), con.Reset()));
        return 1;
    }
    // Before WireScope opens the driver itself: a change must not find it held.
    if (!o.driverAction.empty()) return DriverCommand(con, o);

    auto bridge = std::make_shared<DriverBridge>();
    auto connRes = bridge->Connect();
    if (!connRes) {
        con.WriteLine(std::format("{}[-] Failed to connect to network driver: {}{}", con.Red(), ToUtf8(connRes.error()), con.Reset()));
        con.WriteLine(std::format("{}    Make sure wsddntf service is installed or active (sc query wsddntf).{}", con.Dim(), con.Reset()));
        return 2;
    }

    // Repair what a session that was killed left in the driver, whatever the command.
    auto controller = std::make_unique<TrafficController>(bridge);
    if (const std::wstring notice = controller->Attach(); !notice.empty() && controller->CanControl()) {
        con.WriteLine(std::format("{}[!] {}{}", con.Yellow(), ToUtf8(notice), con.Reset()));
    }

    if (o.info) return ShowInfo(con, *bridge);
    if (o.firewallShow) return ShowFilterTable(con, *bridge);
    if (o.firewallSelfTest) return FilterSelfTest(con, *bridge, o.force);

    if (o.firewallReset) return ResetFilters(con, *bridge, o.force);
    if (o.adapters) return ListAdapters(con, *bridge);

    if (!o.sniff && !o.firewall && !o.impair && !o.processes) {
        con.WriteLine(std::format("{}[-] Nothing to do. Run with --help for options.{}", con.Red(), con.Reset()));
        return 1;
    }

    return RunSession(con, o, std::move(*rules), *bridge, *controller);
}

} // namespace WS::Cli
