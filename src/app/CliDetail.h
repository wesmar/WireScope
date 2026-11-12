// WireScope - Internal to the Cli*.cpp files: parsed options and the command implementations.
// The command line is always English: scripts parse its output.
#pragma once
#include "app/Console.h"
#include "core/DriverBridge.h"
#include "core/Impairment.h"
#include "core/ProcessTraffic.h"
#include "core/Rules.h"
#include "core/TrafficController.h"
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace WS::Cli {

struct Options {
    bool help{false}, rulesHelp{false}, lngCheck{false}, check{false}, info{false}, adapters{false}, firewallShow{false}, firewallReset{false}, firewallSelfTest{false};
    bool sniff{false}, firewall{false}, impair{false}, processes{false}, force{false}, kernelFilters{false};
    std::optional<uint32_t> adapter;
    uint64_t count{0};
    uint32_t duration{0};
    std::wstring pcap, filter, lngExport, lngFile, trustFile;
    std::wstring driverAction, driverValue;  // --driver <action> [value]
    std::vector<std::wstring> rules, ruleFiles;
    RuleAction policy{RuleAction::Allow};
    ImpairmentProfile impairment;
};

// CliOptions.cpp
[[nodiscard]] std::expected<Options, std::string> ParseOptions(int argc, wchar_t* argv[]);
[[nodiscard]] std::expected<std::vector<Rule>, std::string> LoadRules(const Options& o);

// CliTools.cpp: information, driver diagnostics, translator tools
int ShowInfo(const Console& con, DriverBridge& bridge);
int ListAdapters(const Console& con, DriverBridge& bridge);
int ShowFilterTable(const Console& con, DriverBridge& bridge);
int FilterSelfTest(const Console& con, DriverBridge& bridge, bool force);
int ResetFilters(const Console& con, DriverBridge& bridge, bool force);
int ExportLanguage(const Console& con, const std::wstring& path);
int CheckRules(const Console& con, const Options& o, const std::vector<Rule>& rules);  // --check: no driver
void WarnLockout(const Console& con, const std::vector<Rule>& rules, RuleAction policy);
int CheckLanguages(const Console& con, const std::wstring& file);

// CliProcesses.cpp: programs using the network, file trust (no driver needed)
int TrustFile(const Console& con, const std::wstring& path);  // exit 0, 13 worth a look, 14 suspicious
int ListProcesses(const Console& con);                        // the socket tables, now
void PrintProcessTraffic(const Console& con, std::vector<ProcessTraffic> totals);

// CliDriver.cpp: --driver status | install | uninstall | start | stop | attach | detach | start-type
int DriverCommand(const Console& con, const Options& o);

// CliSession.cpp: capture, firewall, simulator and process counting until Ctrl+C, --duration or --count
int RunSession(const Console& con, const Options& o, std::vector<Rule> rules, DriverBridge& bridge, TrafficController& controller);

void PrintHelp(const Console& con);

} // namespace WS::Cli
