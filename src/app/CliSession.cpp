// WireScope - Command line: one session of capture, firewall and simulator.
#include "app/CliDetail.h"
#include "support/Common.h"
#include "support/Handle.h"
#include "support/Text.h"
#include <atomic>
#include <format>

namespace WS::Cli {

namespace {

std::atomic<bool> g_stopRequested{false};
HANDLE g_cleanupDone = nullptr;  // set once the session has restored the network

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    switch (fdwCtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        g_stopRequested = true;
        return TRUE;
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        // The process ends when this handler returns: give the main thread time to restore the
        // adapter mode and the filter table first.
        g_stopRequested = true;
        if (g_cleanupDone) WaitForSingleObject(g_cleanupDone, 4000);
        return TRUE;
    default:
        return FALSE;
    }
}

std::string GetProtocolColor(const Console& con, ProtocolType proto) {
    switch (proto) {
    case ProtocolType::DNS:  return con.Cyan() + con.Bold();
    case ProtocolType::TLS:  return con.Yellow() + con.Bold();
    case ProtocolType::TCP:  return con.Green();
    case ProtocolType::UDP:  return con.Blue();
    case ProtocolType::ICMP: return con.Red() + con.Bold();
    case ProtocolType::ARP:  return con.Magenta();
    default:                 return con.Dim();
    }
}

std::string Count(uint64_t n) {
    return ToUtf8(FormatCount(n));
}

std::string SessionStatus(TrafficController& ctl, const Options& o) {
    std::string line;
    if (o.firewall) {
        const auto fw = ctl.PollFirewall();
        uint64_t blocked = 0, allowed = 0;
        for (const Rule& r : ctl.Rules()) {
            const auto it = fw.rules.find(r.id);
            if (it == fw.rules.end()) continue;
            (r.action == RuleAction::Block ? blocked : allowed) += it->second.packets;
        }
        (ctl.Policy() == RuleAction::Block ? blocked : allowed) += fw.policy.packets;
        line += std::format("[firewall] {} rules · blocked {} · allowed {}", ctl.Rules().size(), Count(blocked), Count(allowed));
    }
    if (o.impair) {
        const auto s = ctl.Engine().GetStats();
        const double lossShare = s.SimSelected ? 100.0 * static_cast<double>(s.SimDropped + s.SimOverflow) / static_cast<double>(s.SimSelected) : 0.0;
        const double avgMs = s.SimDelayed ? static_cast<double>(s.SimDelaySumUs) / static_cast<double>(s.SimDelayed) / 1000.0 : 0.0;
        if (!line.empty()) line += "   ";
        line += std::format("[simulator] matched {} · delayed {} (avg +{:.1f} ms) · dropped {} ({:.1f} %) · in flight {}",
                            Count(s.SimSelected), Count(s.SimDelayed), avgMs, Count(s.SimDropped + s.SimOverflow), lossShare,
                            s.SimInFlight);
    }
    const auto s = ctl.Engine().GetStats();
    if (!line.empty()) line += "   ";
    line += std::format("[engine] read {} · re-injected {}", Count(s.TotalPackets), Count(s.Reinjected));
    return line;
}

} // namespace

int RunSession(const Console& con, const Options& o, std::vector<Rule> rules, DriverBridge& bridge, TrafficController& controller) {
    // --- Session ---------------------------------------------------------------
    auto adaptersRes = bridge.QueryAdapters();
    if (!adaptersRes || adaptersRes->empty()) {
        con.WriteLine(std::format("{}[-] No network adapters found.{}", con.Red(), con.Reset()));
        return 4;
    }
    uint32_t adapterIdx = 0;
    if (o.adapter) {
        adapterIdx = *o.adapter;
    } else {
        for (const auto& a : *adaptersRes) {
            if (a.HasGateway) {
                adapterIdx = a.Index;
                break;
            }
        }
    }
    if (adapterIdx >= adaptersRes->size()) {
        con.WriteLine(std::format("{}[-] Invalid adapter index {}. Available: 0..{}{}",
                                  con.Red(), adapterIdx, adaptersRes->size() - 1, con.Reset()));
        return 5;
    }
    const auto& adapter = (*adaptersRes)[adapterIdx];

    if (!controller.CanControl() && (o.firewall || o.impair)) {
        con.WriteLine(std::format("{}[-] Another WireScope instance controls the firewall and simulator. Close it first.{}", con.Red(), con.Reset()));
        return 10;
    }
    TrafficController& ctl = controller;
    if (auto r = ctl.SetAdapter(adapter.Handle); !r) {
        con.WriteLine(std::format("{}[-] {}{}", con.Red(), ToUtf8(r.error()), con.Reset()));
        return 5;
    }

    Handle cleanupDone(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    g_cleanupDone = cleanupDone.get();
    g_stopRequested = false;
    SetConsoleCtrlHandler(CtrlHandler, TRUE);
    const ScopeExit restore([&] {
        ctl.Shutdown();
        SetEvent(cleanupDone.get());
    });

    auto failSession = [&](const std::wstring& error, int code) {
        con.WriteLine(std::format("{}[-] {}{}", con.Red(), ToUtf8(error), con.Reset()));
        return code;
    };

    con.WriteLine(std::format("{}[*] Adapter [{}] {} ({}){}", con.Cyan(), adapter.Index, adapter.FriendlyName, adapter.MacAddress, con.Reset()));

    if (o.firewall) {
        if (o.kernelFilters) {
            if (auto r = ctl.SetKernelOffload(true); !r) return failSession(r.error(), 7);
        }
        if (auto foreign = ctl.ForeignFilterCount(); foreign && *foreign > 0) {
            con.WriteLine(std::format("{}[!] The driver holds {} static filters of another application; they are kept and restored.{}",
                                      con.Yellow(), *foreign, con.Reset()));
        }
        WarnLockout(con, rules, o.policy);
        if (auto r = ctl.SetRules(std::move(rules)); !r) return failSession(r.error(), 7);
        if (auto r = ctl.SetPolicy(o.policy); !r) return failSession(r.error(), 7);
        if (auto r = ctl.SetFirewall(true); !r) return failSession(r.error(), 7);
        con.WriteLine(std::format("{}[+] Firewall active: {} rules, default policy {}, enforced by {}{}", con.Green(), ctl.Rules().size(),
                                  o.policy == RuleAction::Allow ? "allow" : "block",
                                  ctl.KernelOffload() ? "the driver's static filter table and the engine" : "the WireScope engine",
                                  con.Reset()));
        for (const Rule& r : ctl.Rules()) {
            con.WriteLine(std::format("      {}{:<6}{} {}", r.action == RuleAction::Block ? con.Red() : con.Green(),
                                      r.action == RuleAction::Block ? "block" : "allow", con.Reset(), r.text));
        }
    }

    if (o.impair) {
        if (auto r = ctl.SetImpairment(o.impairment); !r) return failSession(r.error(), 9);
        const auto& p = o.impairment;
        std::string rateStr;
        if (p.rateKbps > 0) rateStr = std::format(", rate {} kbps", p.rateKbps);
        con.WriteLine(std::format("{}[+] Simulator active: latency {} ms, jitter ±{} ms, loss {:.1f} %{}{}, {}{}", con.Green(),
                                  p.latencyMs, p.jitterMs, p.lossPercent, rateStr,
                                  p.dir == Dir::In ? ", inbound" : p.dir == Dir::Out ? ", outbound" : ", both directions",
                                  p.match.empty() ? std::string() : ", match: " + p.match, con.Reset()));
        if (!ctl.Engine().GetStats().HighResolutionTimer) {
            con.WriteLine(std::format("{}    High-resolution timer unavailable: delays are rounded to ~16 ms.{}", con.Dim(), con.Reset()));
        }
    }

    const std::string filterUtf8 = ToUtf8(o.filter);
    if (o.sniff) {
        if (!o.pcap.empty()) {
            if (ctl.Engine().StartPcap(o.pcap)) {
                con.WriteLine(std::format("{}[+] Recording to PCAP: {}{}", con.Green(), ToUtf8(o.pcap), con.Reset()));
            } else {
                con.WriteLine(std::format("{}[-] Failed to create PCAP file {}{}", con.Yellow(), ToUtf8(o.pcap), con.Reset()));
            }
        }
        ctl.Engine().SetPacketCallback([&con, &filterUtf8](const DecodedPacket& pkt) {
            if (!filterUtf8.empty()) {
                const bool matches = ContainsIgnoreCase(pkt.ProtocolName, filterUtf8) ||
                                     ContainsIgnoreCase(pkt.Source, filterUtf8) ||
                                     ContainsIgnoreCase(pkt.Destination, filterUtf8) ||
                                     ContainsIgnoreCase(pkt.DomainOrHost, filterUtf8) ||
                                     ContainsIgnoreCase(pkt.Info, filterUtf8) ||
                                     ContainsIgnoreCase(pkt.Process, filterUtf8);
                if (!matches) return;
            }

            const std::string protoColor = GetProtocolColor(con, pkt.Protocol);
            const char* dirStr = (pkt.Dir == Direction::Outbound) ? "OUT" : "IN ";
            std::string fate;
            switch (pkt.Fate) {
            case PacketFate::Delayed: fate = std::format(" {}+{} ms{}", con.Yellow(), (pkt.DelayUs + 500) / 1000, con.Reset()); break;
            case PacketFate::Dropped: fate = std::format(" {}[sim drop]{}", con.Red(), con.Reset()); break;
            case PacketFate::Blocked: fate = std::format(" {}[firewall]{}", con.Red(), con.Reset()); break;
            case PacketFate::Killed: fate = std::format(" {}[kill switch]{}", con.Red(), con.Reset()); break;
            default: break;
            }
            std::string procStr;
            if (!pkt.Process.empty()) procStr = std::format(" [{}]", pkt.Process);
            con.WriteLine(std::format("{:6d} [{}] {}{:<6}{}| {:>21} -> {:<21} | {:4d}B | {}{}{}",
                                      pkt.Index, dirStr, protoColor, pkt.ProtocolName, con.Reset(),
                                      pkt.Source, pkt.Destination, pkt.Length, pkt.Info, procStr, fate));
        });
        if (auto r = ctl.SetCapture(true); !r) return failSession(L"Failed to start the capture: " + r.error(), 6);
    }
    if (o.processes) {
        if (auto r = ctl.SetMonitor(true); !r) return failSession(L"Failed to count traffic per program: " + r.error(), 6);
        con.WriteLine(std::format("{}[+] Counting traffic per program from copies of the packets (traffic is not changed){}", con.Green(),
                                  con.Reset()));
    }

    con.WriteLine(std::format("{}[*] Running. Press Ctrl+C to stop and restore the network...{}\r\n", con.Dim(), con.Reset()));

    const uint64_t started = GetTickCount64();
    uint64_t lastStatus = started;
    const bool liveLine = !o.sniff && con.SupportsAnsi();
    while (!g_stopRequested) {
        Sleep(100);
        const uint64_t now = GetTickCount64();
        if (o.duration && now - started >= static_cast<uint64_t>(o.duration) * 1000) break;
        if (o.sniff && o.count > 0 && ctl.Engine().GetStats().TotalPackets >= o.count) break;
        if (!o.sniff && (o.firewall || o.impair)) {
            if (liveLine && now - lastStatus >= 1000) {
                con.Write("\r" + SessionStatus(ctl, o) + "\033[K");
                lastStatus = now;
            } else if (!liveLine && now - lastStatus >= 5000) {
                con.WriteLine(SessionStatus(ctl, o));
                lastStatus = now;
            }
        }
    }
    if (liveLine) con.WriteLine();

    const std::string status = (o.firewall || o.impair) ? SessionStatus(ctl, o) : std::string();
    const auto stats = ctl.Engine().GetStats();
    auto traffic = o.processes ? ctl.Engine().ProcessTotals() : std::vector<ProcessTraffic>();
    ctl.Shutdown();
    SetEvent(cleanupDone.get());

    con.WriteLine();
    con.WriteLine(std::format("{}{}[+] Session ended, network restored.{}", con.Green(), con.Bold(), con.Reset()));
    if (!status.empty()) con.WriteLine("    " + status);
    if (o.sniff) {
        con.WriteLine(std::format("    Captured {} packets ({})", stats.TotalPackets, ToUtf8(FormatBytes(stats.TotalBytes))));
        if (stats.DnsQueries > 0) con.WriteLine(std::format("    DNS Queries: {}", stats.DnsQueries));
        if (stats.TcpPackets > 0) con.WriteLine(std::format("    TCP Packets: {}", stats.TcpPackets));
        if (stats.UdpPackets > 0) con.WriteLine(std::format("    UDP Packets: {}", stats.UdpPackets));
        if (stats.IcmpPackets > 0) con.WriteLine(std::format("    ICMP Packets: {}", stats.IcmpPackets));
    }
    if (stats.SendErrors > 0) {
        con.WriteLine(std::format("{}    Re-injection errors: {}{}", con.Yellow(), stats.SendErrors, con.Reset()));
    }
    if (o.processes) PrintProcessTraffic(con, std::move(traffic));
    return 0;
}

} // namespace WS::Cli
