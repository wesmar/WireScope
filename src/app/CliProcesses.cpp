// WireScope - Command line: programs using the network (socket tables, traffic totals) and the trust
// check of a program file. English only: scripts parse this output.
#include "app/CliDetail.h"
#include "core/ProcessMapper.h"
#include "core/ProcessTrust.h"
#include "support/Common.h"
#include "support/Text.h"
#include <algorithm>
#include <format>
#include <map>

namespace WS::Cli {

namespace {

std::string SignatureText(const TrustReport& t) {
    const std::string signer = ToUtf8(t.signer);
    switch (t.signature) {
    case Signature::Signed: return signer.empty() ? "signed" : "signed: " + signer;
    case Signature::Package: return signer.empty() ? "app package" : "app package: " + signer;
    case Signature::Unsigned: return "not signed";
    case Signature::Invalid: return "signature does not verify";
    case Signature::Unknown: return "file cannot be read";
    case Signature::Pending: break;
    }
    return "not checked";
}

std::string Reasons(uint32_t flags) {
    std::string out;
    auto add = [&](uint32_t flag, const char* text) {
        if (!(flags & flag)) return;
        if (!out.empty()) out += ", ";
        out += text;
    };
    add(TrustFlag::Imitation, "named like a Windows component outside the Windows folder");
    add(TrustFlag::Hidden, "hidden or system file");
    add(TrustFlag::UserFolder, "in a folder any program can write to");
    return out;
}

std::string RiskMark(const Console& con, Risk risk) {
    switch (risk) {
    case Risk::High: return con.Red() + con.Bold() + "[!]" + con.Reset();
    case Risk::Notice: return con.Yellow() + "[?]" + con.Reset();
    case Risk::None: break;
    }
    return "   ";
}

std::string Label(const ProcessInfo* p) {
    if (!p) return "(no process: ARP, ICMP, closed ports, TIME_WAIT)";
    return std::format("{} (pid {})", p->label, p->pid);
}

}  // namespace

int TrustFile(const Console& con, const std::wstring& path) {
    const TrustReport t = ProcessTrust::Verify(path);
    const Risk risk = t.risk();
    con.WriteLine(std::format("{} {}", RiskMark(con, risk), ToUtf8(path)));
    con.WriteLine(std::format("    Signature:  {}", SignatureText(t)));
    if (const std::string reasons = Reasons(t.flags); !reasons.empty()) con.WriteLine(std::format("    Location:   {}", reasons));
    const char* verdict = risk == Risk::High ? "suspicious: unsigned or altered code where it does not belong"
                          : risk == Risk::Notice ? "worth a look"
                                                 : "no concern";
    con.WriteLine(std::format("    Verdict:    {}{}{}", risk == Risk::High ? con.Red() : risk == Risk::Notice ? con.Yellow() : con.Green(), verdict,
                              con.Reset()));
    return risk == Risk::High ? 14 : risk == Risk::Notice ? 13 : 0;
}

int ListProcesses(const Console& con) {
    const auto snapshot = ProcessMapper::Instance().Current();
    std::vector<uint32_t> sockets(snapshot->processes.size(), 0);
    for (const Endpoint& e : snapshot->endpoints) ++sockets[e.process];
    std::vector<size_t> order(snapshot->processes.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::ranges::sort(order, [&](size_t a, size_t b) {
        const auto& pa = *snapshot->processes[a];
        const auto& pb = *snapshot->processes[b];
        return pa.name != pb.name ? pa.name < pb.name : pa.pid < pb.pid;
    });

    con.WriteLine(std::format("{}Programs with network sockets: {}{}", con.Bold(), order.size(), con.Reset()));
    con.WriteLine(std::format("{}        PID  SOCKETS  SIGNATURE                                 PROGRAM{}", con.Dim(), con.Reset()));
    std::map<std::wstring, TrustReport> verified;  // one verification per file
    int suspicious = 0;
    for (const size_t i : order) {
        const ProcessInfo& p = *snapshot->processes[i];
        TrustReport t{Signature::Unknown};
        if (!p.path.empty()) {
            auto [it, inserted] = verified.try_emplace(p.path);
            if (inserted) it->second = ProcessTrust::Verify(p.path);
            t = it->second;
        }
        if (t.risk() == Risk::High) ++suspicious;
        std::string signature = SignatureText(t);
        if (signature.size() > 40) signature = signature.substr(0, 39) + "~";
        con.WriteLine(std::format("{} {:>7}  {:>7}  {:<40}  {}", RiskMark(con, t.risk()), p.pid, sockets[i], signature,
                                  p.path.empty() ? p.label : ToUtf8(p.path)));
        if (t.risk() != Risk::None) {
            if (const std::string reasons = Reasons(t.flags); !reasons.empty()) {
                con.WriteLine(std::format("{}                                                              {}{}", con.Dim(), reasons, con.Reset()));
            }
        }
    }
    if (suspicious) {
        con.WriteLine(std::format("{}[!] {} program(s) look suspicious. WireScope.exe --trust <file> explains one file.{}", con.Red(), suspicious,
                                  con.Reset()));
    }
    con.WriteLine(std::format("{}    Traffic per program: WireScope.exe --processes --duration <seconds>{}", con.Dim(), con.Reset()));
    return suspicious ? 14 : 0;
}

void PrintProcessTraffic(const Console& con, std::vector<ProcessTraffic> totals) {
    auto bytes = [](const ProcessTraffic& t) { return t.total.bytesIn + t.total.bytesOut; };
    std::ranges::sort(totals, [&](const ProcessTraffic& a, const ProcessTraffic& b) { return bytes(a) > bytes(b); });
    con.WriteLine();
    con.WriteLine(std::format("{}[+] Traffic per program: {}{}", con.Bold(), totals.size(), con.Reset()));
    con.WriteLine(std::format("{}      RECEIVED        SENT     PACKETS  PROGRAM{}", con.Dim(), con.Reset()));
    constexpr size_t kShown = 30;
    for (size_t i = 0; i < totals.size() && i < kShown; ++i) {
        const ProcessTraffic& t = totals[i];
        con.WriteLine(std::format("  {:>12}  {:>10}  {:>10}  {}", ToUtf8(FormatBytes(t.total.bytesIn)), ToUtf8(FormatBytes(t.total.bytesOut)),
                                  ToUtf8(FormatCount(t.total.packetsIn + t.total.packetsOut)), Label(t.process.get())));
    }
    if (totals.size() > kShown) con.WriteLine(std::format("{}  ... and {} more{}", con.Dim(), totals.size() - kShown, con.Reset()));
}

}  // namespace WS::Cli
