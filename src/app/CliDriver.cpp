// WireScope - Command line: the network driver (status, install, uninstall, start, stop, bindings,
// start type), through the Windows APIs - see core/DriverSetup.h. Every change restarts the network
// adapters for a few seconds, so it needs --force.
#include "app/CliDetail.h"
#include "core/DriverSetup.h"
#include "support/Common.h"
#include "support/Handle.h"
#include "support/Language.h"
#include "support/Text.h"
#include <format>
#include <functional>
#include <optional>

namespace WS::Cli {

namespace {

namespace DS = DriverSetup;

void PrintReport(const Console& con, const DS::Status& status) {
    for (const auto& [label, value] : DS::Report(status)) {
        const bool section = !label.starts_with(L" ");
        con.WriteLine(std::format("{}{:<14}{}{}", section ? con.Bold() : con.Dim(), ToUtf8(label), con.Reset(), ToUtf8(value)));
    }
}

// Another WireScope holds the driver open while it runs: changing the driver under it would hang.
bool OtherInstanceRunning() {
    const Handle mutex(OpenMutexW(SYNCHRONIZE, FALSE, L"Global\\WireScope.DataPlane"));
    if (!mutex) return false;
    const DWORD waited = WaitForSingleObject(mutex.get(), 0);
    if (waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED) {
        ReleaseMutex(mutex.get());
        return false;
    }
    return true;
}

void PrintOutcome(const Console& con, const DS::Outcome& outcome) {
    for (const auto& note : outcome.notes) con.WriteLine("    " + ToUtf8(note));
    if (outcome.reboot) con.WriteLine(std::format("{}[!] {}{}", con.Yellow(), ToUtf8(Text::Get(IDS_DRV_REBOOT)), con.Reset()));
}

}  // namespace

int DriverCommand(const Console& con, const Options& o) {
    const std::wstring& action = o.driverAction;
    if (action == L"status") {
        const DS::Status status = DS::Query();
        PrintReport(con, status);
        if (!status.installed) return 16;
        return status.Running() && status.deviceOpens && status.Attached() ? 0 : 15;
    }

    // What would happen, and the call that does it.
    std::string what;
    std::function<std::expected<DS::Outcome, std::wstring>()> run;
    if (action == L"install") {
        const auto inf = o.driverValue.empty() ? DS::FindPackage() : std::optional<std::wstring>(o.driverValue);
        if (!inf) {
            con.WriteLine(std::format("{}[-] {}{}", con.Red(), ToUtf8(Text::Get(IDS_DRV_NO_PACKAGE_FOLDER)), con.Reset()));
            return 17;
        }
        what = std::format("Install {} and attach the filter to all network adapters.", ToUtf8(*inf));
        run = [inf] { return DS::Install(*inf); };
    } else if (action == L"uninstall") {
        what = "Detach and remove the filter from all network adapters and delete the package from the driver store.";
        run = [] { return DS::Uninstall(); };
    } else if (action == L"start") {
        what = "Start the wsddntf service and reattach the filter to all network adapters.";
        run = [] { return DS::Start(); };
    } else if (action == L"stop") {
        what = "Detach the filter from all network adapters and stop the wsddntf service.";
        run = [] { return DS::Stop(); };
    } else if (action == L"attach" || action == L"detach") {
        const bool attach = action == L"attach";
        what = attach ? "Attach the filter to all network adapters." : "Detach the filter from all network adapters.";
        run = [attach] { return DS::Attach(attach); };
    } else if (action == L"start-type") {
        const auto type = DS::ParseStartType(o.driverValue);
        if (!type) {
            con.WriteLine(std::format("{}[-] --driver start-type needs system, automatic, manual or disabled{}", con.Red(), con.Reset()));
            return 1;
        }
        what = std::format("Set the start type of wsddntf to {}{}.", ToUtf8(DS::StartTypeName(*type)),
                           *type == DS::StartType::Disabled ? ", detaching from all network adapters and stopping first" : "");
        run = [type] { return DS::SetStartType(*type); };
    } else {
        con.WriteLine(std::format("{}[-] Unknown --driver action: {}{}", con.Red(), ToUtf8(action), con.Reset()));
        return 1;
    }

    con.WriteLine(std::format("[*] {}", what));
    if (action == L"start" || action == L"stop" || action == L"attach" || action == L"detach") {
        con.WriteLine(std::format("{}    Active network connections continue without interruption.{}", con.Dim(), con.Reset()));
    }
    if (!o.force) {
        con.WriteLine(std::format("{}[!] Nothing was changed. Add --force to do it.{}", con.Yellow(), con.Reset()));
        return 1;
    }
    if (OtherInstanceRunning()) {
        con.WriteLine(std::format("{}[-] Another WireScope instance holds the driver. Close it first.{}", con.Red(), con.Reset()));
        return 10;
    }
    auto result = run();
    if (!result) {
        con.WriteLine(std::format("{}[-] {}{}", con.Red(), ToUtf8(result.error()), con.Reset()));
        return 17;
    }
    con.WriteLine(std::format("{}[+] Done.{}", con.Green(), con.Reset()));
    PrintOutcome(con, *result);
    con.WriteLine();
    PrintReport(con, DS::Query());
    return 0;
}

}  // namespace WS::Cli
