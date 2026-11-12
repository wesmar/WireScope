// WireScope - Installs, removes, starts, stops and inspects the WinpkFilter network driver (wsddntf)
// through the Windows APIs that netcfg.exe, pnputil.exe and sc.exe wrap - no external program runs:
//
//   install     SetupCopyOEMInfW stages the package in the driver store       (netcfg -l wsddntf.inf)
//               INetCfgClassSetup::Install adds the NDIS filter                (netcfg -c s -i nt_wsddntf)
//   uninstall   INetCfgClassSetup::DeInstall removes the filter                (netcfg -u nt_wsddntf)
//               SetupUninstallOEMInfW deletes every staged copy of the package (pnputil /delete-driver oemNN.inf)
//   attach      INetCfgBindingPath::Enable on every adapter: the filter's tick in the adapter properties
//   start       the service starts, then the filter is attached again          (sc start wsddntf)
//   stop        the filter is detached from every adapter, then the service stops (sc stop wsddntf)
//   start type  ChangeServiceConfigW                                           (sc config wsddntf start= ...)
//
// Adding, removing, attaching or stopping a filter restarts the network adapters it sits on: the
// network is gone for a few seconds. wsddntf is a mandatory filter (FilterRunType 1): an adapter it is
// attached to carries no traffic without it: stopped while still attached (plain sc stop), it holds
// the network - measured: Wi-Fi stays associated, IP traffic stops until the driver starts again.
// Hence the rules here: an installation the driver does not answer is rolled back, Stop detaches
// the filter from every adapter before the service stops (the network keeps working without it),
// Start attaches it again, and "disabled" stops it that way first. Stopped and installed is a
// normal state; the filter stays detached, also across a reboot, until Start.
//
// The calls need administrator rights and a COM single-threaded apartment, which they set up for the
// calling thread. Everything but Query changes the system; the GUI runs them on a worker thread.
#pragma once
#include "core/ProcessTrust.h"
#include <Windows.h>
#include <expected>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace WS::DriverSetup {

inline constexpr wchar_t kComponentId[] = L"nt_wsddntf";
inline constexpr wchar_t kServiceName[] = L"wsddntf";
inline constexpr wchar_t kInfName[] = L"wsddntf.inf";
inline constexpr wchar_t kDevicePath[] = L"\\\\.\\wsddntf";
// Where the package is looked for: embedded inside WireScope.exe (WireScope.bmp), then next to
// WireScope.exe or one level up (bin\..\rsc in the repository).
inline constexpr wchar_t kEmbeddedPackage[] = L"embedded WireScope.bmp";
inline constexpr wchar_t kPackageFolder[] = L"rsc";

// SERVICE_*_START values.
enum class StartType : DWORD { Boot = 0, System = 1, Automatic = 2, Manual = 3, Disabled = 4 };

struct Binding {
    std::wstring adapter;
    bool enabled{false};
};

struct StagedPackage {
    std::wstring name;     // oemNN.inf
    std::wstring version;  // DriverVer: date,version
};

struct Status {
    // Network component (INetCfg)
    bool installed{false};
    std::wstring displayName, instanceId, bindName;
    std::wstring filterClass;  // Ndi: where NDIS puts it in the stack ("compression")
    DWORD filterType{0};       // 1 monitoring, 2 modifying
    DWORD filterRunType{0};    // 1 mandatory, 2 optional
    std::vector<Binding> bindings;
    // Service (SCM)
    bool service{false};
    DWORD state{0};  // SERVICE_RUNNING, SERVICE_STOPPED ...
    StartType startType{StartType::Disabled};
    std::wstring file, fileVersion;
    TrustReport fileTrust{Signature::Unknown};
    std::vector<std::pair<std::wstring, std::wstring>> parameters;  // ...\Services\wsddntf\Parameters
    // Driver store
    std::vector<StagedPackage> staged;
    // Control device
    bool deviceOpens{false};
    DWORD deviceError{0};
    // The package WireScope would install
    std::optional<std::wstring> package;
    std::wstring packageVersion;
    TrustReport packageTrust{Signature::Unknown};
    std::wstring error;  // what could not be read (INetCfg busy ...), empty when complete

    [[nodiscard]] bool Running() const noexcept { return service && state == SERVICE_RUNNING; }
    [[nodiscard]] bool Attached() const noexcept;  // enabled on at least one adapter
};

struct Outcome {
    bool reboot{false};               // Windows asks for a restart to finish
    std::vector<std::wstring> notes;  // things worth telling (staged as oemNN.inf, a copy left in the store ...)
};

[[nodiscard]] std::optional<std::wstring> FindPackage();
// Read-only; `deviceInUse` = WireScope itself holds the control device open (it then counts as opening).
[[nodiscard]] Status Query(bool deviceInUse = false);
// The engineering report: label, value. English, like the command line.
[[nodiscard]] std::vector<std::pair<std::wstring, std::wstring>> Report(const Status& status);

[[nodiscard]] std::expected<Outcome, std::wstring> Install(const std::wstring& inf);  // rolls back if the driver stays silent
[[nodiscard]] std::expected<Outcome, std::wstring> Uninstall();
[[nodiscard]] std::expected<Outcome, std::wstring> Attach(bool enabled);  // every adapter at once
[[nodiscard]] std::expected<Outcome, std::wstring> Start();  // service, attach, wait for the device
[[nodiscard]] std::expected<Outcome, std::wstring> Stop();   // detach, then stop the service
// Disabled detaches and stops the driver first (see above); the other types leave its state alone.
[[nodiscard]] std::expected<Outcome, std::wstring> SetStartType(StartType type);
[[nodiscard]] bool WaitForDevice(DWORD timeoutMs);

[[nodiscard]] const wchar_t* StartTypeName(StartType type) noexcept;  // "system", "automatic" ... (command line)
[[nodiscard]] std::optional<StartType> ParseStartType(std::wstring_view text) noexcept;

} // namespace WS::DriverSetup
