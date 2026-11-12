#include "core/DriverSetup.h"
#include "core/DriverPackage.h"
#include "resources/resource.h"
#include "support/Common.h"
#include "support/Handle.h"
#include "support/Language.h"
#include "support/Text.h"
#include <SetupAPI.h>
#include <netcfgx.h>
#include <wrl/client.h>
#include <algorithm>
#include <format>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "version.lib")

namespace WS::DriverSetup {

namespace {

using Microsoft::WRL::ComPtr;

// {5B035261-40F9-11D1-AAEC-00805FC1270E}: the coclass behind netcfg.exe (netcfgx.idl).
constexpr CLSID kNetCfg = {0x5B035261, 0x40F9, 0x11D1, {0xAA, 0xEC, 0x00, 0x80, 0x5F, 0xC1, 0x27, 0x0E}};
// GUID_DEVCLASS_NETSERVICE, the class of wsddntf.inf.
constexpr GUID kNetServiceClass = {0x4D36E974, 0xE325, 0x11CE, {0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18}};
constexpr DWORD kLockTimeoutMs = 5000;
constexpr DWORD kServiceTimeoutMs = 15000;
constexpr DWORD kDeviceTimeoutMs = 15000;

// INetCfg wants a single-threaded apartment; a thread that has one already keeps it.
class Apartment {
public:
    Apartment() noexcept : m_hr(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)) {}
    ~Apartment() { if (SUCCEEDED(m_hr)) CoUninitialize(); }
    Apartment(const Apartment&) = delete;
    Apartment& operator=(const Apartment&) = delete;
    [[nodiscard]] bool Ready() const noexcept { return SUCCEEDED(m_hr); }
private:
    HRESULT m_hr;
};

std::wstring ApiError(const wchar_t* call, HRESULT hr) {
    std::wstring text = FormatError(static_cast<DWORD>(hr));
    if (text.empty() || text.starts_with(L"Unknown")) text = std::format(L"0x{:08X}", static_cast<uint32_t>(hr));
    return Text::Format(IDS_DRV_API, call, text);
}

std::wstring Win32Error(const wchar_t* call, DWORD code = GetLastError()) {
    return ApiError(call, HRESULT_FROM_WIN32(code));
}

// Opens INetCfg (with the write lock when `write`), runs f, and always closes it again.
template <class F>
auto WithNetCfg(bool write, F&& f) -> decltype(f(static_cast<INetCfg*>(nullptr))) {
    const Apartment apartment;
    if (!apartment.Ready()) return std::unexpected(Text::Get(IDS_DRV_APARTMENT));
    ComPtr<INetCfg> cfg;
    HRESULT hr = CoCreateInstance(kNetCfg, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&cfg));
    if (FAILED(hr)) return std::unexpected(ApiError(L"CoCreateInstance(CNetCfg)", hr));
    ComPtr<INetCfgLock> lock;
    if (write) {
        if (hr = cfg.As(&lock); FAILED(hr)) return std::unexpected(ApiError(L"INetCfgLock", hr));
        LPWSTR holder = nullptr;
        hr = lock->AcquireWriteLock(kLockTimeoutMs, L"WireScope", &holder);
        const std::wstring who = holder ? holder : L"?";
        CoTaskMemFree(holder);
        if (hr == S_FALSE) return std::unexpected(Text::Format(IDS_DRV_LOCKED, who));
        if (FAILED(hr)) return std::unexpected(ApiError(L"INetCfgLock::AcquireWriteLock", hr));
    }
    if (hr = cfg->Initialize(nullptr); FAILED(hr)) {
        if (lock) lock->ReleaseWriteLock();
        return std::unexpected(ApiError(L"INetCfg::Initialize", hr));
    }
    auto result = f(cfg.Get());
    cfg->Uninitialize();
    if (lock) lock->ReleaseWriteLock();
    return result;
}

std::wstring TakeString(LPWSTR text) {
    std::wstring out = text ? text : L"";
    CoTaskMemFree(text);
    return out;
}

// Calls f(path) for every binding path below the component (one per adapter it can sit on).
template <class F>
HRESULT ForEachBinding(INetCfgComponent* component, F&& f) {
    ComPtr<INetCfgComponentBindings> bindings;
    if (HRESULT hr = component->QueryInterface(IID_PPV_ARGS(&bindings)); FAILED(hr)) return hr;
    ComPtr<IEnumNetCfgBindingPath> paths;
    if (HRESULT hr = bindings->EnumBindingPaths(EBP_BELOW, &paths); FAILED(hr)) return hr;
    ComPtr<INetCfgBindingPath> path;
    ULONG fetched = 0;
    while (paths->Next(1, path.ReleaseAndGetAddressOf(), &fetched) == S_OK) {
        if (HRESULT hr = f(path.Get()); FAILED(hr)) return hr;
    }
    return S_OK;
}

std::wstring AdapterOf(INetCfgBindingPath* path) {
    // The lowest component of the path is the adapter.
    std::wstring adapter;
    ComPtr<IEnumNetCfgBindingInterface> interfaces;
    if (FAILED(path->EnumBindingInterfaces(&interfaces))) return adapter;
    ComPtr<INetCfgBindingInterface> item;
    ULONG fetched = 0;
    while (interfaces->Next(1, item.ReleaseAndGetAddressOf(), &fetched) == S_OK) {
        ComPtr<INetCfgComponent> lower;
        LPWSTR name = nullptr;
        if (SUCCEEDED(item->GetLowerComponent(&lower)) && SUCCEEDED(lower->GetDisplayName(&name))) adapter = TakeString(name);
    }
    return adapter;
}

std::wstring WindowsFolder() {
    std::wstring path(MAX_PATH, L'\0');
    path.resize(GetWindowsDirectoryW(path.data(), MAX_PATH));
    return path;
}

// "\SystemRoot\System32\drivers\x.sys", "System32\drivers\x.sys" or "\??\C:\..." to a plain path.
std::wstring DriverFilePath(std::wstring image) {
    if (image.starts_with(L"\\??\\")) return image.substr(4);
    if (_wcsnicmp(image.c_str(), L"\\SystemRoot\\", 12) == 0) return WindowsFolder() + image.substr(11);
    if (image.size() > 1 && image[1] != L':') return WindowsFolder() + L"\\" + image;
    return image;
}

std::wstring FileVersion(const std::wstring& file) {
    DWORD ignored = 0;
    const DWORD size = GetFileVersionInfoSizeW(file.c_str(), &ignored);
    if (size == 0) return {};
    std::vector<BYTE> data(size);
    VS_FIXEDFILEINFO* info = nullptr;
    UINT length = 0;
    if (!GetFileVersionInfoW(file.c_str(), 0, size, data.data()) || !VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &length) ||
        !info) {
        return {};
    }
    return std::format(L"{}.{}.{}.{}", HIWORD(info->dwFileVersionMS), LOWORD(info->dwFileVersionMS), HIWORD(info->dwFileVersionLS),
                       LOWORD(info->dwFileVersionLS));
}

// DriverVer of [Version] as written, "07/10/2025,3.2.26.2" (SetupQueryInfVersionInformation gives the date only).
std::wstring InfVersion(const std::wstring& path) {
    const HINF inf = SetupOpenInfFileW(path.c_str(), nullptr, INF_STYLE_WIN4, nullptr);
    if (inf == INVALID_HANDLE_VALUE) return {};
    const ScopeExit close([&] { SetupCloseInfFile(inf); });
    INFCONTEXT line{};
    std::wstring value(256, L'\0');
    DWORD needed = 0;
    if (!SetupFindFirstLineW(inf, L"Version", L"DriverVer", &line) ||
        !SetupGetLineTextW(&line, nullptr, nullptr, nullptr, value.data(), static_cast<DWORD>(value.size()), &needed)) {
        return {};
    }
    value.resize(needed ? needed - 1 : 0);
    return value;
}

std::vector<BYTE> InfInformation(const std::wstring& path) {
    DWORD size = 0;
    if (!SetupGetInfInformationW(path.c_str(), INFINFO_INF_NAME_IS_ABSOLUTE, nullptr, 0, &size) || size == 0) return {};
    std::vector<BYTE> buffer(size);
    if (!SetupGetInfInformationW(path.c_str(), INFINFO_INF_NAME_IS_ABSOLUTE, reinterpret_cast<SP_INF_INFORMATION*>(buffer.data()), size, nullptr)) {
        return {};
    }
    return buffer;
}

// Every copy of wsddntf.inf in the driver store, as pnputil /enum-drivers lists them.
std::vector<StagedPackage> Staged() {
    std::vector<StagedPackage> packages;
    const std::wstring folder = WindowsFolder() + L"\\INF\\";
    WIN32_FIND_DATAW found{};
    const FindHandle find(FindFirstFileW((folder + L"oem*.inf").c_str(), &found));
    if (!find) return packages;
    do {
        auto buffer = InfInformation(folder + found.cFileName);
        if (buffer.empty()) continue;
        auto* info = reinterpret_cast<SP_INF_INFORMATION*>(buffer.data());
        SP_ORIGINAL_FILE_INFO_W original{sizeof original};
        if (!SetupQueryInfOriginalFileInformationW(info, 0, nullptr, &original) || _wcsicmp(original.OriginalInfName, kInfName) != 0) continue;
        packages.push_back({found.cFileName, InfVersion(folder + found.cFileName)});
    } while (FindNextFileW(find.get(), &found));
    return packages;
}

ServiceHandle OpenDriverService(DWORD access) {
    const ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager) return ServiceHandle();
    return ServiceHandle(OpenServiceW(manager.get(), kServiceName, access));
}

bool WaitForState(SC_HANDLE service, DWORD state, DWORD timeoutMs) {
    const uint64_t deadline = GetTickCount64() + timeoutMs;
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    while (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof status, &needed)) {
        if (status.dwCurrentState == state) return true;
        if (GetTickCount64() >= deadline) return false;
        Sleep(100);
    }
    return false;
}

// Rejects a package that would not load: a mandatory filter that cannot start takes every adapter down.
std::expected<void, std::wstring> CheckPackage(const std::wstring& inf) {
    const std::wstring folder = inf.substr(0, inf.find_last_of(L'\\') + 1);
    for (const wchar_t* file : {kInfName, L"wsddntf.sys", L"wsddntf.cat"}) {
        if (GetFileAttributesW((folder + file).c_str()) == INVALID_FILE_ATTRIBUTES) {
            return std::unexpected(Text::Format(IDS_DRV_NO_PACKAGE, folder + file));
        }
    }
    for (const wchar_t* signedFile : {L"wsddntf.cat", L"wsddntf.sys"}) {
        const TrustReport trust = ProcessTrust::Verify(folder + signedFile);
        if (trust.signature != Signature::Signed) return std::unexpected(Text::Format(IDS_DRV_BAD_PACKAGE, folder + signedFile));
    }
    return {};
}

std::wstring SignatureText(const TrustReport& t) {
    switch (t.signature) {
    case Signature::Signed: return t.signer.empty() ? L"signed" : L"signed: " + t.signer;
    case Signature::Package: return L"app package";
    case Signature::Unsigned: return L"not signed";
    case Signature::Invalid: return L"signature does not verify";
    case Signature::Unknown: return L"cannot be read";
    case Signature::Pending: break;
    }
    return L"not checked";
}

const wchar_t* StateName(DWORD state) noexcept {
    switch (state) {
    case SERVICE_STOPPED: return L"stopped";
    case SERVICE_START_PENDING: return L"starting";
    case SERVICE_STOP_PENDING: return L"stopping";
    case SERVICE_RUNNING: return L"running";
    case SERVICE_CONTINUE_PENDING: return L"continuing";
    case SERVICE_PAUSE_PENDING: return L"pausing";
    case SERVICE_PAUSED: return L"paused";
    default: return L"unknown";
    }
}

struct EmbeddedInfo {
    std::wstring version;
    TrustReport trust{Signature::Unknown};
};

const EmbeddedInfo& GetEmbeddedInfo() {
    static const EmbeddedInfo info = [] {
        EmbeddedInfo out;
        if (auto staged = DriverPackage::StagedFolder::Create()) {
            out.version = InfVersion(staged->InfPath());
            out.trust = ProcessTrust::Verify(staged->CatPath());
        }
        return out;
    }();
    return info;
}

}  // namespace

bool Status::Attached() const noexcept {
    return std::ranges::any_of(bindings, [](const Binding& b) { return b.enabled; });
}

const wchar_t* StartTypeName(StartType type) noexcept {
    switch (type) {
    case StartType::Boot: return L"boot";
    case StartType::System: return L"system";
    case StartType::Automatic: return L"automatic";
    case StartType::Manual: return L"manual";
    case StartType::Disabled: return L"disabled";
    }
    return L"unknown";
}

std::optional<StartType> ParseStartType(std::wstring_view text) noexcept {
    for (StartType t : {StartType::System, StartType::Automatic, StartType::Manual, StartType::Disabled}) {
        if (_wcsicmp(std::wstring(text).c_str(), StartTypeName(t)) == 0) return t;
    }
    if (_wcsicmp(std::wstring(text).c_str(), L"auto") == 0) return StartType::Automatic;
    if (_wcsicmp(std::wstring(text).c_str(), L"demand") == 0) return StartType::Manual;
    return std::nullopt;
}

std::optional<std::wstring> FindPackage() {
    if (DriverPackage::HasEmbeddedPackage()) return kEmbeddedPackage;
    std::wstring exe(32768, L'\0');
    exe.resize(GetModuleFileNameW(nullptr, exe.data(), static_cast<DWORD>(exe.size())));
    const std::wstring folder = exe.substr(0, exe.find_last_of(L'\\'));
    for (const std::wstring& base : {folder, folder.substr(0, folder.find_last_of(L'\\'))}) {
        const std::wstring candidate = base + L"\\" + kPackageFolder + L"\\" + kInfName;
        if (GetFileAttributesW(candidate.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        std::wstring full(32768, L'\0');
        full.resize(GetFullPathNameW(candidate.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr));
        return full;
    }
    return std::nullopt;
}

Status Query(bool deviceInUse) {
    Status s;
    // Network component and its bindings.
    auto component = WithNetCfg(false, [&](INetCfg* cfg) -> std::expected<void, std::wstring> {
        ComPtr<INetCfgComponent> c;
        const HRESULT hr = cfg->FindComponent(kComponentId, &c);
        if (FAILED(hr)) return std::unexpected(ApiError(L"INetCfg::FindComponent", hr));
        if (hr != S_OK) return {};
        s.installed = true;
        LPWSTR text = nullptr;
        if (SUCCEEDED(c->GetDisplayName(&text))) s.displayName = TakeString(text);
        if (SUCCEEDED(c->GetBindName(&text))) s.bindName = TakeString(text);
        GUID instance{};
        if (SUCCEEDED(c->GetInstanceGuid(&instance))) {
            wchar_t guid[64]{};
            StringFromGUID2(instance, guid, static_cast<int>(std::size(guid)));
            s.instanceId = guid;
        }
        ForEachBinding(c.Get(), [&](INetCfgBindingPath* path) {
            s.bindings.push_back({AdapterOf(path), path->IsEnabled() == S_OK});
            return S_OK;
        });
        return {};
    });
    if (!component) s.error = component.error();
    if (!s.instanceId.empty()) {
        // What the INF told NDIS about the filter (Ndi key of the network component).
        RegKey ndi;
        const std::wstring key = L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E974-E325-11CE-BFC1-08002BE10318}\\" + s.instanceId + L"\\Ndi";
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, ndi.put()) == ERROR_SUCCESS) {
            DWORD size = sizeof(DWORD);
            RegGetValueW(ndi.get(), nullptr, L"FilterType", RRF_RT_REG_DWORD, nullptr, &s.filterType, &size);
            size = sizeof(DWORD);
            RegGetValueW(ndi.get(), nullptr, L"FilterRunType", RRF_RT_REG_DWORD, nullptr, &s.filterRunType, &size);
            wchar_t text[128]{};
            size = sizeof text;
            if (RegGetValueW(ndi.get(), nullptr, L"FilterClass", RRF_RT_REG_SZ, nullptr, text, &size) == ERROR_SUCCESS) s.filterClass = text;
        }
    }

    // Service.
    if (const ServiceHandle service = OpenDriverService(SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG)) {
        s.service = true;
        SERVICE_STATUS_PROCESS status{};
        DWORD needed = 0;
        if (QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof status, &needed)) {
            s.state = status.dwCurrentState;
        }
        QueryServiceConfigW(service.get(), nullptr, 0, &needed);
        std::vector<BYTE> buffer(needed);
        if (needed && QueryServiceConfigW(service.get(), reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data()), needed, &needed)) {
            const auto* config = reinterpret_cast<const QUERY_SERVICE_CONFIGW*>(buffer.data());
            s.startType = static_cast<StartType>(config->dwStartType);
            if (config->lpBinaryPathName) s.file = DriverFilePath(config->lpBinaryPathName);
        }
        if (!s.file.empty()) {
            s.fileVersion = FileVersion(s.file);
            s.fileTrust = ProcessTrust::Verify(s.file);
        }
    }
    RegKey parameters;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\wsddntf\\Parameters", 0, KEY_READ, parameters.put()) ==
        ERROR_SUCCESS) {
        for (DWORD i = 0;; ++i) {
            wchar_t name[256]{};
            BYTE data[512]{};
            DWORD nameLength = static_cast<DWORD>(std::size(name)), type = 0, size = sizeof data;
            if (RegEnumValueW(parameters.get(), i, name, &nameLength, nullptr, &type, data, &size) != ERROR_SUCCESS) break;
            std::wstring value;
            if (type == REG_DWORD && size == sizeof(DWORD)) value = std::to_wstring(*reinterpret_cast<const DWORD*>(data));
            else if (type == REG_SZ || type == REG_EXPAND_SZ) value = std::wstring(reinterpret_cast<const wchar_t*>(data), size / sizeof(wchar_t)).c_str();
            else value = std::format(L"({} bytes, type {})", size, type);
            s.parameters.emplace_back(name, value);
        }
    }

    s.staged = Staged();

    // Control device.
    if (deviceInUse) {
        s.deviceOpens = true;
    } else {
        const FileHandle device(CreateFileW(kDevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
        s.deviceOpens = static_cast<bool>(device);
        if (!device) s.deviceError = GetLastError();
    }

    // The embedded or side-by-side driver package.
    s.package = FindPackage();
    if (s.package) {
        if (*s.package == kEmbeddedPackage) {
            const EmbeddedInfo& embedded = GetEmbeddedInfo();
            s.packageVersion = embedded.version;
            s.packageTrust = embedded.trust;
        } else {
            s.packageVersion = InfVersion(*s.package);
            s.packageTrust = ProcessTrust::Verify(s.package->substr(0, s.package->find_last_of(L'\\') + 1) + L"wsddntf.cat");
        }
    }
    return s;
}

std::vector<std::pair<std::wstring, std::wstring>> Report(const Status& s) {
    std::vector<std::pair<std::wstring, std::wstring>> r;
    r.emplace_back(L"Component", s.installed ? std::format(L"{}  installed", kComponentId) : std::format(L"{}  not installed", kComponentId));
    if (s.installed) {
        r.emplace_back(L"  Name", s.displayName);
        r.emplace_back(L"  Instance", s.instanceId);
        r.emplace_back(L"  Bind name", s.bindName);
        if (s.filterRunType) {
            const wchar_t* type = s.filterType == 2 ? L"modifying" : s.filterType == 1 ? L"monitoring" : L"unknown type";
            const wchar_t* run = s.filterRunType == 1 ? L"mandatory: an adapter it is attached to carries no traffic without it"
                                                      : L"optional: traffic goes around it when it is not running";
            r.emplace_back(L"  Filter", std::format(L"{}, class {}, {}", type, s.filterClass, run));
        }
        const auto attached = std::ranges::count_if(s.bindings, [](const Binding& b) { return b.enabled; });
        r.emplace_back(L"  Bindings", s.bindings.empty() ? std::wstring(L"none reported")
                                                         : std::format(L"attached to {} of {} adapters", attached, s.bindings.size()));
    }
    if (s.service) {
        r.emplace_back(L"Service", std::format(L"{}  {}, start {}", kServiceName, StateName(s.state), StartTypeName(s.startType)));
        r.emplace_back(L"  File", s.fileVersion.empty() ? s.file : std::format(L"{}  {}", s.file, s.fileVersion));
        r.emplace_back(L"  Signature", SignatureText(s.fileTrust));
        for (const auto& [name, value] : s.parameters) r.emplace_back(L"  Parameter", std::format(L"{} = {}", name, value));
    } else {
        r.emplace_back(L"Service", std::format(L"{}  not present", kServiceName));
    }
    if (s.staged.empty()) r.emplace_back(L"Driver store", std::format(L"no copy of {}", kInfName));
    for (const StagedPackage& p : s.staged) r.emplace_back(L"Driver store", std::format(L"{}  {}", p.name, p.version));
    std::wstring device = L"opens";
    if (!s.deviceOpens) {
        // Without a running driver there is no device: that is the state, not an error.
        device = !s.installed  ? std::wstring(L"absent: the driver is not installed")
                 : !s.Running() ? std::wstring(L"absent while the driver is stopped")
                                : std::format(L"error {}: {}", s.deviceError, FormatError(s.deviceError));
    }
    r.emplace_back(L"Device", std::format(L"{}  {}", kDevicePath, device));
    if (s.package) {
        r.emplace_back(L"Package", std::format(L"{}  {}", *s.package, s.packageVersion));
        r.emplace_back(L"  Catalog", SignatureText(s.packageTrust));
    } else {
        r.emplace_back(L"Package", std::format(L"none in {}\\ next to WireScope.exe or one folder up", kPackageFolder));
    }
    if (!s.error.empty()) r.emplace_back(L"Incomplete", s.error);
    // Long and least telling (Windows keeps adapters that are gone): last, so the rest stays in view.
    if (!s.bindings.empty()) r.emplace_back(L"Bindings", std::format(L"{} adapters", s.bindings.size()));
    for (const Binding& b : s.bindings) r.emplace_back(L"  Adapter", std::format(L"{}  {}", b.enabled ? L"attached" : L"detached", b.adapter));
    return r;
}

bool WaitForDevice(DWORD timeoutMs) {
    const uint64_t deadline = GetTickCount64() + timeoutMs;
    for (;;) {
        const FileHandle device(CreateFileW(kDevicePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
        if (device) return true;
        if (GetTickCount64() >= deadline) return false;
        Sleep(200);
    }
}

std::expected<Outcome, std::wstring> Install(const std::wstring& inf) {
    std::optional<DriverPackage::StagedFolder> staged;
    std::wstring actualInf = inf;
    if (actualInf.empty() || actualInf == kEmbeddedPackage) {
        auto extracted = DriverPackage::StagedFolder::Create();
        if (!extracted) return std::unexpected(extracted.error());
        staged = std::move(*extracted);
        actualInf = staged->InfPath();
    }
    if (auto ok = CheckPackage(actualInf); !ok) return std::unexpected(ok.error());
    std::wstring published(MAX_PATH, L'\0');
    if (!SetupCopyOEMInfW(actualInf.c_str(), nullptr, SPOST_PATH, 0, published.data(), MAX_PATH, nullptr, nullptr)) {
        return std::unexpected(Win32Error(L"SetupCopyOEMInf"));
    }
    published.resize(wcslen(published.c_str()));
    auto installed = WithNetCfg(true, [&](INetCfg* cfg) -> std::expected<Outcome, std::wstring> {
        ComPtr<INetCfgComponent> existing;
        if (cfg->FindComponent(kComponentId, &existing) == S_OK) return std::unexpected(Text::Get(IDS_DRV_ALREADY));
        ComPtr<INetCfgClassSetup> setup;
        HRESULT hr = cfg->QueryNetCfgClass(&kNetServiceClass, IID_PPV_ARGS(&setup));
        if (FAILED(hr)) return std::unexpected(ApiError(L"INetCfg::QueryNetCfgClass", hr));
        OBO_TOKEN obo{};
        obo.Type = OBO_USER;
        ComPtr<INetCfgComponent> component;
        hr = setup->Install(kComponentId, &obo, 0, 0, nullptr, nullptr, &component);
        if (FAILED(hr)) {
            cfg->Cancel();
            return std::unexpected(ApiError(L"INetCfgClassSetup::Install", hr));
        }
        Outcome out;
        out.reboot = hr == NETCFG_S_REBOOT;
        hr = cfg->Apply();
        if (FAILED(hr)) {
            cfg->Cancel();
            return std::unexpected(ApiError(L"INetCfg::Apply", hr));
        }
        out.reboot = out.reboot || hr == NETCFG_S_REBOOT;
        out.notes.push_back(Text::Format(IDS_DRV_STAGED, published.substr(published.find_last_of(L'\\') + 1)));
        return out;
    });
    if (!installed) return installed;
    // A mandatory filter that does not answer may keep the adapters down: take it out again.
    if (!installed->reboot && !WaitForDevice(kDeviceTimeoutMs)) {
        const DWORD error = GetLastError();
        auto undone = Uninstall();
        return std::unexpected(Text::Format(IDS_DRV_ROLLED_BACK, FormatError(error)) + (undone ? std::wstring() : L"\n" + undone.error()));
    }
    return installed;
}

std::expected<Outcome, std::wstring> Uninstall() {
    auto removed = WithNetCfg(true, [&](INetCfg* cfg) -> std::expected<Outcome, std::wstring> {
        Outcome out;
        ComPtr<INetCfgComponent> component;
        HRESULT hr = cfg->FindComponent(kComponentId, &component);
        if (FAILED(hr)) return std::unexpected(ApiError(L"INetCfg::FindComponent", hr));
        if (hr != S_OK) return out;  // not installed: only the driver store is left to clean
        ComPtr<INetCfgClassSetup> setup;
        if (hr = cfg->QueryNetCfgClass(&kNetServiceClass, IID_PPV_ARGS(&setup)); FAILED(hr)) {
            return std::unexpected(ApiError(L"INetCfg::QueryNetCfgClass", hr));
        }
        OBO_TOKEN obo{};
        obo.Type = OBO_USER;
        hr = setup->DeInstall(component.Get(), &obo, nullptr);
        if (FAILED(hr)) {
            cfg->Cancel();
            return std::unexpected(ApiError(L"INetCfgClassSetup::DeInstall", hr));
        }
        if (hr == NETCFG_S_STILL_REFERENCED) out.notes.push_back(Text::Get(IDS_DRV_STILL_REFERENCED));
        out.reboot = hr == NETCFG_S_REBOOT;
        hr = cfg->Apply();
        if (FAILED(hr)) {
            cfg->Cancel();
            return std::unexpected(ApiError(L"INetCfg::Apply", hr));
        }
        out.reboot = out.reboot || hr == NETCFG_S_REBOOT;
        return out;
    });
    if (!removed) return removed;
    // Complete cleanup: every staged copy, also those of older installations.
    for (const StagedPackage& p : Staged()) {
        if (SetupUninstallOEMInfW(p.name.c_str(), 0, nullptr)) {
            removed->notes.push_back(Text::Format(IDS_DRV_STORE_DELETED, p.name));
        } else {
            removed->notes.push_back(Text::Format(IDS_DRV_STORE_LEFT, p.name, FormatError()));
        }
    }
    return removed;
}

std::expected<Outcome, std::wstring> Attach(bool enabled) {
    return WithNetCfg(true, [&](INetCfg* cfg) -> std::expected<Outcome, std::wstring> {
        ComPtr<INetCfgComponent> component;
        HRESULT hr = cfg->FindComponent(kComponentId, &component);
        if (FAILED(hr)) return std::unexpected(ApiError(L"INetCfg::FindComponent", hr));
        if (hr != S_OK) return std::unexpected(Text::Get(IDS_DRV_NOT_INSTALLED));
        size_t changed = 0;
        hr = ForEachBinding(component.Get(), [&](INetCfgBindingPath* path) {
            if ((path->IsEnabled() == S_OK) == enabled) return S_OK;
            ++changed;
            return path->Enable(enabled ? TRUE : FALSE);
        });
        if (FAILED(hr)) {
            cfg->Cancel();
            return std::unexpected(ApiError(L"INetCfgBindingPath::Enable", hr));
        }
        Outcome out;
        if (changed == 0) return out;
        hr = cfg->Apply();
        if (FAILED(hr)) {
            cfg->Cancel();
            return std::unexpected(ApiError(L"INetCfg::Apply", hr));
        }
        out.reboot = hr == NETCFG_S_REBOOT;
        return out;
    });
}

namespace {

std::expected<void, std::wstring> ServiceStart() {
    const ServiceHandle service = OpenDriverService(SERVICE_START | SERVICE_QUERY_STATUS);
    if (!service) return std::unexpected(Win32Error(L"OpenService"));
    if (!StartServiceW(service.get(), 0, nullptr)) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DISABLED) return std::unexpected(Text::Get(IDS_DRV_DISABLED));
        if (error != ERROR_SERVICE_ALREADY_RUNNING) return std::unexpected(Win32Error(L"StartService", error));
    }
    if (!WaitForState(service.get(), SERVICE_RUNNING, kServiceTimeoutMs)) return std::unexpected(Text::Get(IDS_DRV_TIMEOUT));
    return {};
}

std::expected<void, std::wstring> ServiceStop() {
    const ServiceHandle service = OpenDriverService(SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!service) return std::unexpected(Win32Error(L"OpenService"));
    SERVICE_STATUS status{};
    if (!ControlService(service.get(), SERVICE_CONTROL_STOP, &status)) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE) return std::unexpected(Win32Error(L"ControlService(STOP)", error));
    }
    if (!WaitForState(service.get(), SERVICE_STOPPED, kServiceTimeoutMs)) return std::unexpected(Text::Get(IDS_DRV_TIMEOUT));
    return {};
}

}  // namespace

std::expected<Outcome, std::wstring> Start() {
    if (auto started = ServiceStart(); !started) return std::unexpected(started.error());
    auto attached = Attach(true);
    if (!attached) return attached;
    if (!attached->reboot && !WaitForDevice(kDeviceTimeoutMs)) return std::unexpected(Text::Get(IDS_DRV_SILENT));
    return attached;
}

std::expected<Outcome, std::wstring> Stop() {
    // Detached first: a mandatory filter that stops while still attached holds the adapters' traffic
    // (sc stop does exactly that). Detached, the adapters run without it and the network keeps working.
    auto detached = Attach(false);
    if (!detached) return detached;
    if (auto stopped = ServiceStop(); !stopped) return std::unexpected(stopped.error());
    return detached;
}

std::expected<Outcome, std::wstring> SetStartType(StartType type) {
    Outcome out;
    if (type == StartType::Disabled) {
        // Disabled but still attached, a mandatory filter could keep the adapters down at boot.
        auto stopped = Stop();
        if (!stopped) return stopped;
        out = *stopped;
    }
    const ServiceHandle service = OpenDriverService(SERVICE_CHANGE_CONFIG);
    if (!service) return std::unexpected(Win32Error(L"OpenService"));
    if (!ChangeServiceConfigW(service.get(), SERVICE_NO_CHANGE, static_cast<DWORD>(type), SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr,
                              nullptr, nullptr, nullptr)) {
        return std::unexpected(Win32Error(L"ChangeServiceConfig"));
    }
    return out;
}

} // namespace WS::DriverSetup
