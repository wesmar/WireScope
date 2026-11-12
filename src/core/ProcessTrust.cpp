#include "core/ProcessTrust.h"
#include "support/Handle.h"
#include "support/Text.h"
#include <Windows.h>
#include <ShlObj.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <bcrypt.h>
#include <array>
#include <format>
#include <optional>
#include <string_view>
#include <vector>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace WS {

namespace {

// Catalogs sign Windows components, which are far smaller; hashing a huge file for a catalog that
// cannot exist would only keep the verifier busy (and WireScope from exiting) for seconds.
constexpr LONGLONG kMaxCatalogFile = 256LL * 1024 * 1024;

// Names Windows components run under. Elsewhere than in the Windows folder they are an imitation.
constexpr std::wstring_view kSystemNames[] = {
    L"svchost.exe", L"lsass.exe",    L"csrss.exe",     L"smss.exe",       L"wininit.exe",  L"winlogon.exe",   L"services.exe",
    L"spoolsv.exe", L"dwm.exe",      L"taskhostw.exe", L"conhost.exe",    L"rundll32.exe", L"dllhost.exe",    L"explorer.exe",
    L"ctfmon.exe",  L"sihost.exe",   L"fontdrvhost.exe", L"wmiprvse.exe", L"lsaiso.exe",   L"runtimebroker.exe", L"taskmgr.exe",
    L"regsvr32.exe", L"mshta.exe",   L"cmd.exe",       L"powershell.exe", L"searchindexer.exe", L"audiodg.exe", L"wudfhost.exe",
};

std::wstring KnownFolder(REFKNOWNFOLDERID id) {
    PWSTR path = nullptr;
    std::wstring out;
    if (SUCCEEDED(SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, nullptr, &path)) && path) out = path;
    CoTaskMemFree(path);
    return out;
}

// Folded folder prefixes ending in a backslash.
struct Places {
    std::wstring windows;
    std::wstring packages;                 // Program Files\WindowsApps: installed app packages
    std::array<std::wstring, 3> writable;  // user profiles, ProgramData, the Windows temporary folder

    Places() {
        auto folder = [](std::wstring path) {
            if (path.empty()) return path;
            if (path.back() != L'\\') path += L'\\';
            return FoldCase(path);
        };
        windows = folder(KnownFolder(FOLDERID_Windows));
        const std::wstring programs = folder(KnownFolder(FOLDERID_ProgramFiles));
        packages = programs.empty() ? std::wstring() : programs + L"windowsapps\\";
        writable = {folder(KnownFolder(FOLDERID_UserProfiles)), folder(KnownFolder(FOLDERID_ProgramData)),
                    windows.empty() ? std::wstring() : windows + L"temp\\"};
    }
};

const Places& Folders() {
    static const Places places;
    return places;
}

bool Under(std::wstring_view path, const std::wstring& folder) {
    return !folder.empty() && path.starts_with(folder);
}

uint32_t PlaceFlags(const std::wstring& path, const std::wstring& folded) {
    const Places& places = Folders();
    const bool windows = Under(folded, places.windows);
    uint32_t flags = 0;
    for (const auto& folder : places.writable) {
        if (Under(folded, folder)) flags |= TrustFlag::UserFolder;
    }
    if (const DWORD attributes = GetFileAttributesW(path.c_str());
        attributes != INVALID_FILE_ATTRIBUTES && (attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) && !windows) {
        flags |= TrustFlag::Hidden;
    }
    const std::wstring_view name = std::wstring_view(folded).substr(folded.find_last_of(L'\\') + 1);
    for (const auto system : kSystemNames) {
        if (name == system && !windows) flags |= TrustFlag::Imitation;
    }
    return flags;
}

// Store and MSIX apps carry no Authenticode signature in their files: the package as a whole is
// signed (AppxSignature.p7x) and checked by Windows when it is installed into WindowsApps, which only
// the system may write to. Returns the package publisher, or nullopt outside that folder.
std::optional<std::wstring> PackagePublisher(const std::wstring& path, const std::wstring& folded) {
    const std::wstring& packages = Folders().packages;
    if (!Under(folded, packages) || folded.size() != path.size()) return std::nullopt;
    const size_t end = folded.find(L'\\', packages.size());  // end of the package folder name
    if (end == std::wstring::npos) return std::nullopt;
    const std::wstring manifest = path.substr(0, end) + L"\\AppxManifest.xml";
    const FileHandle file(CreateFileW(manifest.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
    if (!file) return std::nullopt;
    std::string xml(64 * 1024, '\0');
    DWORD read = 0;
    if (!ReadFile(file.get(), xml.data(), static_cast<DWORD>(xml.size()), &read, nullptr)) return std::nullopt;
    xml.resize(read);

    // <Identity Name="..." Publisher="CN=Microsoft Corporation, O=..., C=US" .../>
    const size_t identity = xml.find("<Identity");
    const size_t close = identity == std::string::npos ? std::string::npos : xml.find('>', identity);
    const size_t attribute = identity == std::string::npos ? std::string::npos : xml.find(" Publisher=\"", identity);
    if (attribute == std::string::npos || attribute > close) return std::wstring();
    const size_t begin = attribute + 12;
    std::string publisher = xml.substr(begin, xml.find('"', begin) - begin);
    if (publisher.starts_with("CN=")) {  // the common name reads best
        publisher.erase(0, 3);
        if (const size_t comma = publisher.find(','); comma != std::string::npos) publisher.resize(comma);
    }
    return ToWide(publisher);
}

std::wstring SignerName(HANDLE state) {
    CRYPT_PROVIDER_DATA* provider = WTHelperProvDataFromStateData(state);
    if (!provider) return {};
    CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
    if (!signer || signer->csCertChain == 0 || !signer->pasCertChain || !signer->pasCertChain[0].pCert) return {};
    std::wstring name(256, L'\0');
    const DWORD n = CertGetNameStringW(signer->pasCertChain[0].pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name.data(),
                                       static_cast<DWORD>(name.size()));
    name.resize(n > 0 ? n - 1 : 0);
    return name;
}

// WinVerifyTrust without any user interface or network access; fills `signer` on success.
LONG Verify(WINTRUST_DATA& data, std::wstring& signer) {
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.cbStruct = sizeof data;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    if (status == ERROR_SUCCESS) signer = SignerName(data.hWVTStateData);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &data);
    return status;
}

// Windows components are signed in catalogs (.cat) rather than in the file itself.
std::optional<LONG> VerifyCatalog(const std::wstring& path, HANDLE file, const wchar_t* algorithm, std::wstring& signer) {
    HCATADMIN admin = nullptr;
    if (!CryptCATAdminAcquireContext2(&admin, nullptr, algorithm, nullptr, 0)) return std::nullopt;
    const ScopeExit releaseAdmin([&] { CryptCATAdminReleaseContext(admin, 0); });

    SetFilePointer(file, 0, nullptr, FILE_BEGIN);
    DWORD size = 0;
    CryptCATAdminCalcHashFromFileHandle2(admin, file, &size, nullptr, 0);
    if (size == 0) return std::nullopt;
    std::vector<BYTE> hash(size);
    SetFilePointer(file, 0, nullptr, FILE_BEGIN);
    if (!CryptCATAdminCalcHashFromFileHandle2(admin, file, &size, hash.data(), 0)) return std::nullopt;

    HCATINFO catalog = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), size, 0, nullptr);
    if (!catalog) return std::nullopt;
    const ScopeExit releaseCatalog([&] { CryptCATAdminReleaseCatalogContext(admin, catalog, 0); });
    CATALOG_INFO info{sizeof info};
    if (!CryptCATCatalogInfoFromContext(catalog, &info, 0)) return std::nullopt;

    std::wstring tag;  // the catalog member is the hash in upper-case hex
    for (const BYTE b : hash) tag += std::format(L"{:02X}", b);
    WINTRUST_CATALOG_INFO member{sizeof member};
    member.pcwszCatalogFilePath = info.wszCatalogFile;
    member.pcwszMemberTag = tag.c_str();
    member.pcwszMemberFilePath = path.c_str();
    member.hMemberFile = file;
    member.pbCalculatedFileHash = hash.data();
    member.cbCalculatedFileHash = size;
    member.hCatAdmin = admin;
    WINTRUST_DATA data{};
    data.dwUnionChoice = WTD_CHOICE_CATALOG;
    data.pCatalog = &member;
    return Verify(data, signer);
}

TrustReport Inspect(const std::wstring& path, const std::wstring& folded) {
    TrustReport report;
    report.flags = PlaceFlags(path, folded);
    const FileHandle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                      OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
    if (!file) {
        report.signature = Signature::Unknown;
        return report;
    }
    WINTRUST_FILE_INFO fileInfo{sizeof fileInfo};
    fileInfo.pcwszFilePath = path.c_str();
    fileInfo.hFile = file.get();
    WINTRUST_DATA data{};
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    const LONG embedded = Verify(data, report.signer);
    if (embedded == ERROR_SUCCESS) {
        report.signature = Signature::Signed;
        return report;
    }
    if (embedded != TRUST_E_NOSIGNATURE && embedded != TRUST_E_SUBJECT_FORM_UNKNOWN && embedded != TRUST_E_PROVIDER_UNKNOWN) {
        report.signature = Signature::Invalid;  // a signature is there and does not hold
        return report;
    }
    LARGE_INTEGER size{};
    if (GetFileSizeEx(file.get(), &size) && size.QuadPart <= kMaxCatalogFile) {
        for (const wchar_t* algorithm : {BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA1_ALGORITHM}) {
            if (const auto status = VerifyCatalog(path, file.get(), algorithm, report.signer)) {
                report.signature = *status == ERROR_SUCCESS ? Signature::Signed : Signature::Invalid;
                return report;
            }
        }
    }
    if (auto publisher = PackagePublisher(path, folded)) {
        report.signature = Signature::Package;
        report.signer = std::move(*publisher);
        return report;
    }
    report.signature = Signature::Unsigned;
    return report;
}

}  // namespace

Risk TrustReport::risk() const noexcept {
    const bool unsigned_ = signature == Signature::Unsigned;
    if ((flags & TrustFlag::Imitation) || signature == Signature::Invalid) return Risk::High;
    if (unsigned_ && (flags & (TrustFlag::UserFolder | TrustFlag::Hidden))) return Risk::High;
    if (unsigned_ || (flags & TrustFlag::Hidden)) return Risk::Notice;
    return Risk::None;
}

TrustReport ProcessTrust::Verify(const std::wstring& path) {
    if (path.empty()) return {Signature::Unknown};
    return Inspect(path, FoldCase(path));
}

ProcessTrust& ProcessTrust::Instance() {
    static ProcessTrust instance;
    return instance;
}

ProcessTrust::~ProcessTrust() {
    if (m_thread.joinable()) {
        m_thread.request_stop();
        m_wake.notify_all();
        m_thread.join();
    }
}

TrustReport ProcessTrust::Check(const std::wstring& path) {
    if (path.empty()) return {Signature::Unknown};
    std::call_once(m_started, [this] { m_thread = std::jthread([this](std::stop_token stop) { Run(stop); }); });
    std::wstring key = FoldCase(path);
    std::lock_guard lock(m_mutex);
    if (const auto it = m_cache.find(key); it != m_cache.end()) return it->second;
    m_cache.emplace(std::move(key), TrustReport{});
    m_queue.push_back(path);
    m_wake.notify_one();
    return {};
}

void ProcessTrust::Run(std::stop_token stop) {
    std::unique_lock lock(m_mutex);
    while (!stop.stop_requested()) {
        if (!m_wake.wait(lock, stop, [this] { return !m_queue.empty(); })) break;
        const std::wstring path = std::move(m_queue.front());
        m_queue.pop_front();
        lock.unlock();
        std::wstring key = FoldCase(path);
        TrustReport report = Inspect(path, key);
        lock.lock();
        m_cache[std::move(key)] = std::move(report);
    }
}

} // namespace WS
