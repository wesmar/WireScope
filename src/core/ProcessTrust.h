// WireScope - Is a program what it claims to be?
//
// For every image path the Processes page shows: the Authenticode signature (embedded, or a Windows
// catalog for system files) and a few facts about where the file lives. Verification hashes the
// file, which takes from milliseconds to seconds, so it runs on one background thread and is cached
// per path for the session. Revocation is never checked online: WireScope must not cause traffic
// while it watches traffic, and it may run with the network blocked.
//
// The verdict is a hint, not a malware scan: a signed program can misbehave and an unsigned one is
// often a harmless home-made tool. What raises the alarm is a combination that legitimate software
// rarely shows - unsigned code in a folder any program can write to, a hidden executable, a file
// named like a Windows component outside the Windows folder, or a signature that does not verify.
#pragma once
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <unordered_map>

namespace WS {

enum class Signature : uint8_t {
    Pending,   // queued for verification
    Signed,    // valid signature from a trusted publisher
    Unsigned,  // no signature, embedded or in a catalog
    Invalid,   // signed, but the signature does not verify (altered file, untrusted or revoked certificate)
    Unknown,   // the file could not be read
    Package,   // part of an app package (MSIX) in the protected WindowsApps folder: the package is signed,
               // Windows verified it at installation, and only the system can write there
};

namespace TrustFlag {
inline constexpr uint32_t UserFolder = 1;  // under C:\Users, ProgramData or a temporary folder
inline constexpr uint32_t Hidden = 2;      // hidden or system file outside the Windows folder
inline constexpr uint32_t Imitation = 4;   // name of a Windows component, outside the Windows folder
}  // namespace TrustFlag

enum class Risk : uint8_t { None, Notice, High };

struct TrustReport {
    Signature signature{Signature::Pending};
    std::wstring signer;  // subject of the signing certificate, e.g. "Microsoft Windows"
    uint32_t flags{0};    // TrustFlag bits
    [[nodiscard]] Risk risk() const noexcept;
};

class ProcessTrust {
public:
    static ProcessTrust& Instance();
    ~ProcessTrust();

    ProcessTrust(const ProcessTrust&) = delete;
    ProcessTrust& operator=(const ProcessTrust&) = delete;

    // Never blocks: a path seen for the first time is queued and reported as Pending.
    [[nodiscard]] TrustReport Check(const std::wstring& path);
    // Verifies one file now, on the calling thread (the command line).
    [[nodiscard]] static TrustReport Verify(const std::wstring& path);

private:
    ProcessTrust() = default;
    void Run(std::stop_token stop);

    std::mutex m_mutex;
    std::condition_variable_any m_wake;
    std::unordered_map<std::wstring, TrustReport> m_cache;  // by folded path
    std::deque<std::wstring> m_queue;
    std::once_flag m_started;
    std::jthread m_thread;  // last member: joined before the rest is destroyed
};

} // namespace WS
