#include "support/Common.h"
#include <format>
#include <vector>

namespace WS {

bool IsElevated() noexcept {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const BOOL success = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return success && elevation.TokenIsElevated != 0;
}

std::wstring FormatError(DWORD code) {
    wchar_t* message = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&message),
        0,
        nullptr
    );

    if (length == 0 || !message) {
        return std::format(L"Error 0x{:08X} ({})", code, code);
    }

    std::wstring result(message, length);
    LocalFree(message);

    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
        result.pop_back();
    }
    return result;
}

std::wstring FormatBytes(uint64_t bytes) {
    constexpr double KiB = 1024.0;
    constexpr double MiB = KiB * 1024.0;
    constexpr double GiB = MiB * 1024.0;

    const double b = static_cast<double>(bytes);
    if (b >= GiB) {
        return std::format(L"{:.2f} GiB", b / GiB);
    }
    if (b >= MiB) {
        return std::format(L"{:.2f} MiB", b / MiB);
    }
    if (b >= KiB) {
        return std::format(L"{:.1f} KiB", b / KiB);
    }
    return std::format(L"{} B", bytes);
}

std::wstring FormatRate(double bytesPerSec) {
    constexpr double KiB = 1024.0;
    constexpr double MiB = KiB * 1024.0;

    if (bytesPerSec >= MiB) {
        return std::format(L"{:.2f} MiB/s", bytesPerSec / MiB);
    }
    if (bytesPerSec >= KiB) {
        return std::format(L"{:.1f} KiB/s", bytesPerSec / KiB);
    }
    return std::format(L"{:.0f} B/s", bytesPerSec);
}

std::wstring FormatCount(uint64_t value) {
    std::wstring digits = std::to_wstring(value);
    std::wstring out;
    out.reserve(digits.size() + digits.size() / 3);
    const size_t lead = digits.size() % 3;
    for (size_t i = 0; i < digits.size(); ++i) {
        if (i != 0 && i >= lead && (i - lead) % 3 == 0) out.push_back(L',');
        out.push_back(digits[i]);
    }
    return out;
}

uint64_t MonotonicMicroseconds() noexcept {
    static const uint64_t frequency = [] {
        LARGE_INTEGER f{};
        QueryPerformanceFrequency(&f);
        return static_cast<uint64_t>(f.QuadPart ? f.QuadPart : 1);
    }();
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    const uint64_t ticks = static_cast<uint64_t>(now.QuadPart);
    return (ticks / frequency) * 1'000'000ULL + (ticks % frequency) * 1'000'000ULL / frequency;
}

uint64_t BootTimeSeconds() noexcept {
    return GetCurrentTimestampMicroseconds() / 1'000'000ULL - GetTickCount64() / 1000ULL;
}

uint64_t GetCurrentTimestampMicroseconds() noexcept {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    const uint64_t t = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    // Convert 100-nanosecond intervals (since Jan 1, 1601) to microseconds (since epoch Jan 1, 1970)
    constexpr uint64_t EpochDiff = 116444736000000000ULL;
    if (t < EpochDiff) return 0;
    return (t - EpochDiff) / 10;
}

} // namespace WS
