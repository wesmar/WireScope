// WireScope - Common utilities and system helpers
#pragma once
#include <Windows.h>
#include <chrono>
#include <string>
#include <cstdint>

namespace WS {

enum class Level { Info, Success, Warning, Error };

[[nodiscard]] bool IsElevated() noexcept;
[[nodiscard]] std::wstring FormatError(DWORD code = GetLastError());
[[nodiscard]] std::wstring FormatBytes(uint64_t bytes);
[[nodiscard]] std::wstring FormatRate(double bytesPerSec);
[[nodiscard]] std::wstring FormatCount(uint64_t value);  // 1,234,567
[[nodiscard]] uint64_t GetCurrentTimestampMicroseconds() noexcept;  // wall clock, Unix epoch
[[nodiscard]] uint64_t MonotonicMicroseconds() noexcept;           // QueryPerformanceCounter
[[nodiscard]] uint64_t BootTimeSeconds() noexcept;                 // approximate, Unix epoch

} // namespace WS
