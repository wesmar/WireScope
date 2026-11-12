// WireScope - Per-user settings in HKCU\Software\WireScope (shared by the GUI and the command line).
#pragma once
#include <Windows.h>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace WS::Settings {

[[nodiscard]] std::wstring Read(const wchar_t* name, std::wstring_view fallback = {});
void Write(const wchar_t* name, std::wstring_view value);
[[nodiscard]] DWORD ReadDword(const wchar_t* name, DWORD fallback);
void WriteDword(const wchar_t* name, DWORD value);
[[nodiscard]] std::optional<std::vector<uint8_t>> ReadBinary(const wchar_t* name);
void WriteBinary(const wchar_t* name, std::span<const uint8_t> data);
void Delete(const wchar_t* name);

} // namespace WS::Settings
