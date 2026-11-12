#include "support/Settings.h"
#include "support/Handle.h"

namespace WS::Settings {

namespace {

constexpr wchar_t kKey[] = L"Software\\WireScope";

RegKey Open(bool write) {
    RegKey key;
    if (write) {
        RegCreateKeyExW(HKEY_CURRENT_USER, kKey, 0, nullptr, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, key.put(), nullptr);
    } else {
        RegOpenKeyExW(HKEY_CURRENT_USER, kKey, 0, KEY_QUERY_VALUE, key.put());
    }
    return key;
}

} // namespace

std::wstring Read(const wchar_t* name, std::wstring_view fallback) {
    const RegKey key = Open(false);
    if (!key) return std::wstring(fallback);
    DWORD bytes = 0;
    if (RegGetValueW(key.get(), nullptr, name, RRF_RT_REG_SZ, nullptr, nullptr, &bytes) != ERROR_SUCCESS || bytes < sizeof(wchar_t)) {
        return std::wstring(fallback);
    }
    std::wstring value(bytes / sizeof(wchar_t), L'\0');
    if (RegGetValueW(key.get(), nullptr, name, RRF_RT_REG_SZ, nullptr, value.data(), &bytes) != ERROR_SUCCESS) {
        return std::wstring(fallback);
    }
    value.resize(wcsnlen(value.c_str(), value.size()));
    return value;
}

void Write(const wchar_t* name, std::wstring_view value) {
    const RegKey key = Open(true);
    if (!key) return;
    const std::wstring copy(value);
    RegSetValueExW(key.get(), name, 0, REG_SZ, reinterpret_cast<const BYTE*>(copy.c_str()),
                   static_cast<DWORD>((copy.size() + 1) * sizeof(wchar_t)));
}

DWORD ReadDword(const wchar_t* name, DWORD fallback) {
    const RegKey key = Open(false);
    if (!key) return fallback;
    DWORD value = 0;
    DWORD bytes = sizeof(value);
    if (RegGetValueW(key.get(), nullptr, name, RRF_RT_REG_DWORD, nullptr, &value, &bytes) != ERROR_SUCCESS) return fallback;
    return value;
}

void WriteDword(const wchar_t* name, DWORD value) {
    const RegKey key = Open(true);
    if (!key) return;
    RegSetValueExW(key.get(), name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
}

std::optional<std::vector<uint8_t>> ReadBinary(const wchar_t* name) {
    const RegKey key = Open(false);
    if (!key) return std::nullopt;
    DWORD bytes = 0;
    if (RegGetValueW(key.get(), nullptr, name, RRF_RT_REG_BINARY, nullptr, nullptr, &bytes) != ERROR_SUCCESS) return std::nullopt;
    std::vector<uint8_t> data(bytes);
    if (bytes && RegGetValueW(key.get(), nullptr, name, RRF_RT_REG_BINARY, nullptr, data.data(), &bytes) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    data.resize(bytes);
    return data;
}

void WriteBinary(const wchar_t* name, std::span<const uint8_t> data) {
    const RegKey key = Open(true);
    if (!key) return;
    RegSetValueExW(key.get(), name, 0, REG_BINARY, data.data(), static_cast<DWORD>(data.size()));
}

void Delete(const wchar_t* name) {
    const RegKey key = Open(true);
    if (key) RegDeleteValueW(key.get(), name);
}

} // namespace WS::Settings
