#include "support/Text.h"
#include <Windows.h>
#include <algorithm>
#include <format>

namespace WS {

std::wstring ToWide(std::string_view utf8) {
    if (utf8.empty()) return {};
    const int req = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (req <= 0) return {};
    std::wstring wide(static_cast<size_t>(req), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), req);
    return wide;
}

std::string ToUtf8(std::wstring_view wide) {
    if (wide.empty()) return {};
    const int req = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (req <= 0) return {};
    std::string utf8(static_cast<size_t>(req), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), utf8.data(), req, nullptr, nullptr);
    return utf8;
}

std::wstring FoldCase(std::wstring_view text) {
    if (text.empty()) return {};
    std::wstring out(text);
    const int n = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, text.data(), static_cast<int>(text.size()), out.data(),
                                static_cast<int>(out.size()), nullptr, nullptr, 0);
    if (n <= 0) return std::wstring(text);
    out.resize(static_cast<size_t>(n));
    return out;
}

std::string FoldCase(std::string_view utf8) {
    return ToUtf8(FoldCase(ToWide(utf8)));
}

std::string FormatMac(std::span<const uint8_t, 6> mac) {
    return std::format("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

std::string FormatIpv4(uint32_t ipNetworkOrder) {
    const uint8_t b1 = static_cast<uint8_t>(ipNetworkOrder & 0xFF);
    const uint8_t b2 = static_cast<uint8_t>((ipNetworkOrder >> 8) & 0xFF);
    const uint8_t b3 = static_cast<uint8_t>((ipNetworkOrder >> 16) & 0xFF);
    const uint8_t b4 = static_cast<uint8_t>((ipNetworkOrder >> 24) & 0xFF);
    return std::format("{}.{}.{}.{}", b1, b2, b3, b4);
}

std::string FormatIpv6(std::span<const uint8_t, 16> ip) {
    std::string out;
    for (size_t i = 0; i < 16; i += 2) {
        if (i > 0) out += ':';
        const uint16_t word = static_cast<uint16_t>((ip[i] << 8) | ip[i + 1]);
        out += std::format("{:x}", word);
    }
    return out;
}

std::string FormatHexDump(std::span<const uint8_t> data, size_t maxBytes) {
    const size_t len = std::min(data.size(), maxBytes);
    std::string out;
    out.reserve(len * 4);

    for (size_t i = 0; i < len; i += 16) {
        out += std::format("{:04X}  ", i);
        // Hex bytes
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len) {
                out += std::format("{:02X} ", data[i + j]);
            } else {
                out += "   ";
            }
            if (j == 7) out += ' ';
        }
        out += " |";
        // ASCII representation
        for (size_t j = 0; j < 16 && (i + j) < len; ++j) {
            const uint8_t b = data[i + j];
            out += (b >= 32 && b <= 126) ? static_cast<char>(b) : '.';
        }
        out += "|\n";
    }

    if (data.size() > maxBytes) {
        out += std::format("... [{} more bytes truncated]\n", data.size() - maxBytes);
    }
    return out;
}

bool ContainsIgnoreCase(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;
    const auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
        [](char ch1, char ch2) {
            return std::tolower(static_cast<unsigned char>(ch1)) ==
                   std::tolower(static_cast<unsigned char>(ch2));
        });
    return it != haystack.end();
}

bool ContainsIgnoreCase(std::wstring_view haystack, std::wstring_view needle) noexcept {
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;
    const auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
        [](wchar_t ch1, wchar_t ch2) {
            return towlower(ch1) == towlower(ch2);
        });
    return it != haystack.end();
}

} // namespace WS
