// WireScope - Text, encoding and formatting utilities
#pragma once
#include <string>
#include <string_view>
#include <span>
#include <cstdint>

namespace WS {

[[nodiscard]] std::wstring ToWide(std::string_view utf8);
[[nodiscard]] std::string ToUtf8(std::wstring_view wide);
// Lower case for comparisons, the same for every locale ("Ł" -> "ł"; std::tolower only knows ASCII).
[[nodiscard]] std::wstring FoldCase(std::wstring_view text);
[[nodiscard]] std::string FoldCase(std::string_view utf8);

[[nodiscard]] std::string FormatMac(std::span<const uint8_t, 6> mac);
[[nodiscard]] std::string FormatIpv4(uint32_t ipNetworkOrder);
[[nodiscard]] std::string FormatIpv6(std::span<const uint8_t, 16> ip);

[[nodiscard]] std::string FormatHexDump(std::span<const uint8_t> data, size_t maxBytes = 256);

[[nodiscard]] bool ContainsIgnoreCase(std::string_view haystack, std::string_view needle) noexcept;
[[nodiscard]] bool ContainsIgnoreCase(std::wstring_view haystack, std::wstring_view needle) noexcept;

} // namespace WS
