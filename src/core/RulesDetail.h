// WireScope - Internal to Rules.cpp and RuleCompiler.cpp: address formatting, masks, messages.
#pragma once
#include "support/Language.h"
#include "support/Text.h"
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>

namespace WS::RulesDetail {

inline constexpr size_t kMaxEntriesPerSelector = 1024;

[[nodiscard]] std::string FormatIpv4Host(uint32_t ip);  // host byte order
[[nodiscard]] std::string FormatIpv6Bytes(const uint8_t* bytes);
void MaskV6(std::array<uint8_t, 16>& bytes, uint32_t prefix);
[[nodiscard]] std::array<uint8_t, 16> MaskBytes(uint32_t prefix);

// Localised message as UTF-8 (the rule layer works in UTF-8); arguments are UTF-8 or numbers.
template <class... Args>
[[nodiscard]] std::string Msg(UINT id, const Args&... args) {
    auto widen = [](const auto& a) {
        if constexpr (std::is_convertible_v<decltype(a), std::string_view>) return ToWide(std::string_view(a));
        else return a;
    };
    return ToUtf8(Text::Format(id, widen(args)...));
}

} // namespace WS::RulesDetail
