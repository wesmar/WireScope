// WireScope - Console attachment and ANSI output formatting
#pragma once
#include "support/Handle.h"
#include <string>
#include <string_view>

namespace WS::Cli {

class Console {
public:
    Console();
    ~Console();

    Console(const Console&) = delete;
    Console& operator=(const Console&) = delete;

    [[nodiscard]] bool IsAttached() const noexcept { return m_attached; }
    [[nodiscard]] bool SupportsAnsi() const noexcept { return m_supportsAnsi; }
    // Output goes to a console window: someone can watch it and press Ctrl+C.
    [[nodiscard]] bool IsInteractive() const noexcept { return m_out.console; }

    void Write(std::string_view text) const;
    void WriteLine(std::string_view line = "") const;

    // ANSI Colors (empty when redirected)
    [[nodiscard]] std::string Reset() const;
    [[nodiscard]] std::string Bold() const;
    [[nodiscard]] std::string Dim() const;
    [[nodiscard]] std::string Red() const;
    [[nodiscard]] std::string Green() const;
    [[nodiscard]] std::string Yellow() const;
    [[nodiscard]] std::string Blue() const;
    [[nodiscard]] std::string Magenta() const;
    [[nodiscard]] std::string Cyan() const;

private:
    struct Stream {
        HANDLE handle{nullptr};
        bool console{false};
    };

    Stream m_out;
    FileHandle m_conout;
    bool m_attached{false};
    bool m_allocated{false};
    bool m_supportsAnsi{false};
    DWORD m_originalOutMode{0};
};

} // namespace WS::Cli
