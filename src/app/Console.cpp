#include "app/Console.h"
#include "support/Text.h"
#include <Windows.h>

namespace WS::Cli {

namespace {

enum class Kind { None, Console, Redirected };

Kind KindOf(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE) return Kind::None;
    switch (GetFileType(h)) {
    case FILE_TYPE_DISK:
    case FILE_TYPE_PIPE: return Kind::Redirected;
    case FILE_TYPE_CHAR: return Kind::Console;
    default: return Kind::None;
    }
}

FileHandle OpenConsole(const wchar_t* name) {
    return FileHandle(CreateFileW(name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                  OPEN_EXISTING, 0, nullptr));
}

void QueueEnter() {
    const FileHandle in = OpenConsole(L"CONIN$");
    if (!in) return;
    INPUT_RECORD keys[2]{};
    keys[0].EventType = KEY_EVENT;
    keys[0].Event.KeyEvent.bKeyDown = TRUE;
    keys[0].Event.KeyEvent.wRepeatCount = 1;
    keys[0].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
    keys[0].Event.KeyEvent.wVirtualScanCode = static_cast<WORD>(MapVirtualKeyW(VK_RETURN, MAPVK_VK_TO_VSC));
    keys[0].Event.KeyEvent.uChar.UnicodeChar = L'\r';
    keys[1] = keys[0];
    keys[1].Event.KeyEvent.bKeyDown = FALSE;
    DWORD written = 0;
    WriteConsoleInputW(in.get(), keys, 2, &written);
}

void WaitForKey() {
    const FileHandle in = OpenConsole(L"CONIN$");
    if (!in) return;
    FlushConsoleInputBuffer(in.get());
    for (;;) {
        INPUT_RECORD record{};
        DWORD read = 0;
        if (!ReadConsoleInputW(in.get(), &record, 1, &read) || !read) break;
        if (record.EventType == KEY_EVENT && record.Event.KeyEvent.bKeyDown) break;
    }
}

} // namespace

Console::Console() {
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    const Kind outKind = KindOf(out);
    if (outKind == Kind::Redirected) {
        m_out = { out, false };
    }

    if (!m_out.handle) {
        if (AttachConsole(ATTACH_PARENT_PROCESS)) {
            m_attached = true;
        } else if (AllocConsole()) {
            m_allocated = true;
        }

        if (m_attached || m_allocated) {
            m_conout = OpenConsole(L"CONOUT$");
        }

        if (m_conout) {
            m_out = { m_conout.get(), true };
            if (GetConsoleMode(m_conout.get(), &m_originalOutMode)) {
                if (SetConsoleMode(m_conout.get(), m_originalOutMode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
                    m_supportsAnsi = true;
                }
            }
        }
    }

    // ANSI coloring only active when output is a real console, never when piped
    m_supportsAnsi = m_supportsAnsi && m_out.console;
    if (m_allocated) {
        SetConsoleTitleW(L"WireScope");
    }
}

Console::~Console() {
    if (m_allocated) {
        WriteLine("\nPress any key to close this window.");
        WaitForKey();
    } else if (m_attached) {
        if (m_supportsAnsi && m_conout) {
            SetConsoleMode(m_conout.get(), m_originalOutMode);
        }
        QueueEnter();
    }
    m_conout.reset();
    if (m_attached || m_allocated) {
        FreeConsole();
    }
}

void Console::Write(std::string_view text) const {
    if (!m_out.handle || text.empty()) return;
    DWORD written = 0;
    if (m_out.console) {
        const std::wstring wide = ToWide(text);
        WriteConsoleW(m_out.handle, wide.data(), static_cast<DWORD>(wide.size()), &written, nullptr);
        return;
    }
    // Files and pipes get CRLF line ends
    std::string crlf;
    crlf.reserve(text.size() + 8);
    for (char c : text) {
        if (c == '\n' && (crlf.empty() || crlf.back() != '\r')) crlf.push_back('\r');
        crlf.push_back(c);
    }
    WriteFile(m_out.handle, crlf.data(), static_cast<DWORD>(crlf.size()), &written, nullptr);
}

void Console::WriteLine(std::string_view line) const {
    Write(line);
    Write("\n");
}

std::string Console::Reset() const { return m_supportsAnsi ? "\033[0m" : ""; }
std::string Console::Bold() const { return m_supportsAnsi ? "\033[1m" : ""; }
std::string Console::Dim() const { return m_supportsAnsi ? "\033[2m" : ""; }
std::string Console::Red() const { return m_supportsAnsi ? "\033[91m" : ""; }
std::string Console::Green() const { return m_supportsAnsi ? "\033[92m" : ""; }
std::string Console::Yellow() const { return m_supportsAnsi ? "\033[93m" : ""; }
std::string Console::Blue() const { return m_supportsAnsi ? "\033[94m" : ""; }
std::string Console::Magenta() const { return m_supportsAnsi ? "\033[95m" : ""; }
std::string Console::Cyan() const { return m_supportsAnsi ? "\033[96m" : ""; }

} // namespace WS::Cli
