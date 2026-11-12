// WireScope - Modal dialogs in the same Mica style as the main window (instead of light MessageBox windows).
#pragma once
#include <Windows.h>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace WS::Ui {

struct DialogField {
    std::wstring label;
    std::wstring value;
    std::wstring cue;      // placeholder text
    bool mono = false;     // monospace input (rules, filters)
};

struct DialogSpec {
    std::wstring heading;
    std::wstring message;    // wrapped paragraph, may be empty
    std::wstring monospace;  // scrollable read-only text block (help), may be empty
    int monospaceHeight = 220;  // DIP
    std::vector<DialogField> fields;
    std::wstring ok;           // empty = "OK" in the current language
    std::wstring cancel;       // empty = "Cancel" in the current language
    bool cancelButton = true;  // false: only OK (and the extra button)
    std::wstring extra;        // optional third button (result 2)
    bool danger = false;       // heading in the critical colour
    int width = 480;           // DIP
    // Called while typing and on OK: returns an error to show (OK stays) or nullopt.
    std::function<std::optional<std::wstring>(const std::vector<std::wstring>&)> validate;
    // Shown under the fields while the values are valid (e.g. what a rule means).
    std::function<std::wstring(const std::vector<std::wstring>&)> preview;
};

struct DialogResult {
    int button = 0;  // 0 = cancel / closed, 1 = ok, 2 = extra
    std::vector<std::wstring> values;
};

DialogResult RunDialog(HWND owner, const DialogSpec& spec);

bool Confirm(HWND owner, std::wstring heading, std::wstring message, std::wstring ok, bool danger = false);

// Windows file dialog (IFileOpenDialog / IFileSaveDialog). `extension` is the default for saving.
struct FileFilter {
    std::wstring name;
    std::wstring pattern;  // "*.pcap" or "*.rules;*.txt"
};
std::optional<std::wstring> PickFile(HWND owner, bool save, const std::vector<FileFilter>& filters, const std::wstring& fileName = {},
                                     const wchar_t* extension = nullptr);
void Inform(HWND owner, std::wstring heading, std::wstring message, bool danger = false);

}  // namespace WS::Ui
