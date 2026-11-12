// WireScope - Process list: one row per program instance with its traffic rates, totals and
// sockets, a warning mark for programs that do not look like what they claim to be, and a header
// that sorts by any column. Notifies the parent with WM_COMMAND:
//   LBN_SELCHANGE  selection changed     LBN_DBLCLK  double click or Enter
// Right-click and the menu key raise WM_CONTEXTMENU in the parent.
#pragma once
#include "core/ProcessTrust.h"
#include "gui/Widgets.h"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace WS::Ui {

struct ProcessRow {
    uint32_t id = 0;   // ProcessInfo::id; 0 = traffic that belongs to no process
    DWORD pid = 0;
    std::wstring name;
    std::wstring path;
    double rateIn = 0, rateOut = 0;  // bytes per second
    uint64_t bytesIn = 0, bytesOut = 0;
    uint64_t packetsIn = 0, packetsOut = 0;
    uint32_t sockets = 0;
    bool counted = false;  // traffic totals exist (counting was on)
    bool running = true;
    Signature signature = Signature::Unknown;
    Risk risk = Risk::None;
};

class ProcessList {
public:
    enum class Sort { Name, Pid, Download, Upload, Total, Sockets };

    explicit ProcessList(const Fonts& fonts) : m_fonts(fonts) {}
    ProcessList(const ProcessList&) = delete;
    ProcessList& operator=(const ProcessList&) = delete;

    HWND Create(HWND parent, int id);
    [[nodiscard]] HWND hwnd() const noexcept { return m_hwnd; }
    void SetRows(std::vector<ProcessRow> rows);  // sorted here; keeps the selected process
    void SetPlaceholder(std::wstring text);
    [[nodiscard]] const ProcessRow* Selected() const noexcept;
    [[nodiscard]] const std::vector<ProcessRow>& Rows() const noexcept { return m_rows; }
    void Relayout();

private:
    struct Columns {
        float mark, name, pid, down, up, total, sockets, right;
    };
    static LRESULT CALLBACK Proc(HWND, UINT, WPARAM, LPARAM);
    LRESULT Handle(UINT, WPARAM, LPARAM);
    void Paint();
    void SortRows();
    void Resort();  // sorts and finds the selected process again
    void Select(int row);
    void Notify(WORD code);
    void UpdateExtent();
    [[nodiscard]] Columns Layout(float width) const;
    [[nodiscard]] float RowH() const { return m_fonts.F(46); }
    [[nodiscard]] float HeaderH() const { return m_fonts.F(32); }
    [[nodiscard]] int RowAt(POINT p) const;
    [[nodiscard]] std::optional<Sort> HeaderAt(POINT p) const;

    const Fonts& m_fonts;
    HWND m_hwnd = nullptr;
    std::vector<ProcessRow> m_rows;
    int m_selected = -1;
    uint32_t m_selectedId = 0;
    bool m_hasSelection = false;
    int m_hot = -1;
    bool m_tracking = false;
    Sort m_sort = Sort::Download;
    bool m_descending = true;
    Scroller m_scroll;
    std::wstring m_placeholder;
};

}  // namespace WS::Ui
