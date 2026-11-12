// WireScope - Packet list: virtual (only visible rows are drawn), keyboard and mouse driven.
//
// Sorted by any column (click the header; again for the other direction). In the order of arrival it
// follows the newest packet while scrolled to that end; scrolling or selecting a row pins the view.
// Several packets can be selected: Ctrl+click toggles one, Shift+click or Shift+arrows a range,
// Ctrl+A all. The selection belongs to the packets, so it survives sorting and new arrivals; the
// focused packet is the one the details pane shows.
//
// Notifies the parent with WM_COMMAND: LBN_SELCHANGE (selection), PacketListCopy (Ctrl+C).
// Right-click and the menu key raise WM_CONTEXTMENU in the parent.
#pragma once
#include "core/PacketEngine.h"
#include "gui/Widgets.h"
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace WS::Ui {

inline constexpr WORD PacketListCopy = 0x0200;

D2D1_COLOR_F ProtocolColor(const DecodedPacket& p);

class PacketList {
public:
    enum class Sort { Number, Time, Direction, Protocol, Source, Destination, Length, Info };

    explicit PacketList(const Fonts& fonts) : m_fonts(fonts) {}
    PacketList(const PacketList&) = delete;
    PacketList& operator=(const PacketList&) = delete;

    HWND Create(HWND parent, int id);
    [[nodiscard]] HWND hwnd() const noexcept { return m_hwnd; }

    void SetRows(std::vector<PacketRef> rows);       // replaces the rows (in capture order), keeps the selection
    void Append(const std::vector<PacketRef>& rows);  // newer packets, in capture order
    void Clear();
    void SetBaseTime(uint64_t timestampUs);
    void SetPlaceholder(std::wstring text);
    [[nodiscard]] PacketRef Selected() const;                 // the focused packet
    [[nodiscard]] std::vector<PacketRef> Marked() const;       // every selected packet, in capture order
    [[nodiscard]] size_t MarkedCount() const noexcept { return m_marked.size(); }
    void SelectAll();
    [[nodiscard]] size_t Count() const noexcept { return m_rows.size(); }
    void Relayout();

private:
    struct Columns {
        float no, time, dir, proto, src, dst, len, info, right;
    };
    static LRESULT CALLBACK Proc(HWND, UINT, WPARAM, LPARAM);
    LRESULT Handle(UINT, WPARAM, LPARAM);
    void Paint();  // PacketListPaint.cpp
    [[nodiscard]] Columns Layout(float width) const;
    [[nodiscard]] float RowH() const { return m_fonts.F(26); }
    [[nodiscard]] float HeaderH() const { return m_fonts.F(30); }
    [[nodiscard]] int RowAt(POINT p) const;
    [[nodiscard]] std::optional<Sort> HeaderAt(POINT p) const;
    [[nodiscard]] int RowOf(uint64_t index) const;  // -1 when the packet is not listed
    [[nodiscard]] bool Before(const DecodedPacket& a, const DecodedPacket& b) const;  // the current order
    [[nodiscard]] bool Chronological() const noexcept { return m_sort == Sort::Number && !m_descending; }
    void SetSort(Sort sort);
    // Moves the focus to `row`. extend: select the range from the anchor; toggle: flip this row only.
    void Focus(int row, bool extend, bool toggle);
    void Notify(WORD code);
    void Refocus();  // the focused row after the rows moved
    void UpdateExtent();
    void Trim();

    const Fonts& m_fonts;
    HWND m_hwnd = nullptr;
    std::vector<PacketRef> m_rows;  // in display order
    Sort m_sort = Sort::Number;
    bool m_descending = false;
    std::unordered_set<uint64_t> m_marked;  // selected packets by Index
    uint64_t m_focus = 0, m_anchor = 0;     // packet Index, 0 = none (indexes start at 1)
    int m_selected = -1;                    // row of m_focus
    int m_hot = -1;
    bool m_follow = true;
    bool m_tracking = false;
    uint64_t m_baseTime = 0;
    Scroller m_scroll;
    std::wstring m_placeholder;
};

}  // namespace WS::Ui
