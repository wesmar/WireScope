// WireScope - Firewall rule list: one row per rule (switch, action, rule text, meaning, hit counters)
// and a closing row for the default policy. Notifies the parent with WM_COMMAND:
//   LBN_SELCHANGE   selection changed           LBN_DBLCLK  edit the selected rule (double click, Enter)
//   RuleListToggle  switch clicked / Space      RuleListDelete  Delete key
//   RuleListMoveUp / RuleListMoveDown  Alt+Up / Alt+Down
#pragma once
#include "core/Rules.h"
#include "gui/Widgets.h"
#include <string>
#include <vector>

namespace WS::Ui {

inline constexpr WORD RuleListToggle = 0x0300, RuleListDelete = 0x0301, RuleListMoveUp = 0x0302, RuleListMoveDown = 0x0303;

struct RuleRow {
    uint64_t id = 0;
    bool enabled = true;
    RuleAction action = RuleAction::Block;
    std::wstring text;     // rule without the action word
    std::wstring summary;  // what it means
    HitCounter hits;
};

class RuleList {
public:
    explicit RuleList(const Fonts& fonts) : m_fonts(fonts) {}
    RuleList(const RuleList&) = delete;
    RuleList& operator=(const RuleList&) = delete;

    HWND Create(HWND parent, int id);
    [[nodiscard]] HWND hwnd() const noexcept { return m_hwnd; }
    void SetRows(std::vector<RuleRow> rows);  // keeps the selected rule (by id)
    void SetPolicy(RuleAction policy, HitCounter hits, bool active);
    void SetHits(uint64_t id, HitCounter hits);
    [[nodiscard]] int Selected() const noexcept { return m_selected; }  // index into the rows, -1 = none
    void Select(int index);
    void Relayout();

private:
    static LRESULT CALLBACK Proc(HWND, UINT, WPARAM, LPARAM);
    LRESULT Handle(UINT, WPARAM, LPARAM);
    void Paint();
    void Notify(WORD code);
    [[nodiscard]] float RowH() const { return m_fonts.F(52); }
    [[nodiscard]] int RowAt(POINT p) const;
    [[nodiscard]] D2D1_RECT_F SwitchRect(int row) const;
    void UpdateExtent();

    const Fonts& m_fonts;
    HWND m_hwnd = nullptr;
    std::vector<RuleRow> m_rows;
    RuleAction m_policy = RuleAction::Allow;
    HitCounter m_policyHits;
    bool m_active = false;
    int m_selected = -1;
    int m_hot = -1;
    bool m_tracking = false;
    Scroller m_scroll;
};

}  // namespace WS::Ui
