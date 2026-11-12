#include "gui/RuleList.h"
#include "resources/resource.h"
#include "support/Common.h"
#include "support/Language.h"
#include <windowsx.h>
#include <algorithm>
#include <cmath>
#include <format>

namespace WS::Ui {
namespace {
constexpr wchar_t kClass[] = L"WireScope.RuleList";
}

HWND RuleList::Create(HWND parent, int id) {
    RegisterControlClass(kClass, Proc);
    m_hwnd = CreateWindowExW(0, kClass, L"Firewall rules", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 10, 10, parent,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), this);
    return m_hwnd;
}

LRESULT CALLBACK RuleList::Proc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* self = ControlFromWindow<RuleList>(hwnd, message, lParam);
    if (message == WM_NCCREATE && self) self->m_hwnd = hwnd;
    if (message == WM_NCDESTROY) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        if (self) self->m_hwnd = nullptr;
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
    return self ? self->Handle(message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
}

void RuleList::UpdateExtent() {
    RECT rc{};
    if (m_hwnd) GetClientRect(m_hwnd, &rc);
    m_scroll.view = static_cast<float>(rc.bottom);
    m_scroll.content = static_cast<float>(m_rows.size() + 1) * RowH() + m_fonts.F(8);
    m_scroll.Clamp();
}

void RuleList::SetRows(std::vector<RuleRow> rows) {
    const uint64_t keep = m_selected >= 0 && m_selected < static_cast<int>(m_rows.size()) ? m_rows[static_cast<size_t>(m_selected)].id : 0;
    m_rows = std::move(rows);
    m_selected = -1;
    for (size_t i = 0; i < m_rows.size(); ++i) {
        if (m_rows[i].id == keep) m_selected = static_cast<int>(i);
    }
    m_hot = -1;
    UpdateExtent();
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

void RuleList::SetPolicy(RuleAction policy, HitCounter hits, bool active) {
    m_policy = policy;
    m_policyHits = hits;
    m_active = active;
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

void RuleList::SetHits(uint64_t id, HitCounter hits) {
    for (auto& r : m_rows) {
        if (r.id == id && (r.hits.packets != hits.packets || r.hits.bytes != hits.bytes)) {
            r.hits = hits;
            if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
        }
    }
}

void RuleList::Select(int index) {
    if (m_rows.empty()) return;
    index = std::clamp(index, 0, static_cast<int>(m_rows.size()) - 1);
    const bool changed = index != m_selected;
    m_selected = index;
    m_scroll.EnsureVisible(static_cast<float>(index) * RowH(), static_cast<float>(index + 1) * RowH());
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
    if (changed) Notify(LBN_SELCHANGE);
}

void RuleList::Relayout() {
    UpdateExtent();
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

void RuleList::Notify(WORD code) {
    SendMessageW(GetParent(m_hwnd), WM_COMMAND, MAKEWPARAM(GetDlgCtrlID(m_hwnd), code), reinterpret_cast<LPARAM>(m_hwnd));
}

int RuleList::RowAt(POINT p) const {
    const int row = static_cast<int>(std::floor((static_cast<float>(p.y) + m_scroll.offset - m_fonts.F(4)) / RowH()));
    return row >= 0 && row < static_cast<int>(m_rows.size()) ? row : -1;
}

D2D1_RECT_F RuleList::SwitchRect(int row) const {
    const float top = m_fonts.F(4) + static_cast<float>(row) * RowH() - m_scroll.offset;
    const float mid = top + RowH() / 2;
    return {m_fonts.F(16), mid - m_fonts.F(10), m_fonts.F(56), mid + m_fonts.F(10)};
}

LRESULT RuleList::Handle(UINT message, WPARAM wParam, LPARAM lParam) {
    RECT client{};
    GetClientRect(m_hwnd, &client);
    switch (message) {
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        Paint();
        return 0;
    case WM_SIZE:
        UpdateExtent();
        InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    case WM_GETDLGCODE:
        return DLGC_WANTARROWS | DLGC_WANTCHARS;
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
        InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    case WM_SYSKEYDOWN:
        if (wParam == VK_UP) {
            Notify(RuleListMoveUp);
            return 0;
        }
        if (wParam == VK_DOWN) {
            Notify(RuleListMoveDown);
            return 0;
        }
        break;
    case WM_KEYDOWN:
        switch (wParam) {
        case VK_UP: Select(m_selected < 0 ? 0 : m_selected - 1); return 0;
        case VK_DOWN: Select(m_selected + 1); return 0;
        case VK_HOME: Select(0); return 0;
        case VK_END: Select(static_cast<int>(m_rows.size()) - 1); return 0;
        case VK_SPACE: if (m_selected >= 0) Notify(RuleListToggle); return 0;
        case VK_DELETE: if (m_selected >= 0) Notify(RuleListDelete); return 0;
        case VK_RETURN: if (m_selected >= 0) Notify(LBN_DBLCLK); return 0;
        }
        break;
    case WM_CHAR:
        return 0;  // Space and Enter are handled on key down
    case WM_LBUTTONDOWN:
    case WM_LBUTTONDBLCLK:
    case WM_RBUTTONDOWN: {
        SetFocus(m_hwnd);
        const POINT p{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        if (message != WM_RBUTTONDOWN && m_scroll.MouseDown(p, client, m_fonts)) {
            SetCapture(m_hwnd);
            InvalidateRect(m_hwnd, nullptr, FALSE);
            return 0;
        }
        const int row = RowAt(p);
        if (row < 0) return 0;
        Select(row);
        const D2D1_RECT_F sw = SwitchRect(row);
        const bool onSwitch = static_cast<float>(p.x) >= sw.left - m_fonts.F(6) && static_cast<float>(p.x) <= sw.right + m_fonts.F(6);
        if (message == WM_LBUTTONDOWN && onSwitch) Notify(RuleListToggle);
        else if (message == WM_LBUTTONDBLCLK && !onSwitch) Notify(LBN_DBLCLK);
        return 0;
    }
    case WM_MOUSEMOVE: {
        const POINT p{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        if (!m_tracking) {
            TRACKMOUSEEVENT tme{sizeof tme, TME_LEAVE, m_hwnd, 0};
            m_tracking = TrackMouseEvent(&tme) != FALSE;
        }
        bool repaint = m_scroll.MouseMove(p, client, m_fonts);
        const int hot = m_scroll.dragging || m_scroll.hot ? -1 : RowAt(p);
        if (hot != m_hot) {
            m_hot = hot;
            repaint = true;
        }
        if (repaint) InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_LBUTTONUP:
        if (m_scroll.dragging) {
            m_scroll.dragging = false;
            ReleaseCapture();
            InvalidateRect(m_hwnd, nullptr, FALSE);
        }
        return 0;
    case WM_CAPTURECHANGED:
        m_scroll.dragging = false;
        return 0;
    case WM_MOUSELEAVE:
        m_tracking = false;
        m_hot = -1;
        m_scroll.hot = false;
        InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    case WM_MOUSEWHEEL:
        if (m_scroll.Wheel(GET_WHEEL_DELTA_WPARAM(wParam), WheelStep(m_fonts, RowH()))) InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    }
    return DefWindowProcW(m_hwnd, message, wParam, lParam);
}

void RuleList::Paint() {
    PaintScope ps(m_hwnd);
    RECT client{};
    GetClientRect(m_hwnd, &client);
    const auto& f = m_fonts;
    const bool focused = GetFocus() == m_hwnd;
    m_scroll.view = static_cast<float>(client.bottom);
    m_scroll.Clamp();
    Ui::Paint(ps.dc(), client, f, [&](Canvas& c) {
        c.Clear(Graphics::Get().Surface(Color::Card));
        const float width = static_cast<float>(client.right);
        const float right = width - (m_scroll.Visible() ? f.F(14) : f.F(6));
        const float rowH = RowH();
        c.PushClip(ToF(client));

        auto hitsText = [](const HitCounter& h) {
            return h.packets ? Text::Format(IDS_RULES_HITS, FormatCount(h.packets), FormatBytes(h.bytes)) : Text::Get(IDS_RULES_NO_HITS);
        };
        auto actionPill = [&](RuleAction action, float x, float mid, bool dim) {
            const bool block = action == RuleAction::Block;
            const D2D1_COLOR_F color = block ? Color::Critical : Color::Success;
            const std::wstring text = Text::Get(block ? IDS_PILL_BLOCK : IDS_PILL_ALLOW);
            const D2D1_RECT_F pill{x, mid - f.F(10), x + std::max(f.F(54), c.Width(text, Font::Label) + f.F(14)), mid + f.F(10)};
            c.Fill(pill, WithAlpha(color, dim ? 0.07f : 0.16f), f.F(3));
            c.Text(text, pill, Font::Label, dim ? WithAlpha(color, 0.55f) : color, Align::Center);
        };

        for (size_t i = 0; i < m_rows.size(); ++i) {
            const RuleRow& r = m_rows[i];
            const float top = f.F(4) + static_cast<float>(i) * rowH - m_scroll.offset;
            if (top + rowH < 0 || top > static_cast<float>(client.bottom)) continue;
            const float mid = top + rowH / 2;
            const D2D1_RECT_F box{f.F(4), top + f.F(1), right, top + rowH - f.F(1)};
            const int index = static_cast<int>(i);
            if (index == m_selected) {
                c.Fill(box, Color::Selected, f.F(4));
                c.Fill({box.left + f.F(1), mid - f.F(8), box.left + f.F(4), mid + f.F(8)}, Color::AccentText, f.F(1.5f));
                if (focused) c.Stroke(box, White(0.18f), f.F(4));
            } else if (index == m_hot) {
                c.Fill(box, Color::Hover, f.F(4));
            }

            // Switch
            const D2D1_RECT_F sw = SwitchRect(index);
            const float h = sw.bottom - sw.top;
            if (r.enabled) c.Fill(sw, Color::Accent, h / 2);
            else {
                c.Fill(sw, Color::Control, h / 2);
                c.Stroke(sw, Color::Text3, h / 2);
            }
            c.Circle({r.enabled ? sw.right - h / 2 : sw.left + h / 2, mid}, f.F(6), r.enabled ? Color::Text : Color::Text2);

            // Position, action, text and meaning
            c.Text(std::to_wstring(i + 1), {f.F(62), top, f.F(84), top + rowH}, Font::Caption, Color::Text3, Align::Center);
            actionPill(r.action, f.F(90), mid, !r.enabled);
            const float x = f.F(170);
            const std::wstring hits = hitsText(r.hits);
            const float hitsW = std::min(c.Width(hits, Font::Caption) + f.F(4), (right - x) * 0.4f);
            const float textRight = right - hitsW - f.F(16);
            c.Text(r.text, {x, top + f.F(7), textRight, mid + f.F(1)}, Font::Mono, r.enabled ? Color::Text : Color::TextDisabled);
            c.Text(r.summary, {x, mid + f.F(1), textRight, top + rowH - f.F(7)}, Font::Caption, r.enabled ? Color::Text3 : Color::TextDisabled);
            c.Text(hits, {right - hitsW - f.F(8), top, right - f.F(8), top + rowH}, Font::Caption,
                   r.hits.packets && r.enabled ? Color::Text2 : Color::Text3, Align::Right);
        }

        // Default policy row
        const float top = f.F(4) + static_cast<float>(m_rows.size()) * rowH - m_scroll.offset;
        const float mid = top + rowH / 2;
        c.Line({f.F(12), top + f.F(4)}, {right - f.F(4), top + f.F(4)}, Color::CardStroke);
        c.Text(L"—", {f.F(62), top, f.F(84), top + rowH}, Font::Caption, Color::Text3, Align::Center);
        actionPill(m_policy, f.F(90), mid, false);
        c.Text(Text::Get(IDS_RULES_POLICY), {f.F(170), top + f.F(7), right * 0.6f, mid + f.F(1)}, Font::Strong, Color::Text);
        c.Text(Text::Get(m_rows.empty() ? IDS_RULES_POLICY_EMPTY : IDS_RULES_POLICY_NOTE),
               {f.F(170), mid + f.F(1), right * 0.75f, top + rowH - f.F(7)}, Font::Caption, Color::Text3);
        c.Text(m_active ? hitsText(m_policyHits) : Text::Get(IDS_RULES_OFF), {right * 0.6f, top, right - f.F(8), top + rowH},
               Font::Caption, Color::Text3, Align::Right);
        c.PopClip();
        m_scroll.Draw(c, client);
    });
}

}  // namespace WS::Ui
