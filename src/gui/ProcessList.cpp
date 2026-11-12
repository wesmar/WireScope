#include "gui/ProcessList.h"
#include "resources/resource.h"
#include "support/Common.h"
#include "support/Language.h"
#include <windowsx.h>
#include <algorithm>
#include <cmath>
#include <format>

namespace WS::Ui {
namespace {

constexpr wchar_t kClass[] = L"WireScope.ProcessList";

uint64_t Total(const ProcessRow& r) {
    return r.bytesIn + r.bytesOut;
}

}  // namespace

HWND ProcessList::Create(HWND parent, int id) {
    RegisterControlClass(kClass, Proc);
    m_hwnd = CreateWindowExW(0, kClass, L"Processes", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 10, 10, parent,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), this);
    return m_hwnd;
}

LRESULT CALLBACK ProcessList::Proc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* self = ControlFromWindow<ProcessList>(hwnd, message, lParam);
    if (message == WM_NCCREATE && self) self->m_hwnd = hwnd;
    if (message == WM_NCDESTROY) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        if (self) self->m_hwnd = nullptr;
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
    return self ? self->Handle(message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
}

void ProcessList::UpdateExtent() {
    RECT rc{};
    if (m_hwnd) GetClientRect(m_hwnd, &rc);
    m_scroll.view = std::max(0.0f, static_cast<float>(rc.bottom) - HeaderH());
    m_scroll.content = static_cast<float>(m_rows.size()) * RowH() + m_fonts.F(4);
    m_scroll.Clamp();
}

void ProcessList::SortRows() {
    auto key = [this](const ProcessRow& a, const ProcessRow& b) -> int {  // <0: a first in ascending order
        auto cmp = [](auto x, auto y) { return x < y ? -1 : x > y ? 1 : 0; };
        switch (m_sort) {
        case Sort::Name: return _wcsicmp(a.name.c_str(), b.name.c_str());
        case Sort::Pid: return cmp(a.pid, b.pid);
        case Sort::Download: return cmp(a.rateIn, b.rateIn);
        case Sort::Upload: return cmp(a.rateOut, b.rateOut);
        case Sort::Total: return cmp(Total(a), Total(b));
        case Sort::Sockets: return cmp(a.sockets, b.sockets);
        }
        return 0;
    };
    std::stable_sort(m_rows.begin(), m_rows.end(), [&](const ProcessRow& a, const ProcessRow& b) {
        if ((a.id == 0) != (b.id == 0)) return b.id == 0;  // traffic without a process stays last
        if (const int k = key(a, b); k != 0) return m_descending ? k > 0 : k < 0;
        if (Total(a) != Total(b)) return Total(a) > Total(b);
        if (const int n = _wcsicmp(a.name.c_str(), b.name.c_str()); n != 0) return n < 0;
        return a.id < b.id;
    });
}

void ProcessList::SetRows(std::vector<ProcessRow> rows) {
    m_rows = std::move(rows);
    Resort();
}

void ProcessList::Resort() {
    SortRows();
    m_selected = -1;
    if (m_hasSelection) {
        for (size_t i = 0; i < m_rows.size(); ++i) {
            if (m_rows[i].id == m_selectedId) m_selected = static_cast<int>(i);
        }
    }
    if (m_selected < 0 && m_hasSelection) {
        m_hasSelection = false;  // the process left the list
        Notify(LBN_SELCHANGE);
    }
    UpdateExtent();
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

void ProcessList::SetPlaceholder(std::wstring text) {
    if (text == m_placeholder) return;
    m_placeholder = std::move(text);
    if (m_hwnd && m_rows.empty()) InvalidateRect(m_hwnd, nullptr, FALSE);
}

const ProcessRow* ProcessList::Selected() const noexcept {
    return m_selected >= 0 && m_selected < static_cast<int>(m_rows.size()) ? &m_rows[static_cast<size_t>(m_selected)] : nullptr;
}

void ProcessList::Relayout() {
    UpdateExtent();
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

void ProcessList::Select(int index) {
    if (m_rows.empty()) return;
    index = std::clamp(index, 0, static_cast<int>(m_rows.size()) - 1);
    const bool changed = index != m_selected || !m_hasSelection;
    m_selected = index;
    m_selectedId = m_rows[static_cast<size_t>(index)].id;
    m_hasSelection = true;
    m_scroll.EnsureVisible(static_cast<float>(index) * RowH(), static_cast<float>(index + 1) * RowH());
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
    if (changed) Notify(LBN_SELCHANGE);
}

void ProcessList::Notify(WORD code) {
    if (m_hwnd) SendMessageW(GetParent(m_hwnd), WM_COMMAND, MAKEWPARAM(GetDlgCtrlID(m_hwnd), code), reinterpret_cast<LPARAM>(m_hwnd));
}

ProcessList::Columns ProcessList::Layout(float width) const {
    const auto& f = m_fonts;
    Columns c{};
    c.right = width - (m_scroll.Visible() ? f.F(14) : f.F(8));
    c.sockets = c.right - f.F(64);
    c.total = c.sockets - f.F(100);
    c.up = c.total - f.F(96);
    c.down = c.up - f.F(96);
    c.pid = c.down - f.F(64);
    c.mark = f.F(8);
    c.name = f.F(38);
    return c;
}

int ProcessList::RowAt(POINT p) const {
    const float y = static_cast<float>(p.y) - HeaderH();
    if (y < 0) return -1;
    const int row = static_cast<int>(std::floor((y + m_scroll.offset) / RowH()));
    return row >= 0 && row < static_cast<int>(m_rows.size()) ? row : -1;
}

std::optional<ProcessList::Sort> ProcessList::HeaderAt(POINT p) const {
    if (static_cast<float>(p.y) >= HeaderH()) return std::nullopt;
    RECT client{};
    GetClientRect(m_hwnd, &client);
    const Columns c = Layout(static_cast<float>(client.right));
    const float x = static_cast<float>(p.x);
    if (x < c.name) return std::nullopt;
    if (x < c.pid) return Sort::Name;
    if (x < c.down) return Sort::Pid;
    if (x < c.up) return Sort::Download;
    if (x < c.total) return Sort::Upload;
    if (x < c.sockets) return Sort::Total;
    if (x < c.right) return Sort::Sockets;
    return std::nullopt;
}

LRESULT ProcessList::Handle(UINT message, WPARAM wParam, LPARAM lParam) {
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
        return DLGC_WANTARROWS;
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
        InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    case WM_KEYDOWN: {
        const int page = std::max(1, static_cast<int>(m_scroll.view / RowH()) - 1);
        switch (wParam) {
        case VK_UP: Select(m_selected < 0 ? 0 : m_selected - 1); return 0;
        case VK_DOWN: Select(m_selected + 1); return 0;
        case VK_PRIOR: Select(m_selected - page); return 0;
        case VK_NEXT: Select(m_selected < 0 ? 0 : m_selected + page); return 0;
        case VK_HOME: Select(0); return 0;
        case VK_END: Select(static_cast<int>(m_rows.size()) - 1); return 0;
        case VK_RETURN: if (m_selected >= 0) Notify(LBN_DBLCLK); return 0;
        }
        break;
    }
    case WM_LBUTTONDOWN:
    case WM_LBUTTONDBLCLK:
    case WM_RBUTTONDOWN: {
        SetFocus(m_hwnd);
        const POINT p{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        if (message != WM_RBUTTONDOWN && m_scroll.MouseDown(p, client, m_fonts, HeaderH())) {
            SetCapture(m_hwnd);
            InvalidateRect(m_hwnd, nullptr, FALSE);
            return 0;
        }
        if (message == WM_LBUTTONDOWN) {
            if (const auto sort = HeaderAt(p)) {
                if (*sort == m_sort) {
                    m_descending = !m_descending;
                } else {
                    m_sort = *sort;
                    m_descending = *sort != Sort::Name && *sort != Sort::Pid;  // biggest first, names A to Z
                }
                Resort();
                if (m_selected >= 0) m_scroll.EnsureVisible(static_cast<float>(m_selected) * RowH(), static_cast<float>(m_selected + 1) * RowH());
                return 0;
            }
        }
        const int row = RowAt(p);
        if (row < 0) return 0;
        Select(row);
        if (message == WM_LBUTTONDBLCLK) Notify(LBN_DBLCLK);
        return 0;
    }
    case WM_MOUSEMOVE: {
        const POINT p{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        if (!m_tracking) {
            TRACKMOUSEEVENT tme{sizeof tme, TME_LEAVE, m_hwnd, 0};
            m_tracking = TrackMouseEvent(&tme) != FALSE;
        }
        bool repaint = m_scroll.MouseMove(p, client, m_fonts, HeaderH());
        const int hot = m_scroll.dragging || m_scroll.hot ? -1 : RowAt(p);
        if (hot != m_hot) {
            m_hot = hot;
            repaint = true;
        }
        if (repaint) InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_SETCURSOR:
        if (LOWORD(lParam) == HTCLIENT) {
            POINT p{};
            GetCursorPos(&p);
            ScreenToClient(m_hwnd, &p);
            SetCursor(LoadCursorW(nullptr, HeaderAt(p) ? IDC_HAND : IDC_ARROW));
            return TRUE;
        }
        break;
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

void ProcessList::Paint() {
    PaintScope ps(m_hwnd);
    RECT client{};
    GetClientRect(m_hwnd, &client);
    const auto& f = m_fonts;
    const bool focused = GetFocus() == m_hwnd;
    UpdateExtent();
    Ui::Paint(ps.dc(), client, f, [&](Canvas& c) {
        c.Clear(Graphics::Get().Surface(Color::Card));
        const float width = static_cast<float>(client.right);
        const Columns col = Layout(width);
        const float headerH = HeaderH();

        // Header: the sorted column is brighter and carries the direction.
        struct Head {
            UINT text;
            Sort sort;
            float left, right;
            Align align;
        };
        const Head heads[] = {
            {IDS_PROC_COL_PROGRAM, Sort::Name, col.name, col.pid - f.F(8), Align::Left},
            {IDS_PROC_COL_PID, Sort::Pid, col.pid, col.down - f.F(8), Align::Right},
            {IDS_PROC_COL_DOWN, Sort::Download, col.down, col.up - f.F(8), Align::Right},
            {IDS_PROC_COL_UP, Sort::Upload, col.up, col.total - f.F(8), Align::Right},
            {IDS_PROC_COL_TOTAL, Sort::Total, col.total, col.sockets - f.F(8), Align::Right},
            {IDS_PROC_COL_SOCKETS, Sort::Sockets, col.sockets, col.right - f.F(4), Align::Right},
        };
        for (const Head& h : heads) {
            const bool sorted = h.sort == m_sort;
            float right = h.right;
            if (sorted) {
                const wchar_t arrow = m_descending ? Icon::ChevronDown : Icon::Up;
                if (h.align == Align::Right) {
                    c.Text(std::wstring(1, arrow), {right - f.F(12), 0, right, headerH}, Font::IconSmall, Color::AccentText, Align::Center);
                    right -= f.F(16);
                } else {
                    const float w = c.Width(Text::Get(h.text), Font::Label);
                    c.Text(std::wstring(1, arrow), {h.left + w + f.F(4), 0, h.left + w + f.F(16), headerH}, Font::IconSmall, Color::AccentText,
                           Align::Center);
                }
            }
            c.Text(Text::Get(h.text), {h.left, 0, right, headerH}, Font::Label, sorted ? Color::Text2 : Color::Text3, h.align);
        }
        c.Line({f.F(6), headerH - 0.5f}, {width - f.F(6), headerH - 0.5f}, Color::CardStroke);

        if (m_rows.empty()) {
            c.Text(m_placeholder, {f.F(16), headerH, width - f.F(16), static_cast<float>(client.bottom)}, Font::Body, Color::Text3, Align::Center);
            return;
        }

        double maxIn = 1, maxOut = 1;  // scale of the rate bars: the busiest row fills its column
        for (const auto& r : m_rows) {
            maxIn = std::max(maxIn, r.rateIn);
            maxOut = std::max(maxOut, r.rateOut);
        }
        const float rowH = RowH();
        c.PushClip({0, headerH, width, static_cast<float>(client.bottom)});
        const int first = static_cast<int>(std::floor(m_scroll.offset / rowH));
        const int last = std::min(static_cast<int>(m_rows.size()) - 1, static_cast<int>((m_scroll.offset + m_scroll.view) / rowH) + 1);
        for (int i = std::max(first, 0); i <= last; ++i) {
            const ProcessRow& r = m_rows[static_cast<size_t>(i)];
            const float top = headerH + static_cast<float>(i) * rowH - m_scroll.offset;
            const float bottom = top + rowH, mid = top + rowH / 2;
            const D2D1_RECT_F box{f.F(4), top + f.F(1), col.right + f.F(4), bottom - f.F(1)};
            if (i == m_selected) {
                c.Fill(box, Color::Selected, f.F(4));
                c.Fill({box.left + f.F(1), mid - f.F(8), box.left + f.F(4), mid + f.F(8)}, Color::AccentText, f.F(1.5f));
                if (focused) c.Stroke(box, White(0.18f), f.F(4));
            } else if (i == m_hot) {
                c.Fill(box, Color::Hover, f.F(4));
            }
            const bool dim = !r.running || r.id == 0;

            // Mark: a warning for suspicious programs, a dot for unsigned ones.
            const D2D1_RECT_F mark{col.mark + f.F(4), top, col.name - f.F(4), bottom};
            if (r.risk == Risk::High) {
                c.Text(std::wstring(1, Icon::Warning), mark, Font::Icon, Color::Critical, Align::Center);
            } else if (r.risk == Risk::Notice) {
                c.Circle({(mark.left + mark.right) / 2, mid}, f.F(3.5f), Color::Caution);
            }

            // Name, a status pill, the path below.
            const std::wstring name = r.id == 0 ? Text::Get(IDS_PROC_NO_PROCESS) : r.name;
            const float nameRight = col.pid - f.F(12);
            const float nameW = std::min(c.Width(name, Font::Strong) + 1, nameRight - col.name);
            c.Text(name, {col.name, top + f.F(6), col.name + nameW, mid + f.F(1)}, Font::Strong, dim ? Color::Text2 : Color::Text);
            UINT pill = 0;
            D2D1_COLOR_F pillColor = Color::Text3;
            if (!r.running) {
                pill = IDS_PROC_EXITED;
            } else if (r.risk == Risk::High) {
                pill = IDS_PILL_SUSPICIOUS;
                pillColor = Color::Critical;
            } else if (r.signature == Signature::Unsigned) {
                pill = IDS_PILL_UNSIGNED;
                pillColor = Color::Caution;
            }
            if (pill) {
                const std::wstring text = Text::Get(pill);
                const float x = col.name + nameW + f.F(8);
                const float w = c.Width(text, Font::Label) + f.F(12);
                if (x + w <= nameRight) {
                    const D2D1_RECT_F p{x, top + f.F(9), x + w, mid - f.F(1)};
                    c.Fill(p, WithAlpha(pillColor, 0.16f), f.F(3));
                    c.Text(text, p, Font::Label, pillColor, Align::Center);
                }
            }
            const std::wstring detail = r.id == 0 ? Text::Get(IDS_PROC_NO_PROCESS_NOTE) : r.path;
            c.Text(detail, {col.name, mid + f.F(1), nameRight, bottom - f.F(6)}, Font::Caption, Color::Text3);

            // Numbers
            auto number = [&](const std::wstring& text, float left, float right, bool strong) {
                c.Text(text, {left, top, right, bottom}, Font::Body, strong ? Color::Text : Color::Text3, Align::Right);
            };
            number(r.id == 0 ? std::wstring(L"—") : std::to_wstring(r.pid), col.pid, col.down - f.F(8), false);
            auto rate = [&](double value, double peak, float left, float right, D2D1_COLOR_F color) {
                if (!r.counted) {
                    number(L"—", left, right, false);
                    return;
                }
                number(value >= 1 ? FormatRate(value) : std::wstring(L"0"), left, right, value >= 1);
                // Share of the busiest row (square root: quiet programs stay visible next to a download).
                const float w = (right - left) * static_cast<float>(std::sqrt(value / peak));
                if (w >= f.F(3)) c.Fill({right - w, bottom - f.F(7), right, bottom - f.F(5)}, WithAlpha(color, 0.7f), f.F(1));
            };
            rate(r.rateIn, maxIn, col.down, col.up - f.F(8), Color::Success);
            rate(r.rateOut, maxOut, col.up, col.total - f.F(8), Color::AccentText);
            number(r.counted ? FormatBytes(Total(r)) : std::wstring(L"—"), col.total, col.sockets - f.F(8), r.counted && Total(r) > 0);
            number(r.id == 0 ? std::wstring(L"—") : std::to_wstring(r.sockets), col.sockets, col.right - f.F(4), r.sockets > 0);
        }
        c.PopClip();
        m_scroll.Draw(c, client, headerH);
    });
}

}  // namespace WS::Ui
