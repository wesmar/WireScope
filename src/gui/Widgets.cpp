#include "gui/Widgets.h"
#include <CommCtrl.h>
#include <windowsx.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <memory>

#pragma comment(lib, "comctl32.lib")

namespace WS::Ui {
namespace {

HINSTANCE Instance() { return GetModuleHandleW(nullptr); }

// Button hover tracking. Only one control can be under the mouse, so one HWND is enough.
HWND g_hotButton = nullptr;

LRESULT CALLBACK ButtonProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam, UINT_PTR id, DWORD_PTR) {
    switch (message) {
    case WM_MOUSEMOVE:
        if (g_hotButton != hwnd) {
            if (HWND old = std::exchange(g_hotButton, hwnd)) InvalidateRect(old, nullptr, FALSE);
            TRACKMOUSEEVENT tme{sizeof tme, TME_LEAVE, hwnd, 0};
            TrackMouseEvent(&tme);
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        break;
    case WM_MOUSELEAVE:
        if (g_hotButton == hwnd) {
            g_hotButton = nullptr;
            InvalidateRect(hwnd, nullptr, FALSE);
        }
        break;
    case WM_LBUTTONDBLCLK:
        // Owner-drawn buttons turn a quick second click into BN_DOUBLECLICKED; treat it as a click.
        return DefSubclassProc(hwnd, WM_LBUTTONDOWN, wParam, lParam);
    case WM_ERASEBKGND:
        return 1;
    case WM_ENABLE:
        if (!wParam && g_hotButton == hwnd) g_hotButton = nullptr;
        break;
    case WM_NCDESTROY:
        if (g_hotButton == hwnd) g_hotButton = nullptr;
        RemoveWindowSubclass(hwnd, ButtonProc, id);
        break;
    }
    return DefSubclassProc(hwnd, message, wParam, lParam);
}

}  // namespace

float WheelStep(const Fonts& f, float rowHeight) {
    UINT lines = 3;
    SystemParametersInfoW(SPI_GETWHEELSCROLLLINES, 0, &lines, 0);
    if (lines == WHEEL_PAGESCROLL) lines = 10;
    return std::max(rowHeight, f.F(18)) * static_cast<float>(std::max(lines, 1u));
}

void RegisterControlClass(const wchar_t* name, WNDPROC proc) {
    WNDCLASSEXW wc{sizeof wc};
    if (GetClassInfoExW(Instance(), name, &wc)) return;
    wc.style = CS_DBLCLKS;
    wc.lpfnWndProc = proc;
    wc.hInstance = Instance();
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = name;
    RegisterClassExW(&wc);
}

// ---------------------------------------------------------------------------
// Buttons
// ---------------------------------------------------------------------------
HWND CreateButton(HWND parent, int id, const wchar_t* text) {
    HWND b = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW, 0, 0, 10, 10, parent,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), Instance(), nullptr);
    if (b) SetWindowSubclass(b, ButtonProc, 1, 0);
    return b;
}

void DrawButton(const DRAWITEMSTRUCT& dis, const Fonts& f, const ButtonLook& look) {
    const bool disabled = dis.itemState & ODS_DISABLED;
    const bool pressed = (dis.itemState & ODS_SELECTED) && !disabled;
    const bool focus = (dis.itemState & ODS_FOCUS) && !(dis.itemState & ODS_NOFOCUSRECT);
    const bool hot = g_hotButton == dis.hwndItem && !disabled;
    wchar_t label[200]{};
    GetWindowTextW(dis.hwndItem, label, static_cast<int>(std::size(label)));
    const std::wstring_view text(label);
    auto& g = Graphics::Get();

    Paint(dis.hDC, dis.rcItem, f, [&](Canvas& c) {
        const D2D1_RECT_F r = ToF(dis.rcItem);
        c.Clear(look.onCard ? g.Surface(Color::Card) : g.Base());
        const float radius = f.F(4);
        D2D1_COLOR_F fg = disabled ? Color::TextDisabled : pressed ? Color::Text2 : Color::Text;
        const std::wstring icon = look.icon ? std::wstring(1, look.icon) : std::wstring();

        // Icon + label centred as one group (Standard, Accent, Danger, Segment).
        auto iconAndLabel = [&](D2D1_COLOR_F iconColor, D2D1_COLOR_F textColor, Font font) {
            const float pad = f.F(10);
            const float iconW = look.icon ? f.F(16) + (text.empty() ? 0 : f.F(8)) : 0;
            const float tw = std::min(c.Width(text, font), std::max(0.0f, r.right - r.left - 2 * pad - iconW));
            float x = r.left + (r.right - r.left - iconW - tw) / 2;
            if (look.icon) {
                c.Text(icon, {x, r.top, x + f.F(16), r.bottom}, Font::Icon, iconColor, Align::Center);
                x += iconW;
            }
            if (!text.empty()) c.Text(text, {x, r.top, x + tw + 1, r.bottom}, font, textColor);
        };

        switch (look.kind) {
        case ButtonKind::Accent: {
            const D2D1_COLOR_F fill = disabled ? Color::ControlDisabled : pressed ? Color::AccentPressed : hot ? Color::AccentHot : Color::Accent;
            c.Fill(r, fill, radius);
            if (disabled) c.Stroke(r, Color::ControlStroke, radius);
            else fg = pressed ? White(0.8f) : Color::Text;
            iconAndLabel(fg, fg, Font::Body);
            break;
        }
        case ButtonKind::Danger: {
            D2D1_COLOR_F fill = look.checked ? (hot ? Color::DangerHot : Color::Danger)
                                : disabled ? Color::ControlDisabled
                                : pressed ? Color::ControlPressed
                                : hot     ? Color::ControlHot
                                          : Color::Control;
            c.Fill(r, fill, radius);
            if (!look.checked) c.Stroke(r, WithAlpha(Color::Critical, disabled ? 0.15f : 0.35f), radius);
            const D2D1_COLOR_F ink = disabled ? Color::TextDisabled : look.checked ? Color::Text : Color::Critical;
            iconAndLabel(ink, look.checked ? Color::Text : fg, Font::Strong);
            break;
        }
        case ButtonKind::Icon:
            if (hot || pressed) c.Fill(r, pressed ? Color::ControlPressed : Color::Hover, radius);
            c.Text(icon, r, Font::Icon, fg, Align::Center);
            break;
        case ButtonKind::Nav: {
            if (look.checked || hot || pressed) c.Fill(Inset(r, 0, f.F(1)), look.checked ? Color::Selected : pressed ? Color::ControlPressed : Color::Hover, radius);
            if (look.checked) {
                const float mid = (r.top + r.bottom) / 2;
                c.Fill({r.left + f.F(1), mid - f.F(8), r.left + f.F(4), mid + f.F(8)}, Color::AccentText, f.F(1.5f));
            }
            const float x = r.left + f.F(14);
            c.Text(icon, {x, r.top, x + f.F(18), r.bottom}, Font::Icon, look.checked ? Color::AccentText : Color::Text2, Align::Center);
            const float tx = x + f.F(30);
            const float tw = c.Width(text, Font::Body);
            c.Text(text, {tx, r.top, r.right - f.F(8), r.bottom}, Font::Body, disabled ? Color::TextDisabled : Color::Text);
            if (!look.badge.empty()) {
                const float bw = c.Width(look.badge, Font::Label) + f.F(12);
                const float bx = std::min(tx + tw + f.F(8), r.right - f.F(8) - bw);
                const D2D1_RECT_F b{bx, r.top + f.F(9), bx + bw, r.bottom - f.F(9)};
                const D2D1_COLOR_F ink = look.alert ? Color::Critical : Color::AccentText;
                c.Fill(b, WithAlpha(ink, 0.16f), (b.bottom - b.top) / 2);
                c.Text(look.badge, b, Font::Label, ink, Align::Center);
            }
            break;
        }
        case ButtonKind::Toggle: {
            // Windows 11 toggle switch with its label to the right.
            const float h = f.F(20), w = f.F(40);
            const float top = (r.top + r.bottom - h) / 2;
            const D2D1_RECT_F pill{r.left + f.F(2), top, r.left + f.F(2) + w, top + h};
            if (look.checked) {
                c.Fill(pill, disabled ? Color::ControlDisabled : hot ? Color::AccentHot : Color::Accent, h / 2);
            } else {
                c.Fill(pill, hot ? Color::ControlHot : Color::Control, h / 2);
                c.Stroke(pill, disabled ? Color::TextDisabled : Color::Text3, h / 2, f.F(1));
            }
            const float knob = (hot || pressed) ? f.F(7) : f.F(6);
            const float kx = look.checked ? pill.right - h / 2 : pill.left + h / 2;
            c.Circle({kx, (pill.top + pill.bottom) / 2}, knob, disabled ? Color::TextDisabled : look.checked ? Color::Text : Color::Text2);
            c.Text(text, {pill.right + f.F(10), r.top, r.right, r.bottom}, Font::Body, disabled ? Color::TextDisabled : Color::Text);
            if (focus) c.Stroke(Inset(pill, -f.F(3), -f.F(3)), Color::Text, (h + f.F(6)) / 2, f.F(1.5f));
            return;
        }
        case ButtonKind::Segment: {
            const D2D1_COLOR_F fill = look.checked ? WithAlpha(Color::AccentText, 0.14f)
                                      : pressed    ? Color::ControlPressed
                                      : hot        ? Color::ControlHot
                                                   : Color::Control;
            c.Fill(r, fill, radius);
            c.Stroke(r, look.checked ? WithAlpha(Color::AccentText, 0.55f) : Color::ControlStroke, radius);
            const D2D1_COLOR_F ink = disabled ? Color::TextDisabled : look.checked ? Color::AccentText : Color::Text2;
            iconAndLabel(ink, look.checked ? Color::Text : fg, Font::Body);
            break;
        }
        case ButtonKind::Combo: {
            c.Fill(r, disabled ? Color::ControlDisabled : pressed ? Color::ControlPressed : hot ? Color::ControlHot : Color::Control, radius);
            c.Stroke(r, Color::ControlStroke, radius);
            float x = r.left + f.F(10);
            if (look.icon) {
                c.Text(icon, {x, r.top, x + f.F(16), r.bottom}, Font::Icon, disabled ? Color::TextDisabled : Color::Text2, Align::Center);
                x += f.F(24);
            }
            c.Text(text, {x, r.top, r.right - f.F(30), r.bottom}, Font::Body, fg);
            c.Text(std::wstring(1, Icon::ChevronDown), {r.right - f.F(28), r.top, r.right - f.F(8), r.bottom}, Font::IconSmall,
                   disabled ? Color::TextDisabled : Color::Text2, Align::Center);
            break;
        }
        case ButtonKind::Standard:
            c.Fill(r, disabled ? Color::ControlDisabled : pressed ? Color::ControlPressed : hot ? Color::ControlHot : Color::Control, radius);
            c.Stroke(r, Color::ControlStroke, radius);
            iconAndLabel(disabled ? Color::TextDisabled : Color::Text2, fg, Font::Body);
            break;
        }
        if (focus) c.Stroke(r, Color::Text, radius, f.F(1.5f));
    });
}

// ---------------------------------------------------------------------------
// Scroller
// ---------------------------------------------------------------------------
void Scroller::Clamp() { offset = std::clamp(offset, 0.0f, Max()); }

void Scroller::EnsureVisible(float top, float bottom) {
    if (top < offset) offset = top;
    else if (bottom > offset + view) offset = bottom - view;
    Clamp();
}

D2D1_RECT_F Scroller::Track(const RECT& client, const Fonts& f, float top) const {
    return {static_cast<float>(client.right) - f.F(9), static_cast<float>(client.top) + top + f.F(3),
            static_cast<float>(client.right) - f.F(2), static_cast<float>(client.bottom) - f.F(3)};
}

D2D1_RECT_F Scroller::Thumb(const RECT& client, const Fonts& f, float top) const {
    const D2D1_RECT_F t = Track(client, f, top);
    const float h = t.bottom - t.top;
    const float thumb = std::max(f.F(24), h * (content > 0 ? view / content : 1.0f));
    const float y = t.top + (Max() > 0 ? (h - thumb) * offset / Max() : 0);
    return {t.left, y, t.right, y + thumb};
}

void Scroller::Draw(Canvas& c, const RECT& client, float top) const {
    if (!Visible()) return;
    const auto& f = c.fonts();
    D2D1_RECT_F t = Thumb(client, f, top);
    const float w = (hot || dragging) ? f.F(6) : f.F(3);
    t.left = t.right - w;
    c.Fill(t, White(hot || dragging ? 0.50f : 0.30f), w / 2);
}

bool Scroller::MouseDown(POINT p, const RECT& client, const Fonts& f, float top) {
    if (!Visible()) return false;
    const D2D1_RECT_F t = Track(client, f, top);
    if (static_cast<float>(p.x) < t.left - f.F(3) || static_cast<float>(p.y) < t.top) return false;
    const D2D1_RECT_F thumb = Thumb(client, f, top);
    const float y = static_cast<float>(p.y);
    if (y < thumb.top) offset -= view;
    else if (y > thumb.bottom) offset += view;
    Clamp();
    dragging = true;
    grabY = y;
    grabOffset = offset;
    return true;
}

bool Scroller::MouseMove(POINT p, const RECT& client, const Fonts& f, float top) {
    if (dragging) {
        const D2D1_RECT_F t = Track(client, f, top), thumb = Thumb(client, f, top);
        const float range = (t.bottom - t.top) - (thumb.bottom - thumb.top);
        const float before = offset;
        if (range > 0) offset = grabOffset + (static_cast<float>(p.y) - grabY) * Max() / range;
        Clamp();
        return offset != before;
    }
    const bool now = Visible() && static_cast<float>(p.x) >= Track(client, f, top).left - f.F(3);
    if (now == hot) return false;
    hot = now;
    return true;
}

bool Scroller::Wheel(int delta, float step) {
    const float before = offset;
    offset -= static_cast<float>(delta) / WHEEL_DELTA * step;
    Clamp();
    return offset != before;
}

// ---------------------------------------------------------------------------
// Slider
// ---------------------------------------------------------------------------
namespace {
constexpr wchar_t kSliderClass[] = L"WireScope.Slider";
}

HWND Slider::Create(HWND parent, int id, double min, double max, double step, double gamma) {
    m_min = min;
    m_max = max;
    m_step = step;
    m_gamma = gamma;
    m_value = min;
    RegisterControlClass(kSliderClass, Proc);
    m_hwnd = CreateWindowExW(0, kSliderClass, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 10, 10, parent,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), Instance(), this);
    return m_hwnd;
}

LRESULT CALLBACK Slider::Proc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* self = ControlFromWindow<Slider>(hwnd, message, lParam);
    if (message == WM_NCCREATE && self) self->m_hwnd = hwnd;
    if (message == WM_NCDESTROY) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        if (self) self->m_hwnd = nullptr;
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
    return self ? self->Handle(message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
}

double Slider::Position() const {
    if (m_max <= m_min) return 0;
    const double linear = std::clamp((m_value - m_min) / (m_max - m_min), 0.0, 1.0);
    return std::pow(linear, 1.0 / m_gamma);
}

double Slider::FromPosition(double t) const {
    return m_min + (m_max - m_min) * std::pow(std::clamp(t, 0.0, 1.0), m_gamma);
}

D2D1_RECT_F Slider::TrackRect() const {
    RECT rc{};
    GetClientRect(m_hwnd, &rc);
    const float pad = m_fonts.F(10);
    return {static_cast<float>(rc.left) + pad, static_cast<float>(rc.top), static_cast<float>(rc.right) - pad, static_cast<float>(rc.bottom)};
}

void Slider::SetValue(double value, bool notify) {
    value = std::clamp(value, m_min, m_max);
    if (m_step > 0) value = m_min + std::round((value - m_min) / m_step) * m_step;
    value = std::clamp(value, m_min, m_max);
    if (value == m_value) return;
    m_value = value;
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
    if (notify && m_hwnd) {
        SendMessageW(GetParent(m_hwnd), WM_COMMAND, MAKEWPARAM(GetDlgCtrlID(m_hwnd), SliderChanged), reinterpret_cast<LPARAM>(m_hwnd));
    }
}

void Slider::SetFromX(int x) {
    const D2D1_RECT_F t = TrackRect();
    const double pos = (static_cast<double>(x) - t.left) / std::max(1.0f, t.right - t.left);
    SetValue(FromPosition(pos), true);
}

void Slider::Paint() {
    PaintScope ps(m_hwnd);
    RECT client{};
    GetClientRect(m_hwnd, &client);
    const auto& f = m_fonts;
    const bool enabled = IsWindowEnabled(m_hwnd);
    Ui::Paint(ps.dc(), client, f, [&](Canvas& c) {
        c.Clear(m_onCard ? Graphics::Get().Surface(Color::Card) : Graphics::Get().Base());
        const D2D1_RECT_F t = TrackRect();
        const float mid = (t.top + t.bottom) / 2;
        const float x = t.left + static_cast<float>(Position()) * (t.right - t.left);
        c.Fill({t.left, mid - f.F(2), t.right, mid + f.F(2)}, Color::Track, f.F(2));
        c.Fill({t.left, mid - f.F(2), x, mid + f.F(2)}, enabled ? Color::AccentText : Color::TextDisabled, f.F(2));
        // Thumb: ring + accent centre that grows under the mouse (Windows 11 slider).
        c.Circle({x, mid}, f.F(10), Rgb(0x454545));
        c.Circle({x, mid}, f.F(9), Rgb(0x2D2D2D));
        c.Circle({x, mid}, (m_hot || m_dragging) ? f.F(6.5f) : f.F(5), enabled ? Color::AccentText : Color::TextDisabled);
        if (GetFocus() == m_hwnd) c.Stroke({x - f.F(13), mid - f.F(13), x + f.F(13), mid + f.F(13)}, Color::Text, f.F(13), f.F(1.5f));
    });
}

LRESULT Slider::Handle(UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        Paint();
        return 0;
    case WM_SIZE:
    case WM_ENABLE:
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
        InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    case WM_GETDLGCODE:
        return DLGC_WANTARROWS;
    case WM_KEYDOWN: {
        const double big = std::max(m_step * 10, (m_max - m_min) / 20);
        switch (wParam) {
        case VK_LEFT: case VK_DOWN: SetValue(m_value - m_step, true); return 0;
        case VK_RIGHT: case VK_UP: SetValue(m_value + m_step, true); return 0;
        case VK_PRIOR: SetValue(m_value + big, true); return 0;
        case VK_NEXT: SetValue(m_value - big, true); return 0;
        case VK_HOME: SetValue(m_min, true); return 0;
        case VK_END: SetValue(m_max, true); return 0;
        }
        break;
    }
    case WM_LBUTTONDOWN:
        SetFocus(m_hwnd);
        SetCapture(m_hwnd);
        m_dragging = true;
        SetFromX(GET_X_LPARAM(lParam));
        return 0;
    case WM_MOUSEMOVE:
        if (!m_tracking) {
            TRACKMOUSEEVENT tme{sizeof tme, TME_LEAVE, m_hwnd, 0};
            m_tracking = TrackMouseEvent(&tme) != FALSE;
        }
        if (!m_hot) {
            m_hot = true;
            InvalidateRect(m_hwnd, nullptr, FALSE);
        }
        if (m_dragging) SetFromX(GET_X_LPARAM(lParam));
        return 0;
    case WM_MOUSELEAVE:
        m_tracking = false;
        m_hot = false;
        InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    case WM_LBUTTONUP:
        if (m_dragging) {
            m_dragging = false;
            ReleaseCapture();
            InvalidateRect(m_hwnd, nullptr, FALSE);
        }
        return 0;
    case WM_CAPTURECHANGED:
        m_dragging = false;
        return 0;
    case WM_MOUSEWHEEL:
        SetValue(m_value + (GET_WHEEL_DELTA_WPARAM(wParam) > 0 ? m_step : -m_step), true);
        return 0;
    }
    return DefWindowProcW(m_hwnd, message, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------
bool CopyToClipboard(HWND owner, const std::wstring& text) {
    if (!OpenClipboard(owner)) return false;
    const ScopeExit close([] { CloseClipboard(); });
    EmptyClipboard();
    const std::size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    struct GlobalFreer {
        void operator()(void* h) const noexcept { GlobalFree(h); }
    };
    std::unique_ptr<void, GlobalFreer> memory(GlobalAlloc(GMEM_MOVEABLE, bytes));
    if (!memory) return false;
    if (void* p = GlobalLock(memory.get())) {
        std::memcpy(p, text.c_str(), bytes);
        GlobalUnlock(memory.get());
    } else {
        return false;
    }
    if (!SetClipboardData(CF_UNICODETEXT, memory.get())) return false;
    (void)memory.release();  // owned by the clipboard now
    return true;
}

}  // namespace WS::Ui
