// WireScope - Controls drawn with the Direct2D canvas: owner-drawn buttons (push, accent, combo,
// navigation, toggle switch, segment, kill switch), a slider and the shared scroll bar. All of them
// are real child windows, so Tab, focus and keyboard work as usual.
#pragma once
#include "gui/Theme.h"
#include <Windows.h>
#include <functional>
#include <string>

namespace WS::Ui {

// ---------------------------------------------------------------------------
// Buttons (BS_OWNERDRAW, drawn from the parent's WM_DRAWITEM)
// ---------------------------------------------------------------------------
enum class ButtonKind { Standard, Accent, Combo, Icon, Nav, Toggle, Segment, Danger };

struct ButtonLook {
    ButtonKind kind = ButtonKind::Standard;
    wchar_t icon = 0;        // Segoe Fluent Icons code point
    bool onCard = false;     // sits on a card layer (else directly on the window background)
    bool checked = false;    // Nav: current page, Toggle: on, Segment: chosen, Danger: engaged
    std::wstring badge;      // Nav: small pill after the label
    bool alert = false;      // Nav: the badge asks for attention (critical colour)
};

HWND CreateButton(HWND parent, int id, const wchar_t* text);
void DrawButton(const DRAWITEMSTRUCT& dis, const Fonts& fonts, const ButtonLook& look);

// Common icon code points (Segoe Fluent Icons / Segoe MDL2 Assets).
namespace Icon {
inline constexpr wchar_t ChevronDown = 0xE70D, ChevronRight = 0xE76C, ArrowUp = 0xE74A, ArrowDown = 0xE74B;
inline constexpr wchar_t Delete = 0xE74D, Add = 0xE710, Edit = 0xE70F, Play = 0xE768, Stop = 0xE71A;
inline constexpr wchar_t Save = 0xE74E, Clear = 0xE894, Search = 0xE721, Shield = 0xEA18, Network = 0xE968;
inline constexpr wchar_t Speed = 0xEC4A, Power = 0xE7E8, Refresh = 0xE72C, Import = 0xE8B5, Export = 0xEDE1;
inline constexpr wchar_t Info = 0xE946, Check = 0xE73E, Warning = 0xE7BA, Globe = 0xE774, Filter = 0xE71C;
inline constexpr wchar_t Up = 0xE70E, Down = 0xE70D, Admin = 0xE7EF, Language = 0xF2B7;
inline constexpr wchar_t Apps = 0xE71D, Blocked = 0xE733, Folder = 0xE8B7, Copy = 0xE8C8, Repair = 0xE90F;
}  // namespace Icon

// ---------------------------------------------------------------------------
// Vertical scrolling shared by the lists.
// ---------------------------------------------------------------------------
struct Scroller {
    float offset = 0, content = 0, view = 0;
    bool dragging = false, hot = false;
    float grabY = 0, grabOffset = 0;

    [[nodiscard]] float Max() const { return content > view ? content - view : 0; }
    [[nodiscard]] bool Visible() const { return content > view + 0.5f; }
    [[nodiscard]] bool AtEnd() const { return offset >= Max() - 1.0f; }
    void Clamp();
    void ScrollTo(float y) { offset = y; Clamp(); }
    void EnsureVisible(float top, float bottom);
    [[nodiscard]] D2D1_RECT_F Track(const RECT& client, const Fonts& f, float top = 0) const;
    [[nodiscard]] D2D1_RECT_F Thumb(const RECT& client, const Fonts& f, float top = 0) const;
    void Draw(Canvas& c, const RECT& client, float top = 0) const;
    bool MouseDown(POINT p, const RECT& client, const Fonts& f, float top = 0);  // true = handled (capture)
    bool MouseMove(POINT p, const RECT& client, const Fonts& f, float top = 0);  // true = repaint needed
    bool Wheel(int delta, float step);                                          // true = offset changed
};

float WheelStep(const Fonts& f, float rowHeight);

// ---------------------------------------------------------------------------
// Slider: value in [min, max] snapped to `step`. `gamma` > 1 gives the low end more travel
// (position = ((value - min) / (max - min)) ^ (1 / gamma)). Notifies the parent with
// WM_COMMAND(id, SliderChanged) while the value changes.
// ---------------------------------------------------------------------------
inline constexpr WORD SliderChanged = 0x0100;

class Slider {
public:
    explicit Slider(const Fonts& fonts) : m_fonts(fonts) {}
    Slider(const Slider&) = delete;
    Slider& operator=(const Slider&) = delete;

    HWND Create(HWND parent, int id, double min, double max, double step, double gamma);
    [[nodiscard]] HWND hwnd() const noexcept { return m_hwnd; }
    [[nodiscard]] double Value() const noexcept { return m_value; }
    void SetValue(double value, bool notify = false);
    void SetOnCard(bool onCard) { m_onCard = onCard; }

private:
    static LRESULT CALLBACK Proc(HWND, UINT, WPARAM, LPARAM);
    LRESULT Handle(UINT, WPARAM, LPARAM);
    void Paint();
    [[nodiscard]] double Position() const;          // 0..1
    [[nodiscard]] double FromPosition(double t) const;
    [[nodiscard]] D2D1_RECT_F TrackRect() const;
    void SetFromX(int x);

    const Fonts& m_fonts;
    HWND m_hwnd = nullptr;
    double m_min = 0, m_max = 1, m_step = 1, m_gamma = 1, m_value = 0;
    bool m_dragging = false, m_hot = false, m_tracking = false, m_onCard = true;
};

// ---------------------------------------------------------------------------
// Helpers for the custom controls
// ---------------------------------------------------------------------------
void RegisterControlClass(const wchar_t* name, WNDPROC proc);

template <class T>
T* ControlFromWindow(HWND hwnd, UINT message, LPARAM lParam) {
    if (message == WM_NCCREATE) {
        auto* self = static_cast<T*>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        return self;
    }
    return reinterpret_cast<T*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// Copies text to the clipboard (CF_UNICODETEXT).
bool CopyToClipboard(HWND owner, const std::wstring& text);

}  // namespace WS::Ui
