#include "gui/PacketDetails.h"
#include "gui/PacketList.h"
#include "resources/resource.h"
#include "support/Language.h"
#include "support/Text.h"
#include <windowsx.h>
#include <algorithm>
#include <format>

namespace WS::Ui {
namespace {

constexpr wchar_t kClass[] = L"WireScope.PacketDetails";

std::wstring WallClock(uint64_t timestampUs) {
    const uint64_t ft = timestampUs * 10 + 116444736000000000ULL;  // Unix epoch -> FILETIME
    FILETIME utc{static_cast<DWORD>(ft), static_cast<DWORD>(ft >> 32)}, local{};
    SYSTEMTIME st{};
    FileTimeToLocalFileTime(&utc, &local);
    FileTimeToSystemTime(&local, &st);
    return std::format(L"{:02}:{:02}:{:02}.{:06}", st.wHour, st.wMinute, st.wSecond, timestampUs % 1'000'000);
}

}  // namespace

HWND PacketDetails::Create(HWND parent, int id) {
    RegisterControlClass(kClass, Proc);
    m_hwnd = CreateWindowExW(0, kClass, L"Packet details", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 10, 10, parent,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), this);
    return m_hwnd;
}

LRESULT CALLBACK PacketDetails::Proc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* self = ControlFromWindow<PacketDetails>(hwnd, message, lParam);
    if (message == WM_NCCREATE && self) self->m_hwnd = hwnd;
    if (message == WM_NCDESTROY) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        if (self) self->m_hwnd = nullptr;
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
    return self ? self->Handle(message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
}

void PacketDetails::SetPacket(PacketRef packet, uint64_t baseTimeUs) {
    if (packet == m_packet) return;
    m_packet = std::move(packet);
    m_fields.clear();
    m_title.clear();
    m_subtitle.clear();
    m_fate.clear();
    m_scroll.offset = 0;
    if (m_packet) {
        const DecodedPacket& p = *m_packet;
        m_title = Text::Format(IDS_DET_TITLE, p.Index, ToWide(p.ProtocolName));
        const double rel = p.TimestampUs >= baseTimeUs ? static_cast<double>(p.TimestampUs - baseTimeUs) / 1e6 : 0.0;
        m_subtitle = std::format(L"{}  \u00B7  {}  \u00B7  {}  \u00B7  +{:.6f} s", Text::Get(p.Dir == Direction::Outbound ? IDS_DIR_OUT : IDS_DIR_IN),
                                 Text::Format(IDS_DET_LENGTH, p.Length), WallClock(p.TimestampUs), rel);
        if (!p.DomainOrHost.empty()) m_subtitle += L"  ·  " + ToWide(p.DomainOrHost);
        if (!p.Process.empty()) m_subtitle += L"  ·  [" + ToWide(p.Process) + L"]";
        switch (p.Fate) {
        case PacketFate::Observed: m_fate = Text::Get(IDS_FATE_OBSERVED_LONG); m_fateColor = Color::Text3; break;
        case PacketFate::Passed: m_fate = Text::Get(IDS_FATE_PASSED_LONG); m_fateColor = Color::Success; break;
        case PacketFate::Delayed:
            m_fate = Text::Format(IDS_FATE_DELAYED_LONG, static_cast<double>(p.DelayUs) / 1000.0);
            m_fateColor = Color::Caution;
            break;
        case PacketFate::Dropped: m_fate = Text::Get(IDS_FATE_DROPPED_LONG); m_fateColor = Color::Critical; break;
        case PacketFate::Blocked: m_fate = Text::Get(IDS_FATE_BLOCKED_LONG); m_fateColor = Color::Critical; break;
        case PacketFate::Killed: m_fate = Text::Get(IDS_FATE_KILLED_LONG); m_fateColor = Color::Critical; break;
        }
        m_fields = PacketParser::Breakdown(p.RawData);
        if (!p.Info.empty()) m_fields.push_back({"Summary", "Info", p.Info});
    }
    m_measuredWidth = -1;
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

std::wstring PacketDetails::Text() const {
    if (!m_packet) return {};
    std::wstring out = m_title + L"\r\n" + m_subtitle + L"\r\n" + m_fate + L"\r\n";
    std::string layer;
    for (const auto& field : m_fields) {
        if (field.layer != layer) {
            layer = field.layer;
            out += L"\r\n" + ToWide(layer) + L"\r\n";
        }
        out += std::format(L"  {:<22}{}\r\n", ToWide(field.name), ToWide(field.value));
    }
    return out;
}

std::wstring PacketDetails::HexText() const {
    if (!m_packet) return {};
    std::wstring hex = ToWide(FormatHexDump(m_packet->RawData, m_packet->RawData.size()));
    std::wstring out;
    for (wchar_t c : hex) {
        if (c == L'\n') out += L'\r';
        out += c;
    }
    return out;
}

void PacketDetails::Relayout() {
    m_measuredWidth = -1;
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

void PacketDetails::Measure(float width) {
    const auto& f = m_fonts;
    m_measuredWidth = width;
    m_twoColumns = width >= f.F(820);
    const float line = f.F(20);
    // Header block + one line per field + a line per layer heading.
    size_t layers = 0;
    std::string layer;
    for (const auto& field : m_fields) {
        if (field.layer != layer) {
            layer = field.layer;
            ++layers;
        }
    }
    const float headers = f.F(78) + static_cast<float>(m_fields.size()) * line + static_cast<float>(layers) * f.F(28);
    const size_t hexLines = m_packet ? (m_packet->RawData.size() + 15) / 16 : 0;
    const float hex = f.F(34) + static_cast<float>(hexLines) * f.F(17);
    m_scroll.content = (m_twoColumns ? std::max(headers, hex) : headers + hex) + f.F(12);
}

LRESULT PacketDetails::Handle(UINT message, WPARAM wParam, LPARAM lParam) {
    RECT client{};
    GetClientRect(m_hwnd, &client);
    switch (message) {
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        Paint();
        return 0;
    case WM_SIZE:
        m_measuredWidth = -1;
        InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    case WM_GETDLGCODE:
        return DLGC_WANTARROWS;
    case WM_KEYDOWN: {
        const float step = m_fonts.F(20), before = m_scroll.offset;
        switch (wParam) {
        case VK_UP: m_scroll.ScrollTo(m_scroll.offset - step); break;
        case VK_DOWN: m_scroll.ScrollTo(m_scroll.offset + step); break;
        case VK_PRIOR: m_scroll.ScrollTo(m_scroll.offset - m_scroll.view); break;
        case VK_NEXT: m_scroll.ScrollTo(m_scroll.offset + m_scroll.view); break;
        case VK_HOME: m_scroll.ScrollTo(0); break;
        case VK_END: m_scroll.ScrollTo(m_scroll.Max()); break;
        default: return DefWindowProcW(m_hwnd, message, wParam, lParam);
        }
        if (m_scroll.offset != before) InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN: {
        SetFocus(m_hwnd);
        if (message == WM_LBUTTONDOWN && m_scroll.MouseDown({GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)}, client, m_fonts)) {
            SetCapture(m_hwnd);
            InvalidateRect(m_hwnd, nullptr, FALSE);
        }
        return 0;
    }
    case WM_MOUSEMOVE: {
        TRACKMOUSEEVENT tme{sizeof tme, TME_LEAVE, m_hwnd, 0};
        TrackMouseEvent(&tme);
        if (m_scroll.MouseMove({GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)}, client, m_fonts)) InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_MOUSELEAVE:
        if (m_scroll.hot) {
            m_scroll.hot = false;
            InvalidateRect(m_hwnd, nullptr, FALSE);
        }
        return 0;
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
    case WM_MOUSEWHEEL:
        if (m_scroll.Wheel(GET_WHEEL_DELTA_WPARAM(wParam), WheelStep(m_fonts, m_fonts.F(20)))) InvalidateRect(m_hwnd, nullptr, FALSE);
        return 0;
    }
    return DefWindowProcW(m_hwnd, message, wParam, lParam);
}

void PacketDetails::Paint() {
    PaintScope ps(m_hwnd);
    RECT client{};
    GetClientRect(m_hwnd, &client);
    const auto& f = m_fonts;
    Ui::Paint(ps.dc(), client, f, [&](Canvas& c) {
        c.Clear(Graphics::Get().Surface(Color::Card));
        const float width = static_cast<float>(client.right);
        if (!m_packet) {
            c.Text(Text::Get(IDS_DET_EMPTY), ToF(client), Font::Body, Color::Text3, Align::Center);
            return;
        }
        if (width != m_measuredWidth) Measure(width);
        m_scroll.view = static_cast<float>(client.bottom);
        m_scroll.Clamp();

        const float pad = f.F(16);
        const float right = width - f.F(14);
        const float split = m_twoColumns ? std::floor(width * 0.46f) : right;
        c.PushClip(ToF(client));
        float y = f.F(12) - m_scroll.offset;

        // Title, subtitle and what happened to the packet.
        const D2D1_COLOR_F pc = ProtocolColor(*m_packet);
        c.Fill({pad, y + f.F(6), pad + f.F(4), y + f.F(24)}, pc, f.F(2));
        c.Text(m_title, {pad + f.F(12), y, split - pad, y + f.F(30)}, Font::Title, Color::Text);
        y += f.F(30);
        c.Text(m_subtitle, {pad, y, split - pad, y + f.F(18)}, Font::Caption, Color::Text2);
        y += f.F(20);
        c.Circle({pad + f.F(4), y + f.F(9)}, f.F(3.5f), m_fateColor);
        c.Text(m_fate, {pad + f.F(14), y, split - pad, y + f.F(18)}, Font::Caption, m_fateColor);
        y += f.F(28);

        // Header fields grouped by layer.
        const float keyW = std::min(f.F(150), (split - pad * 2) * 0.42f);
        std::string layer;
        for (const auto& field : m_fields) {
            if (field.layer != layer) {
                layer = field.layer;
                y += f.F(6);
                c.Text(ToWide(layer), {pad, y, split - pad, y + f.F(18)}, Font::Label, Color::AccentText);
                y += f.F(22);
            }
            c.Text(ToWide(field.name), {pad + f.F(8), y, pad + keyW, y + f.F(20)}, Font::Caption, Color::Text3);
            c.Text(ToWide(field.value), {pad + keyW, y, split - pad, y + f.F(20)}, Font::Body, Color::Text);
            y += f.F(20);
        }

        // Hex dump: offset, 16 bytes, ASCII.
        float hx = m_twoColumns ? split + pad : pad;
        float hy = m_twoColumns ? f.F(12) - m_scroll.offset : y + f.F(14);
        if (m_twoColumns) c.Line({split, f.F(12)}, {split, static_cast<float>(client.bottom) - f.F(12)}, Color::CardStroke);
        c.Text(Text::Format(IDS_DET_BYTES, m_packet->RawData.size()), {hx, hy, right, hy + f.F(18)}, Font::Label, Color::Text3);
        hy += f.F(26);
        const auto& raw = m_packet->RawData;
        const float charW = c.Width(L"0", Font::Mono);
        for (size_t at = 0; at < raw.size(); at += 16) {
            const float lineTop = hy, lineBottom = hy + f.F(17);
            hy = lineBottom;
            if (lineBottom < 0 || lineTop > static_cast<float>(client.bottom)) continue;
            std::wstring bytes, ascii;
            for (size_t i = at; i < at + 16; ++i) {
                if (i < raw.size()) {
                    bytes += std::format(L"{:02X} ", raw[i]);
                    ascii += (raw[i] >= 32 && raw[i] < 127) ? static_cast<wchar_t>(raw[i]) : L'·';
                } else {
                    bytes += L"   ";
                }
                if (i - at == 7) bytes += L' ';
            }
            c.Text(std::format(L"{:04X}", at), {hx, lineTop, hx + charW * 5, lineBottom}, Font::Mono, Color::Text3);
            const float bx = hx + charW * 6;
            c.Text(bytes, {bx, lineTop, bx + charW * 50, lineBottom}, Font::Mono, Color::Text2);
            c.Text(ascii, {bx + charW * 50, lineTop, right, lineBottom}, Font::Mono, Color::Text3);
        }
        c.PopClip();
        m_scroll.Draw(c, client);
    });
}

}  // namespace WS::Ui
