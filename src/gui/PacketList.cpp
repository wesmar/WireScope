#include "gui/PacketList.h"
#include "support/Text.h"
#include <windowsx.h>
#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>

namespace WS::Ui {
namespace {

constexpr wchar_t kClass[] = L"WireScope.PacketList";
constexpr size_t kMaxRows = 20000;

bool CtrlDown() { return (GetKeyState(VK_CONTROL) & 0x8000) != 0; }
bool ShiftDown() { return (GetKeyState(VK_SHIFT) & 0x8000) != 0; }

// "192.168.0.10" as a number, so that 10.0.0.2 sorts before 192.168.0.1; nullopt for anything else.
std::optional<uint32_t> Ipv4(std::string_view s) {
    uint32_t value = 0;
    for (int part = 0; part < 4; ++part) {
        unsigned octet = 0;
        const auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), octet);
        if (ec != std::errc{} || octet > 255 || end == s.data()) return std::nullopt;
        value = (value << 8) | octet;
        s.remove_prefix(static_cast<size_t>(end - s.data()));
        if (part < 3) {
            if (s.empty() || s.front() != '.') return std::nullopt;
            s.remove_prefix(1);
        }
    }
    return s.empty() ? std::optional<uint32_t>(value) : std::nullopt;
}

// IPv4 first and in numeric order, then the rest (IPv6, MAC) as text; the port breaks a tie.
int CompareEndpoint(const std::string& a, uint16_t portA, const std::string& b, uint16_t portB) {
    const auto va = Ipv4(a), vb = Ipv4(b);
    if (va && vb) {
        if (*va != *vb) return *va < *vb ? -1 : 1;
    } else if (va || vb) {
        return va ? -1 : 1;
    } else if (const int c = a.compare(b); c != 0) {
        return c < 0 ? -1 : 1;
    }
    return portA < portB ? -1 : portA > portB ? 1 : 0;
}

int CompareText(const std::string& a, const std::string& b) {
    const int c = _stricmp(a.c_str(), b.c_str());
    return c < 0 ? -1 : c > 0 ? 1 : 0;
}

template <class T>
int Compare(T a, T b) {
    return a < b ? -1 : a > b ? 1 : 0;
}

}  // namespace

HWND PacketList::Create(HWND parent, int id) {
    RegisterControlClass(kClass, Proc);
    m_hwnd = CreateWindowExW(0, kClass, L"Packets", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 10, 10, parent,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), GetModuleHandleW(nullptr), this);
    return m_hwnd;
}

LRESULT CALLBACK PacketList::Proc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* self = ControlFromWindow<PacketList>(hwnd, message, lParam);
    if (message == WM_NCCREATE && self) self->m_hwnd = hwnd;
    if (message == WM_NCDESTROY) {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        if (self) self->m_hwnd = nullptr;
        return DefWindowProcW(hwnd, message, wParam, lParam);
    }
    return self ? self->Handle(message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
}

// ---------------------------------------------------------------------------
// Order
// ---------------------------------------------------------------------------
bool PacketList::Before(const DecodedPacket& a, const DecodedPacket& b) const {
    int key = 0;
    switch (m_sort) {
    case Sort::Number: break;
    case Sort::Time: key = Compare(a.TimestampUs, b.TimestampUs); break;
    case Sort::Direction: key = Compare(static_cast<int>(a.Dir), static_cast<int>(b.Dir)); break;
    case Sort::Protocol: key = CompareText(a.ProtocolName, b.ProtocolName); break;
    case Sort::Source: key = CompareEndpoint(a.Source, a.SourcePort, b.Source, b.SourcePort); break;
    case Sort::Destination: key = CompareEndpoint(a.Destination, a.DestPort, b.Destination, b.DestPort); break;
    case Sort::Length: key = Compare(a.Length, b.Length); break;
    case Sort::Info: key = CompareText(a.Info, b.Info); break;
    }
    if (key == 0) key = Compare(a.Index, b.Index);  // a strict order: equal keys keep capture order
    return m_descending ? key > 0 : key < 0;
}

void PacketList::SetSort(Sort sort) {
    if (sort == m_sort) {
        m_descending = !m_descending;
    } else {
        m_sort = sort;
        m_descending = false;
    }
    std::stable_sort(m_rows.begin(), m_rows.end(), [this](const PacketRef& a, const PacketRef& b) { return Before(*a, *b); });
    m_hot = -1;
    Refocus();
    // The newest packet is at one end only when sorted by number; then the view follows it again.
    m_follow = m_sort == Sort::Number && m_focus == 0;
    if (m_follow) m_scroll.offset = m_descending ? 0 : m_scroll.Max();
    UpdateExtent();
    if (m_selected >= 0) m_scroll.EnsureVisible(static_cast<float>(m_selected) * RowH(), static_cast<float>(m_selected + 1) * RowH());
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

int PacketList::RowOf(uint64_t index) const {
    if (index == 0) return -1;
    if (m_sort == Sort::Number) {  // sorted by Index: binary search
        auto less = [this](const PacketRef& p, uint64_t i) { return m_descending ? p->Index > i : p->Index < i; };
        const auto it = std::lower_bound(m_rows.begin(), m_rows.end(), index, less);
        return it != m_rows.end() && (*it)->Index == index ? static_cast<int>(it - m_rows.begin()) : -1;
    }
    const auto it = std::find_if(m_rows.begin(), m_rows.end(), [index](const PacketRef& p) { return p->Index == index; });
    return it == m_rows.end() ? -1 : static_cast<int>(it - m_rows.begin());
}

void PacketList::Refocus() {
    m_selected = RowOf(m_focus);
    if (m_selected < 0) m_focus = 0;
}

void PacketList::UpdateExtent() {
    RECT rc{};
    if (m_hwnd) GetClientRect(m_hwnd, &rc);
    m_scroll.view = std::max(0.0f, static_cast<float>(rc.bottom) - HeaderH());
    m_scroll.content = static_cast<float>(m_rows.size()) * RowH();
    if (m_follow) m_scroll.offset = m_sort == Sort::Number && m_descending ? 0 : m_scroll.Max();
    m_scroll.Clamp();
}

void PacketList::Trim() {
    if (m_rows.size() <= kMaxRows) return;
    const size_t drop = m_rows.size() - kMaxRows + kMaxRows / 10;
    if (Chronological()) {
        m_rows.erase(m_rows.begin(), m_rows.begin() + static_cast<std::ptrdiff_t>(drop));
        m_scroll.offset -= static_cast<float>(drop) * RowH();
    } else {
        // The oldest packets go, wherever the order put them.
        std::vector<uint64_t> indexes;
        indexes.reserve(m_rows.size());
        for (const auto& p : m_rows) indexes.push_back(p->Index);
        std::nth_element(indexes.begin(), indexes.begin() + static_cast<std::ptrdiff_t>(drop), indexes.end());
        const uint64_t keepFrom = indexes[drop];
        std::erase_if(m_rows, [keepFrom](const PacketRef& p) { return p->Index < keepFrom; });
    }
    const uint64_t oldest = m_rows.empty() ? 0 : (*std::min_element(m_rows.begin(), m_rows.end(), [](const PacketRef& a, const PacketRef& b) {
                                                     return a->Index < b->Index;
                                                 }))->Index;
    std::erase_if(m_marked, [oldest](uint64_t i) { return i < oldest; });
    if (m_anchor < oldest) m_anchor = 0;
    Refocus();
    m_hot = -1;
}

void PacketList::SetRows(std::vector<PacketRef> rows) {
    m_rows = std::move(rows);
    if (!Chronological()) {
        std::stable_sort(m_rows.begin(), m_rows.end(), [this](const PacketRef& a, const PacketRef& b) { return Before(*a, *b); });
    }
    std::unordered_set<uint64_t> listed;  // a filter may have hidden selected packets
    listed.reserve(m_rows.size());
    for (const auto& p : m_rows) listed.insert(p->Index);
    std::erase_if(m_marked, [&](uint64_t i) { return !listed.contains(i); });
    m_hot = -1;
    Refocus();
    Trim();
    UpdateExtent();
    if (m_selected >= 0 && !m_follow) m_scroll.EnsureVisible(static_cast<float>(m_selected) * RowH(), static_cast<float>(m_selected + 1) * RowH());
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

void PacketList::Append(const std::vector<PacketRef>& rows) {
    if (rows.empty()) return;
    if (Chronological()) {
        m_rows.insert(m_rows.end(), rows.begin(), rows.end());
    } else {
        // Sort the new batch and merge it in: linear, instead of sorting the whole list every tick.
        auto before = [this](const PacketRef& a, const PacketRef& b) { return Before(*a, *b); };
        const auto middle = static_cast<std::ptrdiff_t>(m_rows.size());
        m_rows.insert(m_rows.end(), rows.begin(), rows.end());
        std::stable_sort(m_rows.begin() + middle, m_rows.end(), before);
        std::inplace_merge(m_rows.begin(), m_rows.begin() + middle, m_rows.end(), before);
        const float anchorTop = static_cast<float>(m_selected) * RowH() - m_scroll.offset;
        Refocus();
        // Keep the focused row where it was on the screen while rows arrive above it.
        if (m_selected >= 0 && !m_follow) m_scroll.offset = static_cast<float>(m_selected) * RowH() - anchorTop;
    }
    Trim();
    UpdateExtent();
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

void PacketList::Clear() {
    m_rows.clear();
    m_marked.clear();
    m_focus = m_anchor = 0;
    m_selected = m_hot = -1;
    m_follow = true;
    m_scroll = {};
    UpdateExtent();
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

void PacketList::SetBaseTime(uint64_t timestampUs) {
    m_baseTime = timestampUs;
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

void PacketList::SetPlaceholder(std::wstring text) {
    m_placeholder = std::move(text);
    if (m_hwnd && m_rows.empty()) InvalidateRect(m_hwnd, nullptr, FALSE);
}

PacketRef PacketList::Selected() const {
    if (m_selected < 0 || m_selected >= static_cast<int>(m_rows.size())) return {};
    return m_rows[static_cast<size_t>(m_selected)];
}

std::vector<PacketRef> PacketList::Marked() const {
    std::vector<PacketRef> out;
    out.reserve(m_marked.size());
    for (const auto& p : m_rows) {
        if (m_marked.contains(p->Index)) out.push_back(p);
    }
    std::ranges::sort(out, {}, [](const PacketRef& p) { return p->Index; });
    return out;
}

void PacketList::SelectAll() {
    if (m_rows.empty()) return;
    for (const auto& p : m_rows) m_marked.insert(p->Index);
    if (m_focus == 0) {
        m_focus = m_anchor = m_rows.front()->Index;
        m_selected = 0;
    }
    InvalidateRect(m_hwnd, nullptr, FALSE);
    Notify(LBN_SELCHANGE);
}

void PacketList::Relayout() {
    UpdateExtent();
    if (m_hwnd) InvalidateRect(m_hwnd, nullptr, FALSE);
}

PacketList::Columns PacketList::Layout(float width) const {
    const auto& f = m_fonts;
    Columns c{};
    c.right = width - f.F(12);
    c.no = f.F(10);
    c.time = c.no + f.F(62);
    c.dir = c.time + f.F(74);
    c.proto = c.dir + f.F(30);
    c.src = c.proto + f.F(74);
    const float fixedTail = f.F(64);  // length column
    const float flexible = std::max(f.F(200), c.right - c.src - fixedTail);
    const float endpoint = std::clamp(flexible * 0.27f, f.F(120), f.F(270));
    c.dst = c.src + endpoint;
    c.len = c.dst + endpoint;
    c.info = c.len + fixedTail;
    return c;
}

int PacketList::RowAt(POINT p) const {
    const float y = static_cast<float>(p.y) - HeaderH();
    if (y < 0) return -1;
    const int row = static_cast<int>(std::floor((y + m_scroll.offset) / RowH()));
    return row >= 0 && row < static_cast<int>(m_rows.size()) ? row : -1;
}

std::optional<PacketList::Sort> PacketList::HeaderAt(POINT p) const {
    if (static_cast<float>(p.y) >= HeaderH()) return std::nullopt;
    RECT client{};
    GetClientRect(m_hwnd, &client);
    const Columns c = Layout(static_cast<float>(client.right));
    const float x = static_cast<float>(p.x);
    if (x < c.time) return Sort::Number;
    if (x < c.dir) return Sort::Time;
    if (x < c.proto) return Sort::Direction;
    if (x < c.src) return Sort::Protocol;
    if (x < c.dst) return Sort::Source;
    if (x < c.len) return Sort::Destination;
    if (x < c.info) return Sort::Length;
    return Sort::Info;
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------
void PacketList::Notify(WORD code) {
    SendMessageW(GetParent(m_hwnd), WM_COMMAND, MAKEWPARAM(GetDlgCtrlID(m_hwnd), code), reinterpret_cast<LPARAM>(m_hwnd));
}

void PacketList::Focus(int row, bool extend, bool toggle) {
    if (m_rows.empty()) return;
    row = std::clamp(row, 0, static_cast<int>(m_rows.size()) - 1);
    const uint64_t index = m_rows[static_cast<size_t>(row)]->Index;
    if (toggle) {
        if (!m_marked.erase(index)) m_marked.insert(index);
        m_anchor = index;
    } else if (extend && m_anchor) {
        const int from = RowOf(m_anchor) < 0 ? row : RowOf(m_anchor);
        if (!CtrlDown()) m_marked.clear();
        for (int i = std::min(from, row); i <= std::max(from, row); ++i) m_marked.insert(m_rows[static_cast<size_t>(i)]->Index);
    } else {
        m_marked = {index};
        m_anchor = index;
    }
    m_focus = index;
    m_selected = row;
    m_scroll.EnsureVisible(static_cast<float>(row) * RowH(), static_cast<float>(row + 1) * RowH());
    const bool newestEnd = m_sort == Sort::Number && (m_descending ? row == 0 : row == static_cast<int>(m_rows.size()) - 1);
    m_follow = newestEnd && (m_descending ? m_scroll.offset <= 0.5f : m_scroll.AtEnd());
    InvalidateRect(m_hwnd, nullptr, FALSE);
    Notify(LBN_SELCHANGE);
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------
LRESULT PacketList::Handle(UINT message, WPARAM wParam, LPARAM lParam) {
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
        const bool shift = ShiftDown();
        if (CtrlDown() && wParam == 'C') {
            Notify(PacketListCopy);
            return 0;
        }
        if (CtrlDown() && wParam == 'A') {
            SelectAll();
            return 0;
        }
        const int last = static_cast<int>(m_rows.size()) - 1;
        switch (wParam) {
        case VK_UP: Focus(m_selected < 0 ? last : m_selected - 1, shift, false); return 0;
        case VK_DOWN: Focus(m_selected + 1, shift, false); return 0;
        case VK_PRIOR: Focus(m_selected - page, shift, false); return 0;
        case VK_NEXT: Focus(m_selected + page, shift, false); return 0;
        case VK_HOME: Focus(0, shift, false); return 0;
        case VK_END:
            Focus(last, shift, false);
            m_follow = Chronological();
            return 0;
        case VK_ESCAPE:
            m_marked.clear();
            m_focus = m_anchor = 0;
            m_selected = -1;
            m_follow = m_sort == Sort::Number;
            UpdateExtent();
            InvalidateRect(m_hwnd, nullptr, FALSE);
            Notify(LBN_SELCHANGE);
            return 0;
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
            m_follow = false;
            InvalidateRect(m_hwnd, nullptr, FALSE);
            return 0;
        }
        if (message == WM_LBUTTONDOWN) {
            if (const auto sort = HeaderAt(p)) {
                SetSort(*sort);
                return 0;
            }
        }
        const int row = RowAt(p);
        if (row < 0) return 0;
        if (message == WM_RBUTTONDOWN) {
            // The context menu acts on the selection: a click inside it keeps it.
            if (!m_marked.contains(m_rows[static_cast<size_t>(row)]->Index)) Focus(row, false, false);
            return 0;
        }
        const bool ctrl = (wParam & MK_CONTROL) != 0, shift = (wParam & MK_SHIFT) != 0;
        Focus(row, shift, ctrl && !shift);
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
    case WM_MOUSEMOVE: {
        const POINT p{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
        if (!m_tracking) {
            TRACKMOUSEEVENT tme{sizeof tme, TME_LEAVE, m_hwnd, 0};
            m_tracking = TrackMouseEvent(&tme) != FALSE;
        }
        bool repaint = m_scroll.MouseMove(p, client, m_fonts, HeaderH());
        if (m_scroll.dragging) m_follow = Chronological() && m_scroll.AtEnd();
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
        if (m_scroll.Wheel(GET_WHEEL_DELTA_WPARAM(wParam), WheelStep(m_fonts, RowH()))) {
            m_follow = m_sort == Sort::Number && (m_descending ? m_scroll.offset <= 0.5f : m_scroll.AtEnd());
            InvalidateRect(m_hwnd, nullptr, FALSE);
        }
        return 0;
    }
    return DefWindowProcW(m_hwnd, message, wParam, lParam);
}

}  // namespace WS::Ui
