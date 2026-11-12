// WireScope - Packet list: painting (header with the sort mark, rows, selection, protocol and fate pills).
#include "gui/PacketList.h"
#include "resources/resource.h"
#include "support/Language.h"
#include "support/Text.h"
#include <algorithm>
#include <cmath>
#include <format>

namespace WS::Ui {
namespace {

std::wstring Endpoint(const std::string& address, uint16_t port) {
    if (port == 0) return ToWide(address);
    if (address.find(':') != std::string::npos) return std::format(L"[{}]:{}", ToWide(address), port);
    return std::format(L"{}:{}", ToWide(address), port);
}

}  // namespace

D2D1_COLOR_F ProtocolColor(const DecodedPacket& p) {
    if (p.ProtocolName == "HTTP") return Color::Http;
    switch (p.Protocol) {
    case ProtocolType::TCP: return Color::Tcp;
    case ProtocolType::UDP: return p.ProtocolName == "UDP" ? Color::Udp : Color::Dns;  // DHCP, NTP
    case ProtocolType::DNS: return Color::Dns;
    case ProtocolType::TLS: return Color::Tls;
    case ProtocolType::ICMP: return Color::Icmp;
    case ProtocolType::ARP: return Color::Arp;
    default: return p.ProtocolName == "ICMPv6" ? Color::Icmp : Color::OtherProtocol;
    }
}

void PacketList::Paint() {
    PaintScope ps(m_hwnd);
    RECT client{};
    GetClientRect(m_hwnd, &client);
    const auto& f = m_fonts;
    const bool focused = GetFocus() == m_hwnd;
    Ui::Paint(ps.dc(), client, f, [&](Canvas& c) {
        c.Clear(Graphics::Get().Surface(Color::Card));
        const float width = static_cast<float>(client.right);
        const Columns col = Layout(width);
        const float headerH = HeaderH();

        // Column header: the sorted column is brighter and carries the direction.
        struct Head {
            UINT text;  // 0 = no title (the direction arrows)
            Sort sort;
            float left, right;
            Align align;
        };
        const Head heads[] = {
            {IDS_COL_NO, Sort::Number, col.no, col.time - f.F(12), Align::Right},
            {IDS_COL_TIME, Sort::Time, col.time, col.dir - f.F(6), Align::Left},
            {0, Sort::Direction, col.dir, col.proto - f.F(6), Align::Center},
            {IDS_COL_PROTOCOL, Sort::Protocol, col.proto, col.src - f.F(6), Align::Left},
            {IDS_COL_SOURCE, Sort::Source, col.src, col.dst - f.F(8), Align::Left},
            {IDS_COL_DESTINATION, Sort::Destination, col.dst, col.len - f.F(8), Align::Left},
            {IDS_COL_LENGTH, Sort::Length, col.len, col.info - f.F(16), Align::Right},
            {IDS_COL_INFO, Sort::Info, col.info, col.right, Align::Left},
        };
        for (const Head& h : heads) {
            const bool sorted = h.sort == m_sort;
            const std::wstring title = h.text ? Text::Get(h.text) : std::wstring();
            if (sorted) {
                const std::wstring arrow(1, m_descending ? Icon::ChevronDown : Icon::Up);
                const float tw = title.empty() ? 0.0f : c.Width(title, Font::Label);
                float ax = h.align == Align::Right ? h.right - tw - f.F(16) : h.left + tw + f.F(4);
                if (h.align == Align::Center) ax = (h.left + h.right) / 2 - f.F(6);
                c.Text(arrow, {ax, 0, ax + f.F(12), headerH}, Font::IconSmall, Color::AccentText, Align::Center);
            }
            if (!title.empty()) c.Text(title, {h.left, 0, h.right, headerH}, Font::Label, sorted ? Color::Text2 : Color::Text3, h.align);
        }
        c.Line({f.F(6), headerH - 0.5f}, {width - f.F(6), headerH - 0.5f}, Color::CardStroke);

        if (m_rows.empty()) {
            c.Text(m_placeholder, {0, headerH, width, static_cast<float>(client.bottom)}, Font::Body, Color::Text3, Align::Center);
            return;
        }

        const float rowH = RowH();
        const D2D1_RECT_F area{0, headerH, width, static_cast<float>(client.bottom)};
        c.PushClip(area);
        const int first = static_cast<int>(std::floor(m_scroll.offset / rowH));
        const int last = std::min(static_cast<int>(m_rows.size()) - 1, static_cast<int>((m_scroll.offset + m_scroll.view) / rowH) + 1);
        const float rightEdge = width - (m_scroll.Visible() ? f.F(12) : f.F(4));
        for (int i = std::max(first, 0); i <= last; ++i) {
            const DecodedPacket& p = *m_rows[static_cast<size_t>(i)];
            const float top = headerH + static_cast<float>(i) * rowH - m_scroll.offset;
            const float bottom = top + rowH;
            const D2D1_RECT_F box{f.F(4), top + f.F(1), rightEdge, bottom - f.F(1)};
            const bool marked = m_marked.contains(p.Index), current = i == m_selected, hot = i == m_hot;
            if (marked) {
                c.Fill(box, Color::Selected, f.F(4));
            } else if (hot) {
                c.Fill(box, Color::Hover, f.F(4));
            }
            if (current) {  // the packet the details pane shows
                const float mid = (top + bottom) / 2;
                c.Fill({box.left + f.F(1), mid - f.F(7), box.left + f.F(4), mid + f.F(7)}, Color::AccentText, f.F(1.5f));
                if (focused) c.Stroke(box, White(0.18f), f.F(4));
            }
            const bool dead = p.Fate == PacketFate::Dropped || p.Fate == PacketFate::Blocked || p.Fate == PacketFate::Killed;
            const D2D1_COLOR_F ink = dead ? Color::Text3 : Color::Text;

            c.Text(std::to_wstring(p.Index), {col.no, top, col.time - f.F(12), bottom}, Font::Caption, Color::Text3, Align::Right);
            const double seconds = p.TimestampUs >= m_baseTime ? static_cast<double>(p.TimestampUs - m_baseTime) / 1e6 : 0.0;
            c.Text(std::format(L"{:.3f}", seconds), {col.time, top, col.dir - f.F(6), bottom}, Font::Caption, Color::Text2);
            const bool out = p.Dir == Direction::Outbound;
            c.Text(std::wstring(1, out ? Icon::ArrowUp : Icon::ArrowDown), {col.dir, top, col.dir + f.F(18), bottom}, Font::IconSmall,
                   out ? Color::AccentText : Color::Success, Align::Center);

            // Protocol pill
            const std::wstring proto = ToWide(p.ProtocolName);
            const D2D1_COLOR_F pc = ProtocolColor(p);
            const float pw = std::min(c.Width(proto, Font::Label) + f.F(12), col.src - col.proto - f.F(8));
            const D2D1_RECT_F pill{col.proto, top + f.F(5), col.proto + pw, bottom - f.F(5)};
            c.Fill(pill, WithAlpha(pc, dead ? 0.08f : 0.16f), f.F(3));
            c.Text(proto, pill, Font::Label, dead ? WithAlpha(pc, 0.6f) : pc, Align::Center);

            c.Text(Endpoint(p.Source, p.SourcePort), {col.src, top, col.dst - f.F(8), bottom}, Font::Body, ink);
            c.Text(Endpoint(p.Destination, p.DestPort), {col.dst, top, col.len - f.F(8), bottom}, Font::Body, ink);
            c.Text(std::to_wstring(p.Length), {col.len, top, col.info - f.F(16), bottom}, Font::Caption, Color::Text2, Align::Right);

            // Info: what the data plane did first, then the host name and the summary.
            float x = col.info;
            std::wstring fate;
            D2D1_COLOR_F fateColor = Color::Caution;
            switch (p.Fate) {
            case PacketFate::Delayed: fate = Text::Format(IDS_FATE_DELAY, (p.DelayUs + 500) / 1000); break;
            case PacketFate::Dropped: fate = Text::Get(IDS_FATE_SIMDROP); fateColor = Color::Critical; break;
            case PacketFate::Blocked: fate = Text::Get(IDS_FATE_BLOCKED); fateColor = Color::Critical; break;
            case PacketFate::Killed: fate = Text::Get(IDS_FATE_KILLED); fateColor = Color::Critical; break;
            default: break;
            }
            if (!fate.empty()) {
                const float fw = c.Width(fate, Font::Label) + f.F(12);
                const D2D1_RECT_F b{x, top + f.F(5), x + fw, bottom - f.F(5)};
                c.Fill(b, WithAlpha(fateColor, 0.15f), f.F(3));
                c.Text(fate, b, Font::Label, fateColor, Align::Center);
                x += fw + f.F(8);
            }
            if (!p.DomainOrHost.empty()) {
                const std::wstring host = ToWide(p.DomainOrHost);
                const float hw = std::min(c.Width(host, Font::Strong) + 1, std::max(0.0f, col.right - x));
                c.Text(host, {x, top, x + hw, bottom}, Font::Strong, dead ? Color::Text3 : Color::AccentText);
                x += hw + f.F(10);
            }
            if (!p.Process.empty()) {
                const std::wstring proc = ToWide(p.Process);
                const float procW = std::min(c.Width(proc, Font::Label) + f.F(12), std::max(0.0f, col.right - x));
                if (procW > f.F(10)) {
                    const D2D1_RECT_F pb{x, top + f.F(5), x + procW, bottom - f.F(5)};
                    c.Fill(pb, WithAlpha(Color::AccentText, dead ? 0.06f : 0.12f), f.F(3));
                    c.Text(proc, pb, Font::Label, dead ? Color::Text3 : Color::AccentText, Align::Center);
                    x += procW + f.F(8);
                }
            }
            c.Text(ToWide(p.Info), {x, top, col.right, bottom}, Font::Body, dead ? Color::Text3 : Color::Text2);
        }
        c.PopClip();
        m_scroll.Draw(c, client, headerH);
    });
}

}  // namespace WS::Ui
