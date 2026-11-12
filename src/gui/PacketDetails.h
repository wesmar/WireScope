// WireScope - Details of the selected packet: decoded header fields and a hex/ASCII dump.
// Two columns when there is room, stacked otherwise; one scroll bar for both.
#pragma once
#include "core/PacketEngine.h"
#include "core/PacketParser.h"
#include "gui/Widgets.h"
#include <string>
#include <vector>

namespace WS::Ui {

class PacketDetails {
public:
    explicit PacketDetails(const Fonts& fonts) : m_fonts(fonts) {}
    PacketDetails(const PacketDetails&) = delete;
    PacketDetails& operator=(const PacketDetails&) = delete;

    HWND Create(HWND parent, int id);
    [[nodiscard]] HWND hwnd() const noexcept { return m_hwnd; }
    void SetPacket(PacketRef packet, uint64_t baseTimeUs);
    [[nodiscard]] PacketRef Packet() const { return m_packet; }
    [[nodiscard]] std::wstring Text() const;     // headers as text
    [[nodiscard]] std::wstring HexText() const;  // hex dump as text
    void Relayout();

private:
    static LRESULT CALLBACK Proc(HWND, UINT, WPARAM, LPARAM);
    LRESULT Handle(UINT, WPARAM, LPARAM);
    void Paint();
    void Measure(float width);

    const Fonts& m_fonts;
    HWND m_hwnd = nullptr;
    PacketRef m_packet;
    std::wstring m_title, m_subtitle, m_fate;
    D2D1_COLOR_F m_fateColor{};
    std::vector<HeaderField> m_fields;
    Scroller m_scroll;
    bool m_twoColumns = true;
    float m_measuredWidth = -1;
};

}  // namespace WS::Ui
