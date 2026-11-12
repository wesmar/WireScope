#include "gui/Menus.h"
#include "gui/Widgets.h"
#include <algorithm>
#include <cmath>

namespace WS::Ui {
namespace {
const Fonts* g_fonts = nullptr;  // fonts of the menu being tracked (one modal menu loop at a time)
}

PopupMenu::PopupMenu() : m_menu(CreatePopupMenu()), m_background(CreateSolidBrush(ToColorRef(Color::Flyout))) {
    MENUINFO info{sizeof info};
    info.fMask = MIM_BACKGROUND | MIM_STYLE;
    info.hbrBack = m_background.get();
    info.dwStyle = MNS_CHECKORBMP;
    SetMenuInfo(m_menu.get(), &info);
}

void PopupMenu::AddItem(UINT id, std::wstring text, std::wstring shortcut, bool checked, bool radio, bool enabled) {
    auto data = std::make_unique<Data>(Data{std::move(text), std::move(shortcut), false, radio, false});
    MENUITEMINFOW item{sizeof item};
    item.fMask = MIIM_FTYPE | MIIM_ID | MIIM_DATA | MIIM_STRING | MIIM_STATE;
    item.fType = MFT_OWNERDRAW | (radio ? MFT_RADIOCHECK : 0);
    item.fState = (checked ? MFS_CHECKED : 0) | (enabled ? 0 : MFS_DISABLED);
    item.wID = id;
    item.dwItemData = reinterpret_cast<ULONG_PTR>(data.get());
    item.dwTypeData = data->text.data();  // kept for accessibility tools
    InsertMenuItemW(m_menu.get(), static_cast<UINT>(GetMenuItemCount(m_menu.get())), TRUE, &item);
    m_data.push_back(std::move(data));
}

void PopupMenu::AddHeader(std::wstring text) {
    auto data = std::make_unique<Data>(Data{std::move(text), {}, false, false, true});
    MENUITEMINFOW item{sizeof item};
    item.fMask = MIIM_FTYPE | MIIM_ID | MIIM_DATA | MIIM_STRING | MIIM_STATE;
    item.fType = MFT_OWNERDRAW;
    item.fState = MFS_DISABLED;
    item.wID = 0;
    item.dwItemData = reinterpret_cast<ULONG_PTR>(data.get());
    item.dwTypeData = data->text.data();
    InsertMenuItemW(m_menu.get(), static_cast<UINT>(GetMenuItemCount(m_menu.get())), TRUE, &item);
    m_data.push_back(std::move(data));
}

void PopupMenu::AddSeparator() {
    auto data = std::make_unique<Data>(Data{{}, {}, true, false, false});
    MENUITEMINFOW item{sizeof item};
    item.fMask = MIIM_FTYPE | MIIM_DATA;
    item.fType = MFT_OWNERDRAW | MFT_SEPARATOR;
    item.dwItemData = reinterpret_cast<ULONG_PTR>(data.get());
    InsertMenuItemW(m_menu.get(), static_cast<UINT>(GetMenuItemCount(m_menu.get())), TRUE, &item);
    m_data.push_back(std::move(data));
}

UINT PopupMenu::Track(HWND owner, const Fonts& fonts, POINT screen, const RECT* exclude) {
    g_fonts = &fonts;
    TPMPARAMS params{sizeof params, {}};
    if (exclude) params.rcExclude = *exclude;
    const UINT command = static_cast<UINT>(TrackPopupMenuEx(m_menu.get(), TPM_LEFTALIGN | TPM_TOPALIGN | TPM_VERTICAL | TPM_RETURNCMD |
                                                                              TPM_RIGHTBUTTON,
                                                            screen.x, screen.y, owner, exclude ? &params : nullptr));
    g_fonts = nullptr;
    return command;
}

bool PopupMenu::Measure(MEASUREITEMSTRUCT& mis) {
    const auto* data = reinterpret_cast<const Data*>(mis.itemData);
    if (!data || !g_fonts) return false;
    const Fonts& f = *g_fonts;
    if (data->separator) {
        mis.itemWidth = static_cast<UINT>(f.S(40));
        mis.itemHeight = static_cast<UINT>(f.S(9));
        return true;
    }
    const Font font = data->header ? Font::Label : Font::Body;
    const float text = TextWidth(f, font, data->text);
    const float shortcut = data->shortcut.empty() ? 0 : TextWidth(f, Font::Caption, data->shortcut) + f.F(32);
    mis.itemWidth = static_cast<UINT>(f.F(36) + text + shortcut + f.F(20));
    mis.itemHeight = static_cast<UINT>(f.S(data->header ? 26 : 32));
    return true;
}

bool PopupMenu::Draw(const DRAWITEMSTRUCT& dis) {
    const auto* data = reinterpret_cast<const Data*>(dis.itemData);
    if (!data || !g_fonts) return false;
    const Fonts& f = *g_fonts;
    const bool disabled = dis.itemState & (ODS_DISABLED | ODS_GRAYED);
    const bool selected = (dis.itemState & ODS_SELECTED) && !disabled;
    const bool checked = dis.itemState & ODS_CHECKED;
    Ui::Paint(dis.hDC, dis.rcItem, f, [&](Canvas& c) {
        const D2D1_RECT_F r = ToF(dis.rcItem);
        c.Clear(Color::Flyout);
        if (data->separator) {
            const float y = std::floor((r.top + r.bottom) / 2) + 0.5f;
            c.Line({r.left + f.F(4), y}, {r.right - f.F(4), y}, Color::FlyoutStroke);
            return;
        }
        if (data->header) {
            c.Text(data->text, {r.left + f.F(14), r.top + f.F(4), r.right - f.F(12), r.bottom}, Font::Label, Color::Text3);
            return;
        }
        if (selected) c.Fill(Inset(r, f.F(4), f.F(2)), Color::FlyoutHot, f.F(4));
        const D2D1_COLOR_F fg = disabled ? Color::TextDisabled : Color::Text;
        if (checked) {
            if (data->radio) {
                c.Circle({r.left + f.F(20), (r.top + r.bottom) / 2}, f.F(3.5f), disabled ? Color::TextDisabled : Color::AccentText);
            } else {
                c.Text(std::wstring(1, Icon::Check), {r.left + f.F(10), r.top, r.left + f.F(30), r.bottom}, Font::IconSmall, fg,
                       Align::Center);
            }
        }
        c.Text(data->text, {r.left + f.F(36), r.top, r.right - f.F(12), r.bottom}, Font::Body, fg);
        if (!data->shortcut.empty()) {
            c.Text(data->shortcut, {r.left, r.top, r.right - f.F(16), r.bottom}, Font::Caption,
                   disabled ? Color::TextDisabled : Color::Text3, Align::Right);
        }
    });
    return true;
}

}  // namespace WS::Ui
