// WireScope - Owner-drawn popup menus in the dark palette (adapter picker, presets, context menus).
#pragma once
#include "gui/Theme.h"
#include "support/Handle.h"
#include <Windows.h>
#include <memory>
#include <string>
#include <vector>

namespace WS::Ui {

class PopupMenu {
public:
    PopupMenu();
    PopupMenu(const PopupMenu&) = delete;
    PopupMenu& operator=(const PopupMenu&) = delete;

    void AddItem(UINT id, std::wstring text, std::wstring shortcut = {}, bool checked = false, bool radio = false,
                 bool enabled = true);
    void AddSeparator();
    void AddHeader(std::wstring text);  // disabled caption line

    // Modal; returns the chosen command or 0. `exclude` keeps the menu clear of that screen rectangle
    // (e.g. drops it below the button that opened it).
    UINT Track(HWND owner, const Fonts& fonts, POINT screen, const RECT* exclude = nullptr);

    // The owner forwards WM_MEASUREITEM / WM_DRAWITEM with CtlType == ODT_MENU here.
    static bool Measure(MEASUREITEMSTRUCT& mis);
    static bool Draw(const DRAWITEMSTRUCT& dis);

private:
    struct Data {
        std::wstring text, shortcut;
        bool separator = false, radio = false, header = false;
    };
    MenuHandle m_menu;
    Gdi<HBRUSH> m_background;
    std::vector<std::unique_ptr<Data>> m_data;
};

}  // namespace WS::Ui
