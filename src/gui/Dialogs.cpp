#include "gui/Dialogs.h"
#include "gui/Theme.h"
#include "gui/Widgets.h"
#include "support/Handle.h"
#include "support/Language.h"
#include <CommCtrl.h>
#include <ShObjIdl.h>
#include <uxtheme.h>
#include <algorithm>
#include <cmath>
#include <unordered_map>

#pragma comment(lib, "ole32.lib")

namespace WS::Ui {
namespace {

constexpr wchar_t kClass[] = L"WireScope.Dialog";
constexpr int kExtra = 3, kFieldBase = 100, kMonospace = 300;

Gdi<HFONT> MakeGdiFont(const Fonts& f, const wchar_t* family, float pixels) {
    return Gdi<HFONT>(CreateFontW(-static_cast<int>(f.F(pixels) + 0.5f), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, family));
}

class Dialog {
public:
    Dialog(HWND owner, const DialogSpec& spec) : m_owner(owner), m_spec(spec) {}

    DialogResult Run() {
        RegisterOnce();
        m_fonts.Create(GetDpiForWindow(m_owner));
        m_hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, kClass, L"WireScope", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN,
                                 0, 0, 100, 100, m_owner, nullptr, GetModuleHandleW(nullptr), this);
        if (!m_hwnd) return {};
        const bool ownerWasEnabled = !EnableWindow(m_owner, FALSE);
        ShowWindow(m_hwnd, SW_SHOW);
        if (!m_edits.empty()) {
            SetFocus(m_edits.front());
            SendMessageW(m_edits.front(), EM_SETSEL, 0, -1);
        } else {
            SetFocus(GetDlgItem(m_hwnd, m_spec.cancelButton ? IDCANCEL : IDOK));
        }
        MSG msg;
        while (!m_done) {
            const BOOL got = GetMessageW(&msg, nullptr, 0, 0);
            if (got <= 0) {
                if (got == 0) PostQuitMessage(static_cast<int>(msg.wParam));
                break;
            }
            if (!IsDialogMessageW(m_hwnd, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if (ownerWasEnabled) EnableWindow(m_owner, TRUE);  // before destroying, so activation returns to the owner
        DestroyWindow(m_hwnd);
        return m_result;
    }

private:
    static void RegisterOnce() {
        WNDCLASSEXW wc{sizeof wc};
        if (GetClassInfoExW(GetModuleHandleW(nullptr), kClass, &wc)) return;
        wc.lpfnWndProc = Proc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
        wc.lpszClassName = kClass;
        RegisterClassExW(&wc);
    }

    static LRESULT CALLBACK Proc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
        Dialog* self = nullptr;
        if (message == WM_NCCREATE) {
            self = static_cast<Dialog*>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams);
            self->m_hwnd = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        } else {
            self = reinterpret_cast<Dialog*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        }
        if (message == WM_NCDESTROY) SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return self ? self->Handle(message, wParam, lParam) : DefWindowProcW(hwnd, message, wParam, lParam);
    }

    void Build() {
        ApplyBackdrop(m_hwnd);
        auto& g = Graphics::Get();
        m_fieldBrush.reset(CreateSolidBrush(g.GdiSurface(Color::Control)));
        for (std::size_t i = 0; i < m_spec.fields.size(); ++i) {
            const auto& field = m_spec.fields[i];
            HWND edit = CreateWindowExW(0, L"EDIT", field.value.c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 10,
                                        10, m_hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kFieldBase + i)), nullptr, nullptr);
            if (!field.cue.empty()) SendMessageW(edit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(field.cue.c_str()));
            SendMessageW(edit, EM_SETLIMITTEXT, 4096, 0);
            m_edits.push_back(edit);
        }
        if (!m_spec.monospace.empty()) {
            m_mono = CreateWindowExW(0, L"EDIT", nullptr,
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 0,
                                     10, 10, m_hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kMonospace)), nullptr, nullptr);
            SetWindowTheme(m_mono, L"DarkMode_Explorer", nullptr);
            std::wstring text;
            for (wchar_t c : m_spec.monospace) {  // the EDIT control wants CRLF
                if (c == L'\n') text += L'\r';
                text += c;
            }
            SetWindowTextW(m_mono, text.c_str());
        }
        auto button = [&](int id, const std::wstring& text, ButtonKind kind) {
            HWND b = CreateButton(m_hwnd, id, text.c_str());
            m_looks[b] = {kind, 0, false};
            m_buttons.push_back(b);
        };
        if (!m_spec.extra.empty()) button(kExtra, m_spec.extra, ButtonKind::Standard);
        button(IDOK, m_spec.ok.empty() ? Text::Get(IDS_OK) : m_spec.ok, ButtonKind::Accent);
        if (m_spec.cancelButton) button(IDCANCEL, m_spec.cancel.empty() ? Text::Get(IDS_CANCEL) : m_spec.cancel, ButtonKind::Standard);
        Layout();
        Revalidate();
    }

    void Layout() {
        const auto& f = m_fonts;
        m_editFont = MakeGdiFont(f, f.UiFamily(), 13.0f);
        m_monoFont = MakeGdiFont(f, f.MonoFamily(), 12.0f);
        // One width for every button, wide enough for the longest label (translations run longer);
        // the dialog grows when the buttons need it.
        const float pad = f.F(24), gapX = f.F(8);
        float bw = f.F(124);
        for (HWND b : m_buttons) {
            wchar_t text[128]{};
            GetWindowTextW(b, text, static_cast<int>(std::size(text)));
            bw = std::max(bw, std::ceil(TextWidth(f, Font::Body, text) + f.F(40)));
        }
        const float buttons = static_cast<float>(m_buttons.size());
        const float width = std::max(f.F(static_cast<float>(m_spec.width)), 2 * pad + buttons * bw + (buttons - 1) * gapX);
        const float inner = width - 2 * pad;
        float y = pad;
        m_headingRect = {pad, y, width - pad, y + f.F(28)};
        y += f.F(38);
        if (!m_spec.message.empty()) {
            const float h = TextHeight(f, Font::Body, m_spec.message, inner);
            m_messageRect = {pad, y, width - pad, y + h};
            y += h + f.F(16);
        }
        m_fieldRects.clear();
        m_labelRects.clear();
        for (std::size_t i = 0; i < m_edits.size(); ++i) {
            m_labelRects.push_back({pad, y, width - pad, y + f.F(18)});
            y += f.F(22);
            const D2D1_RECT_F box{pad, y, width - pad, y + f.F(34)};
            m_fieldRects.push_back(box);
            const int lineH = f.S(19);
            SetWindowPos(m_edits[i], nullptr, static_cast<int>(box.left + f.F(10)), static_cast<int>((box.top + box.bottom) / 2) - lineH / 2,
                         static_cast<int>(box.right - box.left - f.F(20)), lineH, SWP_NOZORDER | SWP_NOACTIVATE);
            SendMessageW(m_edits[i], WM_SETFONT, reinterpret_cast<WPARAM>(m_spec.fields[i].mono ? m_monoFont.get() : m_editFont.get()), TRUE);
            y += f.F(34) + f.F(8);
        }
        m_previewRect = {pad, y, width - pad, y + f.F(20)};
        y += m_edits.empty() ? 0 : f.F(26);
        if (m_mono) {
            const D2D1_RECT_F box{pad, y, width - pad, y + f.F(static_cast<float>(m_spec.monospaceHeight))};
            m_monoRect = box;
            SetWindowPos(m_mono, nullptr, static_cast<int>(box.left + f.F(8)), static_cast<int>(box.top + f.F(6)),
                         static_cast<int>(box.right - box.left - f.F(10)), static_cast<int>(box.bottom - box.top - f.F(12)),
                         SWP_NOZORDER | SWP_NOACTIVATE);
            SendMessageW(m_mono, WM_SETFONT, reinterpret_cast<WPARAM>(m_monoFont.get()), TRUE);
            y = box.bottom + f.F(16);
        }
        // Footer with the buttons, right-aligned, all the same width.
        const float footer = f.F(72);
        m_footer = {0, y, width, y + footer};
        const float bh = f.F(32);
        float x = width - pad;
        for (auto it = m_buttons.rbegin(); it != m_buttons.rend(); ++it) {
            x -= bw;
            SetWindowPos(*it, nullptr, static_cast<int>(x), static_cast<int>(y + (footer - bh) / 2), static_cast<int>(bw),
                         static_cast<int>(bh), SWP_NOZORDER | SWP_NOACTIVATE);
            x -= gapX;
        }
        RECT rc{0, 0, static_cast<LONG>(width), static_cast<LONG>(y + footer)};
        AdjustWindowRectExForDpi(&rc, static_cast<DWORD>(GetWindowLongPtrW(m_hwnd, GWL_STYLE)), FALSE,
                                 static_cast<DWORD>(GetWindowLongPtrW(m_hwnd, GWL_EXSTYLE)), f.dpi());
        RECT owner{};
        GetWindowRect(m_owner, &owner);
        const int w = rc.right - rc.left, h = rc.bottom - rc.top;
        SetWindowPos(m_hwnd, nullptr, owner.left + (owner.right - owner.left - w) / 2, owner.top + (owner.bottom - owner.top - h) / 3, w,
                     h, SWP_NOZORDER | SWP_NOACTIVATE);
    }

    std::vector<std::wstring> Values() const {
        std::vector<std::wstring> values;
        for (HWND e : m_edits) {
            const int n = GetWindowTextLengthW(e);
            std::wstring v(static_cast<std::size_t>(n) + 1, L'\0');
            GetWindowTextW(e, v.data(), n + 1);
            v.resize(static_cast<std::size_t>(n));
            const auto first = v.find_first_not_of(L" \t\"");
            const auto last = v.find_last_not_of(L" \t\"");
            values.push_back(first == std::wstring::npos ? std::wstring() : v.substr(first, last - first + 1));
        }
        return values;
    }

    void Revalidate() {
        const auto values = Values();
        m_error.clear();
        m_previewText.clear();
        if (m_spec.validate) {
            if (auto error = m_spec.validate(values)) m_error = *error;
        }
        if (m_error.empty() && m_spec.preview) m_previewText = m_spec.preview(values);
        EnableWindow(GetDlgItem(m_hwnd, IDOK), m_error.empty());
        const RECT r = ToRect(m_previewRect);
        InvalidateRect(m_hwnd, &r, FALSE);
    }

    void PaintSurface() {
        PaintScope ps(m_hwnd);
        RECT client{};
        GetClientRect(m_hwnd, &client);
        const auto& f = m_fonts;
        HWND focus = GetFocus();
        Paint(
            ps.dc(), client, f,
            [&](Canvas& c) {
                c.Clear(Graphics::Get().Base());
                c.Text(m_spec.heading, m_headingRect, Font::Title, m_spec.danger ? Color::Critical : Color::Text);
                if (!m_spec.message.empty()) c.Paragraph(m_spec.message, m_messageRect, Font::Body, Color::Text2);
                for (std::size_t i = 0; i < m_fieldRects.size(); ++i) {
                    c.Text(m_spec.fields[i].label, m_labelRects[i], Font::Caption, Color::Text2);
                    const D2D1_RECT_F& box = m_fieldRects[i];
                    c.Fill(box, Color::Control, f.F(4));
                    c.Stroke(box, Color::ControlStroke, f.F(4));
                    const bool focused = focus == m_edits[i];
                    c.Fill({box.left + f.F(1), box.bottom - f.F(focused ? 2.0f : 1.0f), box.right - f.F(1), box.bottom},
                           focused ? Color::AccentText : White(0.30f));
                }
                if (!m_error.empty()) c.Text(m_error, m_previewRect, Font::Caption, Color::Critical);
                else if (!m_previewText.empty()) c.Text(m_previewText, m_previewRect, Font::Caption, Color::AccentText);
                if (m_mono) {
                    c.Fill(m_monoRect, Color::Control, f.F(4));
                    c.Stroke(m_monoRect, Color::ControlStroke, f.F(4));
                }
                c.Fill(m_footer, Black(0.18f));
                c.Line({m_footer.left, m_footer.top + 0.5f}, {m_footer.right, m_footer.top + 0.5f}, White(0.06f));
            },
            [&](HDC dc) {
                // The EDIT controls paint with GDI; the padding around them is filled the same way so
                // field and control are one surface.
                for (const auto& box : m_fieldRects) {
                    const RECT r{static_cast<LONG>(box.left + f.F(3)), static_cast<LONG>(box.top + f.F(3)),
                                 static_cast<LONG>(box.right - f.F(3)), static_cast<LONG>(box.bottom - f.F(3))};
                    FillRect(dc, &r, m_fieldBrush.get());
                }
                if (m_mono) {
                    const RECT r{static_cast<LONG>(m_monoRect.left + f.F(3)), static_cast<LONG>(m_monoRect.top + f.F(3)),
                                 static_cast<LONG>(m_monoRect.right - f.F(3)), static_cast<LONG>(m_monoRect.bottom - f.F(3))};
                    FillRect(dc, &r, m_fieldBrush.get());
                }
            });
    }

    void Finish(int button) {
        auto values = Values();
        if (button == 1 && m_spec.validate) {
            if (auto error = m_spec.validate(values)) {
                m_error = *error;
                InvalidateRect(m_hwnd, nullptr, FALSE);
                return;
            }
        }
        m_result = {button, std::move(values)};
        m_done = true;
    }

    LRESULT Handle(UINT message, WPARAM wParam, LPARAM lParam) {
        switch (message) {
        case WM_CREATE:
            Build();
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT:
            PaintSurface();
            return 0;
        case WM_DPICHANGED:
            m_fonts.Create(HIWORD(wParam));
            Layout();
            InvalidateRect(m_hwnd, nullptr, TRUE);
            return 0;
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            SetTextColor(dc, ToColorRef(Color::Text));
            SetBkColor(dc, Graphics::Get().GdiSurface(Color::Control));
            return reinterpret_cast<LRESULT>(m_fieldBrush.get());
        }
        case WM_DRAWITEM: {
            const auto& dis = *reinterpret_cast<const DRAWITEMSTRUCT*>(lParam);
            if (auto it = m_looks.find(dis.hwndItem); it != m_looks.end()) DrawButton(dis, m_fonts, it->second);
            return TRUE;
        }
        case DM_GETDEFID:
            return MAKELRESULT(IDOK, DC_HASDEFID);
        case WM_COMMAND: {
            const int id = LOWORD(wParam), code = HIWORD(wParam);
            if (id >= kFieldBase && id < kFieldBase + 100) {
                if (code == EN_SETFOCUS || code == EN_KILLFOCUS) InvalidateRect(m_hwnd, nullptr, FALSE);
                if (code == EN_CHANGE) Revalidate();
                return 0;
            }
            if (id == IDOK) Finish(1);
            else if (id == IDCANCEL) Finish(m_spec.cancelButton ? 0 : 1);
            else if (id == kExtra) Finish(2);
            return 0;
        }
        case WM_CLOSE:
            Finish(m_spec.cancelButton ? 0 : 1);
            return 0;
        }
        return DefWindowProcW(m_hwnd, message, wParam, lParam);
    }

    HWND m_owner;
    const DialogSpec& m_spec;
    HWND m_hwnd = nullptr;
    Fonts m_fonts;
    Gdi<HFONT> m_editFont, m_monoFont;
    Gdi<HBRUSH> m_fieldBrush;
    std::vector<HWND> m_edits, m_buttons;
    HWND m_mono = nullptr;
    std::unordered_map<HWND, ButtonLook> m_looks;
    D2D1_RECT_F m_headingRect{}, m_messageRect{}, m_monoRect{}, m_previewRect{}, m_footer{};
    std::vector<D2D1_RECT_F> m_fieldRects, m_labelRects;
    std::wstring m_error, m_previewText;
    DialogResult m_result;
    bool m_done = false;
};

}  // namespace

DialogResult RunDialog(HWND owner, const DialogSpec& spec) {
    Dialog dialog(owner, spec);
    return dialog.Run();
}

bool Confirm(HWND owner, std::wstring heading, std::wstring message, std::wstring ok, bool danger) {
    DialogSpec spec;
    spec.heading = std::move(heading);
    spec.message = std::move(message);
    spec.ok = std::move(ok);
    spec.danger = danger;
    return RunDialog(owner, spec).button == 1;
}

std::optional<std::wstring> PickFile(HWND owner, bool save, const std::vector<FileFilter>& filters, const std::wstring& fileName,
                                     const wchar_t* extension) {
    ComPtr<IFileDialog> dialog;
    if (FAILED(CoCreateInstance(save ? CLSID_FileSaveDialog : CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                IID_PPV_ARGS(dialog.GetAddressOf())))) {
        return std::nullopt;
    }
    std::vector<COMDLG_FILTERSPEC> specs;
    for (const auto& f : filters) specs.push_back({f.name.c_str(), f.pattern.c_str()});
    if (!specs.empty()) dialog->SetFileTypes(static_cast<UINT>(specs.size()), specs.data());
    if (extension) dialog->SetDefaultExtension(extension);
    if (!fileName.empty()) dialog->SetFileName(fileName.c_str());
    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_FORCEFILESYSTEM | (save ? FOS_OVERWRITEPROMPT : FOS_FILEMUSTEXIST));
    if (FAILED(dialog->Show(owner))) return std::nullopt;
    ComPtr<IShellItem> item;
    if (FAILED(dialog->GetResult(item.GetAddressOf()))) return std::nullopt;
    PWSTR path = nullptr;
    if (FAILED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) || !path) return std::nullopt;
    std::wstring result(path);
    CoTaskMemFree(path);
    return result;
}

void Inform(HWND owner, std::wstring heading, std::wstring message, bool danger) {
    DialogSpec spec;
    spec.heading = std::move(heading);
    spec.message = std::move(message);
    spec.cancelButton = false;
    spec.danger = danger;
    RunDialog(owner, spec);
}

}  // namespace WS::Ui
