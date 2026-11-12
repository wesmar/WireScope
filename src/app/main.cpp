// WireScope - Modern C++23 Network Packet Monitor & Sniffer
// Entry point: routes between GUI and CLI based on command-line arguments.

#include "app/Cli.h"
#include "gui/MainWindow.h"
#include "support/Common.h"
#include <Windows.h>
#include <objbase.h>
#include <shellapi.h>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comdlg32.lib")

namespace {

class ComApartment {
public:
    ComApartment() noexcept : m_hr(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)) {}
    ~ComApartment() { if (SUCCEEDED(m_hr)) CoUninitialize(); }
    ComApartment(const ComApartment&) = delete;
    ComApartment& operator=(const ComApartment&) = delete;

private:
    HRESULT m_hr;
};

} // namespace

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPWSTR /*lpCmdLine*/, int nShowCmd) {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    // If command-line arguments are provided, process in CLI mode
    if (argc > 1) {
        const int exitCode = WS::Cli::Run(argc, argv);
        LocalFree(argv);
        return exitCode;
    }
    LocalFree(argv);

    // Otherwise launch Graphical User Interface
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    ComApartment com;
    WS::Ui::MainWindow window(hInstance);
    if (!window.Create(nShowCmd)) {
        return 1;
    }

    return window.Run();
}
