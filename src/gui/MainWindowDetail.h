// WireScope - Internal to the MainWindow*.cpp files: command identifiers, layout constants, buttons.
#pragma once
#include "gui/Widgets.h"
#include "resources/resource.h"
#include "support/Language.h"
#include <algorithm>
#include <cmath>
#include <string>
#include <Windows.h>

namespace WS::Ui::MainWindowDetail {

inline constexpr wchar_t kClassName[] = L"WireScope.MainWindow";
inline constexpr wchar_t kAppVersion[] = L"2.0";
inline constexpr wchar_t kCopyright[] = L"\u00A9 2026 Marek Weso\u0142owski - wesmar";
inline constexpr wchar_t kGitHubRepo[] = L"wesmar/WireScope";
inline constexpr UINT_PTR kUiTimer = 1;
inline constexpr UINT kUiTimerMs = 100;
inline constexpr int kSlowTicks = 5;  // every 500 ms: firewall counters, simulator history
inline constexpr int kRevertSeconds = 20;  // changes that can cut the network off are undone unless kept
inline constexpr UINT kDriverJobDone = WM_APP + 1;  // lParam: MainWindow::DriverJobResult*, owned by the window

enum Command : UINT {
    // Header and navigation
    CmdAdapter = 1000, CmdPageCapture, CmdPageProcesses, CmdPageFirewall, CmdPageSimulator, CmdPageDriver, CmdKill, CmdAbout, CmdLanguage, CmdElevate,
    CmdKeepChanges, CmdUndoChanges,
    // Capture
    CmdStart, CmdStop, CmdClear, CmdSave, CmdFocusFilter, CmdToggleCapture,
    // Processes
    CmdProcMonitor, CmdProcReset, CmdProcBlock, CmdProcLimit, CmdProcImpair, CmdProcPackets, CmdProcFolder,
    // Firewall
    CmdFwToggle, CmdFwPolicy, CmdFwAdd, CmdFwImport, CmdFwExport, CmdFwEdit, CmdFwRemove, CmdFwUp, CmdFwDown, CmdFwOffload,
    // Simulator
    CmdSimToggle, CmdSimPreset, CmdSimReset, CmdDirBoth, CmdDirIn, CmdDirOut, CmdSimOrder,
    // Network driver
    CmdDrvInstall, CmdDrvUninstall, CmdDrvStart, CmdDrvStop, CmdDrvStartType, CmdDrvRefresh, CmdDrvCopy,
    // Menus
    CmdCopySummary = 1200, CmdCopyDetails, CmdCopyHex, CmdFilterSource, CmdFilterDestination, CmdFilterHost, CmdFilterProtocol,
    CmdClearFilter, CmdBlockRemote, CmdImpairRemote, CmdPolicyAllow, CmdPolicyBlock, CmdRefreshAdapters, CmdSaveSelected, CmdSelectAll,
    CmdAdapterFirst = 1300, CmdAdapterLast = 1363,
    CmdPresetFirst = 1400, CmdPresetLast = 1431,
    CmdLanguageAuto = 1500, CmdLanguageFirst, CmdLanguageLast = 1599,
    CmdRuleEnable = 1600, CmdRuleDisable,
    CmdProcCopyPath = 1700,
    CmdDrvTypeFirst = 1800, CmdDrvTypeLast = 1803,  // system, automatic, manual, disabled
};

inline constexpr int kIdFilter = 2000, kIdPackets = 2001, kIdDetails = 2002, kIdRules = 2003, kIdLatency = 2004, kIdJitter = 2005,
                     kIdLoss = 2006, kIdMatch = 2007, kIdRate = 2008, kIdProcesses = 2009;

// Bandwidth limit as people read it: "unlimited", "384 kbit/s", "20.0 Mbit/s".
inline std::wstring RateText(uint32_t kbps) {
    if (kbps == 0) return Text::Get(IDS_VALUE_UNLIMITED);
    if (kbps < 1000) return Text::Format(IDS_VALUE_KBPS, kbps);
    return Text::Format(IDS_VALUE_MBPS, static_cast<double>(kbps) / 1000.0);
}

// Slider position to a bandwidth that reads well: coarser steps the faster the link.
inline uint32_t RoundRate(double kbps) {
    const double step = kbps < 100 ? 1 : kbps < 1000 ? 8 : kbps < 10000 ? 100 : kbps < 100000 ? 1000 : 10000;
    return static_cast<uint32_t>(std::max(0.0, std::round(kbps / step) * step));
}

// Layout, in DIP (scaled with the window DPI).
inline constexpr float kMargin = 12, kNavW = 204, kHeaderH = 56, kStatusH = 34, kCmdH = 32, kGap = 10, kPad = 16;
inline constexpr float kNavItemH = 40, kCardHeaderH = 40, kRowH = 46;

struct ButtonSpec {
    UINT id;
    UINT text;  // string id, 0 = set at runtime
    ButtonLook look;
};

inline const ButtonSpec kButtons[] = {
    {CmdAdapter, 0, {ButtonKind::Combo, Icon::Network}},
    {CmdPageCapture, IDS_NAV_CAPTURE, {ButtonKind::Nav, Icon::Search}},
    {CmdPageProcesses, IDS_NAV_PROCESSES, {ButtonKind::Nav, Icon::Apps}},
    {CmdPageFirewall, IDS_NAV_FIREWALL, {ButtonKind::Nav, Icon::Shield}},
    {CmdPageSimulator, IDS_NAV_SIMULATOR, {ButtonKind::Nav, Icon::Speed}},
    {CmdPageDriver, IDS_NAV_DRIVER, {ButtonKind::Nav, Icon::Repair}},
    {CmdKill, IDS_KILL, {ButtonKind::Danger, Icon::Power}},
    {CmdLanguage, IDS_LANGUAGE, {ButtonKind::Nav, Icon::Language}},
    {CmdAbout, IDS_NAV_ABOUT, {ButtonKind::Nav, Icon::Info}},
    {CmdElevate, IDS_ELEVATE, {ButtonKind::Accent, Icon::Admin}},
    {CmdKeepChanges, IDS_REVERT_KEEP, {ButtonKind::Accent, Icon::Check}},
    {CmdUndoChanges, IDS_REVERT_UNDO, {ButtonKind::Standard, Icon::Refresh}},

    {CmdStart, IDS_START, {ButtonKind::Accent, Icon::Play}},
    {CmdStop, IDS_STOP, {ButtonKind::Standard, Icon::Stop}},
    {CmdClear, IDS_CLEAR, {ButtonKind::Standard, Icon::Clear}},
    {CmdSave, IDS_SAVE_PCAP, {ButtonKind::Standard, Icon::Save}},

    {CmdProcMonitor, IDS_PROC_MONITOR, {ButtonKind::Toggle}},
    {CmdProcReset, IDS_PROC_RESET, {ButtonKind::Standard, Icon::Refresh}},
    {CmdProcBlock, IDS_PROC_BLOCK, {ButtonKind::Standard, Icon::Blocked, true}},
    {CmdProcLimit, IDS_PROC_LIMIT, {ButtonKind::Standard, Icon::Speed, true}},
    {CmdProcImpair, IDS_PROC_IMPAIR, {ButtonKind::Standard, Icon::Globe, true}},
    {CmdProcPackets, IDS_PROC_PACKETS, {ButtonKind::Standard, Icon::Search, true}},
    {CmdProcFolder, IDS_PROC_FOLDER, {ButtonKind::Standard, Icon::Folder, true}},

    {CmdFwToggle, IDS_FW_TOGGLE, {ButtonKind::Toggle}},
    {CmdFwPolicy, 0, {ButtonKind::Combo, Icon::Filter}},
    {CmdFwAdd, IDS_FW_ADD, {ButtonKind::Accent, Icon::Add}},
    {CmdFwImport, IDS_FW_IMPORT, {ButtonKind::Standard, Icon::Import}},
    {CmdFwExport, IDS_FW_EXPORT, {ButtonKind::Standard, Icon::Export}},
    {CmdFwEdit, IDS_FW_EDIT, {ButtonKind::Standard, Icon::Edit}},
    {CmdFwRemove, IDS_FW_REMOVE, {ButtonKind::Standard, Icon::Delete}},
    {CmdFwUp, IDS_FW_UP, {ButtonKind::Standard, Icon::ArrowUp}},
    {CmdFwDown, IDS_FW_DOWN, {ButtonKind::Standard, Icon::ArrowDown}},
    {CmdFwOffload, IDS_FW_OFFLOAD, {ButtonKind::Toggle}},

    {CmdSimToggle, IDS_SIM_TOGGLE, {ButtonKind::Toggle}},
    {CmdSimPreset, IDS_SIM_PRESETS, {ButtonKind::Combo, Icon::Globe}},
    {CmdSimReset, IDS_SIM_RESET, {ButtonKind::Standard, Icon::Refresh}},
    {CmdDirBoth, IDS_DIR_BOTH, {ButtonKind::Segment, 0, true}},
    {CmdDirIn, IDS_DIR_IN, {ButtonKind::Segment, Icon::ArrowDown, true}},
    {CmdDirOut, IDS_DIR_OUT, {ButtonKind::Segment, Icon::ArrowUp, true}},
    {CmdSimOrder, IDS_SIM_ORDER, {ButtonKind::Toggle, 0, true}},

    {CmdDrvInstall, IDS_DRV_INSTALL, {ButtonKind::Accent, Icon::Add}},
    {CmdDrvUninstall, IDS_DRV_UNINSTALL, {ButtonKind::Standard, Icon::Delete}},
    {CmdDrvStart, IDS_DRV_START, {ButtonKind::Standard, Icon::Play}},
    {CmdDrvStop, IDS_DRV_STOP, {ButtonKind::Standard, Icon::Stop}},
    {CmdDrvStartType, 0, {ButtonKind::Combo, Icon::Power}},
    {CmdDrvRefresh, IDS_DRV_REFRESH, {ButtonKind::Standard, Icon::Refresh}},
    {CmdDrvCopy, IDS_DRV_COPY, {ButtonKind::Standard, Icon::Copy}},
};

}  // namespace WS::Ui::MainWindowDetail
