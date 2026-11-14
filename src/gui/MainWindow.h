// WireScope - Main window: Mica backdrop, Per-Monitor-V2 aware, navigation rail with five pages
// (Capture, Processes, Firewall, Simulator, Network driver), the kill switch and a live status strip.
#pragma once
#include "core/DriverBridge.h"
#include "core/DriverSetup.h"
#include "core/ProcessMapper.h"
#include "core/TrafficController.h"
#include "gui/Menus.h"
#include "gui/PacketDetails.h"
#include "gui/PacketList.h"
#include "gui/ProcessList.h"
#include "gui/RuleList.h"
#include "gui/Theme.h"
#include "gui/Widgets.h"
#include "support/Common.h"
#include "support/Language.h"
#include <Windows.h>
#include <array>
#include <deque>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace WS::Ui {

class MainWindow {
public:
    explicit MainWindow(HINSTANCE instance);
    ~MainWindow();

    MainWindow(const MainWindow&) = delete;
    MainWindow& operator=(const MainWindow&) = delete;

    bool Create(int showCommand);
    int Run();

private:
    enum class Page { Capture, Firewall, Simulator, Processes, Driver };  // saved as a number: append only

    static LRESULT CALLBACK Proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT Handle(UINT msg, WPARAM wParam, LPARAM lParam);

    // Construction, layout, painting (MainWindow.cpp / MainWindowLayout.cpp)
    void OnCreate();
    void BuildAccelerators();
    void CreateFieldResources();
    void Layout();
    void Paint();
    void PaintHeader(Canvas& c);
    void PaintStatus(Canvas& c);
    void PaintCapture(Canvas& c);
    void PaintFirewall(Canvas& c);
    void PaintSimulator(Canvas& c);
    void PaintProcesses(Canvas& c);
    void PaintProcessDetails(Canvas& c);
    void PaintDriver(Canvas& c);
    void PaintField(Canvas& c, const D2D1_RECT_F& box, HWND edit, bool onCard, bool error = false);
    void PaintCard(Canvas& c, const D2D1_RECT_F& card, const std::wstring& title, const std::wstring& note = {});
    void PaintChart(Canvas& c, const D2D1_RECT_F& r, const std::wstring& title, const std::deque<double>& values,
                    const std::wstring& unit, bool bars, D2D1_COLOR_F color);
    void FillFieldsGdi(HDC dc);
    void ShowPage(Page page);
    void RestorePlacement(int showCommand);
    void SavePlacement();
    [[nodiscard]] int MinClientWidth() const;
    [[nodiscard]] int MinClientHeight() const;

    // State (MainWindowState.cpp)
    void ConnectDriver();
    void UpdateDriverPrompt(bool notifyStatus = true);
    void RefreshAdapters();
    void UpdateControls();
    void SetStatus(Level level, std::wstring text);
    bool Report(const std::expected<void, std::wstring>& result, const wchar_t* heading);
    void OnTimer();
    void PullPackets();
    void RebuildView();
    [[nodiscard]] bool PassesFilter(const DecodedPacket& p) const;
    void RefreshRuleRows();
    void SampleSimulator();
    void LoadSettings();
    void SaveRules();
    void SaveSimulator();
    void SyncSimulatorControls();
    void InvalidateArea(const D2D1_RECT_F& r);

    // Commands (MainWindowCommands.cpp)
    void OnCommand(UINT id, UINT code, HWND control);
    void ShowAdapterMenu();
    void SelectAdapter(size_t index);
    void SetCapture(bool on);
    void ClearCapture();
    void SavePcap(bool selected);
    void ToggleKillSwitch();
    void ToggleFirewall();
    void ShowPolicyMenu();
    void SetPolicy(RuleAction policy);
    bool AddRule(std::wstring initial = {});
    void EditRule();
    void RemoveRule();
    void MoveRule(int delta);
    void ToggleRule();
    void ImportRules();
    void ExportRules();
    void ToggleOffload();
    bool PushRules(std::vector<Rule> rules);
    void ToggleSimulator();
    void ShowPresetMenu();
    void ResetSimulator();
    void SetDirection(Dir dir);
    void OnMatchChanged();
    void ApplyProfile();
    void ShowContextMenu(HWND target, POINT screen);
    void ShowLanguageMenu();
    void SetLanguage(UINT command);
    void ApplyLanguage();
    void ShowAbout();
    void ApplyPreset(size_t index);
    void CopySummaries();  // the selected packets, else the focused one
    void RestartElevated();
    // Safety net for changes that can cut the network off (kill switch, risky firewall rules):
    // they are undone after kRevertSeconds unless the user keeps them.
    enum class Guarded { None, KillSwitch, Firewall };
    void ArmRevert(Guarded what, std::function<void()> undo);
    void KeepChanges();
    void UndoChanges(bool automatic);
    [[nodiscard]] bool ConfirmRisks(const std::vector<Rule>& rules, RuleAction policy);
    [[nodiscard]] std::optional<std::wstring> RuleDialog(const std::wstring& heading, const std::wstring& text, const std::wstring& ok);

    // Processes (MainWindowProcesses.cpp)
    void RefreshProcesses();
    void ToggleMonitor();
    void ResetProcessCounters();
    void BlockProcess();
    void LimitProcess();
    void ImpairProcess();
    void ShowProcessPackets();
    void OpenProcessFolder();
    void CopyProcessPath();
    [[nodiscard]] std::shared_ptr<const ProcessInfo> SelectedProcess() const;
    [[nodiscard]] static bool Actionable(const ProcessInfo* process);  // can be named in a rule
    [[nodiscard]] std::string AppToken(const ProcessInfo& process) const;  // "app NAME" or "app PATH"

    // Network driver (MainWindowDriver.cpp)
    struct DriverJobResult;
    void RefreshDriver();
    void RunDriverJob(UINT doing, std::wstring done, std::function<std::expected<DriverSetup::Outcome, std::wstring>()> work, bool release);
    void OnDriverJobDone(LPARAM lParam);
    void ReleaseDriver();   // everything off, the driver closed: before it is changed
    void RestoreMonitor();  // the saved per-program counting, once the driver is open
    void DriverAction(UINT command);
    void ShowStartTypeMenu();
    void UpdateDriverControls();

    HINSTANCE m_instance{nullptr};
    HWND m_hwnd{nullptr};
    Fonts m_fonts;
    AccelHandle m_accel;
    IconHandle m_icon, m_smallIcon;
    std::unordered_map<UINT, ButtonLook> m_looks;
    std::vector<Text::Language> m_languages;  // the language menu's order
    Page m_page{Page::Capture};
    bool m_closing{false};

    // Child controls
    PacketList m_list{m_fonts};
    PacketDetails m_details{m_fonts};
    RuleList m_rules{m_fonts};
    ProcessList m_procList{m_fonts};
    Slider m_latency{m_fonts}, m_jitter{m_fonts}, m_loss{m_fonts}, m_rate{m_fonts};
    HWND m_filterEdit{nullptr}, m_matchEdit{nullptr};
    Gdi<HFONT> m_editFont, m_monoFont;
    Gdi<HBRUSH> m_fieldBrush, m_cardFieldBrush;

    // Layout (client pixels)
    D2D1_RECT_F m_header{}, m_nav{}, m_content{}, m_status{}, m_banner{};
    D2D1_RECT_F m_filterBox{}, m_listCard{}, m_detailsCard{}, m_splitter{};
    D2D1_RECT_F m_rulesCard{};
    D2D1_RECT_F m_condCard{}, m_liveCard{}, m_matchBox{}, m_matchHint{};
    std::array<D2D1_RECT_F, 4> m_sliderRows{};
    D2D1_RECT_F m_dirRow{}, m_matchRow{}, m_tiles{}, m_delayChart{}, m_dropChart{}, m_throughputChart{};
    D2D1_RECT_F m_procSummary{}, m_procCard{}, m_procDetailsCard{}, m_procDetailsBody{};
    D2D1_RECT_F m_drvCard{};
    float m_split{0.58f};
    bool m_dragSplit{false};

    // Core
    std::shared_ptr<DriverBridge> m_bridge;
    std::unique_ptr<TrafficController> m_ctl;
    std::vector<AdapterDescription> m_adapters;
    size_t m_adapterIndex{0};
    bool m_driverOk{false};
    std::wstring m_driverText;

    // Capture view
    uint64_t m_lastIndex{0};
    uint64_t m_clearGeneration{0};
    uint64_t m_baseTime{0};
    std::wstring m_filter;
    EngineStats m_stats{};

    // Firewall
    std::vector<Rule> m_ruleSet;  // the edited list (pushed to the controller)
    RuleAction m_policy{RuleAction::Allow};
    bool m_offload{true};
    FirewallStatus m_fw{};

    // Simulator
    ImpairmentProfile m_profile;
    bool m_profileDirty{false};
    std::wstring m_matchError;
    std::deque<double> m_delayHistory, m_dropHistory, m_throughputHistory;
    uint64_t m_lastDelayed{0}, m_lastDelaySum{0}, m_lastDropped{0}, m_lastSimBytes{0};
    uint64_t m_lastSampleUs{0};
    int m_tick{0};

    // Processes
    struct ProcessRate {
        uint64_t bytesIn = 0, bytesOut = 0;
        double rateIn = 0, rateOut = 0;  // bytes per second, smoothed
    };
    struct ProcessState {
        bool running = true;
        uint64_t checkedAt = 0;  // GetTickCount64 of the last liveness check
    };
    std::shared_ptr<const ProcessMapper::Snapshot> m_procSnapshot;
    std::unordered_map<uint32_t, std::shared_ptr<const ProcessInfo>> m_procInfo;  // by id: the listed processes
    std::unordered_map<uint32_t, ProcessRate> m_procRates;
    std::unordered_map<uint32_t, ProcessState> m_procStates;
    uint64_t m_procSampleUs{0};
    double m_procIn{0}, m_procOut{0};  // all programs, bytes per second
    size_t m_procCount{0};
    int m_procAlerts{0};               // running programs that look suspicious

    // Automatic undo
    Guarded m_guarded{Guarded::None};
    std::function<void()> m_undo;
    uint64_t m_revertAt{0};  // GetTickCount64 deadline, 0 = nothing pending

    // Status strip
    Level m_statusLevel{Level::Info};
    std::wstring m_statusText;
    uint64_t m_statusUntil{0};

    // Network driver
    DriverSetup::Status m_drvStatus;
    bool m_drvKnown{false};
    UINT m_drvDoing{0};       // string id of the running job, 0 = idle
    std::jthread m_drvThread;  // last member: joined before the rest is destroyed
};

}  // namespace WS::Ui
