// GuardDog 前端（阶段三）：主窗口 + 托盘图标。
//
// 启动模式由配置文件决定（settings.startup_mode），启动时读取一次：
//   gui    —— 显示主窗口
//   hidden —— 纯隐藏：不显示任何窗口，仅驻留托盘图标；双击托盘或右键"显示主窗口"可唤出
//
// 设计取向：这是一个"看得见"的通道，不是第二个控制台。
//   - 只提供查询类动作（状态、日志、只读扫描）与"临时放行"这一个干预类动作；
//   - 刻意不提供"删除/终止"类命令：前端以普通用户身份运行，
//     把危险动作经管道暴露出去等于给本机任何进程开了一个提权后门；
//   - 关闭主窗口只是隐藏到托盘，不会停止防护服务；退出程序也不影响服务。
//
// 编译为 GUI 子系统，入口 wWinMain，无控制台窗口。

#include <windows.h>
#include <shellapi.h>

#include <string>
#include <vector>

#include "Core/Constants.h"
#include "Core/IPC.h"
#include "Core/Json.h"
#include "UI/RuleManager.h"

#pragma comment(lib, "shell32.lib")

namespace {

constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayCallbackMessage = WM_APP + 1;
constexpr wchar_t kWindowClassName[] = L"GuardDogMainWindow";
constexpr wchar_t kRunKeyPath[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr wchar_t kRunValueName[] = L"GuardDogUI";

constexpr int kWindowWidth = 1020;
constexpr int kWindowHeight = 740;
constexpr int kMinWindowWidth = 920;
constexpr int kMinWindowHeight = 620;
constexpr int kUiFontSize = 10;   // 窗口放大后字号同步放大，避免显得空旷

// 控件与命令 ID（托盘菜单复用同一套 ID，命令处理只需写一份）
enum ControlId : int {
    kIdStatusText = 2000,
    kIdLogEdit,
    kIdRefresh = 2010,
    kIdFullLog,
    kIdScan,
    kIdConfig,
    kIdAllowLast,
    kIdWatchdog,
    kIdServiceCtrl,
    kIdHide,
    kIdAbout,
    kIdExit,
    kIdRules,   // 规则管理（可视化配置）
};

HWND g_mainWindow = nullptr;
HWND g_statusText = nullptr;
HWND g_logEdit = nullptr;
HWND g_serviceButton = nullptr;  // 文字随服务状态在"启动服务/停止服务"间切换
std::vector<HWND> g_buttons;
NOTIFYICONDATAW g_trayData{};
bool g_startedHidden = false;
HFONT g_uiFont = nullptr;    // 界面字体
HFONT g_monoFont = nullptr;  // 日志字体

// ---------------------------------------------------------------------------
// 字体
//
// 不用 DEFAULT_GUI_FONT：那是上世纪的 System 字体，中文落到宋体点阵上，
// 没有抗锯齿，看起来是明显的"像素风"。
// 优先选 Microsoft YaHei UI（Win10/11 的系统 UI 字体），退回雅黑、Segoe UI，
// 全都没有才回退到系统默认——保证在任何系统上都不至于没字体可用。
// ---------------------------------------------------------------------------

bool IsFontAvailable(const wchar_t* faceName) {
    HDC deviceContext = GetDC(nullptr);
    if (deviceContext == nullptr) {
        return false;
    }

    LOGFONTW query{};
    query.lfCharSet = DEFAULT_CHARSET;
    wcscpy_s(query.lfFaceName, faceName);

    bool found = false;
    EnumFontFamiliesExW(
        deviceContext, &query,
        [](const LOGFONTW*, const TEXTMETRICW*, DWORD, LPARAM parameter) -> int {
            *reinterpret_cast<bool*>(parameter) = true;
            return 0;  // 找到一个就停
        },
        reinterpret_cast<LPARAM>(&found), 0);

    ReleaseDC(nullptr, deviceContext);
    return found;
}

HFONT CreateFontBySize(const wchar_t* faceName, int pointSize, bool monospaced) {
    LOGFONTW logFont{};
    HDC deviceContext = GetDC(nullptr);
    logFont.lfHeight =
        -MulDiv(pointSize, GetDeviceCaps(deviceContext, LOGPIXELSY), 72);  // 按 DPI 换算
    ReleaseDC(nullptr, deviceContext);

    logFont.lfWeight = FW_NORMAL;
    logFont.lfCharSet = DEFAULT_CHARSET;
    logFont.lfQuality = CLEARTYPE_QUALITY;  // 关键：开启抗锯齿，消除点阵颗粒感
    logFont.lfPitchAndFamily = monospaced ? FIXED_PITCH : VARIABLE_PITCH;
    wcscpy_s(logFont.lfFaceName, faceName);

    HFONT font = CreateFontIndirectW(&logFont);
    if (font != nullptr) {
        return font;
    }
    return static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
}

const wchar_t* PickUiFace() {
    if (IsFontAvailable(L"Microsoft YaHei UI")) {
        return L"Microsoft YaHei UI";
    }
    if (IsFontAvailable(L"Microsoft YaHei")) {
        return L"Microsoft YaHei";
    }
    if (IsFontAvailable(L"Segoe UI")) {
        return L"Segoe UI";
    }
    return L"Tahoma";
}

void CreateFonts() {
    g_uiFont = CreateFontBySize(PickUiFace(), kUiFontSize, false);
    // 日志区用等宽字体更好读（时间戳与级别能对齐）；
    // Consolas 不含中文，找不到时退回界面字体，避免中文回退成点阵宋体。
    const wchar_t* logFace = IsFontAvailable(L"Consolas") ? L"Consolas" : PickUiFace();
    g_monoFont = CreateFontBySize(logFace, kUiFontSize, true);
}

void DestroyFonts() {
    if (g_uiFont != nullptr) {
        DeleteObject(g_uiFont);
        g_uiFont = nullptr;
    }
    if (g_monoFont != nullptr) {
        DeleteObject(g_monoFont);
        g_monoFont = nullptr;
    }
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

// 取自身 exe 路径。
// 自己实现而不复用 ServiceInstaller 的同名函数：前端以普通用户运行，
// 不该为了一个取路径的动作去链接整套服务安装逻辑。
std::wstring GetSelfPath() {
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        const DWORD length =
            GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length == 0) {
            return std::wstring();
        }
        if (length < path.size() - 1) {
            path.resize(length);
            return path;
        }
        path.resize(path.size() * 2);
    }
}

std::wstring ConfigPath() {
    return std::wstring(GuardDog::Constants::kProgramDataDir) + L"\\" +
           GuardDog::Constants::kConfigFileName;
}

// 启动时读取启动模式。读不到或取值异常都回退到 gui——
// 前端是用户的可见通道，宁可多显示一个窗口，也不要让用户找不到入口。
std::wstring ReadStartupMode() {
    std::wstring error;
    const GuardDog::JsonValue root = GuardDog::JsonValue::ParseFile(ConfigPath(), &error);
    if (root.IsNull()) {
        return L"gui";
    }
    return root.Find(L"settings").Find(L"startup_mode").AsString(L"gui");
}

void ShowInfo(const std::wstring& text, UINT flags = MB_OK | MB_ICONINFORMATION) {
    MessageBoxW(g_mainWindow != nullptr && IsWindowVisible(g_mainWindow) ? g_mainWindow : nullptr,
                text.c_str(), L"GuardDog", flags | MB_SETFOREGROUND);
}

// 与服务通信。
// showError 用于区分两类调用方：
//   - 用户主动点按钮（扫描、放行）失败时必须弹框说明，否则会有"点了没反应"的困惑；
//   - 状态区/日志区的自动刷新失败则不弹框——状态区本来就能显示原因，
//     而且刚点完"停止服务"再刷新就弹一个错误框，会把正常操作渲染成"出故障了"。
bool SendCommand(const std::wstring& request, std::wstring& response, bool showError = true) {
    if (!GuardDog::IpcClient::Send(request, response)) {
        if (showError) {
            ShowInfo(L"无法连接到 GuardDog 服务。\n\n"
                     L"可能的原因：\n"
                     L"  - 主服务未安装或未启动（可用界面上的「启动服务」按钮）\n"
                     L"  - 服务正在重启中，稍后重试",
                     MB_OK | MB_ICONWARNING);
        }
        return false;
    }
    return true;
}

UINT FlagsForResponse(const std::wstring& response) {
    return MB_OK | (response.rfind(L"ERR|", 0) == 0 ? MB_ICONWARNING : MB_ICONINFORMATION);
}

// 把 "OK|" / "ERR|" 之后的内容取出来展示
std::wstring StripStatusPrefix(const std::wstring& response) {
    const size_t separator = response.find(L'|');
    return separator == std::wstring::npos ? response : response.substr(separator + 1);
}

// ---------------------------------------------------------------------------
// 窗口布局
// ---------------------------------------------------------------------------

void CreateControls(HWND window) {
    const HFONT uiFont = (g_uiFont != nullptr) ? g_uiFont
                                               : static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    const HFONT logFont = (g_monoFont != nullptr) ? g_monoFont : uiFont;

    g_statusText = CreateWindowExW(0, L"STATIC", L"正在读取状态…",
                                   WS_CHILD | WS_VISIBLE | SS_LEFT | SS_SUNKEN, 0, 0, 0, 0, window,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdStatusText)),
                                   nullptr, nullptr);

    g_logEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                                    ES_READONLY | ES_AUTOVSCROLL,
                                0, 0, 0, 0, window,
                                reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdLogEdit)), nullptr,
                                nullptr);

    struct ButtonSpec {
        int id;
        const wchar_t* text;
    };
    const ButtonSpec specs[] = {
        {kIdRefresh, L"刷新状态"},     {kIdFullLog, L"完整日志"},
        {kIdScan, L"手动扫描"},        {kIdRules, L"规则管理"},
        {kIdAllowLast, L"临时放行"},   {kIdWatchdog, L"看门狗"},
        {kIdServiceCtrl, L"启动服务"}, {kIdHide, L"隐藏到托盘"},
        {kIdExit, L"退出"},
    };

    for (const ButtonSpec& spec : specs) {
        HWND button = CreateWindowExW(0, L"BUTTON", spec.text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                      0, 0, 0, 0, window,
                                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(spec.id)),
                                      nullptr, nullptr);
        if (button != nullptr) {
            SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont), TRUE);
            g_buttons.push_back(button);
            if (spec.id == kIdServiceCtrl) {
                g_serviceButton = button;
            }
        }
    }

    if (g_statusText != nullptr) {
        SendMessageW(g_statusText, WM_SETFONT, reinterpret_cast<WPARAM>(uiFont), TRUE);
    }
    if (g_logEdit != nullptr) {
        SendMessageW(g_logEdit, WM_SETFONT, reinterpret_cast<WPARAM>(logFont), TRUE);
    }
}

void LayoutControls(HWND /*window*/, int width, int height) {
    constexpr int margin = 10;
    constexpr int statusHeight = 96;
    constexpr int buttonHeight = 34;
    constexpr int buttonWidth = 106;  // 9 个按钮 + 8 个间隔要能放进 1020 宽的窗口
    constexpr int gap = 6;

    if (g_statusText != nullptr) {
        MoveWindow(g_statusText, margin, margin, width - margin * 2, statusHeight, TRUE);
    }

    const int logTop = margin + statusHeight + gap;
    const int logHeight = height - logTop - buttonHeight - margin * 2 - gap;
    if (g_logEdit != nullptr) {
        MoveWindow(g_logEdit, margin, logTop, width - margin * 2,
                   logHeight > 60 ? logHeight : 60, TRUE);
    }

    int x = margin;
    const int y = height - buttonHeight - margin;
    for (HWND button : g_buttons) {
        MoveWindow(button, x, y, buttonWidth, buttonHeight, TRUE);
        x += buttonWidth + gap;
    }
}

// ---------------------------------------------------------------------------
// 命令处理
// ---------------------------------------------------------------------------

// 前向声明：RefreshStatus 需要先查询服务状态来决定按钮文字
bool IsMainServiceRunning();
void ControlMainService(bool start);

void RefreshStatus() {
    // 按钮文字跟着服务状态走，用户一眼就知道点下去会发生什么
    if (g_serviceButton != nullptr) {
        SetWindowTextW(g_serviceButton, IsMainServiceRunning() ? L"停止服务" : L"启动服务");
    }

    std::wstring response;
    if (!SendCommand(L"STATUS", response, false)) {
        // 静默失败：在状态区把原因和下一步说清楚，而不是弹模态框打断用户
        if (g_statusText != nullptr) {
            SetWindowTextW(g_statusText,
                           IsMainServiceRunning()
                               ? L"防护服务正在启动中…请稍后点击「刷新状态」。"
                               : L"防护服务当前未运行。\r\n\r\n"
                                 L"点击下方的「启动服务」即可恢复防护（会弹出 UAC 授权窗口）。\r\n"
                                 L"若尚未安装服务，请以管理员身份执行：\r\n"
                                 L"    GuardDogService.exe install");
        }
        return;
    }
    if (g_statusText != nullptr) {
        const std::wstring text = StripStatusPrefix(response);
        SetWindowTextW(g_statusText, text.c_str());
    }
}

void RefreshLog() {
    std::wstring response;
    if (!SendCommand(L"LOG|200", response, false)) {
        return;  // 日志拉取失败不打扰用户，状态区已经说明了服务状态
    }
    if (g_logEdit != nullptr) {
        const std::wstring text = StripStatusPrefix(response);
        SetWindowTextW(g_logEdit, text.c_str());
        // 滚到底部，让用户直接看到最新记录
        SendMessageW(g_logEdit, EM_SETSEL, 0, -1);
        SendMessageW(g_logEdit, EM_SETSEL, static_cast<WPARAM>(-1), static_cast<LPARAM>(-1));
        SendMessageW(g_logEdit, EM_SCROLLCARET, 0, 0);
    }
}

void OpenFullLog() {
    std::wstring response;
    if (!SendCommand(L"LOG|500", response)) {
        return;
    }
    if (response.rfind(L"ERR|", 0) == 0) {
        ShowInfo(StripStatusPrefix(response), MB_OK | MB_ICONWARNING);
        return;
    }

    // 写到临时文件再用记事本打开：比自绘只读窗口更实用（可搜索、可复制）
    wchar_t tempPath[MAX_PATH] = {};
    GetTempPathW(_countof(tempPath), tempPath);
    const std::wstring logFile = std::wstring(tempPath) + L"GuardDog_日志快照.txt";

    const std::wstring content =
        L"GuardDog 日志快照（由前端拉取）\r\n\r\n" + StripStatusPrefix(response);
    HANDLE file = CreateFileW(logFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        ShowInfo(L"无法写入日志快照文件。", MB_OK | MB_ICONWARNING);
        return;
    }

    // 以 UTF-16LE + BOM 写出，记事本才能正确显示中文
    const unsigned char bom[2] = {0xFF, 0xFE};
    DWORD written = 0;
    WriteFile(file, bom, sizeof(bom), &written, nullptr);
    WriteFile(file, content.c_str(), static_cast<DWORD>(content.size() * sizeof(wchar_t)), &written,
              nullptr);
    CloseHandle(file);

    ShellExecuteW(nullptr, L"open", L"notepad.exe", logFile.c_str(), nullptr, SW_SHOWNORMAL);
}

void RunScan() {
    SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    std::wstring response;
    if (SendCommand(L"SCAN", response)) {
        ShowInfo(L"存量扫描结果（仅发现，不会自动处置）：\n\n" + StripStatusPrefix(response),
                 FlagsForResponse(response));
    }
    SetCursor(LoadCursorW(nullptr, IDC_ARROW));
}

void OpenConfig() {
    const std::wstring path = ConfigPath();
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ShowInfo(L"配置文件尚不存在：\n" + path +
                     L"\n\n请先启动一次 GuardDog 服务，它会自动生成默认配置。",
                 MB_OK | MB_ICONWARNING);
        return;
    }
    ShellExecuteW(nullptr, L"open", L"notepad.exe", path.c_str(), nullptr, SW_SHOWNORMAL);
}

void AllowLastTarget() {
    std::wstring response;
    if (SendCommand(L"ALLOW_LAST", response)) {
        ShowInfo(StripStatusPrefix(response), FlagsForResponse(response));
    }
}

// 打开规则管理界面。关闭后顺手刷新一次状态与日志：
// 用户很可能刚保存了新规则，状态区能立刻反映"启用规则数"的变化。
void OpenRuleManager() {
    if (g_uiFont == nullptr) {
        return;
    }
    GuardDog::ShowRuleManagerDialog(g_mainWindow, g_uiFont);
    RefreshStatus();
    RefreshLog();
}

// 查询主服务当前是否在运行（用于决定按钮文字）
bool IsMainServiceRunning() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        return false;
    }

    bool running = false;
    SC_HANDLE service = OpenServiceW(scm, GuardDog::Constants::kServiceName, SERVICE_QUERY_STATUS);
    if (service != nullptr) {
        SERVICE_STATUS status{};
        if (QueryServiceStatus(service, &status)) {
            running = (status.dwCurrentState == SERVICE_RUNNING ||
                       status.dwCurrentState == SERVICE_START_PENDING);
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);
    return running;
}

// 启动/停止主服务。
//
// 服务控制需要管理员权限，而前端刻意以普通用户运行（不让整个界面常驻高权限）。
// 因此这里用 runas 拉起一个**提升的 sc.exe** 完成任务——UAC 只在这一个动作上出现，
// 界面的其余部分始终是普通权限。
void ControlMainService(bool start) {
    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = L"runas";  // 触发 UAC 提升
    info.lpFile = L"sc.exe";
    info.lpParameters = start ? L"start GuardDogService" : L"stop GuardDogService";
    info.nShow = SW_HIDE;

    if (!ShellExecuteExW(&info)) {
        const DWORD error = GetLastError();
        if (error == ERROR_CANCELLED) {
            return;  // 用户取消了 UAC，静默返回即可
        }
        ShowInfo(L"无法发起服务控制操作（需要管理员权限）。", MB_OK | MB_ICONWARNING);
        return;
    }

    if (info.hProcess != nullptr) {
        WaitForSingleObject(info.hProcess, 20000);
        CloseHandle(info.hProcess);
    }

    Sleep(2000);  // 给 SCM 一点时间完成状态切换
    RefreshStatus();
    RefreshLog();
}

void ShowWatchdogStatus() {
    std::wstring text;

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        ShowInfo(L"无法打开服务控制管理器（查询服务需要管理员权限）。", MB_OK | MB_ICONWARNING);
        return;
    }

    SC_HANDLE service =
        OpenServiceW(scm, GuardDog::Constants::kWatchdogServiceName, SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        text = L"看门狗服务未安装。\n\n安装命令（管理员）：\n    GuardDogWatchdog.exe install";
    } else {
        SERVICE_STATUS status{};
        if (QueryServiceStatus(service, &status)) {
            const wchar_t* stateText = L"未知";
            switch (status.dwCurrentState) {
                case SERVICE_RUNNING:       stateText = L"运行中"; break;
                case SERVICE_STOPPED:       stateText = L"已停止"; break;
                case SERVICE_START_PENDING: stateText = L"正在启动"; break;
                case SERVICE_STOP_PENDING:  stateText = L"正在停止"; break;
                default: break;
            }
            text = std::wstring(L"看门狗服务状态：") + stateText +
                   L"\n\n它每 30 秒检查一次主服务，发现未运行会自动拉起。";
        } else {
            text = L"查询看门狗状态失败。";
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);

    ShowInfo(text);
}

void ShowAbout() {
    const std::wstring mode = ReadStartupMode();
    ShowInfo(std::wstring(L"GuardDog ") + GuardDog::Constants::kVersion + L"\n" +
             GuardDog::Constants::kBuildStage +
             L"\n\n纯用户态防流氓软件防护工具。\n"
             L"服务端负责监控与清理；本界面用于查看状态，"
             L"并可通过「规则管理」可视化编辑拦截规则与防护开关。\n\n"
             L"当前启动模式：" + mode + L"（在配置文件的 startup_mode 中修改）\n"
             L"关闭窗口只是隐藏到托盘，退出程序也不会停止防护服务。");
}

void ShowMainWindow() {
    if (g_mainWindow == nullptr) {
        return;
    }
    ShowWindow(g_mainWindow, SW_SHOWNORMAL);
    SetForegroundWindow(g_mainWindow);
    RefreshStatus();
    RefreshLog();
}

void HideMainWindow() {
    if (g_mainWindow != nullptr) {
        ShowWindow(g_mainWindow, SW_HIDE);
    }
}

void ShowTrayMenu(HWND window) {
    POINT cursor{};
    GetCursorPos(&cursor);

    HMENU menu = CreatePopupMenu();
    if (menu == nullptr) {
        return;
    }

    AppendMenuW(menu, MF_STRING, kIdRefresh, L"显示主窗口");
    AppendMenuW(menu, MF_STRING, kIdFullLog, L"查看日志");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kIdScan, L"手动扫描（只读）");
    AppendMenuW(menu, MF_STRING, kIdAllowLast, L"临时放行最近处置的目标");
    AppendMenuW(menu, MF_STRING, kIdWatchdog, L"看门狗状态");
    AppendMenuW(menu, MF_STRING, kIdServiceCtrl,
                IsMainServiceRunning() ? L"停止防护服务" : L"启动防护服务");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kIdRules, L"规则管理（可视化配置）");
    AppendMenuW(menu, MF_STRING, kIdConfig, L"打开配置文件（高级）");
    AppendMenuW(menu, MF_STRING, kIdAbout, L"关于");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kIdExit, L"退出（不影响防护）");

    // TrackPopupMenu 要求先让本窗口成为前台窗口，否则点击菜单外部不会消失
    SetForegroundWindow(window);

    const UINT command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, cursor.x, cursor.y, 0,
                                        window, nullptr);
    DestroyMenu(menu);

    if (command == 0) {
        return;
    }

    switch (command) {
        case kIdRefresh:    ShowMainWindow(); break;
        case kIdFullLog:    OpenFullLog(); break;
        case kIdScan:       RunScan(); break;
        case kIdAllowLast:  AllowLastTarget(); break;
        case kIdWatchdog:   ShowWatchdogStatus(); break;
        case kIdServiceCtrl: ControlMainService(!IsMainServiceRunning()); break;
        case kIdRules:      OpenRuleManager(); break;
        case kIdConfig:     OpenConfig(); break;
        case kIdAbout:      ShowAbout(); break;
        case kIdHide:       HideMainWindow(); break;
        case kIdExit:       DestroyWindow(window); break;
        default: break;
    }
}

void HandleCommand(int id) {
    switch (id) {
        case kIdRefresh:    RefreshStatus(); RefreshLog(); break;
        case kIdFullLog:    OpenFullLog(); break;
        case kIdScan:       RunScan(); break;
        case kIdRules:      OpenRuleManager(); break;
        case kIdConfig:     OpenConfig(); break;
        case kIdAllowLast:  AllowLastTarget(); break;
        case kIdWatchdog:   ShowWatchdogStatus(); break;
        case kIdServiceCtrl: ControlMainService(!IsMainServiceRunning()); break;
        case kIdHide:       HideMainWindow(); break;
        case kIdExit:       DestroyWindow(g_mainWindow); break;
        default: break;
    }
}

// ---------------------------------------------------------------------------
// 窗口过程
// ---------------------------------------------------------------------------

LRESULT CALLBACK MainWindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE:
            CreateFonts();  // 控件创建前先把字体准备好
            CreateControls(window);
            return 0;

        case WM_SIZE:
            LayoutControls(window, LOWORD(lParam), HIWORD(lParam));
            return 0;

        case WM_GETMINMAXINFO: {
            auto* info = reinterpret_cast<MINMAXINFO*>(lParam);
            info->ptMinTrackSize.x = kMinWindowWidth;
            info->ptMinTrackSize.y = kMinWindowHeight;
            return 0;
        }

        case WM_COMMAND:
            HandleCommand(LOWORD(wParam));
            return 0;

        case kTrayCallbackMessage:
            if (LOWORD(lParam) == WM_LBUTTONDBLCLK) {
                ShowMainWindow();
            } else if (LOWORD(lParam) == WM_RBUTTONUP || LOWORD(lParam) == WM_CONTEXTMENU) {
                ShowTrayMenu(window);
            }
            return 0;

        case WM_CLOSE:
            // 关闭主窗口只隐藏到托盘：用户很容易把"关掉界面"理解成"停了防护"，
            // 如果这里真的退出进程，反而会让人以为防护没了（其实服务一直独立运行）。
            HideMainWindow();
            return 0;

        case WM_DESTROY:
            Shell_NotifyIconW(NIM_DELETE, &g_trayData);
            DestroyFonts();
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProcW(window, message, wParam, lParam);
    }
}

// ---------------------------------------------------------------------------
// 登录启动项
// ---------------------------------------------------------------------------

bool InstallAutoStart() {
    const std::wstring executable = GetSelfPath();
    if (executable.empty()) {
        return false;
    }

    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRunKeyPath, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key,
                        nullptr) != ERROR_SUCCESS) {
        return false;
    }

    const std::wstring command = L"\"" + executable + L"\"";
    const LSTATUS status =
        RegSetValueExW(key, kRunValueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(command.c_str()),
                       static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    return status == ERROR_SUCCESS;
}

bool UninstallAutoStart() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunKeyPath, 0, KEY_SET_VALUE, &key) != ERROR_SUCCESS) {
        return true;  // 键不存在等于"已无自启动项"
    }
    const LSTATUS status = RegDeleteValueW(key, kRunValueName);
    RegCloseKey(key);
    return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
}

void RegisterTrayIcon(HWND window) {
    g_trayData.cbSize = sizeof(g_trayData);
    g_trayData.hWnd = window;
    g_trayData.uID = kTrayIconId;
    g_trayData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_trayData.uCallbackMessage = kTrayCallbackMessage;
    g_trayData.hIcon = LoadIconW(nullptr, IDI_APPLICATION);  // 用系统图标，避免引入资源文件
    wcscpy_s(g_trayData.szTip, L"GuardDog 防护中（双击显示主窗口）");

    Shell_NotifyIconW(NIM_ADD, &g_trayData);
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE /*prevInstance*/, LPWSTR commandLine,
                    int /*showCommand*/) {
    // 命令行：install / uninstall 用于把前端注册到当前用户的登录启动项
    const std::wstring command(commandLine != nullptr ? commandLine : L"");
    if (!command.empty()) {
        if (_wcsicmp(command.c_str(), L"install") == 0) {
            const bool ok = InstallAutoStart();
            MessageBoxW(nullptr,
                        ok ? L"已把 GuardDog 前端加入当前用户的登录启动项。"
                           : L"写入登录启动项失败（请检查当前用户权限）。",
                        L"GuardDog", MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONWARNING));
            return ok ? 0 : 1;
        }
        if (_wcsicmp(command.c_str(), L"uninstall") == 0) {
            const bool ok = UninstallAutoStart();
            MessageBoxW(nullptr, ok ? L"已移除登录启动项。" : L"移除登录启动项失败。", L"GuardDog",
                        MB_OK | (ok ? MB_ICONINFORMATION : MB_ICONWARNING));
            return ok ? 0 : 1;
        }
    }

    // 启动模式：配置文件说了算
    const std::wstring startupMode = ReadStartupMode();
    g_startedHidden = (_wcsicmp(startupMode.c_str(), L"hidden") == 0);

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = MainWindowProc;
    windowClass.hInstance = instance;
    windowClass.lpszClassName = kWindowClassName;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);

    if (RegisterClassExW(&windowClass) == 0) {
        return 1;
    }

    g_mainWindow = CreateWindowExW(0, kWindowClassName, L"GuardDog 防护面板",
                                   WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, kWindowWidth,
                                   kWindowHeight, nullptr, nullptr, instance, nullptr);
    if (g_mainWindow == nullptr) {
        return 1;
    }

    // 托盘图标无论哪种模式都要注册：
    // hidden 模式下它是用户唯一的入口，gui 模式下关闭窗口后也靠它唤回。
    RegisterTrayIcon(g_mainWindow);

    if (!g_startedHidden) {
        ShowWindow(g_mainWindow, SW_SHOWNORMAL);
        UpdateWindow(g_mainWindow);
        RefreshStatus();
        RefreshLog();
    }

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }

    return 0;
}